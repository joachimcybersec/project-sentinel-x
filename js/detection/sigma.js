/**
 * In-browser Sigma subset: validator, compiler and evaluator (pure functions).
 *
 * Implemented from the public Sigma specification (https://github.com/SigmaHQ/sigma-specification):
 *   - logsource matching on product / category / service
 *   - selections as maps (AND across fields, OR across a field's value list),
 *     lists of maps (OR) and keyword lists (full-text, case-insensitive)
 *   - value wildcards * and ?, case-insensitive string matching, null values
 *   - modifiers: contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte
 *   - conditions: and, or, not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them"
 * Not implemented (reported as validation errors): other modifiers (base64, windash, …),
 * aggregation conditions ("| count() …") and correlation rules.
 *
 * This is NOT pySigma. Rules tested here should still be checked with sigma-cli /
 * pySigma and against real backend data before production use.
 */
import { parseYaml } from './yaml.js';

export const SUPPORTED_MODIFIERS = ['contains', 'startswith', 'endswith', 'all', 're', 'cidr', 'gt', 'gte', 'lt', 'lte'];
const STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];
const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TAG = /^[a-z0-9_-]+\.[a-z0-9._-]+$/;
const MAX_RE = 200;

/* ------------------------------------------------------------------ */
/* Condition parsing                                                    */
/* ------------------------------------------------------------------ */

export function tokenizeCondition(cond) {
  const re = /\s*(\(|\)|\b(?:and|or|not)\b|\b(?:1|all|any) of\s+[\w*]+|[\w*]+)\s*/gy;
  const out = []; let m; re.lastIndex = 0;
  const s = String(cond);
  while (re.lastIndex < s.length) {
    const start = re.lastIndex;
    m = re.exec(s);
    if (!m || m.index !== start) throw new Error(`Unexpected character in condition near "${s.slice(start, start + 15)}"`);
    out.push(m[1]);
  }
  return out;
}

/** Recursive descent: or > and > not > primary. Returns an AST. */
export function parseCondition(cond) {
  if (/\|/.test(cond)) throw new Error('Aggregation conditions (| count() …) are not supported by this evaluator');
  const t = tokenizeCondition(cond);
  let i = 0;
  const peek = () => t[i];
  const expr = () => { let n = term(); while (peek() === 'or') { i++; n = { op: 'or', a: n, b: term() }; } return n; };
  const term = () => { let n = factor(); while (peek() === 'and') { i++; n = { op: 'and', a: n, b: factor() }; } return n; };
  const factor = () => {
    const tok = t[i++];
    if (tok === undefined) throw new Error('Condition ended unexpectedly');
    if (tok === 'not') return { op: 'not', a: factor() };
    if (tok === '(') { const n = expr(); if (t[i++] !== ')') throw new Error('Missing closing parenthesis'); return n; }
    if (tok === ')' || tok === 'and' || tok === 'or') throw new Error(`Unexpected "${tok}" in condition`);
    const of = tok.match(/^(1|all|any) of\s+([\w*]+)$/);
    if (of) return { op: 'of', quant: of[1] === 'all' ? 'all' : 'any', pattern: of[2] };
    return { op: 'id', name: tok };
  };
  const ast = expr();
  if (i < t.length) throw new Error(`Unexpected "${t[i]}" in condition`);
  return ast;
}

const globRe = (p) => new RegExp(`^${p.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);

function resolveOf(pattern, names) {
  if (pattern === 'them') return names.filter((n) => !n.startsWith('_'));
  const re = globRe(pattern);
  return names.filter((n) => re.test(n));
}

function conditionIds(ast, names, acc = new Set()) {
  if (!ast) return acc;
  if (ast.op === 'id') acc.add(ast.name);
  else if (ast.op === 'of') resolveOf(ast.pattern, names).forEach((n) => acc.add(n));
  else { conditionIds(ast.a, names, acc); conditionIds(ast.b, names, acc); }
  return acc;
}

/* ------------------------------------------------------------------ */
/* Value matching                                                       */
/* ------------------------------------------------------------------ */

/** Sigma wildcard → RegExp. \* \? \\ are escapes; other backslashes are literal. */
export function sigmaPattern(value, { prefix = false, suffix = false } = {}) {
  const s = String(value);
  let out = '';
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === '\\' && (s[k + 1] === '*' || s[k + 1] === '?' || s[k + 1] === '\\')) { out += `\\${s[++k]}`; continue; }
    if (c === '*') out += '.*';
    else if (c === '?') out += '.';
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${prefix ? '.*' : ''}${out}${suffix ? '.*' : ''}$`, 'is');
}

function ipv4ToInt(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
export function inCidr(ip, cidr) {
  const [net, bits] = String(cidr).split('/');
  const a = ipv4ToInt(ip), n = ipv4ToInt(net), b = Number(bits);
  if (a === null || n === null || !Number.isInteger(b) || b < 0 || b > 32) return false;
  const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
  return ((a & mask) >>> 0) === ((n & mask) >>> 0);
}

/** Build a predicate for one "Field|mod|mod: values" entry. */
function fieldMatcher(spec, values) {
  const [field, ...mods] = spec.split('|');
  for (const m of mods) if (!SUPPORTED_MODIFIERS.includes(m)) throw new Error(`Unsupported modifier "${m}" on ${field}`);
  const list = Array.isArray(values) ? values : [values];
  const all = mods.includes('all');
  const has = (m) => mods.includes(m);
  const tests = list.map((v) => {
    if (v === null) return (x) => x === undefined || x === null || x === '';
    if (has('re')) {
      if (String(v).length > MAX_RE) throw new Error(`Regular expression on ${field} longer than ${MAX_RE} characters`);
      let re; try { re = new RegExp(String(v)); } catch (e) { throw new Error(`Invalid regular expression on ${field}: ${e.message}`); }
      return (x) => x !== undefined && x !== null && re.test(String(x));
    }
    if (has('cidr')) return (x) => x !== undefined && inCidr(x, v);
    for (const op of ['gte', 'gt', 'lte', 'lt']) {
      if (has(op)) {
        const n = Number(v);
        if (!Number.isFinite(n)) throw new Error(`Modifier ${op} on ${field} needs a number`);
        return (x) => { const y = Number(x); return x !== undefined && x !== '' && Number.isFinite(y) && ({ gte: y >= n, gt: y > n, lte: y <= n, lt: y < n })[op]; };
      }
    }
    const re = sigmaPattern(v, { prefix: has('contains') || has('endswith'), suffix: has('contains') || has('startswith') });
    return (x) => x !== undefined && x !== null && re.test(String(x));
  });
  return (event) => {
    const x = event.fields[field];
    return all ? tests.every((t) => t(x)) : tests.some((t) => t(x));
  };
}

/** Compile one detection identifier (map, list of maps, or keyword list). */
function compileSelection(name, def) {
  if (def && typeof def === 'object' && !Array.isArray(def)) {
    const preds = Object.entries(def).map(([k, v]) => fieldMatcher(k, v));
    if (!preds.length) throw new Error(`Selection "${name}" is empty`);
    return (e) => preds.every((p) => p(e));
  }
  if (Array.isArray(def) && def.length && def.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
    const subs = def.map((d, k) => compileSelection(`${name}[${k}]`, d));
    return (e) => subs.some((s) => s(e));
  }
  if (Array.isArray(def) || typeof def === 'string' || typeof def === 'number') {
    const kws = (Array.isArray(def) ? def : [def]).map((v) => sigmaPattern(v, { prefix: true, suffix: true }));
    return (e) => kws.some((re) => re.test(e.raw));
  }
  throw new Error(`Selection "${name}" must be a map, a list of maps or a keyword list`);
}

/* ------------------------------------------------------------------ */
/* Validation & compilation                                             */
/* ------------------------------------------------------------------ */

/** Parse YAML text and validate it as a Sigma rule. Returns { rule, errors, warnings }. */
export function validateSigma(textOrObj) {
  const errors = [], warnings = [];
  let rule = textOrObj;
  if (typeof textOrObj === 'string') {
    try { rule = parseYaml(textOrObj); } catch (e) { return { rule: null, errors: [e.message], warnings }; }
  }
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return { rule: null, errors: ['Rule must be a YAML mapping'], warnings };

  if (typeof rule.title !== 'string' || !rule.title) errors.push('title is required');
  else if (rule.title.length > 256) errors.push('title must be at most 256 characters');
  if (!UUID.test(String(rule.id || ''))) errors.push('id must be a UUID');
  if (!STATUSES.includes(rule.status)) errors.push(`status must be one of ${STATUSES.join(', ')}`);
  if (!LEVELS.includes(rule.level)) errors.push(`level must be one of ${LEVELS.join(', ')}`);
  const ls = rule.logsource;
  if (!ls || typeof ls !== 'object' || !['product', 'category', 'service'].some((k) => ls[k])) errors.push('logsource needs at least one of product, category, service');
  if (!rule.description) warnings.push('description is recommended');
  if (!rule.author) warnings.push('author is recommended');
  if (rule.date !== undefined && !/^\d{4}[-/]\d{2}[-/]\d{2}$/.test(String(rule.date))) warnings.push('date should be YYYY-MM-DD');
  if (!Array.isArray(rule.falsepositives)) warnings.push('falsepositives list is recommended');
  if (rule.tags !== undefined) {
    if (!Array.isArray(rule.tags)) errors.push('tags must be a list');
    else rule.tags.forEach((t) => { if (!TAG.test(String(t))) warnings.push(`tag "${t}" should look like namespace.value in lowercase`); });
    if (Array.isArray(rule.tags) && !rule.tags.some((t) => /^attack\.t\d{4}/.test(t))) warnings.push('no ATT&CK technique tag (attack.tNNNN)');
  } else warnings.push('tags are recommended (ATT&CK mapping)');

  const det = rule.detection;
  if (!det || typeof det !== 'object' || Array.isArray(det)) { errors.push('detection must be a mapping'); return { rule, errors, warnings }; }
  if (!det.condition) { errors.push('detection.condition is required'); return { rule, errors, warnings }; }
  const names = Object.keys(det).filter((k) => k !== 'condition' && k !== 'timeframe');
  if (!names.length) errors.push('detection needs at least one search identifier');
  const conds = Array.isArray(det.condition) ? det.condition : [det.condition];
  const used = new Set();
  for (const c of conds) {
    try {
      const ast = parseCondition(String(c));
      conditionIds(ast, names).forEach((n) => used.add(n));
      (function check(a) {
        if (!a) return;
        if (a.op === 'id' && !names.includes(a.name)) errors.push(`condition references unknown identifier "${a.name}"`);
        if (a.op === 'of' && !resolveOf(a.pattern, names).length) errors.push(`"${a.pattern}" in condition matches no identifier`);
        check(a.a); check(a.b);
      })(ast);
    } catch (e) { errors.push(`condition: ${e.message}`); }
  }
  names.filter((n) => !used.has(n)).forEach((n) => warnings.push(`identifier "${n}" is not used in the condition`));
  for (const n of names) { try { compileSelection(n, det[n]); } catch (e) { errors.push(e.message); } }
  return { rule, errors, warnings };
}

/** Compile a validated rule into { logsource, match(event) }. Throws on invalid rules. */
export function compileSigma(rule) {
  const det = rule.detection;
  const names = Object.keys(det).filter((k) => k !== 'condition' && k !== 'timeframe');
  const sel = Object.fromEntries(names.map((n) => [n, compileSelection(n, det[n])]));
  const conds = (Array.isArray(det.condition) ? det.condition : [det.condition]).map((c) => parseCondition(String(c)));
  const evalAst = (a, e) => {
    switch (a.op) {
      case 'and': return evalAst(a.a, e) && evalAst(a.b, e);
      case 'or': return evalAst(a.a, e) || evalAst(a.b, e);
      case 'not': return !evalAst(a.a, e);
      case 'id': return sel[a.name](e);
      case 'of': { const ids = resolveOf(a.pattern, names); return a.quant === 'all' ? ids.every((n) => sel[n](e)) : ids.some((n) => sel[n](e)); }
      default: return false;
    }
  };
  return { logsource: rule.logsource || {}, match: (e) => conds.some((c) => evalAst(c, e)) };
}

/* ------------------------------------------------------------------ */
/* Mapping parsed logs to Sigma events                                  */
/* ------------------------------------------------------------------ */

const SYSMON_CATEGORY = { 1: 'process_creation', 3: 'network_connection', 10: 'process_access', 11: 'file_event', 13: ['registry_set', 'registry_event'], 22: 'dns_query' };

/**
 * Convert a processed log entry ({ raw, parsed }) into a Sigma event:
 * { tags: { product, category, service }, fields, raw }. Field names follow the
 * Sigma taxonomy for each log source.
 */
export function toSigmaEvent(entry) {
  const p = entry.parsed;
  if (!p || p.type === 'unknown') return null;
  const f = p.fields;
  switch (p.type) {
    case 'sysmon': return { tags: { product: 'windows', category: SYSMON_CATEGORY[f.EventID] || null, service: 'sysmon' }, fields: f, raw: entry.raw };
    case 'powershell': return { tags: { product: 'windows', category: f.EventID === '4104' ? 'ps_script' : null, service: 'powershell' }, fields: f, raw: entry.raw };
    case 'windows': return { tags: { product: 'windows', service: 'security' }, fields: f, raw: entry.raw };
    case 'linux-auth': return { tags: { product: 'linux', service: [f.program, 'auth'] }, fields: { message: f.message, program: f.program }, raw: entry.raw };
    case 'firewall': return { tags: { category: 'firewall' }, fields: { ...f, src_ip: f.src, dst_ip: f.dst, src_port: f.spt, dst_port: f.dpt }, raw: entry.raw };
    // Taxonomy names (dns.question.*) plus the short "query" name common in community rules
    case 'dns': return { tags: { category: 'dns', service: 'dns' }, fields: { 'dns.question.name': f.query, 'dns.question.type': f.qtype, query: f.query, src_ip: f.client }, raw: entry.raw };
    case 'web': {
      const [stem, ...q] = f.path.split('?');
      return { tags: { category: 'webserver' }, fields: { 'c-ip': f.clientIp, 'cs-method': f.method, 'cs-uri-stem': stem, 'cs-uri-query': q.join('?'), 'sc-status': f.status, 'cs-user-agent': f.userAgent, 'cs-referrer': f.referrer }, raw: entry.raw };
    }
    default: return { tags: {}, fields: f, raw: entry.raw };
  }
}

export function logsourceMatches(ls, tags) {
  const keys = ['product', 'category', 'service'].filter((k) => ls[k]);
  if (!keys.length) return false;
  return keys.every((k) => { const v = tags[k]; return Array.isArray(v) ? v.includes(ls[k]) : v === ls[k]; });
}

/** Run a rule (YAML text or object) over processed log entries. */
export function runSigma(ruleOrText, entries) {
  const v = validateSigma(ruleOrText);
  if (v.errors.length) return { ...v, matches: [], considered: 0 };
  const compiled = compileSigma(v.rule);
  const matches = []; let considered = 0;
  for (const entry of entries) {
    const ev = toSigmaEvent(entry);
    if (!ev || !logsourceMatches(compiled.logsource, ev.tags)) continue;
    considered++;
    if (compiled.match(ev)) matches.push(entry.id);
  }
  return { ...v, matches, considered };
}
