/**
 * A tiny SIEM-style query language (pure functions).
 *
 *   field:value         exact match (case-insensitive), e.g. event.code:4625
 *   field:*suffix       wildcard; * matches any run of characters
 *   field:"two words"   quoted value
 *   -field:value        negation
 *   free text           substring of the raw line (all terms must match)
 *   -text               raw line must NOT contain text
 *
 * Aliases: ip (source.ip or destination.ip), user, host, code, type, src, dst, domain.
 * Values are never compiled as user-supplied regular expressions; wildcards are
 * escaped first, so a query cannot cause catastrophic backtracking.
 */

export const MAX_QUERY = 300;

export const ALIASES = {
  ip: ['source.ip', 'destination.ip'],
  src: ['source.ip'],
  dst: ['destination.ip'],
  user: ['user.name'],
  host: ['host.name'],
  code: ['event.code'],
  type: ['log.type'],
  domain: ['dns.question.name'],
  action: ['event.action'],
  outcome: ['event.outcome']
};

export function parseQuery(q) {
  const text = String(q || '').slice(0, MAX_QUERY);
  const tokens = text.match(/-?[\w.@]+:"[^"]*"|-?[\w.@]+:\S+|-?"[^"]*"|\S+/g) || [];
  const fields = [];
  const terms = [];
  const errors = [];
  for (let tok of tokens) {
    const neg = tok.startsWith('-') && tok.length > 1;
    if (neg) tok = tok.slice(1);
    const fm = tok.match(/^([\w.@]+):(.*)$/);
    if (fm) {
      const value = fm[2].replace(/^"(.*)"$/, '$1');
      if (!value) { errors.push(`Missing value for ${fm[1]}`); continue; }
      fields.push({ key: fm[1].toLowerCase(), value, neg });
    } else {
      const t = tok.replace(/^"(.*)"$/, '$1');
      if (t) terms.push({ value: t.toLowerCase(), neg });
    }
  }
  return { fields, terms, errors };
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function valueMatcher(value) {
  const v = value.toLowerCase();
  if (!v.includes('*')) return (x) => String(x).toLowerCase() === v;
  const re = new RegExp(`^${v.split('*').map(escapeRe).join('.*')}$`, 's');
  return (x) => re.test(String(x).toLowerCase());
}

/** entry: { raw, norm } */
export function matchQuery(entry, query) {
  const norm = entry.norm || {};
  const raw = String(entry.raw || '').toLowerCase();
  for (const f of query.fields) {
    const keys = ALIASES[f.key] || [f.key];
    const test = valueMatcher(f.value);
    const hit = keys.some((k) => norm[k] !== undefined && norm[k] !== null && test(norm[k]));
    if (hit === f.neg) return false;
  }
  for (const t of query.terms) {
    if (raw.includes(t.value) === t.neg) return false;
  }
  return true;
}

export function runQuery(entries, q) {
  const query = parseQuery(q);
  return { query, results: entries.filter((e) => matchQuery(e, query)) };
}
