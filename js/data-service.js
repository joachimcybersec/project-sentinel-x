/**
 * Data service — the single gateway for all data the UI consumes.
 *
 * Responsibilities
 *  - Fetch same-origin JSON datasets (CSP connect-src 'self').
 *  - Time out slow requests and surface typed errors.
 *  - Validate dataset shape before any view sees it.
 *  - Cache in memory per session so navigation is instant.
 *  - Attach provenance + fetch metadata so the UI can show freshness.
 *
 * Phase 9 adds live endpoints (/api/*) behind the same interface; views will
 * not need to change.
 */

const DEFAULT_TIMEOUT_MS = 8000;
const cache = new Map();

export class DataError extends Error {
  constructor(message, { dataset, cause, kind = 'unknown' } = {}) {
    super(message);
    this.name = 'DataError';
    this.dataset = dataset;
    this.kind = kind; // 'network' | 'timeout' | 'http' | 'parse' | 'schema'
    this.cause = cause;
  }
}

/** Registry of datasets the app is allowed to load, with validators. */
export const DATASETS = {
  modules: { path: 'data/modules.json', validate: validateModules },
  events:  { path: 'data/sample-events.json', validate: validateEvents },
  telemetry: { path: 'data/soc-telemetry.json', validate: validateTelemetry },
  intel: { path: 'data/threat-intelligence.json', validate: validateIntel },
  attacks: { path: 'data/attack-library.json', validate: validateAttacks },
  logs: { path: 'data/sample-logs.json', validate: validateLogs },
  incidents: { path: 'data/incidents.json', validate: validateIncidents },
  siemTools: { path: 'data/siem-tools.json', validate: validateSiemTools },
  detections: { path: 'data/detection-rules.json', validate: validateDetections },
  cves: { path: 'data/cve-snapshot.json', validate: validateCves },
  network: { path: 'data/network.json', validate: validateNetwork },
  tools: { path: 'data/tools.json', validate: validateTools },
  knowledge: { path: 'data/knowledge.json', validate: validateKnowledge }
};

export async function load(name, { force = false, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const spec = DATASETS[name];
  if (!spec) throw new DataError(`Unknown dataset "${name}"`, { dataset: name, kind: 'schema' });
  if (!force && cache.has(name)) return cache.get(name);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(spec.path, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      cache: force ? 'reload' : 'default'
    });
  } catch (err) {
    const kind = err.name === 'AbortError' ? 'timeout' : 'network';
    throw new DataError(`Could not load ${name} (${kind})`, { dataset: name, cause: err, kind });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) throw new DataError(`Could not load ${name} (HTTP ${res.status})`, { dataset: name, kind: 'http' });

  let json;
  try {
    json = await res.json();
  } catch (err) {
    throw new DataError(`${name} is not valid JSON`, { dataset: name, cause: err, kind: 'parse' });
  }

  const problems = spec.validate(json);
  if (problems.length) {
    throw new DataError(`${name} failed validation: ${problems.slice(0, 3).join('; ')}`, { dataset: name, kind: 'schema' });
  }

  const result = { data: json, meta: { dataset: name, fetchedAt: new Date().toISOString(), source: spec.path } };
  cache.set(name, result);
  return result;
}

export function clearCache() { cache.clear(); }

/* ------------------------------------------------------------------ */
/* Validators — return an array of human-readable problems (empty = ok) */
/* ------------------------------------------------------------------ */

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const STATUSES = new Set(['open', 'investigating', 'contained', 'closed']);
const MITRE_ID = /^T\d{4}(\.\d{3})?$/;

export function validateModules(json) {
  const p = [];
  if (!json || !Array.isArray(json.modules)) return ['modules must be an array'];
  const ids = new Set();
  json.modules.forEach((m, i) => {
    const at = `modules[${i}]`;
    for (const k of ['id', 'num', 'route', 'title', 'summary', 'status']) {
      if (typeof m[k] !== 'string' || !m[k]) p.push(`${at}.${k} missing`);
    }
    if (m.route && !m.route.startsWith('/')) p.push(`${at}.route must start with /`);
    if (!['live', 'planned'].includes(m.status)) p.push(`${at}.status invalid`);
    if (!Array.isArray(m.features)) p.push(`${at}.features must be an array`);
    if (ids.has(m.id)) p.push(`${at}.id duplicate "${m.id}"`);
    ids.add(m.id);
  });
  return p;
}

export function validateEvents(json) {
  const p = [];
  if (!json || json.provenance !== 'simulated') p.push('events dataset must declare provenance "simulated"');
  if (!json || !Array.isArray(json.events)) return [...p, 'events must be an array'];
  const ids = new Set();
  json.events.forEach((e, i) => {
    const at = `events[${i}]`;
    if (!e.id || ids.has(e.id)) p.push(`${at}.id missing or duplicate`);
    ids.add(e.id);
    if (Number.isNaN(Date.parse(e.ts))) p.push(`${at}.ts invalid`);
    if (!SEVERITIES.has(e.severity)) p.push(`${at}.severity invalid`);
    if (!STATUSES.has(e.status)) p.push(`${at}.status invalid`);
    if (e.mitre && !MITRE_ID.test(e.mitre)) p.push(`${at}.mitre "${e.mitre}" malformed`);
    if (typeof e.message !== 'string' || !e.message) p.push(`${at}.message missing`);
  });
  return p;
}

const HEALTH = new Set(['operational', 'degraded', 'down', 'not-configured']);

export function validateTelemetry(json) {
  const p = [];
  if (!json || json.provenance !== 'simulated') p.push('telemetry must declare provenance "simulated"');
  if (!json || !Array.isArray(json.network) || !json.network.length) return [...p, 'network must be a non-empty array'];
  let prev = -Infinity;
  json.network.forEach((b, i) => {
    const t = Date.parse(b.ts);
    if (Number.isNaN(t)) p.push(`network[${i}].ts invalid`);
    else if (t <= prev) p.push(`network[${i}].ts not ascending`);
    prev = t;
    for (const k of ['inboundMB', 'outboundMB', 'dnsQueries']) {
      if (!Number.isFinite(b[k]) || b[k] < 0) p.push(`network[${i}].${k} must be a non-negative number`);
    }
  });
  if (!Array.isArray(json.health)) p.push('health must be an array');
  else json.health.forEach((h, i) => {
    if (!h.name) p.push(`health[${i}].name missing`);
    if (!HEALTH.has(h.status)) p.push(`health[${i}].status invalid`);
  });
  return p;
}

/* ---- documented intelligence: every claim must be traceable to a source ---- */

const SOURCE_DATE = /^(\d{4}(-\d{2}(-\d{2})?)?|n\.d\.|continuously updated)$/;
const ID = /^[a-z0-9-]{2,60}$/;

function validateSources(sources, at, p) {
  if (!Array.isArray(sources) || !sources.length) { p.push(`${at}: at least one source required`); return; }
  sources.forEach((s, i) => {
    if (!s.title || !s.publisher) p.push(`${at}.sources[${i}] title/publisher missing`);
    if (typeof s.url !== 'string' || !s.url.startsWith('https://')) p.push(`${at}.sources[${i}].url must be https`);
    if (!SOURCE_DATE.test(String(s.date))) p.push(`${at}.sources[${i}].date "${s.date}" invalid`);
  });
}

function validateCitedFacts(facts, sources, at, p) {
  if (!Array.isArray(facts) || !facts.length) { p.push(`${at}: facts required`); return; }
  facts.forEach((f, i) => {
    if (!f.text) p.push(`${at}.facts[${i}].text missing`);
    if (!Number.isInteger(f.source) || !sources || !sources[f.source]) p.push(`${at}.facts[${i}] cites missing source ${f.source}`);
  });
}

function validateTechniques(list, at, p) {
  if (!Array.isArray(list) || !list.length) p.push(`${at}.techniques required`);
  else list.forEach((t) => { if (!MITRE_ID.test(t)) p.push(`${at}.techniques "${t}" malformed`); });
}

export const INTEL_TYPES = ['apt', 'ransomware', 'cybercrime', 'botnet', 'phishing', 'exploitation'];

export function validateIntel(json) {
  const p = [];
  if (!json || json.provenance !== 'documented') p.push('intel must declare provenance "documented"');
  if (!json || !Array.isArray(json.profiles)) return [...p, 'profiles must be an array'];
  const ids = new Set();
  json.profiles.forEach((x, i) => {
    const at = `profiles[${i}]`;
    if (!ID.test(x.id || '') || ids.has(x.id)) p.push(`${at}.id missing, malformed or duplicate`);
    ids.add(x.id);
    if (!INTEL_TYPES.includes(x.type)) p.push(`${at}.type invalid`);
    for (const k of ['name', 'summary', 'attribution']) if (!x[k]) p.push(`${at}.${k} missing`);
    validateSources(x.sources, at, p);
    validateCitedFacts(x.facts, x.sources, at, p);
    validateTechniques(x.techniques, at, p);
    (x.incidents || []).forEach((inc, j) => {
      if (!x.sources || !x.sources[inc.source]) p.push(`${at}.incidents[${j}] cites missing source`);
      if (!SOURCE_DATE.test(inc.date)) p.push(`${at}.incidents[${j}].date invalid`);
    });
  });
  const ioc = json.iocWatchlist;
  if (!ioc || ioc.provenance !== 'simulated' || !Array.isArray(ioc.items)) p.push('iocWatchlist must be simulated with items');
  return p;
}

export const ATTACK_CATEGORIES = ['initial-access', 'execution', 'privilege-escalation', 'credential-access', 'lateral-movement', 'command-and-control', 'web-application', 'impact'];
const DOSSIER_LISTS = ['methodology', 'indicators', 'logSources', 'detections', 'controls', 'response'];

export function validateAttacks(json) {
  const p = [];
  if (!json || json.provenance !== 'documented') p.push('attacks must declare provenance "documented"');
  if (!json || !Array.isArray(json.attacks)) return [...p, 'attacks must be an array'];
  const ids = new Set();
  json.attacks.forEach((a, i) => {
    const at = `attacks[${i}]`;
    if (!ID.test(a.id || '') || ids.has(a.id)) p.push(`${at}.id missing, malformed or duplicate`);
    ids.add(a.id);
    if (!ATTACK_CATEGORIES.includes(a.category)) p.push(`${at}.category invalid`);
    if (!a.name || !a.overview) p.push(`${at}.name/overview missing`);
    for (const k of DOSSIER_LISTS) if (!Array.isArray(a[k]) || !a[k].length) p.push(`${at}.${k} must be a non-empty array`);
    validateSources(a.references, at, p);
    if (!a.incident || !a.incident.title || !SOURCE_DATE.test(a.incident.date || '')) p.push(`${at}.incident title/date invalid`);
    else validateCitedFacts(a.incident.facts, a.references, `${at}.incident`, p);
    validateTechniques(a.techniques, at, p);
  });
  return p;
}

/* ---- Phase 5: logs, incidents, SIEM tool references ---- */

export const LOG_TYPES = ['windows', 'sysmon', 'powershell', 'linux-auth', 'firewall', 'dns', 'web', 'edr'];

export function validateLogs(json) {
  const p = [];
  if (!json || json.provenance !== 'simulated') p.push('logs must declare provenance "simulated"');
  if (!json || !Array.isArray(json.logs) || !json.logs.length) return [...p, 'logs must be a non-empty array'];
  const ids = new Set();
  json.logs.forEach((l, i) => {
    if (!/^LOG-\d{3}$/.test(l.id || '') || ids.has(l.id)) p.push(`logs[${i}].id missing, malformed or duplicate`);
    ids.add(l.id);
    if (!LOG_TYPES.includes(l.type)) p.push(`logs[${i}].type invalid`);
    if (typeof l.raw !== 'string' || !l.raw) p.push(`logs[${i}].raw missing`);
  });
  if (!Array.isArray(json.assets)) p.push('assets must be an array');
  return p;
}

export const INCIDENT_STATUSES = ['open', 'investigating', 'contained', 'closed'];
export const IR_PHASES = ['identification', 'classification', 'analysis', 'containment', 'eradication', 'recovery', 'lessons'];

export function validateIncidents(json) {
  const p = [];
  if (!json || json.provenance !== 'simulated') p.push('incidents must declare provenance "simulated"');
  if (!json || !Array.isArray(json.incidents)) return [...p, 'incidents must be an array'];
  const ids = new Set();
  json.incidents.forEach((x, i) => {
    const at = `incidents[${i}]`;
    if (!/^IR-\d{4}-\d{3}$/.test(x.id || '') || ids.has(x.id)) p.push(`${at}.id missing, malformed or duplicate`);
    ids.add(x.id);
    if (!SEVERITIES.has(x.severity)) p.push(`${at}.severity invalid`);
    if (!INCIDENT_STATUSES.includes(x.status)) p.push(`${at}.status invalid`);
    if (!IR_PHASES.includes(x.phase)) p.push(`${at}.phase invalid`);
    for (const k of ['impact', 'urgency']) if (![1, 2, 3].includes(x[k])) p.push(`${at}.${k} must be 1–3`);
    if (Number.isNaN(Date.parse(x.detectedAt))) p.push(`${at}.detectedAt invalid`);
    for (const k of ['timeline', 'investigation', 'containment', 'eradication', 'recovery', 'lessons', 'logs']) {
      if (!Array.isArray(x[k]) || !x[k].length) p.push(`${at}.${k} must be a non-empty array`);
    }
    validateTechniques(x.techniques, at, p);
  });
  if (Array.isArray(json.references)) validateSources(json.references, 'incidents.references', p);
  return p;
}

export function validateSiemTools(json) {
  const p = [];
  if (!json || !Array.isArray(json.tools)) return ['tools must be an array'];
  json.tools.forEach((t, i) => {
    if (!t.name || !t.role) p.push(`tools[${i}] name/role missing`);
    if (typeof t.url !== 'string' || !t.url.startsWith('https://')) p.push(`tools[${i}].url must be https`);
    if (t.integration !== 'not-integrated') p.push(`tools[${i}].integration must be "not-integrated" until an integration is built and tested`);
  });
  return p;
}

/** Structural check of the rule library file. Sigma semantics are validated by js/detection/sigma.js. */
export function validateDetections(json) {
  const p = [];
  if (!json || json.provenance !== 'lab') p.push('detections must declare provenance "lab"');
  if (!json || !Array.isArray(json.rules) || !json.rules.length) return [...p, 'rules must be a non-empty array'];
  const slugs = new Set();
  json.rules.forEach((r, i) => {
    const at = `rules[${i}]`;
    if (!ID.test(r.slug || '') || slugs.has(r.slug)) p.push(`${at}.slug missing, malformed or duplicate`);
    slugs.add(r.slug);
    if (!Array.isArray(r.yaml) || !r.yaml.every((l) => typeof l === 'string')) p.push(`${at}.yaml must be an array of lines`);
    for (const k of ['investigation', 'remediation', 'expectedMatches']) if (!Array.isArray(r[k])) p.push(`${at}.${k} must be an array`);
    if (!r.objective) p.push(`${at}.objective missing`);
  });
  return p;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

/** CVE snapshot generated by tools/update-cve-snapshot.ps1 from KEV, NVD and EPSS. */
export function validateCves(json) {
  const p = [];
  if (!json || json.provenance !== 'documented') p.push('cve snapshot must declare provenance "documented"');
  if (!json || Number.isNaN(Date.parse(json.generatedAt))) p.push('generatedAt invalid');
  if (!json || !json.sources || !json.sources.kev || !json.sources.kev.catalogVersion) p.push('sources.kev.catalogVersion missing');
  if (!json || !Array.isArray(json.cves) || !json.cves.length) return [...p, 'cves must be a non-empty array'];
  const ids = new Set();
  json.cves.forEach((c, i) => {
    if (!CVE_ID.test(c.cveID || '') || ids.has(c.cveID)) p.push(`cves[${i}].cveID missing, malformed or duplicate`);
    ids.add(c.cveID);
    if (Number.isNaN(Date.parse(c.dateAdded))) p.push(`cves[${i}].dateAdded invalid`);
    if (c.nvd && c.nvd.cvss && !(Number(c.nvd.cvss.baseScore) >= 0 && Number(c.nvd.cvss.baseScore) <= 10)) p.push(`cves[${i}] CVSS score out of range`);
    if (c.epss && !(c.epss.score >= 0 && c.epss.score <= 1)) p.push(`cves[${i}] EPSS score out of range`);
  });
  return p;
}

export function validateNetwork(json) {
  const p = [];
  if (!json || json.provenance !== 'simulated') p.push('network must declare provenance "simulated"');
  for (const k of ['zones', 'hosts', 'flows', 'policies', 'topics', 'references']) if (!json || !Array.isArray(json[k])) p.push(`${k} must be an array`);
  if (p.length) return p;
  const zones = new Set(json.zones.map((z) => z.id));
  json.hosts.forEach((h, i) => { if (!zones.has(h.zone)) p.push(`hosts[${i}] unknown zone ${h.zone}`); });
  json.flows.forEach((f, i) => {
    if (!['attack', 'legitimate'].includes(f.kind)) p.push(`flows[${i}].kind invalid`);
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535) p.push(`flows[${i}].port invalid`);
  });
  json.policies.forEach((pol, i) => {
    if (!['allow', 'deny'].includes(pol.default)) p.push(`policies[${i}].default invalid`);
    pol.rules.forEach((r, j) => { if (!['allow', 'deny'].includes(r.action)) p.push(`policies[${i}].rules[${j}].action invalid`); });
  });
  json.topics.forEach((t, i) => (t.refs || []).forEach((r) => { if (!json.references[r]) p.push(`topics[${i}] cites missing reference ${r}`); }));
  validateSources(json.references, 'network.references', p);
  return p;
}

export const TOOL_LICENCES = ['open-source', 'free', 'commercial', 'cloud-service'];

export function validateTools(json) {
  const p = [];
  if (!json || !Array.isArray(json.tools) || !Array.isArray(json.categories)) return ['tools and categories must be arrays'];
  const cats = new Set(json.categories.map((c) => c.id));
  const ids = new Set();
  json.tools.forEach((t, i) => {
    const at = `tools[${i}]`;
    if (!ID.test(t.id || '') || ids.has(t.id)) p.push(`${at}.id missing, malformed or duplicate`);
    ids.add(t.id);
    if (!cats.has(t.category)) p.push(`${at}.category unknown`);
    if (!TOOL_LICENCES.includes(t.licence)) p.push(`${at}.licence invalid`);
    if (typeof t.url !== 'string' || !t.url.startsWith('https://')) p.push(`${at}.url must be https`);
    if (!t.description || !Array.isArray(t.useCases) || !t.useCases.length) p.push(`${at} description/useCases missing`);
  });
  (json.workflows || []).forEach((w, i) => w.steps.forEach((s, j) => { if (!ids.has(s.tool)) p.push(`workflows[${i}].steps[${j}] unknown tool ${s.tool}`); }));
  return p;
}

export function validateKnowledge(json) {
  const p = [];
  if (!json || !Array.isArray(json.articles) || !Array.isArray(json.pathways) || !json.references) return ['articles, pathways and references are required'];
  const cats = new Set((json.categories || []).map((c) => c.id));
  const ids = new Set();
  json.articles.forEach((a, i) => {
    const at = `articles[${i}]`;
    if (!ID.test(a.id || '') || ids.has(a.id)) p.push(`${at}.id missing, malformed or duplicate`);
    ids.add(a.id);
    if (!cats.has(a.category)) p.push(`${at}.category unknown`);
    if (!['beginner', 'intermediate', 'advanced'].includes(a.level)) p.push(`${at}.level invalid`);
    if (!Array.isArray(a.sections) || !a.sections.length) p.push(`${at}.sections required`);
    (a.refs || []).forEach((r) => { if (!json.references[r]) p.push(`${at} cites unknown reference ${r}`); });
  });
  json.pathways.forEach((pw, i) => pw.steps.forEach((s, j) => {
    if (s.type === 'article' && !ids.has(s.ref)) p.push(`pathways[${i}].steps[${j}] unknown article ${s.ref}`);
    if (s.type === 'practice' && !(s.href || '').startsWith('#/')) p.push(`pathways[${i}].steps[${j}] practice href must be an in-app route`);
  }));
  validateSources(Object.values(json.references), 'knowledge.references', p);
  return p;
}

/** Example impact × urgency → priority mapping (P1 highest). */
export function priorityFor(impact, urgency) {
  const s = impact + urgency;
  if (impact === 3 && urgency === 3) return 'P1';
  if (s === 5) return 'P2';
  if (s === 4) return 'P3';
  return 'P4';
}

/** Severity rank for sorting: critical = 4 … info = 0. */
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Official ATT&CK URL for a technique ID (T1059.001 -> /techniques/T1059/001/), or null. */
export function mitreUrl(id) {
  if (typeof id !== 'string' || !MITRE_ID.test(id)) return null;
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

/** Count events per severity — shared by the landing page and (later) the SOC module. */
export function severityCounts(events) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const e of events) if (e.severity in out) out[e.severity] += 1;
  return out;
}
