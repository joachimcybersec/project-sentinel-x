/**
 * Site-wide search (pure functions).
 *
 * buildIndex(datasets) flattens every searchable item into
 *   { type, id, title, text, href, meta }
 * search(index, query) ranks entries that contain ALL query terms:
 *   exact ID match 50 · title contains the whole query 12 · term in title 4 · term in text 1
 * Matching is case-insensitive substring matching; nothing is compiled as a regex.
 */

export const MAX_SEARCH = 120;
export const TYPE_LABEL = {
  module: 'Module', article: 'Knowledge article', tool: 'Tool', profile: 'Threat profile', attack: 'Attack dossier',
  rule: 'Detection rule', cve: 'CVE', incident: 'Incident case', topic: 'Network topic'
};

const norm = (s) => String(s || '').toLowerCase();

export function buildIndex(d) {
  const idx = [];
  const add = (type, id, title, textParts, href, meta = '') => idx.push({ type, id, title, text: norm([title, ...textParts].join(' ')), titleLc: norm(title), idLc: norm(id), href, meta });

  (d.modules || []).forEach((m) => add('module', m.id, m.title, [m.summary, ...(m.features || [])], `#${m.route}`, `Module ${m.num}`));
  (d.articles || []).forEach((a) => add('article', a.id, a.title,
    [a.summary, a.category, a.level, ...a.sections.flatMap((s) => [s.heading, ...(s.paragraphs || []), ...(s.bullets || [])])], `#/knowledge/${a.id}`, `${a.level}`));
  (d.tools || []).forEach((t) => add('tool', t.id, t.name, [t.description, t.category, t.licence, ...(t.useCases || [])], `#/tools?tool=${t.id}`, t.licence));
  (d.profiles || []).forEach((p) => add('profile', p.id, p.name, [p.summary, ...p.aliases, p.attribution, ...p.techniques], `#/threat-intel/${p.id}`, p.type));
  (d.attacks || []).forEach((a) => add('attack', a.id, a.name, [a.overview, a.category, a.incident.title, ...a.techniques, ...a.indicators], `#/attacks/${a.id}`, a.category));
  // Rule title and level live inside the Sigma YAML lines.
  const yamlField = (r, k) => ((r.yaml || []).find((l) => l.startsWith(`${k}: `)) || '').slice(k.length + 2).trim();
  (d.rules || []).forEach((r) => add('rule', r.slug, r.title || yamlField(r, 'title') || r.slug, [r.objective, r.yaml ? r.yaml.join(' ') : ''], `#/detections/${r.slug}`, r.level || yamlField(r, 'level')));
  (d.cves || []).forEach((c) => add('cve', c.cveID, `${c.cveID}: ${c.vulnerabilityName}`, [c.vendorProject, c.product, c.shortDescription, ...(c.nvd && c.nvd.cwes ? c.nvd.cwes : [])], `#/vulnerabilities/${c.cveID}`, `${c.vendorProject} ${c.product}`));
  (d.incidents || []).forEach((i) => add('incident', i.id, `${i.id}: ${i.title}`, [i.scenario, i.classification, ...i.techniques, ...i.affected.hosts, ...i.affected.users, i.rootCause], `#/incidents/${i.id}`, i.severity));
  (d.topics || []).forEach((t) => add('topic', t.id, t.title, [t.summary, ...t.keyPoints, ...t.defensiveChecks], '#/network', 'Network Security'));
  return idx;
}

export function parseTerms(q) {
  return norm(q).slice(0, MAX_SEARCH).split(/\s+/).filter((t) => t.length > 0);
}

export function search(index, query, { limit = 50 } = {}) {
  const terms = parseTerms(query);
  if (!terms.length) return [];
  const phrase = terms.join(' ');
  const out = [];
  for (const e of index) {
    if (!terms.every((t) => e.text.includes(t) || e.idLc.includes(t))) continue;
    let score = 0;
    if (e.idLc === phrase) score += 50;
    if (e.titleLc.includes(phrase)) score += 12;
    for (const t of terms) { if (e.titleLc.includes(t)) score += 4; if (e.text.includes(t)) score += 1; }
    out.push({ ...e, score });
  }
  return out.sort((a, b) => b.score - a.score || String(a.title).localeCompare(String(b.title))).slice(0, limit);
}

/** Short excerpt around the first matched term (plain text; rendered with textContent). */
export function excerpt(entry, query, width = 140) {
  const terms = parseTerms(query);
  const text = entry.text;
  let at = -1;
  for (const t of terms) { const i = text.indexOf(t); if (i >= 0 && (at < 0 || i < at)) at = i; }
  if (at < 0) return text.slice(0, width);
  const start = Math.max(0, at - Math.floor(width / 3));
  return `${start > 0 ? '…' : ''}${text.slice(start, start + width)}${start + width < text.length ? '…' : ''}`;
}
