/**
 * Shared rendering helpers for documented intelligence (Modules 02 and 03):
 * cited facts, source lists, ATT&CK technique lists, analysis callouts and
 * Markdown export. Every external link goes through el(), so it gets the URL
 * scheme allow-list and rel="noopener noreferrer".
 */
import { el } from '../utils/dom.js';
import { mitreUrl } from '../data-service.js';
import { attackName } from '../utils/attack.js';

export const cap = (s) => String(s).charAt(0).toUpperCase() + String(s).slice(1).replace(/-/g, ' ');

/** "2023-06-14" -> "14 Jun 2023", "2023-05" -> "May 2023", other strings unchanged. */
export function formatSourceDate(d) {
  const m = String(d).match(/^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?$/);
  if (!m) return String(d);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  if (!m[2]) return m[1];
  const mon = months[Number(m[2]) - 1];
  return m[3] ? `${Number(m[3])} ${mon} ${m[1]}` : `${mon} ${m[1]}`;
}

/** Facts list where each item ends with a numbered citation link to its source. */
export function citedFacts(facts, sources) {
  return el('ul', { class: 'fact-list' }, facts.map((f) => {
    const s = sources[f.source];
    return el('li', null,
      el('span', null, f.text, ' '),
      s ? el('a', { class: 'cite', href: s.url, target: '_blank', 'aria-label': `Source ${f.source + 1}: ${s.title} (opens in new tab)`, title: `${s.publisher}, ${formatSourceDate(s.date)}` }, `[${f.source + 1}]`) : null
    );
  }));
}

export function analysisBlock(items, heading = 'Analysis') {
  const list = Array.isArray(items) ? items : [items];
  if (!list.length || !list[0]) return null;
  return el('aside', { class: 'analysis', 'aria-label': 'Analyst interpretation' },
    el('div', { class: 'analysis-head' }, el('span', { class: 'badge prov-analysis' }, heading),
      el('span', { class: 'kpi-sub' }, "Author's interpretation. Not a fact from the cited source.")),
    list.length > 1 ? el('ul', null, list.map((t) => el('li', null, t))) : el('p', null, list[0])
  );
}

export function sourceList(sources) {
  return el('ol', { class: 'source-list' }, sources.map((s) => el('li', null,
    el('a', { href: s.url, target: '_blank' }, s.title, ' ↗'),
    el('span', { class: 'source-meta' }, `${s.publisher} · ${formatSourceDate(s.date)}`)
  )));
}

export function techniqueList(ids) {
  return el('ul', { class: 'technique-list' }, ids.map((id) => {
    const url = mitreUrl(id);
    return el('li', null,
      url ? el('a', { class: 'tech-id', href: url, target: '_blank', 'aria-label': `${id} on MITRE ATT&CK (opens in new tab)` }, id) : el('span', { class: 'tech-id' }, id),
      el('span', { class: 'tech-name' }, attackName(id))
    );
  }));
}

export function bulletList(items, cls = 'checklist') {
  return el('ul', { class: cls }, items.map((t) => el('li', null, t)));
}

/* ---------------- Markdown export (pure) ---------------- */

const mdEscape = (s) => String(s).replace(/([\\`*_[\]<>|])/g, '\\$1');
const mdList = (items) => items.map((t) => `- ${mdEscape(t)}`).join('\n');
const mdSources = (sources) => sources.map((s, i) => `${i + 1}. [${mdEscape(s.title)}](${s.url}) — ${mdEscape(s.publisher)}, ${formatSourceDate(s.date)}`).join('\n');
const mdFacts = (facts) => facts.map((f) => `- ${mdEscape(f.text)} [${f.source + 1}]`).join('\n');
const mdTech = (ids) => ids.map((id) => `- ${id} ${mdEscape(attackName(id))}`).join('\n');

export function dossierToMarkdown(a, reviewed) {
  return [
    `# ${mdEscape(a.name)}`,
    `_Sentinel X attack dossier · category: ${cap(a.category)} · content reviewed ${reviewed}_`,
    '', '## 1. Overview', mdEscape(a.overview),
    '', '## 2. Methodology', a.methodology.map((s, i) => `${i + 1}. ${mdEscape(s)}`).join('\n'),
    '', `## 3. Real-world incident: ${mdEscape(a.incident.title)} (${formatSourceDate(a.incident.date)})`,
    '**Documented facts**', mdFacts(a.incident.facts),
    '', `**Analysis (author's interpretation):** ${mdEscape(a.incident.analysis || '')}`,
    '', '## 4. MITRE ATT&CK mapping', mdTech(a.techniques),
    '', '## 5. Indicators', mdList(a.indicators),
    '', '## 6. Log sources', mdList(a.logSources),
    '', '## 7. Detection opportunities', mdList(a.detections),
    '', '## 8. Recommended controls', mdList(a.controls),
    '', '## 9. Incident response', a.response.map((s, i) => `${i + 1}. ${mdEscape(s)}`).join('\n'),
    '', '## 10. References', mdSources(a.references), ''
  ].join('\n');
}

export function profileToMarkdown(p, reviewed) {
  return [
    `# ${mdEscape(p.name)}`,
    `_Sentinel X threat profile · type: ${cap(p.type)} · content reviewed ${reviewed}_`,
    '', `**Aliases:** ${mdEscape(p.aliases.join(', '))}`, `**Attribution:** ${mdEscape(p.attribution)}`,
    '', '## Summary', mdEscape(p.summary),
    '', '## Documented facts', mdFacts(p.facts),
    '', "## Analysis (author's interpretation)", mdList(p.analysis || []),
    '', '## Timeline', (p.incidents || []).map((i) => `- ${formatSourceDate(i.date)}: ${mdEscape(i.title)}. ${mdEscape(i.text)} [${i.source + 1}]`).join('\n'),
    '', '## ATT&CK techniques', mdTech(p.techniques),
    '', '## Recommended defences', mdList(p.defences),
    '', '## Sources', mdSources(p.sources), ''
  ].join('\n');
}
