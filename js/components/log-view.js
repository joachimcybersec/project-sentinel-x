/**
 * Shared log presentation: field tables, enrichment panel and the log drawer.
 * Used by the SIEM module and the incident case studies.
 */
import { el, formatUtcDateTime, provenanceBadge } from '../utils/dom.js';
import { openDrawer } from './drawer.js';
import { createCodeBlock } from './code-block.js';
import { enrich } from '../siem/correlation.js';

export const LOG_TYPE_LABEL = {
  windows: 'Windows Security', sysmon: 'Sysmon', powershell: 'PowerShell', 'linux-auth': 'Linux auth',
  firewall: 'Firewall', dns: 'DNS (BIND)', web: 'Web access', edr: 'EDR', unknown: 'Unparsed'
};

export function fieldTable(obj, caption) {
  const entries = Object.entries(obj || {});
  if (!entries.length) return el('p', { class: 'bar-empty' }, 'No fields.');
  return el('table', { class: 'kbd-table field-table' },
    el('caption', { class: 'visually-hidden' }, caption),
    el('thead', null, el('tr', null, el('th', { scope: 'col' }, 'Field'), el('th', { scope: 'col' }, 'Value'))),
    el('tbody', null, entries.map(([k, v]) => el('tr', null, el('td', { class: 'mono' }, k), el('td', { class: 'mono' }, String(v)))))
  );
}

export function enrichmentPanel(norm, ctx) {
  const en = enrich(norm, ctx);
  const items = [];
  for (const [field, scope] of Object.entries(en.scopes)) items.push(el('li', null, el('span', { class: 'mono' }, field), ` ${norm[field]}: ${scope}`));
  for (const a of en.assets) items.push(el('li', null, el('span', { class: 'mono' }, a.field), ` → asset ${a.host} (${a.role}, criticality `, el('strong', null, a.criticality), ')'));
  for (const i of en.iocMatches) items.push(el('li', { class: 'ioc-hit' }, '⚑ Matches IOC watchlist: ', el('span', { class: 'mono' }, i.type), ` "${i.role}" (confidence ${i.confidence})`));
  return items.length ? el('ul', { class: 'enrich-list' }, items) : el('p', { class: 'bar-empty' }, 'No enrichment matches.');
}

/** entry: { id, raw, parsed, norm } */
export function openLogDrawer(entry, trigger, ctx = {}) {
  const p = entry.parsed;
  return openDrawer({
    title: entry.summary || entry.id,
    subtitle: `${entry.id} · ${LOG_TYPE_LABEL[p.type] || p.type}`,
    returnFocus: trigger,
    content: [
      el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, entry.norm ? formatUtcDateTime(entry.norm['@timestamp']) : '')),
      el('section', { class: 'drawer-section' }, el('h3', null, 'Raw event'), createCodeBlock({ code: entry.raw, language: 'log', title: `${entry.id} raw` })),
      el('section', { class: 'drawer-section' }, el('h3', null, `Parsed fields · ${p.format || p.error}`), fieldTable(p.fields, 'Parsed fields')),
      el('section', { class: 'drawer-section' }, el('h3', null, 'Normalised (ECS-style)'), fieldTable(entry.norm, 'Normalised fields')),
      el('section', { class: 'drawer-section' }, el('h3', null, 'Enrichment'), enrichmentPanel(entry.norm, ctx))
    ]
  });
}
