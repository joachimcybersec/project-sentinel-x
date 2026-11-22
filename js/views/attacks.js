/**
 * MODULE 03 — Real-World Cyber Attack Intelligence library.
 *   #/attacks       searchable, filterable list of attack dossiers
 *   #/attacks/:id   10-section dossier with cited real-world incident
 */
import { el, clear, provenanceBadge } from '../utils/dom.js';
import { load, ATTACK_CATEGORIES } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { toast } from '../components/toast.js';
import { downloadFile } from '../components/export.js';
import { cap, citedFacts, analysisBlock, sourceList, techniqueList, bulletList, formatSourceDate, dossierToMarkdown } from '../components/intel-ui.js';

export const DOSSIER_SECTIONS = [
  ['overview', 'Attack overview'], ['methodology', 'Attack methodology'], ['incident', 'Real-world incident'],
  ['mitre', 'MITRE ATT&CK mapping'], ['indicators', 'Relevant indicators'], ['logs', 'Log sources for investigation'],
  ['detections', 'Detection opportunities'], ['controls', 'Recommended security controls'],
  ['response', 'Incident response procedures'], ['references', 'References and further reading']
];

const searchText = (a) => [a.name, a.overview, a.category, a.incident.title, ...a.techniques, ...a.techniques.map(attackName), ...a.indicators].join(' ');

export async function renderAttacks(view) {
  const { data } = await load('attacks');
  const attacks = data.attacks.map((a) => ({ ...a, _search: searchText(a) }));
  const grid = el('div', { class: 'grid grid-3 intel-grid' });
  const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });

  const renderGrid = (rows) => {
    clear(grid);
    count.textContent = `${rows.length} of ${attacks.length} attack dossiers`;
    if (!rows.length) grid.append(el('p', { class: 'bar-empty' }, 'No dossiers match the filters.'));
    for (const a of rows) {
      grid.append(el('a', { class: 'card intel-card', href: `#/attacks/${a.id}` },
        el('div', { class: 'intel-card-top' }, el('span', { class: `type-pill cat-${a.category}` }, cap(a.category)), provenanceBadge('documented')),
        el('h3', null, a.name),
        el('p', null, a.overview),
        el('p', { class: 'incident-line' }, el('span', { class: 'kpi-sub' }, 'Case: '), `${a.incident.title} (${String(a.incident.date).slice(0, 4)})`),
        el('div', { class: 'tile-foot' }, a.techniques.slice(0, 4).map((t) => el('span', { class: 'tech-chip' }, t)))
      ));
    }
  };
  const cats = ATTACK_CATEGORIES.filter((c) => attacks.some((a) => a.category === c));
  const filterBar = createFilterBar({
    ariaLabel: 'Filter attack dossiers',
    searchLabel: 'Search dossiers',
    searchPlaceholder: 'Attack, technique ID, indicator, incident…',
    chips: [{ key: 'category', label: 'Category', options: cats.map((c) => ({ value: c, label: cap(c) })) }],
    onChange: (s) => renderGrid(applyFilters(attacks, s, { searchFields: ['_search'] }))
  });
  renderGrid(attacks);

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 03'),
      el('h1', null, 'Attack Intelligence Library'),
      el('p', { class: 'lede' }, 'Fourteen common attack types. Each dossier covers how the attack works, a documented real-world incident, ATT&CK mapping, what to look for in which logs, detection ideas, controls and response steps.'),
      el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'badge prov-analysis' }, 'Analysis labelled'), el('span', { class: 'kpi-sub' }, `Content reviewed ${data.reviewed}`))
    ),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, data.disclaimer)),
    el('h2', { class: 'visually-hidden' }, 'Attack dossiers'),
    filterBar.element,
    el('div', null, count),
    grid
  );
  return () => view.classList.remove('stack');
}

export async function renderAttackDossier(view, { params }) {
  const { data } = await load('attacks');
  const idx = data.attacks.findIndex((a) => a.id === params.id);
  const a = data.attacks[idx];
  if (!a) {
    view.append(el('header', { class: 'page-head' }, el('span', { class: 'eyebrow' }, 'Module 03'), el('h1', null, 'Dossier not found'),
      el('p', { class: 'lede' }, `No attack dossier has the ID “${params.id}”.`)), el('a', { class: 'btn btn-primary', href: '#/attacks' }, '← All dossiers'));
    return;
  }
  document.title = `${a.name} · Attack Library · Joachim's Sentinel X`;
  const { data: intel } = await load('intel').catch(() => ({ data: { profiles: [] } }));
  const relatedProfiles = (a.relatedProfiles || []).map((id) => intel.profiles.find((p) => p.id === id)).filter(Boolean);

  const sections = {};
  const section = (key, num, title, ...content) => {
    const node = el('section', { class: 'card dossier-section', id: `sec-${key}`, 'aria-labelledby': `sec-${key}-h`, tabindex: '-1' },
      el('h2', { id: `sec-${key}-h` }, el('span', { class: 'sec-num', 'aria-hidden': 'true' }, String(num).padStart(2, '0')), title), ...content);
    sections[key] = node;
    return node;
  };

  // Table of contents uses buttons (not #anchors) because the hash is the router's.
  const toc = el('nav', { class: 'card dossier-toc', 'aria-label': 'Dossier sections' },
    el('div', { class: 'chart-title' }, 'Sections'),
    el('ol', null, DOSSIER_SECTIONS.map(([key, title], i) => {
      const b = el('button', { class: 'toc-btn', type: 'button' }, el('span', { class: 'sec-num' }, String(i + 1).padStart(2, '0')), title);
      b.addEventListener('click', () => {
        const target = sections[key];
        target.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
        target.focus({ preventScroll: true });
      });
      return el('li', null, b);
    }))
  );

  const mdBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export dossier (Markdown)');
  mdBtn.addEventListener('click', () => {
    downloadFile(`sentinel-x-dossier-${a.id}.md`, dossierToMarkdown(a, data.reviewed), 'text/markdown;charset=utf-8');
    toast(`Exported ${a.name} dossier as Markdown`, { variant: 'success' });
  });

  const body = el('div', { class: 'dossier-body stack' },
    section('overview', 1, 'Attack overview', el('p', null, a.overview)),
    section('methodology', 2, 'Attack methodology', el('ol', { class: 'steps' }, a.methodology.map((s) => el('li', null, s)))),
    section('incident', 3, 'Real-world incident',
      el('div', { class: 'incident-head' }, el('h3', null, a.incident.title), el('span', { class: 'kpi-sub' }, formatSourceDate(a.incident.date))),
      el('div', { class: 'section-head' }, el('span', { class: 'chart-title' }, 'Verified facts'), provenanceBadge('documented')),
      citedFacts(a.incident.facts, a.references),
      analysisBlock(a.incident.analysis)),
    section('mitre', 4, 'MITRE ATT&CK mapping', techniqueList(a.techniques)),
    section('indicators', 5, 'Relevant indicators', bulletList(a.indicators)),
    section('logs', 6, 'Log sources for investigation', bulletList(a.logSources)),
    section('detections', 7, 'Detection opportunities', bulletList(a.detections),
      el('p', { class: 'kpi-sub' }, 'Validated Sigma rules for these ideas are added in the Detection Engineering module (Phase 6).')),
    section('controls', 8, 'Recommended security controls', bulletList(a.controls)),
    section('response', 9, 'Incident response procedures', el('ol', { class: 'steps' }, a.response.map((s) => el('li', null, s)))),
    section('references', 10, 'References and further reading', sourceList(a.references),
      relatedProfiles.length ? el('div', null, el('h3', { class: 'chart-title' }, 'Related threat profiles'),
        el('div', { class: 'btn-row' }, relatedProfiles.map((p) => el('a', { class: 'btn btn-sm', href: `#/threat-intel/${p.id}` }, p.name)))) : null)
  );

  const prev = data.attacks[idx - 1], next = data.attacks[idx + 1];
  view.classList.add('stack');
  view.append(
    el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' }, el('a', { href: '#/attacks' }, 'Attack Library'), ' / ', el('span', { 'aria-current': 'page' }, a.name)),
    el('header', { class: 'page-head soc-head' },
      el('div', null,
        el('span', { class: 'eyebrow' }, cap(a.category)),
        el('h1', null, a.name),
        el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'kpi-sub' }, `${a.techniques.length} techniques · ${a.references.length} references · reviewed ${data.reviewed}`))
      ),
      el('div', { class: 'btn-row' }, mdBtn)
    ),
    el('div', { class: 'dossier-layout' }, toc, body),
    el('nav', { class: 'hero-actions', 'aria-label': 'Dossier pager' },
      prev ? el('a', { class: 'btn', href: `#/attacks/${prev.id}` }, `← ${prev.name}`) : el('a', { class: 'btn', href: '#/attacks' }, '← All dossiers'),
      next ? el('a', { class: 'btn', href: `#/attacks/${next.id}` }, `${next.name} →`) : el('a', { class: 'btn', href: '#/attacks' }, 'All dossiers →'))
  );
  return () => view.classList.remove('stack');
}
