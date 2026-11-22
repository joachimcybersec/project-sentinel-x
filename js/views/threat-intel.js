/**
 * MODULE 02 — Threat Intelligence Centre.
 *   #/threat-intel       profiles (filterable cards) · IOC watchlist · source reports
 *   #/threat-intel/:id   full profile with cited facts, analysis, timeline, TTPs, sources
 */
import { el, clear, formatUtcDateTime, defang, provenanceBadge } from '../utils/dom.js';
import { load, INTEL_TYPES } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { createTabs } from '../components/tabs.js';
import { createDataTable, sortRows } from '../components/data-table.js';
import { toast } from '../components/toast.js';
import { exportCSV, downloadFile, stamp } from '../components/export.js';
import { createIocLookup } from '../components/ioc-lookup.js';
import { cap, citedFacts, analysisBlock, sourceList, techniqueList, bulletList, formatSourceDate, profileToMarkdown } from '../components/intel-ui.js';

const TYPE_LABEL = { apt: 'APT', ransomware: 'Ransomware', cybercrime: 'Cybercrime', botnet: 'Botnet / malware', phishing: 'Phishing', exploitation: 'Exploitation' };

/** Flatten all sources across profiles, de-duplicated by URL, newest first. */
export function collectReports(profiles) {
  const byUrl = new Map();
  for (const p of profiles) for (const s of p.sources) {
    const entry = byUrl.get(s.url) || { ...s, usedBy: [] };
    entry.usedBy.push({ id: p.id, name: p.name });
    byUrl.set(s.url, entry);
  }
  return sortRows([...byUrl.values()], 'date', 'desc');
}

/** Searchable flat text for a profile. */
const profileSearchText = (p) => [p.name, ...p.aliases, p.summary, p.attribution, ...p.techniques, ...p.techniques.map(attackName)].join(' ');

export async function renderThreatIntel(view) {
  const { data } = await load('intel');
  const profiles = data.profiles.map((p) => ({ ...p, _search: profileSearchText(p) }));

  /* ---------- profiles tab ---------- */
  const grid = el('div', { class: 'grid grid-3 intel-grid' });
  const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
  const renderGrid = (rows) => {
    clear(grid);
    count.textContent = `${rows.length} of ${profiles.length} profiles`;
    if (!rows.length) grid.append(el('p', { class: 'bar-empty' }, 'No profiles match the filters.'));
    for (const p of rows) {
      const latest = p.sources.map((s) => s.date).sort().pop();
      grid.append(el('a', { class: 'card intel-card', href: `#/threat-intel/${p.id}` },
        el('div', { class: 'intel-card-top' }, el('span', { class: `type-pill type-${p.type}` }, TYPE_LABEL[p.type]), provenanceBadge('documented')),
        el('h3', null, p.name),
        p.aliases.length ? el('p', { class: 'aliases' }, `aka ${p.aliases.slice(0, 3).join(', ')}`) : null,
        el('p', null, p.summary),
        el('div', { class: 'tile-foot' },
          el('span', { class: 'kpi-sub' }, `${p.techniques.length} ATT&CK techniques · ${p.sources.length} source${p.sources.length > 1 ? 's' : ''} · latest ${formatSourceDate(latest)}`))
      ));
    }
  };
  const types = INTEL_TYPES.filter((t) => profiles.some((p) => p.type === t));
  const filterBar = createFilterBar({
    ariaLabel: 'Filter threat profiles',
    searchLabel: 'Search profiles',
    searchPlaceholder: 'Name, alias, technique ID or name…',
    chips: [{ key: 'type', label: 'Type', options: types.map((t) => ({ value: t, label: TYPE_LABEL[t] })) }],
    onChange: (s) => renderGrid(applyFilters(profiles, s, { searchFields: ['_search'] }))
  });
  renderGrid(profiles);

  const profilesPanel = () => el('div', { class: 'stack' }, filterBar.element, el('div', null, count), grid);

  /* ---------- IOC watchlist tab ---------- */
  const iocPanel = () => {
    const w = data.iocWatchlist;
    // Only network indicators are defanged; file names are not clickable and stay as-is.
    const NETWORK = new Set(['ipv4', 'ipv6', 'domain', 'url']);
    const rows = w.items.map((i, n) => ({ ...i, id: `IOC-${String(n + 1).padStart(3, '0')}`, display: NETWORK.has(i.type) ? defang(i.value) : i.value }));
    const table = createDataTable({
      caption: 'Simulated IOC watchlist',
      pageSize: 10,
      initialSort: { key: 'firstSeen', dir: 'desc' },
      rows,
      columns: [
        { key: 'type', label: 'Type', sortable: true, className: 'mono' },
        { key: 'display', label: 'Indicator (defanged)', sortable: true, className: 'mono' },
        { key: 'role', label: 'Role', sortable: true },
        { key: 'confidence', label: 'Confidence', sortable: true, sortValue: (r) => ({ high: 3, medium: 2, low: 1 })[r.confidence], render: (r) => el('span', { class: `conf conf-${r.confidence}` }, r.confidence) },
        { key: 'firstSeen', label: 'First seen (UTC)', sortable: true, defaultDir: 'desc', className: 'mono', render: (r) => formatUtcDateTime(r.firstSeen).replace(' UTC', '') },
        { key: 'events', label: 'Related events', className: 'mono', render: (r) => r.events.join(', ') }
      ]
    });
    const exportBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export CSV');
    exportBtn.addEventListener('click', () => {
      const out = table.getSortedRows();
      exportCSV(`sentinel-x-ioc-watchlist-${stamp()}.csv`, out, [
        { key: 'type', label: 'Type' }, { key: 'display', label: 'Indicator (defanged)' }, { key: 'role', label: 'Role' },
        { key: 'confidence', label: 'Confidence' }, { key: 'firstSeen', label: 'First seen (UTC)' }, { key: 'events', label: 'Related events' },
        { key: 'provenance', label: 'Provenance', value: () => 'simulated' }
      ]);
      toast(`Exported ${out.length} simulated indicators (defanged)`, { variant: 'success' });
    });
    return el('div', { class: 'stack' },
      el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'),
        el('span', null, el('strong', null, 'Simulated training indicators. '), w.note, ' For real indicators, use the IOC appendix of each profile\'s linked advisory.')),
      el('div', { class: 'section-head' }, provenanceBadge('simulated'), el('div', { class: 'btn-row' }, exportBtn)),
      table.element
    );
  };

  /* ---------- reports tab ---------- */
  const reportsPanel = () => {
    const reports = collectReports(profiles);
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub' }, `${reports.length} public reports and advisories cited across all profiles, newest first. All links were checked on ${data.reviewed}.`),
      el('ol', { class: 'report-list' }, reports.map((r) => el('li', null,
        el('time', { class: 'report-date', datetime: r.date }, formatSourceDate(r.date)),
        el('div', null,
          el('a', { href: r.url, target: '_blank' }, r.title, ' ↗'),
          el('div', { class: 'source-meta' }, r.publisher, ' · cited by ',
            r.usedBy.map((u, i) => [i ? ', ' : '', el('a', { href: `#/threat-intel/${u.id}` }, u.name)]))
        )
      )))
    );
  };

  const tabs = createTabs({
    label: 'Threat intelligence views',
    tabs: [
      { id: 'profiles', label: `Threat profiles (${profiles.length})`, render: profilesPanel },
      { id: 'iocs', label: `IOC watchlist (${data.iocWatchlist.items.length})`, render: iocPanel },
      { id: 'reports', label: 'Source reports', render: reportsPanel },
      { id: 'lookup', label: 'Live lookup', render: createIocLookup }
    ]
  });

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 02'),
      el('h1', null, 'Threat Intelligence Centre'),
      el('p', { class: 'lede' }, 'Profiles of ransomware groups, state-sponsored actors, botnets, phishing and exploitation campaigns. Each one is summarised from public advisories, and every fact links to its source.'),
      el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'badge prov-analysis' }, 'Analysis labelled'), el('span', { class: 'kpi-sub' }, `Content reviewed ${data.reviewed}`))
    ),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, data.disclaimer)),
    el('section', { class: 'card' }, tabs.element)
  );
  return () => view.classList.remove('stack');
}

export async function renderThreatProfile(view, { params }) {
  const { data } = await load('intel');
  const idx = data.profiles.findIndex((p) => p.id === params.id);
  const p = data.profiles[idx];
  if (!p) {
    view.append(el('header', { class: 'page-head' }, el('span', { class: 'eyebrow' }, 'Module 02'), el('h1', null, 'Profile not found'),
      el('p', { class: 'lede' }, `No threat profile has the ID “${params.id}”.`)), el('a', { class: 'btn btn-primary', href: '#/threat-intel' }, '← All profiles'));
    return;
  }
  document.title = `${p.name} · Threat Intelligence · Sentinel X`;
  const { data: lib } = await load('attacks').catch(() => ({ data: { attacks: [] } }));
  const related = (p.relatedAttacks || []).map((id) => lib.attacks.find((a) => a.id === id)).filter(Boolean);

  const mdBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export profile (Markdown)');
  mdBtn.addEventListener('click', () => {
    downloadFile(`sentinel-x-profile-${p.id}.md`, profileToMarkdown(p, data.reviewed), 'text/markdown;charset=utf-8');
    toast(`Exported ${p.name} profile as Markdown`, { variant: 'success' });
  });
  const prev = data.profiles[idx - 1], next = data.profiles[idx + 1];

  view.classList.add('stack');
  view.append(
    el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' }, el('a', { href: '#/threat-intel' }, 'Threat Intelligence'), ' / ', el('span', { 'aria-current': 'page' }, p.name)),
    el('header', { class: 'page-head soc-head' },
      el('div', null,
        el('span', { class: 'eyebrow' }, TYPE_LABEL[p.type]),
        el('h1', null, p.name),
        el('p', { class: 'lede' }, p.summary),
        el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'kpi-sub' }, `Reviewed ${data.reviewed}`))
      ),
      el('div', { class: 'btn-row' }, mdBtn)
    ),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'id-h' },
        el('h2', { id: 'id-h' }, 'Identity'),
        el('dl', { class: 'dl' },
          el('dt', null, 'Aliases'), el('dd', null, p.aliases.join(', ') || '—'),
          el('dt', null, 'Attribution'), el('dd', null, p.attribution),
          el('dt', null, 'Type'), el('dd', null, TYPE_LABEL[p.type]))
      ),
      el('section', { class: 'card', 'aria-labelledby': 'tl-h' },
        el('h2', { id: 'tl-h' }, 'Timeline'),
        el('ol', { class: 'timeline' }, (p.incidents || []).slice().sort((a, b) => a.date.localeCompare(b.date)).map((i) => el('li', null,
          el('time', { datetime: i.date }, formatSourceDate(i.date)),
          el('div', null, el('strong', null, i.title), el('p', null, i.text, ' ',
            el('a', { class: 'cite', href: p.sources[i.source].url, target: '_blank', 'aria-label': `Source ${i.source + 1} (opens in new tab)` }, `[${i.source + 1}]`))))))
      )
    ),
    el('section', { class: 'card', 'aria-labelledby': 'facts-h' },
      el('div', { class: 'section-head' }, el('h2', { id: 'facts-h' }, 'Documented facts'), provenanceBadge('documented')),
      citedFacts(p.facts, p.sources),
      analysisBlock(p.analysis)
    ),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'ttp-h' }, el('h2', { id: 'ttp-h' }, 'ATT&CK techniques'), techniqueList(p.techniques)),
      el('section', { class: 'card', 'aria-labelledby': 'def-h' }, el('h2', { id: 'def-h' }, 'Recommended defences'), bulletList(p.defences))
    ),
    related.length ? el('section', { class: 'card', 'aria-labelledby': 'rel-h' },
      el('h2', { id: 'rel-h' }, 'Related attack dossiers'),
      el('div', { class: 'btn-row' }, related.map((a) => el('a', { class: 'btn btn-sm', href: `#/attacks/${a.id}` }, a.name)))) : null,
    el('section', { class: 'card', 'aria-labelledby': 'src-h' },
      el('h2', { id: 'src-h' }, 'Sources'),
      sourceList(p.sources),
      el('p', { class: 'kpi-sub' }, 'Real IOCs for this threat are published in the linked advisories. They are not copied here.')
    ),
    el('nav', { class: 'hero-actions', 'aria-label': 'Profile pager' },
      prev ? el('a', { class: 'btn', href: `#/threat-intel/${prev.id}` }, `← ${prev.name}`) : el('a', { class: 'btn', href: '#/threat-intel' }, '← All profiles'),
      next ? el('a', { class: 'btn', href: `#/threat-intel/${next.id}` }, `${next.name} →`) : el('a', { class: 'btn', href: '#/threat-intel' }, 'All profiles →'))
  );
  return () => view.classList.remove('stack');
}
