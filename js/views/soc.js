/**
 * MODULE 01 — Security Operations Centre dashboard (#/soc).
 *
 * Every panel is derived from the SIMULATED datasets and recomputed whenever
 * the filters change. Charts double as filter controls (severity legend,
 * KPI tiles, status bar, category and technique bars).
 */
import { el, clear, formatNumber, formatUtcTime, formatUtcDateTime, severityBadge, provenanceBadge } from '../utils/dom.js';
import { load, severityCounts, SEVERITY_RANK } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { createFilterBar, applyFilters, isEmptyState } from '../components/filter-bar.js';
import { createDataTable } from '../components/data-table.js';
import { openEventDrawer } from '../components/event-drawer.js';
import { toast } from '../components/toast.js';
import { exportCSV, exportJSON, stamp } from '../components/export.js';
import { bucketize, createTimeline, createDonut, createBarList, createLineChart } from '../components/charts.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'investigating', 'contained', 'closed'];
const AUTH_CATEGORIES = new Set(['authentication', 'account']);
const ENDPOINT_CATEGORIES = new Set(['execution', 'credential', 'persistence', 'impact', 'defense-evasion', 'lateral', 'privilege']);
const NETWORK_CATEGORIES = new Set(['network', 'dns', 'exfiltration', 'web']);
const SEARCH_FIELDS = ['id', 'host', 'user', 'source', 'mitre', 'message', 'category'];
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const BUCKET_MIN = 15;
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1).replace(/-/g, ' ');

const EXPORT_COLUMNS = [
  { key: 'id', label: 'Event ID' }, { key: 'ts', label: 'Timestamp (UTC)' }, { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' }, { key: 'category', label: 'Category' }, { key: 'source', label: 'Log source' },
  { key: 'host', label: 'Host' }, { key: 'user', label: 'User' }, { key: 'mitre', label: 'ATT&CK' }, { key: 'message', label: 'Message' }
];

/* ---------------- pure aggregations (exported for tests) ---------------- */

export function countBy(rows, key) {
  const m = new Map();
  for (const r of rows) { const k = r[key]; if (k) m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
}

export function loginStats(rows) {
  const auth = rows.filter((r) => AUTH_CATEGORIES.has(r.category));
  return {
    total: auth.length,
    failed: auth.filter((r) => /failed|brute-force/i.test(r.message)).length,
    spraying: auth.filter((r) => /spray/i.test(r.message)).length,
    anomalousSuccess: auth.filter((r) => /4624/.test(r.source) && (r.severity === 'critical' || r.severity === 'high')).length,
    lockouts: auth.filter((r) => /locked out/i.test(r.message)).length,
    sourceIps: countBy(auth.flatMap((r) => (r.message.match(IPV4) || []).map((ip) => ({ ip }))), 'ip')
  };
}

export function summarise(rows, all) {
  return {
    total: rows.length,
    datasetTotal: all.length,
    severity: severityCounts(rows),
    status: Object.fromEntries(STATUSES.map((s) => [s, rows.filter((r) => r.status === s).length])),
    active: rows.filter((r) => r.status === 'open' || r.status === 'investigating').length,
    categories: countBy(rows, 'category'),
    techniques: countBy(rows, 'mitre')
  };
}

/* ---------------- view ---------------- */

export async function renderSoc(view) {
  const [ev, tel] = await Promise.all([load('events'), load('telemetry')]);
  let all = ev.data.events;
  let telemetry = tel.data;
  let loadedAt = ev.meta.fetchedAt;
  let filtered = all;
  let state;

  const timeBounds = () => {
    const ts = all.map((e) => Date.parse(e.ts)).filter((t) => !Number.isNaN(t));
    return { start: Math.min(...ts), end: Math.max(...ts) };
  };

  /* ---- slots that re-render on every filter change ---- */
  const kpiRow = el('div', { class: 'grid grid-5 kpi-row' });
  const timelineSlot = el('div', { class: 'card soc-timeline' });
  const donutSlot = el('div', { class: 'card soc-donut' });
  const statusSlot = el('div', { class: 'card soc-status' });
  const categorySlot = el('div', { class: 'card' });
  const techniqueSlot = el('div', { class: 'card' });
  const loginSlot = el('section', { class: 'card', 'aria-labelledby': 'login-h' });
  const endpointSlot = el('section', { class: 'card', 'aria-labelledby': 'endpoint-h' });
  const networkSlot = el('section', { class: 'card soc-network', 'aria-labelledby': 'net-h' });
  const healthSlot = el('section', { class: 'card soc-health', 'aria-labelledby': 'health-h' });
  const matchCount = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
  const loadedLabel = el('span', { class: 'kpi-sub' });

  /* ---- filter bar ---- */
  const categories = [...new Set(all.map((e) => e.category))].sort();
  const filterBar = createFilterBar({
    ariaLabel: 'Dashboard filters',
    searchLabel: 'Search',
    searchPlaceholder: 'Host, user, IP, ATT&CK ID, message…',
    chips: [{ key: 'severity', label: 'Severity', options: SEVERITIES.map((s) => ({ value: s, label: s, className: `sev-${s}` })) }],
    selects: [
      { key: 'status', label: 'Status', options: STATUSES.map((s) => ({ value: s, label: cap(s) })) },
      { key: 'category', label: 'Event type', options: categories.map((c) => ({ value: c, label: cap(c) })) }
    ],
    dateRange: { label: 'Date (UTC)' },
    onChange: (s) => { state = s; render(); }
  });
  state = filterBar.getState();

  /* ---- events table ---- */
  const table = createDataTable({
    caption: 'Filtered security events',
    pageSize: 10,
    initialSort: { key: 'ts', dir: 'desc' },
    rows: all,
    onRowActivate: (row, trigger) => openEventDrawer(row, trigger, { related: relatedTo(row) }),
    columns: [
      { key: 'ts', label: 'Time (UTC)', sortable: true, defaultDir: 'desc', className: 'mono', render: (r) => el('time', { datetime: r.ts }, formatUtcDateTime(r.ts).replace(' UTC', '')) },
      { key: 'severity', label: 'Severity', sortable: true, defaultDir: 'desc', sortValue: (r) => SEVERITY_RANK[r.severity], render: (r) => severityBadge(r.severity) },
      { key: 'id', label: 'ID', sortable: true, className: 'mono' },
      { key: 'host', label: 'Host', sortable: true, className: 'mono' },
      { key: 'source', label: 'Source', sortable: true },
      { key: 'mitre', label: 'ATT&CK', sortable: true, className: 'mono', render: (r) => r.mitre || '—' },
      { key: 'status', label: 'Status', sortable: true, render: (r) => el('span', { class: `status-pill st-${r.status}` }, cap(r.status)) },
      { key: 'message', label: 'Message', className: 'col-msg' }
    ]
  });

  const relatedTo = (row) => all.filter((e) => e.host === row.host && e.id !== row.id)
    .sort((a, b) => a.ts.localeCompare(b.ts)).slice(-5);

  /* ---- header actions ---- */
  const refreshBtn = el('button', { class: 'btn btn-sm', type: 'button' }, '↻ Reload data');
  refreshBtn.addEventListener('click', async () => {
    refreshBtn.disabled = true;
    try {
      const [e2, t2] = await Promise.all([load('events', { force: true }), load('telemetry', { force: true })]);
      all = e2.data.events; telemetry = t2.data; loadedAt = e2.meta.fetchedAt;
      render();
      toast(`Reloaded ${all.length} events at ${formatUtcTime(loadedAt)} UTC. Simulated dataset: values change only when the data file changes.`, { variant: 'info' });
    } catch (err) {
      toast(`Reload failed: ${err.message}. Showing previously loaded data.`, { variant: 'error', timeout: 8000 });
    } finally {
      refreshBtn.disabled = false;
    }
  });

  const exportGuard = (fn) => () => {
    const rows = table.getSortedRows();
    if (!rows.length) { toast('Nothing to export: no events match the filters.', { variant: 'warning' }); return; }
    fn(rows);
  };
  const csvBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export CSV');
  csvBtn.addEventListener('click', exportGuard((rows) => {
    exportCSV(`sentinel-x-soc-events-${stamp()}.csv`, rows, EXPORT_COLUMNS);
    toast(`Exported ${rows.length} events to CSV`, { variant: 'success' });
  }));
  const jsonBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export JSON');
  jsonBtn.addEventListener('click', exportGuard((rows) => {
    exportJSON(`sentinel-x-soc-events-${stamp()}.json`, { exportedAt: new Date().toISOString(), provenance: 'simulated', filters: isEmptyState(state) ? null : state, count: rows.length, events: rows });
    toast(`Exported ${rows.length} events to JSON`, { variant: 'success' });
  }));
  const reportBtn = el('button', { class: 'btn btn-sm btn-primary', type: 'button' }, 'Shift summary');
  reportBtn.addEventListener('click', () => {
    const s = summarise(filtered, all);
    exportJSON(`sentinel-x-shift-summary-${stamp()}.json`, {
      report: 'SOC shift summary', generatedAt: new Date().toISOString(), provenance: 'simulated',
      dataLoadedAt: loadedAt, filters: isEmptyState(state) ? null : state,
      totals: { events: s.total, active: s.active, ...s.severity }, status: s.status,
      topCategories: s.categories.slice(0, 5).map(([category, count]) => ({ category, count })),
      topTechniques: s.techniques.slice(0, 5).map(([id, count]) => ({ id, name: attackName(id), count })),
      authentication: (({ sourceIps, ...rest }) => ({ ...rest, topSourceIps: sourceIps.slice(0, 5).map(([ip, count]) => ({ ip, count })) }))(loginStats(filtered)),
      platformHealth: telemetry.health
    });
    toast('Shift summary exported (JSON)', { variant: 'success' });
  });

  /* ---- renderers ---- */

  function toggleSeverity(sev) {
    const cur = state.multi.severity || [];
    filterBar.update({ multi: { severity: cur.includes(sev) ? cur.filter((s) => s !== sev) : [...cur, sev] } });
  }
  function onlySeverity(sev) {
    const cur = state.multi.severity || [];
    filterBar.update({ multi: { severity: cur.length === 1 && cur[0] === sev ? [] : [sev] } });
  }
  const toggleSingle = (key, value) => filterBar.update({ single: { [key]: state.single[key] === value ? '' : value } });
  const toggleQuery = (q) => filterBar.update({ q: state.q === q ? '' : q });

  function renderKpis(s) {
    clear(kpiRow);
    const tile = (label, value, sub, cls, onClick, pressed) => {
      const inner = [el('span', { class: 'kpi-label' }, label), el('span', { class: 'kpi-value' }, formatNumber(value)), el('span', { class: 'kpi-sub' }, sub)];
      if (!onClick) return el('div', { class: `card kpi ${cls}` }, inner);
      const b = el('button', { class: `card kpi kpi-btn ${cls}`, type: 'button', 'aria-pressed': String(pressed), title: `Show only ${label.toLowerCase()} events`, 'data-focus-key': `kpi-${label}` }, inner);
      b.addEventListener('click', onClick);
      return b;
    };
    const sevSel = state.multi.severity || [];
    kpiRow.append(
      tile('Events', s.total, isEmptyState(state) ? 'Entire demo dataset' : `of ${s.datasetTotal} in dataset`, 'status-live'),
      ...['critical', 'high', 'medium', 'low'].map((sev) =>
        tile(cap(sev), s.severity[sev], `${s.total ? Math.round((s.severity[sev] / s.total) * 100) : 0}% of view`, `sev-${sev}`,
          () => onlySeverity(sev), sevSel.length === 1 && sevSel[0] === sev))
    );
  }

  function renderStatus(s) {
    clear(statusSlot);
    const bar = el('div', { class: 'status-bar', role: 'img', 'aria-label': `Status: ${STATUSES.map((k) => `${s.status[k]} ${k}`).join(', ')}` });
    for (const k of STATUSES) {
      if (!s.status[k]) continue;
      const seg = el('span', { class: `status-seg st-bg-${k}`, title: `${cap(k)}: ${s.status[k]}` });
      seg.style.flexGrow = String(s.status[k]);
      bar.append(seg);
    }
    if (!s.total) bar.append(el('span', { class: 'status-seg empty' }));
    statusSlot.append(
      el('div', { class: 'chart-title' }, 'Incident status'),
      el('div', { class: 'status-headline' }, el('span', { class: 'kpi-value' }, formatNumber(s.active)), el('span', { class: 'kpi-sub' }, ' active (open + investigating)')),
      bar,
      el('ul', { class: 'status-legend' }, STATUSES.map((k) => {
        const b = el('button', { class: 'legend-btn', type: 'button', 'aria-pressed': String(state.single.status === k), title: `Filter by status: ${k}`, 'data-focus-key': `status-${k}` },
          el('span', { class: `dot st-bg-${k}` }), el('span', { class: 'legend-label' }, cap(k)), el('span', { class: 'legend-value' }, String(s.status[k])));
        b.addEventListener('click', () => toggleSingle('status', k));
        return el('li', null, b);
      }))
    );
  }

  function miniFeed(rows, emptyText) {
    if (!rows.length) return el('p', { class: 'bar-empty' }, emptyText);
    return el('ul', { class: 'mini-feed' }, rows.map((r) => {
      const b = el('button', { class: 'mini-open', type: 'button', 'aria-haspopup': 'dialog', 'aria-label': `Open details for ${r.id}` }, '›');
      b.addEventListener('click', () => openEventDrawer(r, b, { related: relatedTo(r) }));
      return el('li', null, b, el('time', { datetime: r.ts }, formatUtcTime(r.ts).slice(0, 5)), severityBadge(r.severity), el('span', { class: 'mini-msg' }, `${r.host}: ${r.message}`));
    }));
  }

  function renderLogins() {
    const ls = loginStats(filtered);
    const recent = filtered.filter((r) => AUTH_CATEGORIES.has(r.category)).sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 4);
    const stat = (label, v, cls = '') => el('div', { class: `mini-stat ${cls}` }, el('span', { class: 'mini-stat-v' }, formatNumber(v)), el('span', { class: 'mini-stat-l' }, label));
    clear(loginSlot).append(
      el('div', { class: 'section-head' }, el('h2', { id: 'login-h' }, 'Suspicious login activity'), el('span', { class: 'kpi-sub' }, `${ls.total} auth events`)),
      el('div', { class: 'mini-stats' },
        stat('Failed / brute-force', ls.failed, 'sev-high'), stat('Password spraying', ls.spraying, 'sev-high'),
        stat('Anomalous admin logons', ls.anomalousSuccess, 'sev-critical'), stat('Lockouts', ls.lockouts, 'sev-low')),
      createBarList({
        title: 'Top source IPs in authentication events',
        items: ls.sourceIps.slice(0, 5).map(([ip, n]) => ({ label: ip, value: n, className: 'fill-bg-high', onClick: () => toggleQuery(ip), actionLabel: `Search for ${ip}` }))
      }),
      el('h3', { class: 'chart-title' }, 'Latest authentication events'),
      miniFeed(recent, 'No authentication events match the filters.')
    );
  }

  function renderEndpoint() {
    const ep = filtered.filter((r) => ENDPOINT_CATEGORIES.has(r.category));
    const recent = ep.slice().sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 5);
    clear(endpointSlot).append(
      el('div', { class: 'section-head' }, el('h2', { id: 'endpoint-h' }, 'Endpoint security events'), el('span', { class: 'kpi-sub' }, `${ep.length} EDR / Sysmon / Windows events`)),
      createBarList({
        title: 'Most affected hosts',
        items: countBy(ep, 'host').slice(0, 5).map(([host, n]) => ({ label: host, value: n, className: 'fill-bg-critical', onClick: () => toggleQuery(host), actionLabel: `Search for ${host}` }))
      }),
      el('h3', { class: 'chart-title' }, 'Latest endpoint detections'),
      miniFeed(recent, 'No endpoint events match the filters.')
    );
  }

  function renderNetwork() {
    const from = state.from ? Date.parse(state.from + 'T00:00:00Z') : -Infinity;
    const to = state.to ? Date.parse(state.to + 'T23:59:59.999Z') : Infinity;
    const buckets = telemetry.network.filter((b) => { const t = Date.parse(b.ts); return t >= from && t <= to; });
    const netEvents = filtered.filter((r) => NETWORK_CATEGORIES.has(r.category)).length;
    const labels = buckets.map((b) => formatUtcTime(b.ts).slice(0, 5));
    clear(networkSlot).append(
      el('div', { class: 'section-head' },
        el('h2', { id: 'net-h' }, 'Network traffic monitoring'), provenanceBadge('simulated'),
        el('span', { class: 'kpi-sub' }, `${netEvents} network / DNS / web events in view · telemetry follows the date filter only`)),
      buckets.length
        ? el('div', { class: 'grid grid-2' },
          createLineChart({ title: `Egress vs ingress per ${telemetry.bucketMinutes} min (MB)`, labels, unit: ' MB',
            series: [{ name: 'Outbound', values: buckets.map((b) => b.outboundMB), className: 'series-out' },
              { name: 'Inbound', values: buckets.map((b) => b.inboundMB), className: 'series-in' }] }),
          createLineChart({ title: `DNS queries per ${telemetry.bucketMinutes} min`, labels,
            series: [{ name: 'DNS queries', values: buckets.map((b) => b.dnsQueries), className: 'series-dns' }] }))
        : el('p', { class: 'bar-empty' }, 'No telemetry in the selected date range.')
    );
  }

  function renderHealth() {
    const counts = countBy(telemetry.health, 'status');
    const degraded = telemetry.health.filter((h) => h.status === 'degraded' || h.status === 'down').length;
    clear(healthSlot).append(
      el('div', { class: 'section-head' }, el('h2', { id: 'health-h' }, 'System health'), provenanceBadge('simulated')),
      el('p', { class: 'kpi-sub' }, degraded ? `${degraded} component${degraded > 1 ? 's need' : ' needs'} attention · ${counts.map(([k, n]) => `${n} ${k.replace('-', ' ')}`).join(', ')}` : 'All components operational'),
      el('ul', { class: 'health-list' }, telemetry.health.map((h) => el('li', { class: `health-${h.status}` },
        el('span', { class: 'health-dot', 'aria-hidden': 'true' }),
        el('span', { class: 'health-name' }, h.name),
        el('span', { class: 'health-status' }, cap(h.status)),
        el('span', { class: 'health-detail' }, h.detail))))
    );
  }

  function render() {
    // Panels are rebuilt on every change; remember which control had focus so keyboard users keep their place.
    const focusKey = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.focusKey : null;
    filtered = applyFilters(all, state, { searchFields: SEARCH_FIELDS, dateField: 'ts' });
    const s = summarise(filtered, all);
    matchCount.textContent = `${s.total} of ${s.datasetTotal} events match`;
    loadedLabel.textContent = `Data loaded ${formatUtcTime(loadedAt)} UTC`;
    renderKpis(s);

    const { start, end } = timeBounds();
    clear(timelineSlot).append(createTimeline({ title: `Event timeline (${BUCKET_MIN}-minute intervals, UTC)`, buckets: bucketize(filtered, { start, end, minutes: BUCKET_MIN }) }));
    clear(donutSlot).append(createDonut({
      title: 'Alert distribution by severity',
      segments: SEVERITIES.map((k) => ({ key: k, label: cap(k), value: s.severity[k] })),
      isActive: (k) => (state.multi.severity || []).includes(k),
      onToggle: toggleSeverity
    }));
    renderStatus(s);
    clear(categorySlot).append(createBarList({
      title: 'Events by type',
      items: s.categories.map(([c, n]) => ({ label: cap(c), value: n, className: 'fill-bg-accent', onClick: () => toggleSingle('category', c), actionLabel: `Filter by type: ${c}` }))
    }));
    clear(techniqueSlot).append(createBarList({
      title: 'Detection activity by ATT&CK technique',
      items: s.techniques.slice(0, 6).map(([id, n]) => ({ label: id, hint: attackName(id), value: n, className: 'fill-bg-violet', onClick: () => toggleQuery(id), actionLabel: `Search for ${id}` }))
    }));
    renderLogins();
    renderEndpoint();
    renderNetwork();
    renderHealth();
    table.setRows(filtered);
    if (focusKey) {
      const target = view.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`);
      if (target) target.focus({ preventScroll: true });
    }
  }

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head soc-head' },
      el('div', null,
        el('span', { class: 'eyebrow' }, 'Module 01'),
        el('h1', null, 'Security Operations Centre'),
        el('div', { class: 'meta-row' }, provenanceBadge('simulated'), loadedLabel)
      ),
      el('div', { class: 'btn-row' }, refreshBtn, csvBtn, jsonBtn, reportBtn)
    ),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'),
      el('span', null, el('strong', null, 'Demonstration data. '),
        'Every number on this dashboard comes from synthetic events and telemetry written for this project. It is not connected to any live SIEM, EDR or network sensor. Click the KPI tiles, chart legends and bars to filter.')),
    el('div', { class: 'filter-wrap' }, filterBar.element, el('div', { class: 'filter-summary' }, matchCount)),
    kpiRow,
    el('div', { class: 'soc-grid-a' }, timelineSlot, donutSlot),
    el('div', { class: 'grid grid-3' }, statusSlot, categorySlot, techniqueSlot),
    el('div', { class: 'grid grid-2' }, loginSlot, endpointSlot),
    networkSlot,
    healthSlot,
    el('section', { class: 'card', 'aria-labelledby': 'events-h' },
      el('div', { class: 'section-head' }, el('h2', { id: 'events-h' }, 'Event queue'), el('span', { class: 'kpi-sub' }, 'Select a row to open the investigation panel')),
      table.element)
  );

  render();
  return () => view.classList.remove('stack');
}
