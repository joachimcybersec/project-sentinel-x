/**
 * MODULE 05 — SIEM & Security Log Analysis (#/siem, deep link #/siem?q=<query>).
 *
 * Everything runs in the browser over simulated raw logs:
 *   Log explorer  · query language over parsed + normalised events
 *   Parser lab    · parse any pasted line and see the extracted/normalised fields
 *   Correlation   · tunable rules that generate alerts from the dataset
 *   Pipeline      · collection → parsing → normalisation → enrichment → correlation, with live counts
 */
import { el, clear, formatUtcDateTime, severityBadge, provenanceBadge, formatNumber } from '../utils/dom.js';
import { load } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { processLogs, parseLine, normalise, MAX_LINE } from '../siem/parsers.js';
import { runQuery, MAX_QUERY } from '../siem/query.js';
import { correlate, enrich, RULES } from '../siem/correlation.js';
import { createTabs } from '../components/tabs.js';
import { createDataTable } from '../components/data-table.js';
import { openDrawer } from '../components/drawer.js';
import { toast } from '../components/toast.js';
import { exportCSV, stamp } from '../components/export.js';
import { createCodeBlock } from '../components/code-block.js';
import { LOG_TYPE_LABEL, fieldTable, enrichmentPanel, openLogDrawer } from '../components/log-view.js';

const EXAMPLES = [
  ['Failed Windows logons', 'event.code:4625'],
  ['Everything from one attacker IP', 'src:203.0.113.45'],
  ['Office spawning processes', 'process.parent.executable:*winword.exe'],
  ['Suspicious DNS domain', 'domain:*cdn-sync.example'],
  ['Web errors', 'type:web http.response.status_code:500'],
  ['Domain controller, excluding failures', 'host:DC-01 -code:4625'],
  ['Free text: sqlmap', 'sqlmap']
];

/** Log-explorer query that shows the entity behind an alert. */
export function pivotQuery(alert) {
  switch (alert.ruleId) {
    case 'COR-001': return `src:${alert.key}`;
    case 'COR-002': return `user:${alert.key.split('@')[0]}`;
    case 'COR-005': return `domain:*${alert.key}`;
    case 'COR-006': return `ip:${alert.key.split('→')[1]}`;
    default: return `host:${alert.key}`;
  }
}

/** Read ?q= from the hash (router ignores the query part). */
function hashQuery() {
  const i = location.hash.indexOf('?');
  if (i < 0) return '';
  try { return (new URLSearchParams(location.hash.slice(i + 1)).get('q') || '').slice(0, MAX_QUERY); } catch { return ''; }
}

export async function renderSiem(view) {
  const [{ data }, intelRes, toolsRes] = await Promise.all([load('logs'), load('intel').catch(() => null), load('siemTools').catch(() => null)]);
  const entries = processLogs(data.logs, { year: data.syslogYear });
  // flat keys used by tables for sorting
  entries.forEach((e) => { e.ts = e.norm['@timestamp']; e.type = e.parsed.type; e.host = e.norm['host.name'] || e.norm['source.ip']; });
  const ctx ={ assets: data.assets, iocs: intelRes ? intelRes.data.iocWatchlist.items : [] };
  const byId = new Map(entries.map((e) => [e.id, e]));

  /* ================= Log explorer ================= */
  const explorer = () => {
    const input = el('input', { class: 'input mono', type: 'search', id: 'siem-q', maxlength: String(MAX_QUERY), autocomplete: 'off', spellcheck: 'false',
      placeholder: 'e.g. event.code:4625 src:203.0.113.45 -host:DC-01', 'aria-describedby': 'siem-q-help' });
    const runBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Search');
    const status = el('p', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
    const errorBox = el('p', { class: 'query-error', role: 'alert', hidden: true });
    const typeState = new Set();
    const types = [...new Set(entries.map((e) => e.parsed.type))];
    const chips = types.map((t) => {
      const b = el('button', { class: 'chip', type: 'button', 'aria-pressed': 'false', 'data-value': t }, LOG_TYPE_LABEL[t] || t);
      b.addEventListener('click', () => { typeState.has(t) ? typeState.delete(t) : typeState.add(t); b.setAttribute('aria-pressed', String(typeState.has(t))); search(); });
      return b;
    });

    let current = entries;
    const table = createDataTable({
      caption: 'Log search results', pageSize: 12, initialSort: { key: 'ts', dir: 'asc' }, rows: entries,
      onRowActivate: (row, trigger) => openLogDrawer(row, trigger, ctx),
      columns: [
        { key: 'ts', label: 'Time (UTC)', sortable: true, className: 'mono', render: (r) => formatUtcDateTime(r.ts).replace(' UTC', '') },
        { key: 'type', label: 'Source', sortable: true, render: (r) => el('span', { class: `log-type lt-${r.parsed.type}` }, LOG_TYPE_LABEL[r.parsed.type]) },
        { key: 'host', label: 'Host', sortable: true, className: 'mono' },
        { key: 'summary', label: 'Summary', className: 'col-msg' },
        { key: 'id', label: 'ID', sortable: true, className: 'mono' }
      ]
    });

    function search({ updateUrl = true } = {}) {
      const q = input.value.trim();
      const { query, results } = runQuery(entries, q);
      current = typeState.size ? results.filter((e) => typeState.has(e.parsed.type)) : results;
      table.setRows(current);
      status.textContent = `${current.length} of ${entries.length} events${q ? ` match “${q}”` : ''}${typeState.size ? ` (sources: ${[...typeState].map((t) => LOG_TYPE_LABEL[t]).join(', ')})` : ''}`;
      errorBox.hidden = !query.errors.length;
      errorBox.textContent = query.errors.join('; ');
      if (updateUrl) {
        const url = `#/siem${q ? `?q=${encodeURIComponent(q)}` : ''}`;
        if (location.hash !== url) history.replaceState(null, '', url);
      }
    }
    const form = el('form', { class: 'query-bar', role: 'search', 'aria-label': 'Log search' },
      el('label', { class: 'filter-label', for: 'siem-q' }, 'Query'),
      el('div', { class: 'query-row' }, input, runBtn));
    form.addEventListener('submit', (e) => { e.preventDefault(); search(); });

    const exportBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Export results (CSV)');
    exportBtn.addEventListener('click', () => {
      const rows = table.getSortedRows();
      if (!rows.length) return toast('No results to export.', { variant: 'warning' });
      exportCSV(`sentinel-x-siem-search-${stamp()}.csv`, rows, [
        { key: 'id', label: 'Log ID' }, { key: 'ts', label: 'Timestamp (UTC)' }, { key: 'type', label: 'Source type' },
        { key: 'host', label: 'Host' }, { key: 'summary', label: 'Summary' }, { key: 'raw', label: 'Raw event' }]);
      toast(`Exported ${rows.length} log events`, { variant: 'success' });
    });

    const examples = el('div', { class: 'btn-row example-queries' }, el('span', { class: 'filter-label' }, 'Examples'),
      EXAMPLES.map(([label, q]) => {
        const b = el('button', { class: 'btn btn-sm btn-ghost mono', type: 'button', title: label }, q);
        b.addEventListener('click', () => { input.value = q; search(); input.focus(); });
        return b;
      }));

    input.value = hashQuery();
    search({ updateUrl: false });

    return el('div', { class: 'stack' },
      form,
      el('p', { class: 'kpi-sub', id: 'siem-q-help' }, 'Syntax: field:value (exact, case-insensitive), * wildcard, "quoted values", -negation, plain words search the raw line. Aliases: ip, src, dst, user, host, code, type, domain, action, outcome.'),
      errorBox, examples,
      el('div', { class: 'filter-field' }, el('span', { class: 'filter-label', id: 'src-chips' }, 'Log sources'), el('div', { class: 'chip-group', role: 'group', 'aria-labelledby': 'src-chips' }, chips)),
      el('div', { class: 'section-head' }, status, el('div', { class: 'btn-row' }, exportBtn)),
      table.element
    );
  };

  /* ================= Parser lab ================= */
  const parserLab = () => {
    const samples = [...new Map(entries.map((e) => [e.parsed.type, e])).values()];
    const select = el('select', { class: 'input', id: 'parse-sample' },
      el('option', { value: '' }, 'Choose a sample line…'),
      samples.map((s) => el('option', { value: s.id }, `${LOG_TYPE_LABEL[s.parsed.type]} (${s.id})`)));
    const area = el('textarea', { class: 'input mono parse-input', id: 'parse-input', rows: '4', maxlength: String(MAX_LINE), spellcheck: 'false',
      placeholder: 'Paste a log line (Windows key=value, Sysmon, syslog sshd, firewall key=value, BIND query log, Combined Log Format, or flat JSON)…' });
    const btn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Parse');
    const out = el('div', { class: 'parse-output', 'aria-live': 'polite' });
    select.addEventListener('change', () => { const s = byId.get(select.value); if (s) { area.value = s.raw; doParse(); } });
    btn.addEventListener('click', () => doParse());
    area.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); doParse(); } });

    function doParse() {
      clear(out);
      const parsed = parseLine(area.value, { year: data.syslogYear });
      if (parsed.type === 'unknown') {
        out.append(el('div', { class: 'notice is-error', role: 'alert' }, el('span', { 'aria-hidden': 'true' }, '⚠'),
          el('span', null, el('strong', null, 'Not parsed. '), parsed.error, '. Unparsed lines would be kept as raw text in a real SIEM and flagged for a new parser.')));
        return;
      }
      const norm = normalise(parsed);
      out.append(
        el('div', { class: 'meta-row' }, el('span', { class: `log-type lt-${parsed.type}` }, LOG_TYPE_LABEL[parsed.type]), el('span', { class: 'kpi-sub' }, `Format: ${parsed.format}`)),
        el('div', { class: 'grid grid-2' },
          el('section', null, el('h3', { class: 'chart-title' }, '1 · Extracted fields'), fieldTable({ timestamp: parsed.timestamp, host: parsed.host, ...parsed.fields }, 'Extracted fields')),
          el('section', null, el('h3', { class: 'chart-title' }, '2 · Normalised (ECS-style)'), fieldTable(norm, 'Normalised fields'))),
        el('section', null, el('h3', { class: 'chart-title' }, '3 · Enrichment'), enrichmentPanel(norm, ctx))
      );
    }
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub' }, 'Parsing turns raw text into fields; normalisation renames them to a common schema so one query works across sources. Pasted text is only matched against fixed patterns and displayed as text; it is never executed or sent anywhere.'),
      el('div', { class: 'filter-field' }, el('label', { class: 'filter-label', for: 'parse-sample' }, 'Sample'), select),
      el('div', { class: 'filter-field' }, el('label', { class: 'filter-label', for: 'parse-input' }, 'Log line (Ctrl+Enter to parse)'), area),
      el('div', { class: 'btn-row' }, btn),
      out
    );
  };

  /* ================= Correlation ================= */
  const correlation = () => {
    const enabled = new Set(RULES.map((r) => r.id));
    const params = {};
    const resultSlot = el('div', { class: 'stack' });
    const summary = el('p', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });

    const ruleCards = RULES.map((r) => {
      const cb = el('input', { type: 'checkbox', id: `rule-${r.id}`, checked: true });
      cb.addEventListener('change', () => { cb.checked ? enabled.add(r.id) : enabled.delete(r.id); run(); });
      const paramInputs = Object.entries(r.params).map(([k, v]) => {
        const id = `p-${r.id}-${k}`;
        const inp = el('input', { class: 'input param-input', type: 'number', id, value: String(v), min: '1', max: '100000', inputmode: 'numeric' });
        inp.addEventListener('change', () => {
          const n = Math.round(Number(inp.value));
          if (!Number.isFinite(n) || n < 1) {
            inp.value = String((params[r.id] && params[r.id][k]) ?? v); // restore the value the rule is actually using
            toast('Parameters must be positive whole numbers.', { variant: 'warning' });
            return;
          }
          params[r.id] = { ...(params[r.id] || {}), [k]: n };
          run();
        });
        return el('label', { class: 'param', for: id }, el('span', null, k), inp);
      });
      return el('article', { class: 'card rule-card' },
        el('div', { class: 'rule-head' },
          el('label', { class: 'rule-toggle', for: `rule-${r.id}` }, cb, el('span', { class: 'mono' }, r.id), el('strong', null, r.name)),
          severityBadge(r.severity)),
        el('p', null, r.logic),
        el('p', { class: 'kpi-sub' }, el('strong', null, 'False positives: '), r.falsePositives),
        el('div', { class: 'rule-foot' },
          el('span', { class: 'tech-chip', title: attackName(r.mitre) }, r.mitre),
          paramInputs.length ? el('div', { class: 'params' }, paramInputs) : null)
      );
    });

    function run() {
      const alerts = correlate(entries, { enabled: [...enabled], params });
      summary.textContent = `${alerts.length} alert${alerts.length === 1 ? '' : 's'} from ${enabled.size} enabled rule${enabled.size === 1 ? '' : 's'} over ${entries.length} events`;
      const table = createDataTable({
        caption: 'Generated alerts', pageSize: 10, rows: alerts.map((a, i) => ({ ...a, id: `ALR-${String(i + 1).padStart(3, '0')}` })),
        initialSort: { key: 'ts', dir: 'asc' }, emptyText: 'No alerts. Try enabling rules or lowering thresholds.',
        onRowActivate: (a, trigger) => openDrawer({
          title: a.ruleName, subtitle: `${a.id} · ${a.ruleId}`, returnFocus: trigger,
          content: [
            el('div', { class: 'meta-row' }, severityBadge(a.severity), provenanceBadge('simulated'), el('span', { class: 'tech-chip' }, `${a.mitre} ${attackName(a.mitre)}`)),
            el('p', null, a.summary),
            el('section', { class: 'drawer-section' }, el('h3', null, `Evidence (${a.evidence.length} events)`),
              createCodeBlock({ code: a.evidence.map((id) => `${id}  ${byId.get(id).raw}`).join('\n'), language: 'log', title: 'Evidence' })),
            el('a', { class: 'btn btn-sm', href: `#/siem?q=${encodeURIComponent(pivotQuery(a))}` }, 'Pivot to log explorer')
          ]
        }),
        columns: [
          { key: 'ts', label: 'Time (UTC)', sortable: true, className: 'mono', render: (a) => formatUtcDateTime(a.ts).replace(' UTC', '') },
          { key: 'severity', label: 'Severity', sortable: true, render: (a) => severityBadge(a.severity) },
          { key: 'ruleId', label: 'Rule', sortable: true, className: 'mono' },
          { key: 'key', label: 'Entity', sortable: true, className: 'mono' },
          { key: 'summary', label: 'Summary', className: 'col-msg' }
        ]
      });
      clear(resultSlot).append(table.element);
    }
    const resetBtn = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Reset rules');
    resetBtn.addEventListener('click', () => {
      Object.keys(params).forEach((k) => delete params[k]);
      RULES.forEach((r) => enabled.add(r.id));
      view.querySelectorAll('.rule-card input[type=checkbox]').forEach((c) => { c.checked = true; });
      RULES.forEach((r) => Object.entries(r.params).forEach(([k, v]) => { const i = view.querySelector(`#p-${r.id}-${k}`); if (i) i.value = String(v); }));
      run();
    });
    run();
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub' }, 'Each rule groups or sequences normalised events. Change a threshold and the alerts update immediately, which shows the trade-off between missed detections and false positives.'),
      el('div', { class: 'section-head' }, el('h3', { class: 'chart-title' }, 'Generated alerts'), summary, el('div', { class: 'btn-row' }, resetBtn)),
      resultSlot,
      el('h3', { class: 'chart-title' }, 'Rules'),
      el('div', { class: 'grid grid-2' }, ruleCards)
    );
  };

  /* ================= Pipeline ================= */
  const pipeline = () => {
    const parsedOk = entries.filter((e) => e.norm).length;
    const fieldsAvg = Math.round(entries.reduce((s, e) => s + Object.keys(e.norm || {}).length, 0) / entries.length);
    const enriched = entries.map((e) => enrich(e.norm, ctx));
    const assetHits = enriched.filter((x) => x.assets.length).length;
    const iocHits = enriched.filter((x) => x.iocMatches.length).length;
    const alerts = correlate(entries);
    const typeCounts = entries.reduce((m, e) => ({ ...m, [e.parsed.type]: (m[e.parsed.type] || 0) + 1 }), {});
    const stage = (n, title, value, detail) => el('li', { class: 'pipe-stage' },
      el('span', { class: 'pipe-num' }, String(n)), el('h3', null, title), el('div', { class: 'pipe-value' }, value), el('p', null, detail));
    const tools = toolsRes ? toolsRes.data : { tools: [], note: '' };
    return el('div', { class: 'stack' },
      el('ol', { class: 'pipeline', 'aria-label': 'SIEM processing pipeline with live counts' },
        stage(1, 'Collect', `${entries.length} events`, Object.entries(typeCounts).map(([t, c]) => `${LOG_TYPE_LABEL[t]} ${c}`).join(' · ')),
        stage(2, 'Parse', `${parsedOk}/${entries.length} parsed`, '7 format-specific parsers; unparsed lines would be kept raw and flagged.'),
        stage(3, 'Normalise', `~${fieldsAvg} fields/event`, 'Source-specific names mapped to one ECS-style schema.'),
        stage(4, 'Enrich', `${assetHits} asset · ${iocHits} IOC`, 'Asset inventory (role, criticality) and the Module 02 IOC watchlist.'),
        stage(5, 'Correlate', `${alerts.length} alerts`, `${RULES.length} rules: thresholds, sequences, allow-lists.`),
        stage(6, 'Investigate', '6 cases', el('a', { href: '#/incidents' }, 'Open the incident case studies →'))
      ),
      el('section', { class: 'table-scroll' },
        el('h3', { class: 'chart-title' }, 'Open-source tools mapped to these stages'),
        el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, el('strong', null, 'Not integrated. '), tools.note)),
        el('table', { class: 'kbd-table' }, el('caption', { class: 'visually-hidden' }, 'Open-source tools by pipeline stage'),
          el('thead', null, el('tr', null, ['Tool', 'Stage', 'Role', 'Status'].map((h) => el('th', { scope: 'col' }, h)))),
          el('tbody', null, tools.tools.map((t) => el('tr', null,
            el('td', null, el('a', { href: t.url, target: '_blank' }, t.name, ' ↗')),
            el('td', null, t.stage), el('td', null, t.role), el('td', null, el('span', { class: 'badge status-planned' }, 'Not integrated'))))))
      )
    );
  };

  const tabs = createTabs({
    label: 'SIEM views',
    tabs: [
      { id: 'explorer', label: 'Log explorer', render: explorer },
      { id: 'parser', label: 'Parser lab', render: parserLab },
      { id: 'correlation', label: 'Correlation rules', render: correlation },
      { id: 'pipeline', label: 'Pipeline', render: pipeline }
    ]
  });

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 05'),
      el('h1', null, 'SIEM & Security Log Analysis'),
      el('p', { class: 'lede' }, `Search, parse, normalise, enrich and correlate ${formatNumber(entries.length)} raw log lines from eight source types. Everything runs in your browser over the same simulated intrusion as the SOC dashboard and the incident case studies.`),
      el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, `Dataset generated ${data.generated}`))
    ),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, data.description)),
    el('section', { class: 'card' }, tabs.element)
  );
  return () => view.classList.remove('stack');
}
