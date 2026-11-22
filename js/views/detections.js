/**
 * MODULE 06 — Detection Engineering.
 *   #/detections              rule library · ATT&CK / incident coverage · rule playground
 *   #/detections?edit=<slug>  opens the playground pre-loaded with a rule
 *   #/detections/:slug        rule page: objective, logic, FPs, investigation, remediation, live test
 *
 * Rules are real Sigma YAML evaluated by js/detection/sigma.js against the
 * simulated logs. Labelled "simulated": original rules tested only against the simulated logs. "Lab result" is reserved for data from an actual lab run, and none has been published.
 */
import { el, clear, provenanceBadge, severityBadge } from '../utils/dom.js';
import { load, mitreUrl } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { parseYaml } from '../detection/yaml.js';
import { validateSigma, runSigma } from '../detection/sigma.js';
import { processLogs } from '../siem/parsers.js';
import { createTabs } from '../components/tabs.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { createDataTable } from '../components/data-table.js';
import { createCodeBlock } from '../components/code-block.js';
import { toast } from '../components/toast.js';
import { downloadFile } from '../components/export.js';
import { techniqueList, bulletList, sourceList, cap } from '../components/intel-ui.js';
import { openLogDrawer, LOG_TYPE_LABEL } from '../components/log-view.js';

/** Sigma level → Sentinel X severity scale. */
export const LEVEL_SEVERITY = { informational: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
const logsourceLabel = (ls) => ['product', 'category', 'service'].filter((k) => ls[k]).map((k) => ls[k]).join(' / ');

/** Load rules + logs once and run every rule. */
async function loadContext() {
  const [{ data }, { data: logData }, intelRes] = await Promise.all([load('detections'), load('logs'), load('intel').catch(() => null)]);
  const entries = processLogs(logData.logs, { year: logData.syslogYear });
  const ctx = { assets: logData.assets, iocs: intelRes ? intelRes.data.iocWatchlist.items : [] };
  const rules = data.rules.map((r) => {
    const text = r.yaml.join('\n');
    const parsed = parseYaml(text);
    const res = runSigma(text, entries);
    const techniques = (parsed.tags || []).filter((t) => /^attack\.t\d/.test(t)).map((t) => t.replace('attack.t', 'T').toUpperCase());
    const tactics = (parsed.tags || []).filter((t) => /^attack\.[a-z-]+$/.test(t)).map((t) => t.slice(7));
    const pass = res.errors.length === 0 && JSON.stringify(res.matches) === JSON.stringify(r.expectedMatches);
    return { ...r, text, parsed, res, techniques, tactics, pass, title: parsed.title, level: parsed.level, logsource: logsourceLabel(parsed.logsource) };
  });
  return { data, rules, entries, ctx };
}

function matchList(ids, entries, ctx, expected = null) {
  if (!ids.length) return el('p', { class: 'bar-empty' }, 'No matching sample logs.');
  const byId = new Map(entries.map((e) => [e.id, e]));
  return el('ul', { class: 'log-lines' }, ids.map((id) => {
    const e = byId.get(id);
    const unexpected = expected && !expected.includes(id);
    const b = el('button', { class: `log-line${unexpected ? ' is-unexpected' : ''}`, type: 'button', 'aria-haspopup': 'dialog' },
      el('span', { class: 'mono log-id' }, id), el('span', { class: `log-type lt-${e.parsed.type}` }, LOG_TYPE_LABEL[e.parsed.type]),
      el('code', { class: 'log-raw' }, e.raw));
    b.addEventListener('click', () => openLogDrawer(e, b, ctx));
    return el('li', null, b, unexpected ? el('span', { class: 'kpi-sub' }, 'Not in the expected matches (possible false positive)') : null);
  }));
}

function hashParam(name) {
  const i = location.hash.indexOf('?');
  if (i < 0) return '';
  try { return (new URLSearchParams(location.hash.slice(i + 1)).get(name) || '').slice(0, 80); } catch { return ''; }
}

/* ================= Library page ================= */
export async function renderDetections(view) {
  const { data, rules, entries, ctx } = await loadContext();
  const editSlug = hashParam('edit');

  /* ---- library tab ---- */
  const library = () => {
    const rows = rules.map((r) => ({ ...r, id: r.slug, tactic: r.tactics[0], matchCount: r.res.matches.length, _search: [r.title, r.objective, r.logsource, ...r.techniques, ...r.techniques.map(attackName), ...r.tactics].join(' ') }));
    const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
    const table = createDataTable({
      caption: 'Detection rules', pageSize: 16, rows, initialSort: { key: 'level', dir: 'desc' },
      onRowActivate: (r) => { location.hash = `#/detections/${r.slug}`; },
      rowLabel: (r) => r.title,
      columns: [
        { key: 'title', label: 'Rule', sortable: true, render: (r) => el('a', { href: `#/detections/${r.slug}` }, r.title) },
        { key: 'level', label: 'Level', sortable: true, defaultDir: 'desc', sortValue: (r) => ['informational', 'low', 'medium', 'high', 'critical'].indexOf(r.level), render: (r) => severityBadge(LEVEL_SEVERITY[r.level]) },
        { key: 'logsource', label: 'Log source', sortable: true, className: 'mono' },
        { key: 'techniques', label: 'ATT&CK', className: 'mono', render: (r) => r.techniques.join(', ') },
        { key: 'matchCount', label: 'Sample matches', sortable: true, render: (r) => el('span', { class: r.pass ? 'test-pass' : 'test-fail', title: r.pass ? 'Matches exactly the expected logs' : 'Differs from expected matches' }, `${r.pass ? '✓' : '✗'} ${r.matchCount}`) }
      ]
    });
    const update = (s) => { const out = applyFilters(rows, s, { searchFields: ['_search'] }); table.setRows(out); count.textContent = `${out.length} of ${rows.length} rules`; };
    const sources = [...new Set(rows.map((r) => r.logsource))].sort();
    const tactics = [...new Set(rows.flatMap((r) => r.tactics))].sort();
    const fb = createFilterBar({
      ariaLabel: 'Filter rules', searchLabel: 'Search rules', searchPlaceholder: 'Title, technique, tactic, log source…',
      chips: [{ key: 'level', label: 'Level', options: ['critical', 'high', 'medium', 'low'].map((l) => ({ value: l, label: l, className: `sev-${l}` })) }],
      selects: [
        { key: 'logsource', label: 'Log source', options: sources.map((s) => ({ value: s, label: s })) },
        { key: 'tactic', label: 'Primary tactic', options: tactics.map((t) => ({ value: t, label: cap(t) })) }
      ],
      onChange: update
    });
    update(fb.getState());
    return el('div', { class: 'stack' }, fb.element, el('div', null, count), table.element);
  };

  /* ---- coverage tab ---- */
  const coverage = () => {
    const covered = new Map();
    rules.forEach((r) => r.techniques.forEach((t) => (covered.get(t) || covered.set(t, []).get(t)).push(r)));
    return el('div', { class: 'stack' }, coverageIncidents(), coverageTechniques(covered));
  };
  const coverageIncidentsSlot = el('div');
  const coverageIncidents = () => {
    load('incidents').then(({ data: inc }) => {
      const firing = new Map();
      rules.forEach((r) => r.res.matches.forEach((id) => (firing.get(id) || firing.set(id, []).get(id)).push(r)));
      clear(coverageIncidentsSlot).append(
        el('h3', { class: 'chart-title' }, 'Incident evidence detected by at least one rule'),
        el('table', { class: 'kbd-table' }, el('caption', { class: 'visually-hidden' }, 'Incident evidence coverage by case'),
          el('thead', null, el('tr', null, ['Case', 'Evidence logs detected', 'Rules that fire'].map((h) => el('th', { scope: 'col' }, h)))),
          el('tbody', null, inc.incidents.map((i) => {
            const det = i.logs.filter((id) => firing.has(id));
            const fired = [...new Set(det.flatMap((id) => firing.get(id)))];
            const pct = Math.round((det.length / i.logs.length) * 100);
            return el('tr', null,
              el('td', null, el('a', { href: `#/incidents/${i.id}` }, i.id), ` ${i.title}`),
              el('td', null, el('div', { class: 'cov-bar', 'aria-hidden': 'true' }, (() => { const s = el('span'); s.style.width = `${pct}%`; return s; })()), `${det.length} / ${i.logs.length} (${pct}%)`),
              el('td', null, fired.length ? fired.map((r, k) => [k ? ', ' : '', el('a', { href: `#/detections/${r.slug}` }, r.title)]) : el('span', { class: 'kpi-sub' }, 'Gap: no single-event rule (needs correlation or new content)')));
          }))),
        el('p', { class: 'kpi-sub' }, 'Logs not detected are often context rather than malicious events (for example a successful logon). Those still need correlation rules, like the SIEM module\'s COR-002, rather than single-event Sigma rules.'));
    });
    return coverageIncidentsSlot;
  };
  const coverageTechniques = (covered) =>
    el('section', null,
      el('h3', { class: 'chart-title' }, `ATT&CK techniques covered (${covered.size})`),
      el('ul', { class: 'technique-list cov-list' }, [...covered.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([t, rs]) => el('li', null,
        el('a', { class: 'tech-id', href: mitreUrl(t), target: '_blank' }, t),
        el('span', { class: 'tech-name' }, attackName(t), ' · ', rs.map((r, k) => [k ? ', ' : '', el('a', { href: `#/detections/${r.slug}` }, r.title)])))))
    );

  /* ---- playground tab ---- */
  const playground = () => {
    const select = el('select', { class: 'input', id: 'pg-template' },
      el('option', { value: '' }, 'Load a library rule…'), rules.map((r) => el('option', { value: r.slug }, r.title)));
    const area = el('textarea', { class: 'input mono parse-input pg-editor', id: 'pg-yaml', rows: '22', maxlength: '20000', spellcheck: 'false', 'aria-describedby': 'pg-help' });
    const runBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Validate & run');
    const dlBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Download .yml');
    const out = el('div', { class: 'stack', 'aria-live': 'polite' });
    const load_ = (slug) => { const r = rules.find((x) => x.slug === slug); if (r) { area.value = r.text; select.value = slug; run(); } };
    select.addEventListener('change', () => load_(select.value));
    runBtn.addEventListener('click', () => run());
    area.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
    dlBtn.addEventListener('click', () => {
      const v = validateSigma(area.value);
      const name = v.rule && v.rule.title ? v.rule.title.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 60) : 'sigma_rule';
      downloadFile(`${name}.yml`, area.value.endsWith('\n') ? area.value : `${area.value}\n`, 'application/yaml');
      toast(`Downloaded ${name}.yml`, { variant: 'success' });
    });
    function run() {
      clear(out);
      const res = runSigma(area.value, entries);
      const ok = !res.errors.length;
      out.append(el('div', { class: `notice ${ok ? '' : 'is-error'}`, role: ok ? 'status' : 'alert' },
        el('span', { 'aria-hidden': 'true' }, ok ? '✓' : '⚠'),
        el('span', null, el('strong', null, ok ? 'Valid. ' : `${res.errors.length} error${res.errors.length > 1 ? 's' : ''}. `),
          ok ? `Matched ${res.matches.length} of ${res.considered} logs from this log source (${entries.length} logs in total).` : 'Fix the errors below, then run again.')));
      if (res.errors.length) out.append(bulletList(res.errors, 'pg-errors'));
      if (res.warnings.length) out.append(el('div', null, el('h3', { class: 'chart-title' }, 'Warnings'), bulletList(res.warnings, 'pg-warnings')));
      if (ok) out.append(el('h3', { class: 'chart-title' }, 'Matching sample logs'), matchList(res.matches, entries, ctx));
    }
    if (editSlug) load_(editSlug); else load_(rules[0].slug);
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub', id: 'pg-help' }, 'Edit any Sigma rule and run it against the 52 simulated logs. Supported: logsource product/category/service; selections, keyword lists, lists of maps; modifiers contains, startswith, endswith, all, re, cidr, gt/gte/lt/lte; conditions with and/or/not, parentheses and "1 of" / "all of". Ctrl+Enter runs the rule. Nothing leaves your browser.'),
      el('div', { class: 'filter-field' }, el('label', { class: 'filter-label', for: 'pg-template' }, 'Template'), select),
      el('div', { class: 'filter-field' }, el('label', { class: 'filter-label', for: 'pg-yaml' }, 'Rule (YAML)'), area),
      el('div', { class: 'btn-row' }, runBtn, dlBtn),
      out);
  };

  const passCount = rules.filter((r) => r.pass).length;
  const techCount = new Set(rules.flatMap((r) => r.techniques)).size;
  const kpi = (label, value, sub, cls = '') => el('div', { class: `card kpi ${cls}` }, el('span', { class: 'kpi-label' }, label), el('span', { class: 'kpi-value' }, String(value)), el('span', { class: 'kpi-sub' }, sub));
  const tabs = createTabs({
    label: 'Detection engineering views', initial: editSlug ? 2 : 0,
    tabs: [
      { id: 'library', label: `Rule library (${rules.length})`, render: library },
      { id: 'coverage', label: 'Coverage', render: coverage },
      { id: 'playground', label: 'Rule playground', render: playground }
    ]
  });

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 06'),
      el('h1', null, 'Detection Engineering'),
      el('p', { class: 'lede' }, 'A Sigma rule library for the simulated environment. Every rule is evaluated live in your browser against the same raw logs as the SIEM module, with its expected matches checked by the test suite.'),
      el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, `Reviewed ${data.reviewed}`))),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, el('strong', null, 'How these rules were tested. '), data.testing)),
    el('div', { class: 'grid grid-4' },
      kpi('Rules', rules.length, 'Sigma, status experimental', 'status-live'),
      kpi('Tests passing', `${passCount}/${rules.length}`, 'Exact expected matches', passCount === rules.length ? 'status-live' : 'sev-critical'),
      kpi('ATT&CK techniques', techCount, 'Tagged in rules', 'sev-low'),
      kpi('Log sources', new Set(rules.map((r) => r.logsource)).size, 'Windows, Linux, network, web', 'sev-medium')),
    el('section', { class: 'card' }, tabs.element),
    el('section', { class: 'card', 'aria-labelledby': 'det-refs' }, el('h2', { id: 'det-refs' }, 'References'), sourceList(data.references))
  );
  return () => view.classList.remove('stack');
}

/* ================= Rule page ================= */
export async function renderDetection(view, { params }) {
  const { data, rules, entries, ctx } = await loadContext();
  const idx = rules.findIndex((r) => r.slug === params.id);
  const r = rules[idx];
  if (!r) {
    view.append(el('header', { class: 'page-head' }, el('span', { class: 'eyebrow' }, 'Module 06'), el('h1', null, 'Rule not found'),
      el('p', { class: 'lede' }, `No detection rule has the ID “${params.id}”.`)), el('a', { class: 'btn btn-primary', href: '#/detections' }, '← Rule library'));
    return;
  }
  document.title = `${r.title} · Detection Engineering · Sentinel X`;
  const libRes = await load('attacks').catch(() => null);
  const dossiers = libRes ? r.relatedAttacks.map((id) => libRes.data.attacks.find((a) => a.id === id)).filter(Boolean) : [];
  const p = r.parsed;
  const dl = el('button', { class: 'btn btn-sm', type: 'button' }, 'Download .yml');
  dl.addEventListener('click', () => { downloadFile(`${r.slug}.yml`, `${r.text}\n`, 'application/yaml'); toast(`Downloaded ${r.slug}.yml`, { variant: 'success' }); });
  const missing = r.expectedMatches.filter((id) => !r.res.matches.includes(id));
  const prev = rules[idx - 1], next = rules[idx + 1];

  view.classList.add('stack');
  view.append(
    el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' }, el('a', { href: '#/detections' }, 'Detection Engineering'), ' / ', el('span', { 'aria-current': 'page' }, r.title)),
    el('header', { class: 'page-head soc-head' },
      el('div', null,
        el('span', { class: 'eyebrow' }, `Sigma · ${r.logsource}`),
        el('h1', null, r.title),
        el('p', { class: 'lede' }, r.objective),
        el('div', { class: 'meta-row' }, severityBadge(LEVEL_SEVERITY[r.level]), el('span', { class: 'badge status-planned' }, p.status), provenanceBadge('simulated'), el('span', { class: 'kpi-sub mono' }, p.id))),
      el('div', { class: 'btn-row' }, el('a', { class: 'btn btn-sm', href: `#/detections?edit=${r.slug}` }, 'Open in playground'), dl)),
    el('div', { class: 'grid grid-3' },
      el('section', { class: 'card', 'aria-labelledby': 'ov-h' }, el('h2', { id: 'ov-h' }, 'Rule facts'),
        el('dl', { class: 'dl' },
          el('dt', null, 'Objective'), el('dd', null, r.objective),
          el('dt', null, 'Log source'), el('dd', { class: 'mono' }, Object.entries(p.logsource).map(([k, v]) => `${k}: ${v}`).join(' · ')),
          el('dt', null, 'Severity'), el('dd', null, p.level),
          el('dt', null, 'Status'), el('dd', null, `${p.status} (tested on simulated data only)`),
          el('dt', null, 'Author / date'), el('dd', null, `${p.author}, ${p.date}`))),
      el('section', { class: 'card', 'aria-labelledby': 'tt-h' }, el('h2', { id: 'tt-h' }, 'ATT&CK mapping'), techniqueList(r.techniques),
        el('p', { class: 'kpi-sub' }, `Tactics: ${r.tactics.map(cap).join(', ')}`)),
      el('section', { class: 'card', 'aria-labelledby': 'fp-h' }, el('h2', { id: 'fp-h' }, 'False-positive considerations'), bulletList(p.falsepositives || []))),
    el('section', { class: 'card', 'aria-labelledby': 'logic-h' },
      el('h2', { id: 'logic-h' }, 'Detection logic'),
      el('p', { class: 'kpi-sub' }, p.description),
      createCodeBlock({ code: r.text, language: 'yaml', title: `${r.slug}.yml` })),
    el('section', { class: 'card', 'aria-labelledby': 'test-h' },
      el('div', { class: 'section-head' }, el('h2', { id: 'test-h' }, 'Test against sample logs'),
        el('span', { class: r.pass ? 'test-pass' : 'test-fail' }, r.pass ? `✓ Matches exactly the ${r.expectedMatches.length} expected log${r.expectedMatches.length === 1 ? '' : 's'}` : '✗ Differs from expected')),
      el('p', { class: 'kpi-sub' }, `Evaluated ${r.res.considered} logs from this log source out of ${entries.length}.`),
      matchList(r.res.matches, entries, ctx, r.expectedMatches),
      missing.length ? el('p', { class: 'test-fail' }, `Missed expected: ${missing.join(', ')}`) : null),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'inv-h' }, el('h2', { id: 'inv-h' }, 'Investigation recommendations'), el('ol', { class: 'steps' }, r.investigation.map((s) => el('li', null, s)))),
      el('section', { class: 'card', 'aria-labelledby': 'rem-h' }, el('h2', { id: 'rem-h' }, 'Remediation'), bulletList(r.remediation))),
    dossiers.length ? el('section', { class: 'card', 'aria-labelledby': 'rel-h' }, el('h2', { id: 'rel-h' }, 'Related attack dossiers'),
      el('div', { class: 'btn-row' }, dossiers.map((a) => el('a', { class: 'btn btn-sm', href: `#/attacks/${a.id}` }, a.name)))) : null,
    el('nav', { class: 'hero-actions', 'aria-label': 'Rule pager' },
      prev ? el('a', { class: 'btn', href: `#/detections/${prev.slug}` }, `← ${prev.title}`) : el('a', { class: 'btn', href: '#/detections' }, '← Rule library'),
      next ? el('a', { class: 'btn', href: `#/detections/${next.slug}` }, `${next.title} →`) : el('a', { class: 'btn', href: '#/detections' }, 'Rule library →'))
  );
  return () => view.classList.remove('stack');
}
