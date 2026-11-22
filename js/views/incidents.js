/**
 * MODULE 04 — Incident Response and Investigation.
 *   #/incidents       case dashboard: status KPIs, priority matrix, filterable case table
 *   #/incidents/:id   case study: lifecycle tracker, alert, timeline, step-by-step
 *                     investigation with evidence logs, root cause, chain of custody,
 *                     containment / eradication / recovery, lessons learned, report export
 */
import { el, clear, formatUtcDateTime, formatUtcTime, severityBadge, provenanceBadge } from '../utils/dom.js';
import { load, priorityFor, INCIDENT_STATUSES, IR_PHASES, SEVERITY_RANK } from '../data-service.js';
import { attackName } from '../utils/attack.js';
import { processLogs } from '../siem/parsers.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { createDataTable } from '../components/data-table.js';
import { toast } from '../components/toast.js';
import { downloadFile } from '../components/export.js';
import { techniqueList, bulletList, sourceList, cap } from '../components/intel-ui.js';
import { openLogDrawer, LOG_TYPE_LABEL } from '../components/log-view.js';

export const PHASE_LABEL = {
  identification: 'Identification', classification: 'Classification', analysis: 'Analysis',
  containment: 'Containment', eradication: 'Eradication', recovery: 'Recovery', lessons: 'Lessons learned'
};

/* ---------------- Markdown report (pure) ---------------- */
const md = (s) => String(s).replace(/([\\`*_[\]<>|])/g, '\\$1');
export function incidentToMarkdown(i) {
  const list = (xs) => xs.map((x) => `- ${md(x)}`).join('\n');
  return [
    `# ${i.id}: ${md(i.title)}`,
    '_Sentinel X incident report · SIMULATED case study_',
    '',
    `| Field | Value |`, `|---|---|`,
    `| Classification | ${md(i.classification)} |`, `| Severity | ${i.severity} |`, `| Priority | ${priorityFor(i.impact, i.urgency)} (impact ${i.impact}, urgency ${i.urgency}) |`,
    `| Status / phase | ${i.status} / ${PHASE_LABEL[i.phase]} |`, `| Detected | ${i.detectedAt} via ${md(i.detectionSource)} |`, `| Owner | ${md(i.owner)} |`,
    `| Affected hosts | ${md(i.affected.hosts.join(', '))} |`, `| Affected users | ${md(i.affected.users.join(', ') || '—')} |`,
    '', '## Summary', md(i.scenario),
    '', '## Alert', `${md(i.alert.rule)}: ${md(i.alert.trigger)} (source: ${md(i.alert.source)})`,
    '', '## Timeline (UTC)', i.timeline.map((t) => `- ${t.ts}: ${md(t.text)}`).join('\n'),
    '', '## Investigation', i.investigation.map((s, n) => `${n + 1}. **${md(s.question)}** ${md(s.finding)}${s.evidence.length ? ` _(evidence: ${s.evidence.join(', ')})_` : ''}`).join('\n'),
    '', '## Root cause', md(i.rootCause),
    '', '## Evidence collected', i.evidence.map((e) => `- ${md(e.item)} | source ${md(e.source)} | collected by ${md(e.collectedBy)} | ${md(e.integrity)}`).join('\n'),
    '', '## Containment', list(i.containment), '', '## Eradication', list(i.eradication), '', '## Recovery', list(i.recovery),
    '', '## Lessons learned', list(i.lessons),
    '', '## ATT&CK techniques', i.techniques.map((t) => `- ${t} ${md(attackName(t))}`).join('\n'), ''
  ].join('\n');
}

const priorityPill = (i) => { const p = priorityFor(i.impact, i.urgency); return el('span', { class: `prio prio-${p}` }, p); };
const statusPill = (s) => el('span', { class: `status-pill st-${s}` }, cap(s));

/* ================= Case dashboard ================= */
export async function renderIncidents(view) {
  const { data } = await load('incidents');
  const cases = data.incidents.map((i) => ({ ...i, priority: priorityFor(i.impact, i.urgency), _search: [i.id, i.title, i.scenario, i.classification, ...i.affected.hosts, ...i.affected.users, ...i.techniques].join(' ') }));
  let matrixFilter = null; // { impact, urgency }
  let filterState;

  const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
  const table = createDataTable({
    caption: 'Incident cases', pageSize: 10, rows: cases, initialSort: { key: 'priority', dir: 'asc' },
    rowLabel: (r) => `${r.id} ${r.title}`,
    onRowActivate: (r) => { location.hash = `#/incidents/${r.id}`; },
    columns: [
      { key: 'id', label: 'Case', sortable: true, className: 'mono', render: (r) => el('a', { href: `#/incidents/${r.id}` }, r.id) },
      { key: 'title', label: 'Title', sortable: true },
      { key: 'priority', label: 'Priority', sortable: true, render: priorityPill },
      { key: 'severity', label: 'Severity', sortable: true, defaultDir: 'desc', sortValue: (r) => SEVERITY_RANK[r.severity], render: (r) => severityBadge(r.severity) },
      { key: 'status', label: 'Status', sortable: true, render: (r) => statusPill(r.status) },
      { key: 'phase', label: 'Phase', sortable: true, sortValue: (r) => IR_PHASES.indexOf(r.phase), render: (r) => PHASE_LABEL[r.phase] },
      { key: 'detectedAt', label: 'Detected (UTC)', sortable: true, className: 'mono', render: (r) => formatUtcDateTime(r.detectedAt).replace(' UTC', '') }
    ]
  });

  const matrixSlot = el('div');
  const apply = () => {
    let rows = applyFilters(cases, filterState, { searchFields: ['_search'] });
    if (matrixFilter) rows = rows.filter((r) => r.impact === matrixFilter.impact && r.urgency === matrixFilter.urgency);
    table.setRows(rows);
    count.textContent = `${rows.length} of ${cases.length} cases${matrixFilter ? ` · impact ${matrixFilter.impact} × urgency ${matrixFilter.urgency}` : ''}`;
    renderMatrix();
  };

  function renderMatrix() {
    const grid = el('div', { class: 'matrix', role: 'group', 'aria-label': 'Priority matrix: impact by urgency' });
    grid.append(el('span', { class: 'matrix-corner', 'aria-hidden': 'true' }, 'Impact ↓ / Urgency →'));
    [1, 2, 3].forEach((u) => grid.append(el('span', { class: 'matrix-axis', 'aria-hidden': 'true' }, `U${u}`)));
    [3, 2, 1].forEach((imp) => {
      grid.append(el('span', { class: 'matrix-axis', 'aria-hidden': 'true' }, `I${imp}`));
      [1, 2, 3].forEach((urg) => {
        const p = priorityFor(imp, urg);
        const n = cases.filter((c) => c.impact === imp && c.urgency === urg).length;
        const pressed = !!matrixFilter && matrixFilter.impact === imp && matrixFilter.urgency === urg;
        const b = el('button', { class: `matrix-cell prio-${p}`, type: 'button', 'aria-pressed': String(pressed), 'data-focus-key': `m-${imp}-${urg}`,
          'aria-label': `Impact ${imp}, urgency ${urg}: priority ${p}, ${n} case${n === 1 ? '' : 's'}` },
          el('span', { class: 'matrix-p' }, p), el('span', { class: 'matrix-n' }, n ? `${n} case${n === 1 ? '' : 's'}` : '—'));
        b.addEventListener('click', () => { matrixFilter = pressed ? null : { impact: imp, urgency: urg }; apply(); matrixSlot.querySelector(`[data-focus-key="m-${imp}-${urg}"]`)?.focus(); });
        grid.append(b);
      });
    });
    clear(matrixSlot).append(grid);
  }

  const classifications = [...new Set(cases.map((c) => c.classification))].sort();
  const filterBar = createFilterBar({
    ariaLabel: 'Filter incidents', searchLabel: 'Search cases', searchPlaceholder: 'Case ID, host, user, technique…',
    chips: [{ key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'].map((s) => ({ value: s, label: s, className: `sev-${s}` })) }],
    selects: [
      { key: 'status', label: 'Status', options: INCIDENT_STATUSES.map((s) => ({ value: s, label: cap(s) })) },
      { key: 'classification', label: 'Classification', options: classifications.map((c) => ({ value: c, label: c })) }
    ],
    onChange: (s) => { filterState = s; apply(); }
  });
  filterState = filterBar.getState();

  const kpi = (label, value, cls) => el('div', { class: `card kpi ${cls}` }, el('span', { class: 'kpi-label' }, label), el('span', { class: 'kpi-value' }, String(value)));
  const by = (k, v) => cases.filter((c) => c[k] === v).length;

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 04'),
      el('h1', null, 'Incident Response'),
      el('p', { class: 'lede' }, 'Six simulated case studies taken from detection to lessons learned. Each one comes with its alert, timeline, raw evidence logs, a step-by-step investigation, root cause, and containment, eradication and recovery actions.'),
      el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, 'Fictitious organisation; no real people or incidents'))
    ),
    el('div', { class: 'grid grid-5 kpi-row' },
      kpi('P1 cases', cases.filter((c) => c.priority === 'P1').length, 'sev-critical'),
      kpi('Open', by('status', 'open'), 'st-open'), kpi('Investigating', by('status', 'investigating'), 'st-investigating'),
      kpi('Contained', by('status', 'contained'), 'st-contained'), kpi('Closed', by('status', 'closed'), 'st-closed')),
    el('div', { class: 'ir-grid' },
      el('section', { class: 'card', 'aria-labelledby': 'cases-h' },
        el('div', { class: 'section-head' }, el('h2', { id: 'cases-h' }, 'Cases'), count),
        filterBar.element, table.element),
      el('section', { class: 'card', 'aria-labelledby': 'matrix-h' },
        el('h2', { id: 'matrix-h' }, 'Priority matrix'),
        el('p', { class: 'kpi-sub' }, data.priorityMatrix.note, ' Select a cell to filter the cases.'),
        matrixSlot,
        el('details', { class: 'chart-data' }, el('summary', null, 'Impact and urgency definitions'),
          el('h3', { class: 'chart-title' }, 'Impact'), bulletList(data.priorityMatrix.impact, 'plain-list'),
          el('h3', { class: 'chart-title' }, 'Urgency'), bulletList(data.priorityMatrix.urgency, 'plain-list')))
    ),
    el('section', { class: 'card', 'aria-labelledby': 'life-h' },
      el('h2', { id: 'life-h' }, 'Investigation workflow'),
      el('ol', { class: 'phase-track' }, IR_PHASES.map((p) => el('li', null, PHASE_LABEL[p]))),
      el('p', { class: 'kpi-sub' }, 'The case-study steps follow the classic preparation → detection & analysis → containment, eradication & recovery → post-incident structure. NIST SP 800-61 Rev. 3 (2025) now frames incident response within the CSF 2.0 functions.'),
      sourceList(data.references))
  );
  apply();
  return () => view.classList.remove('stack');
}

/* ================= Case study ================= */
export async function renderIncident(view, { params }) {
  const [{ data }, { data: logData }, evRes, libRes] = await Promise.all([load('incidents'), load('logs'), load('events'), load('attacks').catch(() => null)]);
  const i = data.incidents.find((x) => x.id === params.id);
  if (!i) {
    view.append(el('header', { class: 'page-head' }, el('span', { class: 'eyebrow' }, 'Module 04'), el('h1', null, 'Case not found'),
      el('p', { class: 'lede' }, `No incident has the ID “${params.id}”.`)), el('a', { class: 'btn btn-primary', href: '#/incidents' }, '← All cases'));
    return;
  }
  document.title = `${i.id} ${i.title} · Incident Response · Sentinel X`;
  let intelItems = [];
  try { intelItems = (await load('intel')).data.iocWatchlist.items; } catch { /* enrichment is optional */ }
  const entries = processLogs(logData.logs, { year: logData.syslogYear });
  const logById = new Map(entries.map((e) => [e.id, e]));
  const ctx = { assets: logData.assets, iocs: intelItems };
  const events = evRes.data.events.filter((e) => i.relatedEvents.includes(e.id));
  const dossiers = libRes ? i.relatedAttacks.map((id) => libRes.data.attacks.find((a) => a.id === id)).filter(Boolean) : [];
  const linked = i.linkedIncidents.map((id) => data.incidents.find((x) => x.id === id)).filter(Boolean);

  const evidenceButton = (id) => {
    const entry = logById.get(id);
    const b = el('button', { class: 'evidence-btn mono', type: 'button', 'aria-haspopup': 'dialog', title: entry ? entry.summary : id }, id);
    b.addEventListener('click', () => entry && openLogDrawer(entry, b, ctx));
    return b;
  };

  /* --- lifecycle tracker --- */
  const phaseIdx = IR_PHASES.indexOf(i.phase);
  const tracker = el('ol', { class: 'phase-track is-progress', 'aria-label': `Current phase: ${PHASE_LABEL[i.phase]}` },
    IR_PHASES.map((p, n) => el('li', { class: n < phaseIdx ? 'done' : n === phaseIdx ? 'current' : null, 'aria-current': n === phaseIdx ? 'step' : null }, PHASE_LABEL[p])));

  /* --- interactive investigation --- */
  let revealed = 0;
  const steps = el('ol', { class: 'investigation' });
  const progress = el('div', { class: 'inv-progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(i.investigation.length) });
  const progressLabel = el('span', { class: 'kpi-sub', 'aria-live': 'polite' });
  const revealAll = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Reveal all findings');
  function renderSteps(focusIdx = null) {
    clear(steps);
    i.investigation.forEach((s, n) => {
      const isOpen = n < revealed;
      const li = el('li', { class: `inv-step ${isOpen ? 'is-open' : ''}` },
        el('h3', null, el('span', { class: 'sec-num' }, `Q${n + 1}`), s.question));
      if (isOpen) {
        li.append(el('p', { class: 'finding', tabindex: '-1', id: `finding-${n}` }, s.finding));
        if (s.evidence.length) li.append(el('div', { class: 'evidence-row' }, el('span', { class: 'kpi-sub' }, 'Evidence: '), s.evidence.map(evidenceButton)));
      } else if (n === revealed) {
        const b = el('button', { class: 'btn btn-sm', type: 'button' }, 'Investigate → reveal finding');
        b.addEventListener('click', () => { revealed = n + 1; renderSteps(n); });
        li.append(el('p', { class: 'kpi-sub' }, 'Think about which logs you would check, then reveal the finding.'), b);
      } else {
        li.append(el('p', { class: 'kpi-sub' }, 'Locked until the previous step is complete.'));
      }
      steps.append(li);
    });
    progress.setAttribute('aria-valuenow', String(revealed));
    progress.style.setProperty('--pct', `${(revealed / i.investigation.length) * 100}%`);
    progressLabel.textContent = `${revealed} of ${i.investigation.length} investigation steps complete`;
    revealAll.disabled = revealed >= i.investigation.length;
    if (focusIdx !== null) steps.querySelector(`#finding-${focusIdx}`)?.focus();
  }
  revealAll.addEventListener('click', () => { revealed = i.investigation.length; renderSteps(); });
  renderSteps();

  const reportBtn = el('button', { class: 'btn btn-sm btn-primary', type: 'button' }, 'Export incident report (Markdown)');
  reportBtn.addEventListener('click', () => {
    downloadFile(`sentinel-x-${i.id}.md`, incidentToMarkdown(i), 'text/markdown;charset=utf-8');
    toast(`Exported ${i.id} report`, { variant: 'success' });
  });

  const logRows = i.logs.map((id) => logById.get(id)).filter(Boolean);
  view.classList.add('stack');
  view.append(
    el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' }, el('a', { href: '#/incidents' }, 'Incident Response'), ' / ', el('span', { 'aria-current': 'page' }, i.id)),
    el('header', { class: 'page-head soc-head' },
      el('div', null,
        el('span', { class: 'eyebrow' }, `${i.id} · ${i.classification}`),
        el('h1', null, i.title),
        el('p', { class: 'lede' }, i.scenario),
        el('div', { class: 'meta-row' }, severityBadge(i.severity), priorityPill(i), statusPill(i.status), provenanceBadge('simulated'))),
      el('div', { class: 'btn-row' }, el('a', { class: 'btn btn-sm', href: `#/siem?q=${encodeURIComponent(i.siemQuery)}` }, `Open in SIEM: ${i.siemQuery}`), reportBtn)
    ),
    el('section', { class: 'card' }, el('h2', { class: 'visually-hidden' }, 'Lifecycle'), tracker),
    el('div', { class: 'grid grid-3' },
      el('section', { class: 'card', 'aria-labelledby': 'alert-h' }, el('h2', { id: 'alert-h' }, 'Alert'),
        el('dl', { class: 'dl' }, el('dt', null, 'Rule'), el('dd', null, i.alert.rule), el('dt', null, 'Source'), el('dd', null, i.alert.source),
          el('dt', null, 'Trigger'), el('dd', null, i.alert.trigger), el('dt', null, 'Detected'), el('dd', null, formatUtcDateTime(i.detectedAt)))),
      el('section', { class: 'card', 'aria-labelledby': 'class-h' }, el('h2', { id: 'class-h' }, 'Classification & severity'),
        el('dl', { class: 'dl' }, el('dt', null, 'Type'), el('dd', null, i.classification), el('dt', null, 'Impact'), el('dd', null, data.priorityMatrix.impact[i.impact - 1]),
          el('dt', null, 'Urgency'), el('dd', null, data.priorityMatrix.urgency[i.urgency - 1]), el('dt', null, 'Priority'), el('dd', null, priorityPill(i)),
          el('dt', null, 'Owner'), el('dd', null, i.owner))),
      el('section', { class: 'card', 'aria-labelledby': 'aff-h' }, el('h2', { id: 'aff-h' }, 'Affected'),
        el('dl', { class: 'dl' }, el('dt', null, 'Hosts'), el('dd', null, i.affected.hosts.join(', ')), el('dt', null, 'Users'), el('dd', null, i.affected.users.join(', ') || '—'),
          el('dt', null, 'ATT&CK'), el('dd', null, i.techniques.join(', '))))
    ),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'inv-h' },
        el('div', { class: 'section-head' }, el('h2', { id: 'inv-h' }, 'Investigation'), el('div', { class: 'btn-row' }, revealAll)),
        progress, progressLabel, steps),
      el('section', { class: 'card', 'aria-labelledby': 'tl-h' }, el('h2', { id: 'tl-h' }, 'Timeline (UTC)'),
        el('ol', { class: 'timeline' }, i.timeline.map((t) => el('li', null, el('time', { datetime: t.ts }, formatUtcDateTime(t.ts)), el('p', null, t.text)))))
    ),
    el('section', { class: 'card', 'aria-labelledby': 'logs-h' },
      el('div', { class: 'section-head' }, el('h2', { id: 'logs-h' }, `Sample logs (${logRows.length})`), provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, 'Select a line for parsed fields and enrichment')),
      el('ul', { class: 'log-lines' }, logRows.map((e) => {
        const b = el('button', { class: 'log-line', type: 'button', 'aria-haspopup': 'dialog' },
          el('span', { class: 'mono log-id' }, e.id), el('span', { class: `log-type lt-${e.parsed.type}` }, LOG_TYPE_LABEL[e.parsed.type]),
          el('code', { class: 'log-raw' }, e.raw));
        b.addEventListener('click', () => openLogDrawer(e, b, ctx));
        return el('li', null, b);
      }))),
    el('section', { class: 'card', 'aria-labelledby': 'rc-h' }, el('h2', { id: 'rc-h' }, 'Root cause'), el('p', { class: 'root-cause' }, i.rootCause)),
    el('section', { class: 'card', 'aria-labelledby': 'ev-h' }, el('h2', { id: 'ev-h' }, 'Evidence collected (chain of custody)'),
      el('table', { class: 'kbd-table' }, el('caption', { class: 'visually-hidden' }, 'Chain of custody'),
        el('thead', null, el('tr', null, ['Item', 'Source', 'Collected by', 'Integrity'].map((h) => el('th', { scope: 'col' }, h)))),
        el('tbody', null, i.evidence.map((e) => el('tr', null, el('td', null, e.item), el('td', { class: 'mono' }, e.source), el('td', null, e.collectedBy), el('td', null, e.integrity)))))),
    el('div', { class: 'grid grid-3' },
      el('section', { class: 'card', 'aria-labelledby': 'con-h' }, el('h2', { id: 'con-h' }, 'Containment'), bulletList(i.containment)),
      el('section', { class: 'card', 'aria-labelledby': 'era-h' }, el('h2', { id: 'era-h' }, 'Eradication'), bulletList(i.eradication)),
      el('section', { class: 'card', 'aria-labelledby': 'rec-h' }, el('h2', { id: 'rec-h' }, 'Recovery'), bulletList(i.recovery))),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'les-h' }, el('h2', { id: 'les-h' }, 'Lessons learned'), bulletList(i.lessons)),
      el('section', { class: 'card', 'aria-labelledby': 'ttp-h' }, el('h2', { id: 'ttp-h' }, 'ATT&CK techniques'), techniqueList(i.techniques))),
    el('section', { class: 'card', 'aria-labelledby': 'rel-h' }, el('h2', { id: 'rel-h' }, 'Related'),
      el('h3', { class: 'chart-title' }, 'SOC events'),
      el('ul', { class: 'mini-feed' }, events.map((e) => el('li', null, el('span', { class: 'mono' }, e.id), el('time', { datetime: e.ts }, formatUtcTime(e.ts).slice(0, 5)), severityBadge(e.severity), el('span', { class: 'mini-msg' }, `${e.host}: ${e.message}`)))),
      linked.length ? [el('h3', { class: 'chart-title' }, 'Linked cases'), el('div', { class: 'btn-row' }, linked.map((x) => el('a', { class: 'btn btn-sm', href: `#/incidents/${x.id}` }, `${x.id} ${x.title}`)))] : null,
      dossiers.length ? [el('h3', { class: 'chart-title' }, 'Attack dossiers'), el('div', { class: 'btn-row' }, dossiers.map((a) => el('a', { class: 'btn btn-sm', href: `#/attacks/${a.id}` }, a.name)))] : null)
  );
  return () => view.classList.remove('stack');
}
