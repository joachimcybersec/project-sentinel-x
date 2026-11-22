/**
 * Dependency-free SVG / HTML charts.
 *
 * Why not Chart.js: these four chart types cover the dashboard, add ~0 KB of
 * third-party code, keep the CSP at script-src 'self', and render as real DOM
 * (inspectable, themeable through CSS classes, printable).
 *
 * Accessibility: every chart is a <figure> with a caption, the graphic carries
 * role="img" + an aria-label summary, and a <details> "data table" exposes the
 * exact numbers to screen readers and keyboard users.
 *
 * Pure helpers (bucketize, niceMax, donutSegments, scalePoints) are unit-tested.
 */
import { el, formatNumber, formatUtcTime } from '../utils/dom.js';

export const SEVERITY_STACK = ['info', 'low', 'medium', 'high', 'critical']; // bottom → top

/* ------------------------------------------------------------------ */
/* Pure helpers                                                       */
/* ------------------------------------------------------------------ */

/** Round up to a "nice" axis maximum: 1, 2, 2.5, 5, 10 × 10^n. */
export function niceMax(value) {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const exp = Math.floor(Math.log10(value));
  const base = 10 ** exp;
  for (const m of [1, 2, 2.5, 5, 10]) if (value <= m * base) return m * base;
  return 10 * base;
}

/** Axis maximum for integer counts whose midpoint tick is also an integer (3 → 4, 7 → 8, 23 → 50). */
export function niceIntMax(value) {
  if (!Number.isFinite(value) || value <= 0) return 2;
  if (value <= 10) return Math.ceil(value / 2) * 2;
  const m = niceMax(value);
  return (m / 2) % 1 === 0 ? m : m * 2;
}

/**
 * Count events per time bucket and severity.
 * start/end are ms timestamps; the bucket containing `end` is included.
 * Returns [{ start, end, counts: {critical,...}, total }]
 */
export function bucketize(events, { start, end, minutes = 15, field = 'ts' }) {
  const size = minutes * 60000;
  const first = Math.floor(start / size) * size;
  const n = Math.max(1, Math.floor((end - first) / size) + 1);
  const buckets = Array.from({ length: n }, (_, i) => ({
    start: first + i * size, end: first + (i + 1) * size,
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total: 0
  }));
  for (const e of events) {
    const t = Date.parse(e[field]);
    if (Number.isNaN(t)) continue;
    const i = Math.floor((t - first) / size);
    if (i < 0 || i >= n) continue;
    if (e.severity in buckets[i].counts) buckets[i].counts[e.severity] += 1;
    buckets[i].total += 1;
  }
  return buckets;
}

/**
 * Donut segments on a circle of circumference 100 (r = 15.9155).
 * Returns [{ key, value, fraction, length, offset }] where offset is the
 * cumulative start position (0–100). Zero-value segments are dropped.
 */
export function donutSegments(segments) {
  const total = segments.reduce((s, x) => s + (x.value > 0 ? x.value : 0), 0);
  if (!total) return [];
  let acc = 0;
  return segments.filter((s) => s.value > 0).map((s) => {
    const fraction = s.value / total;
    const seg = { ...s, fraction, length: fraction * 100, offset: acc };
    acc += seg.length;
    return seg;
  });
}

/** Map values to SVG coordinates inside a plot box. Returns [[x, y], ...]. */
export function scalePoints(values, { width, height, max, padX = 0, padTop = 0 }) {
  const m = max || niceMax(Math.max(...values, 0));
  const n = values.length;
  const step = n > 1 ? (width - padX * 2) / (n - 1) : 0;
  return values.map((v, i) => [
    +(padX + i * step).toFixed(2),
    +(padTop + (height - padTop) * (1 - Math.max(0, v) / m)).toFixed(2)
  ]);
}

/* ------------------------------------------------------------------ */
/* Shared building blocks                                             */
/* ------------------------------------------------------------------ */

function figure({ title, summary, graphic, table, legend = null, className = '' }) {
  return el('figure', { class: `chart ${className}` },
    el('figcaption', { class: 'chart-title' }, title),
    graphic,
    legend,
    table ? el('details', { class: 'chart-data' }, el('summary', null, 'View data table'), table) : null,
    summary ? el('p', { class: 'visually-hidden' }, summary) : null
  );
}

function dataTable(headers, rows, caption = 'Chart data') {
  return el('table', { class: 'kbd-table' },
    el('caption', { class: 'visually-hidden' }, caption),
    el('thead', null, el('tr', null, headers.map((h) => el('th', { scope: 'col' }, h)))),
    el('tbody', null, rows.map((r) => el('tr', null, r.map((c) => el('td', null, c)))))
  );
}

/* ------------------------------------------------------------------ */
/* Stacked severity timeline                                          */
/* ------------------------------------------------------------------ */

export function createTimeline({ title, buckets }) {
  const W = 720, H = 220, L = 34, B = 26, T = 10, R = 8;
  const plotW = W - L - R, plotH = H - T - B;
  const max = niceIntMax(Math.max(...buckets.map((b) => b.total), 1));
  const barW = plotW / buckets.length;
  const y = (v) => T + plotH * (1 - v / max);

  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', focusable: 'false',
    'aria-label': `${title}: ${buckets.reduce((s, b) => s + b.total, 0)} events across ${buckets.length} intervals, peak ${Math.max(...buckets.map((b) => b.total))} per interval.` });

  // grid + y labels
  for (const v of [0, max / 2, max]) {
    svg.append(
      el('line', { class: 'grid-line', x1: L, x2: W - R, y1: y(v), y2: y(v) }),
      el('text', { class: 'axis-label', x: L - 6, y: y(v), 'text-anchor': 'end', 'dominant-baseline': 'middle' }, formatNumber(v))
    );
  }

  buckets.forEach((b, i) => {
    const g = el('g', { class: 'bar-group' });
    const x = L + i * barW + barW * 0.15;
    const w = barW * 0.7;
    let acc = 0;
    for (const sev of SEVERITY_STACK) {
      const c = b.counts[sev];
      if (!c) continue;
      g.append(el('rect', { class: `fill-${sev}`, x: x.toFixed(2), y: y(acc + c).toFixed(2), width: w.toFixed(2), height: (y(acc) - y(acc + c)).toFixed(2), rx: '1.5' }));
      acc += c;
    }
    const detail = SEVERITY_STACK.slice().reverse().filter((s) => b.counts[s]).map((s) => `${b.counts[s]} ${s}`).join(', ') || 'no events';
    g.append(el('svg:title', null, `${formatUtcTime(new Date(b.start)).slice(0, 5)}–${formatUtcTime(new Date(b.end)).slice(0, 5)} UTC: ${detail}`));
    // invisible hit area so empty intervals still show a tooltip
    g.prepend(el('rect', { class: 'hit', x: (L + i * barW).toFixed(2), y: T, width: barW.toFixed(2), height: plotH }));
    svg.append(g);
    if (i % 4 === 0) {
      svg.append(el('text', { class: 'axis-label', x: (L + i * barW + barW / 2).toFixed(2), y: H - 8, 'text-anchor': 'middle' }, formatUtcTime(new Date(b.start)).slice(0, 5)));
    }
  });

  const legend = el('ul', { class: 'chart-legend', 'aria-hidden': 'true' },
    SEVERITY_STACK.slice().reverse().map((s) => el('li', null, el('span', { class: `dot fill-bg-${s}` }), s)));

  const table = dataTable(['Interval (UTC)', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total'],
    buckets.map((b) => [formatUtcTime(new Date(b.start)).slice(0, 5), b.counts.critical, b.counts.high, b.counts.medium, b.counts.low, b.counts.info, b.total]), `Data for: ${title}`);

  return figure({ title, graphic: svg, legend, table });
}

/* ------------------------------------------------------------------ */
/* Donut with interactive legend                                      */
/* ------------------------------------------------------------------ */

/**
 * segments: [{ key, label, value, className }]
 * isActive(key) -> bool, onToggle(key) — legend buttons become filter toggles.
 */
export function createDonut({ title, segments, centerLabel = 'events', isActive = null, onToggle = null }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const R = 15.9155;
  const svg = el('svg', { viewBox: '0 0 42 42', class: 'donut-svg', role: 'img', focusable: 'false',
    'aria-label': `${title}: ${segments.map((s) => `${s.label} ${s.value}`).join(', ')}` },
    el('circle', { class: 'donut-track', cx: '21', cy: '21', r: String(R) })
  );
  for (const seg of donutSegments(segments)) {
    svg.append(el('circle', {
      class: `donut-seg stroke-${seg.className || seg.key}`, cx: '21', cy: '21', r: String(R),
      'stroke-dasharray': `${seg.length.toFixed(3)} ${(100 - seg.length).toFixed(3)}`,
      'stroke-dashoffset': (25 - seg.offset).toFixed(3)
    }, el('svg:title', null, `${seg.label}: ${seg.value} (${Math.round(seg.fraction * 100)}%)`)));
  }
  svg.append(
    el('text', { class: 'donut-total', x: '21', y: '20.5', 'text-anchor': 'middle' }, formatNumber(total)),
    el('text', { class: 'donut-sub', x: '21', y: '26', 'text-anchor': 'middle' }, centerLabel)
  );

  const legend = el('ul', { class: 'donut-legend' }, segments.map((s) => {
    const pct = total ? Math.round((s.value / total) * 100) : 0;
    const content = [el('span', { class: `dot fill-bg-${s.className || s.key}` }), el('span', { class: 'legend-label' }, s.label), el('span', { class: 'legend-value' }, `${s.value} · ${pct}%`)];
    if (!onToggle) return el('li', null, content);
    const btn = el('button', { class: 'legend-btn', type: 'button', 'aria-pressed': String(Boolean(isActive && isActive(s.key))), title: `Filter by ${s.label}`, 'data-focus-key': `donut-${s.key}` }, content);
    btn.addEventListener('click', () => onToggle(s.key));
    return el('li', null, btn);
  }));

  return figure({ title, graphic: el('div', { class: 'donut-wrap' }, svg, legend), className: 'chart-donut' });
}

/* ------------------------------------------------------------------ */
/* Horizontal bar list (HTML)                                         */
/* ------------------------------------------------------------------ */

/** items: [{ label, value, className?, href?, onClick?, hint? }] */
export function createBarList({ title, items, emptyText = 'No data for the current filters.', unit = '' }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  const list = el('ul', { class: 'bar-list' });
  if (!items.length) list.append(el('li', { class: 'bar-empty' }, emptyText));
  for (const it of items) {
    const fill = el('span', { class: `bar-fill ${it.className || ''}` });
    fill.style.width = `${(it.value / max) * 100}%`;
    const body = [
      el('span', { class: 'bar-label' }, it.label, it.hint ? el('span', { class: 'bar-hint' }, ` ${it.hint}`) : null),
      el('span', { class: 'bar-value' }, `${formatNumber(it.value)}${unit}`),
      el('span', { class: 'bar-track', 'aria-hidden': 'true' }, fill)
    ];
    let row;
    if (it.onClick) {
      row = el('button', { class: 'bar-row is-action', type: 'button', title: it.actionLabel || null, 'data-focus-key': `bar-${title}-${it.label}` }, body);
      row.addEventListener('click', it.onClick);
    } else {
      row = el('div', { class: 'bar-row' }, body);
    }
    list.append(el('li', null, row));
  }
  return figure({ title, graphic: list, className: 'chart-bars' });
}

/* ------------------------------------------------------------------ */
/* Line / area chart for telemetry series                             */
/* ------------------------------------------------------------------ */

/**
 * labels: x labels (strings), series: [{ name, values, className }]
 * annotateMax: mark the highest point of the first series.
 */
export function createLineChart({ title, labels, series, unit = '', annotateMax = true }) {
  const W = 720, H = 200, L = 46, B = 26, T = 18, R = 12;
  const plotW = W - L - R, plotH = H - T - B;
  const max = niceMax(Math.max(...series.flatMap((s) => s.values), 1));
  const y = (v) => T + plotH * (1 - v / max);
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', focusable: 'false',
    'aria-label': `${title}. ${series.map((s) => `${s.name} peak ${formatNumber(Math.max(...s.values))}${unit}`).join('; ')}.` });

  for (const v of [0, max / 2, max]) {
    svg.append(
      el('line', { class: 'grid-line', x1: L, x2: W - R, y1: y(v), y2: y(v) }),
      el('text', { class: 'axis-label', x: L - 6, y: y(v), 'text-anchor': 'end', 'dominant-baseline': 'middle' }, `${formatNumber(v)}`)
    );
  }
  labels.forEach((lab, i) => {
    if (i % 4 !== 0) return;
    const x = L + (labels.length > 1 ? (plotW * i) / (labels.length - 1) : 0);
    svg.append(el('text', { class: 'axis-label', x: x.toFixed(2), y: H - 8, 'text-anchor': 'middle' }, lab));
  });

  series.forEach((s, si) => {
    const pts = scalePoints(s.values, { width: plotW, height: plotH, max }).map(([x, yy]) => [x + L, yy + T]);
    const line = pts.map((p) => p.join(',')).join(' ');
    if (si === 0) {
      svg.append(el('polygon', { class: `area ${s.className}`, points: `${L},${T + plotH} ${line} ${pts[pts.length - 1][0]},${T + plotH}` }));
    }
    svg.append(el('polyline', { class: `line ${s.className}`, points: line, fill: 'none' }));
    pts.forEach(([x, yy], i) => svg.append(el('circle', { class: `point ${s.className}`, cx: x, cy: yy, r: '2.5' },
      el('svg:title', null, `${labels[i]} UTC — ${s.name}: ${formatNumber(s.values[i])}${unit}`))));
    if (annotateMax && si === 0) {
      const mi = s.values.indexOf(Math.max(...s.values));
      const [mx, my] = pts[mi];
      const anchor = mx > W * 0.55 ? 'end' : 'start'; // keep the label inside the plot at any font size
      svg.append(
        el('circle', { class: `peak ${s.className}`, cx: mx, cy: my, r: '5' }),
        el('text', { class: 'peak-label', x: anchor === 'end' ? mx - 9 : mx + 9, y: Math.max(my + 4, T + 8), 'text-anchor': anchor },
          `Peak ${formatNumber(s.values[mi])}${unit} at ${labels[mi]}`)
      );
    }
  });

  const legend = el('ul', { class: 'chart-legend', 'aria-hidden': 'true' },
    series.map((s) => el('li', null, el('span', { class: `dot ${s.className}-bg` }), s.name)));
  const table = dataTable(['Interval (UTC)', ...series.map((s) => `${s.name}${unit ? ` (${unit.trim()})` : ''}`)],
    labels.map((lab, i) => [lab, ...series.map((s) => formatNumber(s.values[i]))]), `Data for: ${title}`);

  return figure({ title, graphic: svg, legend, table });
}
