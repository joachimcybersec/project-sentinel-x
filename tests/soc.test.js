import { test, assert } from './test-runner.js';
import { niceMax, niceIntMax, bucketize, donutSegments, scalePoints, createTimeline, createDonut } from '../js/components/charts.js';
import { countBy, loginStats, summarise } from '../js/views/soc.js';
import { createFilterBar } from '../js/components/filter-bar.js';
import { load, validateTelemetry } from '../js/data-service.js';
import { ATTACK_NAMES } from '../js/utils/attack.js';
import { el } from '../js/utils/dom.js';

/* ---------- chart maths ---------- */
test('niceMax / niceIntMax produce readable axis maxima', () => {
  assert.equal(niceMax(3), 5);
  assert.equal(niceMax(2412), 2500);
  assert.equal(niceMax(0), 1);
  assert.equal(niceIntMax(3), 4);
  assert.equal(niceIntMax(7), 8);
  assert.equal(niceIntMax(23), 50, '25 would give a 12.5 midpoint');
  assert.equal(niceIntMax(-1), 2);
});

test('bucketize counts by 15-minute interval and severity', () => {
  const ev = [
    { ts: '2026-11-21T22:01:00Z', severity: 'high' },
    { ts: '2026-11-21T22:14:59Z', severity: 'critical' },
    { ts: '2026-11-21T22:15:00Z', severity: 'low' },
    { ts: '2026-11-21T22:44:00Z', severity: 'low' },
    { ts: 'garbage', severity: 'low' }
  ];
  const b = bucketize(ev, { start: Date.parse('2026-11-21T22:01:00Z'), end: Date.parse('2026-11-21T22:44:00Z'), minutes: 15 });
  assert.equal(b.length, 3);
  assert.equal(new Date(b[0].start).toISOString(), '2026-11-21T22:00:00.000Z');
  assert.deepEqual([b[0].total, b[1].total, b[2].total], [2, 1, 1]);
  assert.equal(b[0].counts.critical, 1);
});

test('bucketize over the real dataset accounts for every event', async () => {
  const { data } = await load('events');
  const ts = data.events.map((e) => Date.parse(e.ts));
  const b = bucketize(data.events, { start: Math.min(...ts), end: Math.max(...ts), minutes: 15 });
  assert.equal(b.reduce((s, x) => s + x.total, 0), data.events.length);
});

test('donutSegments: fractions sum to 100, zeros dropped, offsets cumulative', () => {
  const segs = donutSegments([{ key: 'a', value: 1 }, { key: 'b', value: 0 }, { key: 'c', value: 3 }]);
  assert.deepEqual(segs.map((s) => s.key), ['a', 'c']);
  assert.equal(segs[0].length, 25);
  assert.equal(segs[1].offset, 25);
  assert.equal(segs.reduce((s, x) => s + x.length, 0), 100);
  assert.deepEqual(donutSegments([{ key: 'a', value: 0 }]), []);
});

test('scalePoints maps values into the plot box', () => {
  assert.deepEqual(scalePoints([0, 5, 10], { width: 100, height: 50, max: 10 }), [[0, 50], [50, 25], [100, 0]]);
  assert.deepEqual(scalePoints([4], { width: 100, height: 50, max: 8 }), [[0, 25]]);
});

test('charts render SVG in the SVG namespace with accessible labels', () => {
  const svgEl = el('svg', { viewBox: '0 0 1 1' }, el('rect', { x: 0, y: 0, width: 1, height: 1 }));
  assert.equal(svgEl.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(svgEl.firstChild.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(el('title', null, 'x').namespaceURI, 'http://www.w3.org/1999/xhtml', 'plain "title" stays HTML');
  const tl = createTimeline({ title: 'T', buckets: bucketize([{ ts: '2026-01-01T00:00:00Z', severity: 'high' }], { start: Date.parse('2026-01-01T00:00:00Z'), end: Date.parse('2026-01-01T00:30:00Z') }) });
  assert.ok(tl.querySelector('svg[role=img]').getAttribute('aria-label').includes('1 events'));
  assert.ok(tl.querySelector('details table'), 'data-table fallback present');
  let toggled = null;
  const d = createDonut({ title: 'D', segments: [{ key: 'high', label: 'High', value: 2 }], isActive: () => true, onToggle: (k) => { toggled = k; } });
  const btn = d.querySelector('.legend-btn');
  assert.equal(btn.getAttribute('aria-pressed'), 'true');
  btn.click();
  assert.equal(toggled, 'high');
});

/* ---------- aggregations ---------- */
test('countBy sorts by count desc then key', () => {
  assert.deepEqual(countBy([{ k: 'b' }, { k: 'a' }, { k: 'b' }, { k: '' }, { k: 'c' }], 'k'), [['b', 2], ['a', 1], ['c', 1]]);
});

test('loginStats over the dataset matches a hand count', async () => {
  const { data } = await load('events');
  const s = loginStats(data.events);
  assert.equal(s.total, 9, 'authentication + account events');
  assert.equal(s.spraying, 1);
  assert.equal(s.anomalousSuccess, 1, 'EVT-0005 admin logon');
  assert.equal(s.lockouts, 1);
  assert.deepEqual(s.sourceIps[0], ['203.0.113.45', 3]);
});

test('summarise: status counts and active total', async () => {
  const { data } = await load('events');
  const s = summarise(data.events, data.events);
  const statusSum = Object.values(s.status).reduce((a, b) => a + b, 0);
  assert.equal(statusSum, data.events.length);
  assert.equal(s.active, s.status.open + s.status.investigating);
  assert.equal(s.active, 21);
});

/* ---------- data integrity ---------- */
test('every ATT&CK ID in the events has a technique name', async () => {
  const { data } = await load('events');
  const missing = [...new Set(data.events.map((e) => e.mitre).filter(Boolean))].filter((id) => !ATTACK_NAMES[id]);
  assert.deepEqual(missing, []);
});

test('telemetry validates and its story matches the events', async () => {
  const { data } = await load('telemetry');
  assert.equal(data.provenance, 'simulated');
  const peak = data.network.reduce((a, b) => (b.outboundMB > a.outboundMB ? b : a));
  assert.equal(peak.ts, '2026-11-22T00:15:00Z', 'exfil spike bucket');
  const ev = (await load('events')).data.events.find((e) => e.id === 'EVT-0023');
  const t = Date.parse(ev.ts), s = Date.parse(peak.ts);
  assert.ok(t >= s && t < s + 15 * 60000, 'EVT-0023 falls inside the outbound peak bucket');
  const dnsPeak = data.network.reduce((a, b) => (b.dnsQueries > a.dnsQueries ? b : a));
  assert.equal(dnsPeak.ts, '2026-11-21T23:00:00Z', 'DNS tunnelling bucket');
});

test('validateTelemetry rejects bad data', () => {
  assert.ok(validateTelemetry({ provenance: 'live', network: [] }).length >= 2);
  const p = validateTelemetry({ provenance: 'simulated',
    network: [{ ts: '2026-01-01T00:15:00Z', inboundMB: 1, outboundMB: -1, dnsQueries: 1 }, { ts: '2026-01-01T00:00:00Z', inboundMB: 1, outboundMB: 1, dnsQueries: 1 }],
    health: [{ name: 'x', status: 'fine' }] });
  assert.ok(p.some((x) => x.includes('non-negative')));
  assert.ok(p.some((x) => x.includes('ascending')));
  assert.ok(p.some((x) => x.includes('status invalid')));
});

/* ---------- filter bar programmatic updates ---------- */
test('filterBar.update syncs controls and ignores unknown values', () => {
  let last = null;
  const fb = createFilterBar({
    chips: [{ key: 'severity', label: 'S', options: ['high', 'low'].map((v) => ({ value: v, label: v })) }],
    selects: [{ key: 'status', label: 'St', options: [{ value: 'open', label: 'Open' }] }],
    onChange: (s) => { last = s; }
  });
  fb.update({ multi: { severity: ['low', 'bogus'] }, single: { status: 'open' }, q: 'DC-01' });
  assert.deepEqual(last.multi.severity, ['low']);
  assert.equal(last.single.status, 'open');
  assert.equal(fb.element.querySelector('select').value, 'open');
  assert.equal(fb.element.querySelector('input[type=search]').value, 'DC-01');
  assert.equal(fb.element.querySelector('.chip[data-value=low]').getAttribute('aria-pressed'), 'true');
  fb.update({ single: { status: '<script>' } });
  assert.equal(last.single.status, 'open', 'invalid option rejected');
});
