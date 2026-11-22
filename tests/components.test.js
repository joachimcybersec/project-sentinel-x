import { test, assert } from './test-runner.js';
import { sortRows, paginate, createDataTable } from '../js/components/data-table.js';
import { applyFilters, emptyState, isEmptyState } from '../js/components/filter-bar.js';
import { csvCell, toCSV, safeFilename, stamp } from '../js/components/export.js';
import { highlightYaml } from '../js/components/code-block.js';
import { createTabs } from '../js/components/tabs.js';
import { mitreUrl, SEVERITY_RANK } from '../js/data-service.js';

const rows = [
  { id: 'A', sev: 'low', n: 3, ts: '2026-11-20T10:00:00Z', host: 'web-01', msg: 'SQL injection pattern' },
  { id: 'B', sev: 'critical', n: 10, ts: '2026-11-21T23:59:00Z', host: 'DC-01', msg: 'Audit log cleared' },
  { id: 'C', sev: 'high', n: null, ts: '2026-11-22T00:10:00Z', host: 'fs-02', msg: 'Shadow copies deleted' },
  { id: 'D', sev: 'high', n: 2, ts: '2026-11-22T01:00:00Z', host: 'DC-01', msg: 'New account created' }
];

/* ---------- sorting & pagination ---------- */
test('sortRows sorts numbers, strings and custom keys; nulls last; stable', () => {
  assert.deepEqual(sortRows(rows, 'n', 'asc').map((r) => r.id), ['D', 'A', 'B', 'C']);
  assert.deepEqual(sortRows(rows, 'n', 'desc').map((r) => r.id), ['B', 'A', 'D', 'C']);
  assert.deepEqual(sortRows(rows, 'sev', 'desc', (r) => SEVERITY_RANK[r.sev]).map((r) => r.id), ['B', 'C', 'D', 'A']);
  assert.deepEqual(sortRows(rows, 'host', 'asc').map((r) => r.id), ['B', 'D', 'C', 'A'], 'case-insensitive, stable for ties');
  assert.equal(rows[0].id, 'A', 'input not mutated');
});

test('paginate slices and clamps', () => {
  const list = Array.from({ length: 23 }, (_, i) => i);
  const p3 = paginate(list, 3, 10);
  assert.deepEqual(p3.items, [20, 21, 22]);
  assert.equal(p3.pages, 3);
  assert.equal(p3.start, 21);
  assert.equal(paginate(list, 99, 10).page, 3);
  assert.equal(paginate([], 1, 10).pages, 1);
  assert.equal(paginate([], 1, 10).start, 0);
});

test('createDataTable renders, sorts via header and paginates', () => {
  const many = Array.from({ length: 12 }, (_, i) => ({ id: `R${String(i).padStart(2, '0')}`, v: i }));
  const t = createDataTable({ caption: 'test', pageSize: 5, rows: many, columns: [{ key: 'id', label: 'ID', sortable: true }, { key: 'v', label: 'V' }] });
  const body = () => [...t.element.querySelectorAll('tbody tr')].map((tr) => tr.cells[0].textContent);
  assert.equal(body().length, 5);
  const th = t.element.querySelector('th[aria-sort]');
  assert.equal(th.getAttribute('aria-sort'), 'none');
  th.querySelector('button').click();
  assert.equal(t.element.querySelector('th[aria-sort]').getAttribute('aria-sort'), 'ascending');
  t.element.querySelector('th[aria-sort] button').click();
  assert.equal(t.element.querySelector('th[aria-sort]').getAttribute('aria-sort'), 'descending');
  assert.equal(body()[0], 'R11');
  const [prev, next] = t.element.querySelectorAll('.pager button');
  assert.ok(prev.disabled, 'prev disabled on page 1');
  next.click(); next.click();
  assert.ok(next.disabled, 'next disabled on last page');
  assert.equal(body().length, 2);
  t.setRows([]);
  assert.equal(t.element.querySelector('.empty-cell').textContent, 'No matching records.');
});

/* ---------- filtering ---------- */
test('applyFilters: multi, single, search terms (AND, case-insensitive)', () => {
  const st = emptyState({ chips: [{ key: 'sev' }], selects: [{ key: 'host' }] });
  assert.ok(isEmptyState(st));
  assert.equal(applyFilters(rows, st).length, 4);
  assert.deepEqual(applyFilters(rows, { ...st, multi: { sev: ['high', 'critical'] } }).map((r) => r.id), ['B', 'C', 'D']);
  assert.deepEqual(applyFilters(rows, { ...st, single: { host: 'DC-01' } }).map((r) => r.id), ['B', 'D']);
  const opts = { searchFields: ['host', 'msg'] };
  assert.deepEqual(applyFilters(rows, { ...st, q: 'dc-01 ACCOUNT' }, opts).map((r) => r.id), ['D']);
  assert.equal(applyFilters(rows, { ...st, q: 'zzz' }, opts).length, 0);
});

test('applyFilters: inclusive UTC date range', () => {
  const st = { ...emptyState(), from: '2026-11-21', to: '2026-11-21' };
  assert.deepEqual(applyFilters(rows, st, { dateField: 'ts' }).map((r) => r.id), ['B']);
  assert.deepEqual(applyFilters(rows, { ...emptyState(), from: '2026-11-22' }, { dateField: 'ts' }).map((r) => r.id), ['C', 'D']);
});

/* ---------- export ---------- */
test('csvCell neutralises spreadsheet formulas (CSV injection)', () => {
  assert.equal(csvCell('=HYPERLINK("http://x","y")'), '"\'=HYPERLINK(""http://x"",""y"")"');
  assert.equal(csvCell('+cmd'), "'+cmd");
  assert.equal(csvCell('-2+3'), "'-2+3");
  assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(csvCell(-5), '-5', 'real numbers untouched');
});

test('toCSV quotes commas, quotes and newlines; CRLF rows', () => {
  const out = toCSV([{ a: 'x,y', b: 'say "hi"', c: 'l1\nl2' }], [{ key: 'a', label: 'A' }, { key: 'b', label: 'B' }, { key: 'c', label: 'C' }]);
  assert.equal(out, 'A,B,C\r\n"x,y","say ""hi""","l1\nl2"\r\n');
});

test('safeFilename and stamp produce safe names', () => {
  assert.equal(safeFilename('../../etc/passwd'), '..-..-etc-passwd');
  assert.equal(safeFilename('<script>.csv'), 'script-.csv');
  assert.equal(safeFilename(''), 'export');
  assert.equal(stamp(new Date('2026-11-22T01:30:45Z')), '20261122-0130Z');
});

/* ---------- code highlighting ---------- */
test('highlightYaml tokenises keys, modifiers, strings, comments', () => {
  const lines = highlightYaml("detection:\n  sel:\n    ScriptBlockText|contains:\n      - 'IEX'  # note\n  condition: sel");
  const types = (i) => lines[i].filter((t) => t.type !== 'plain').map((t) => `${t.type}:${t.text.trim()}`);
  assert.deepEqual(types(0), ['key:detection', 'punct::']);
  assert.deepEqual(types(2), ['key:ScriptBlockText', 'modifier:|contains', 'punct::']);
  assert.deepEqual(types(3), ['punct:-', "string:'IEX'", 'comment:# note']);
  // round-trip: tokens reassemble to the original text exactly
  assert.equal(lines.map((l) => l.map((t) => t.text).join('')).join('\n'), "detection:\n  sel:\n    ScriptBlockText|contains:\n      - 'IEX'  # note\n  condition: sel");
});

test('highlightYaml treats markup as plain text tokens', () => {
  const text = highlightYaml("title: '<img src=x onerror=alert(1)>'").flat().map((t) => t.text).join('');
  assert.equal(text, "title: '<img src=x onerror=alert(1)>'");
});

/* ---------- tabs ---------- */
test('tabs: roving tabindex, arrow/Home/End keys, lazy panels', () => {
  let renders = 0;
  const t = createTabs({ label: 'x', tabs: ['a', 'b', 'c'].map((id) => ({ id, label: id, render: () => { renders++; return document.createTextNode(id); } })) });
  document.body.append(t.element);
  const tabs = [...t.element.querySelectorAll('[role=tab]')];
  const panels = [...t.element.querySelectorAll('[role=tabpanel]')];
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  assert.equal(renders, 1, 'only the first panel rendered initially');
  const key = (k) => tabs[0].parentElement.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }));
  key('ArrowRight');
  assert.equal(t.active, 1);
  assert.equal(tabs[1].getAttribute('tabindex'), '0');
  assert.equal(tabs[0].getAttribute('tabindex'), '-1');
  assert.ok(panels[0].hidden && !panels[1].hidden);
  key('End'); assert.equal(t.active, 2);
  key('ArrowRight'); assert.equal(t.active, 0, 'wraps around');
  key('Home'); key('ArrowLeft'); assert.equal(t.active, 2);
  assert.equal(renders, 3, 'each panel rendered once');
  t.element.remove();
});

/* ---------- ATT&CK URL ---------- */
test('mitreUrl builds official technique URLs and rejects junk', () => {
  assert.equal(mitreUrl('T1059.001'), 'https://attack.mitre.org/techniques/T1059/001/');
  assert.equal(mitreUrl('T1486'), 'https://attack.mitre.org/techniques/T1486/');
  assert.equal(mitreUrl('javascript:alert(1)'), null);
  assert.equal(mitreUrl(''), null);
});
