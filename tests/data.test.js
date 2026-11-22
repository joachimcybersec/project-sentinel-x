import { test, assert } from './test-runner.js';
import { load, clearCache, validateModules, validateEvents, severityCounts, DATASETS } from '../js/data-service.js';

// Datasets are fetched relative to the document, so point paths at the project root.
for (const spec of Object.values(DATASETS)) if (!spec.path.startsWith('../')) spec.path = '../' + spec.path;

test('modules.json loads and validates', async () => {
  clearCache();
  const { data, meta } = await load('modules');
  assert.equal(data.modules.length, 10, 'expected 10 modules');
  assert.ok(meta.fetchedAt, 'fetch metadata present');
});

test('module routes are unique and numbered 01–10', async () => {
  const { data } = await load('modules');
  const routes = new Set(data.modules.map((m) => m.route));
  assert.equal(routes.size, data.modules.length, 'duplicate route');
  assert.deepEqual(data.modules.map((m) => m.num), ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10']);
});

test('sample-events.json loads, validates and is labelled simulated', async () => {
  const { data } = await load('events');
  assert.equal(data.provenance, 'simulated');
  assert.ok(data.events.length >= 20, 'expected at least 20 events');
});

test('sample events only use RFC 5737 documentation IP ranges', async () => {
  const { data } = await load('events');
  const ipv4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
  const allowed = ['192.0.2.', '198.51.100.', '203.0.113.'];
  for (const e of data.events) {
    for (const m of e.message.matchAll(ipv4)) {
      assert.ok(allowed.some((p) => m[0].startsWith(p)), `${e.id}: ${m[0]} is not a documentation address`);
    }
  }
});

test('severityCounts totals match event count', async () => {
  const { data } = await load('events');
  const c = severityCounts(data.events);
  const sum = Object.values(c).reduce((a, b) => a + b, 0);
  assert.equal(sum, data.events.length);
});

test('validators reject malformed data', () => {
  assert.ok(validateModules({}).length > 0);
  assert.ok(validateModules({ modules: [{ id: 'a' }] }).length > 0);
  const bad = { provenance: 'simulated', events: [{ id: 'X', ts: 'nope', severity: 'urgent', status: 'open', mitre: 'T99', message: 'm' }] };
  const problems = validateEvents(bad);
  assert.ok(problems.some((p) => p.includes('ts')), 'bad timestamp detected');
  assert.ok(problems.some((p) => p.includes('severity')), 'bad severity detected');
  assert.ok(problems.some((p) => p.includes('mitre')), 'bad ATT&CK id detected');
  assert.ok(validateEvents({ provenance: 'live', events: [] }).length > 0, 'non-simulated provenance rejected');
});

test('load() surfaces a typed error for unknown datasets', async () => {
  let err;
  try { await load('does-not-exist'); } catch (e) { err = e; }
  assert.ok(err && err.name === 'DataError' && err.kind === 'schema');
});
