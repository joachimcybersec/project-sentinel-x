import { test, assert } from './test-runner.js';
import { load, validateTools, validateKnowledge } from '../js/data-service.js';
import { buildIndex, search, parseTerms, excerpt } from '../js/search/search.js';
import { hashToPath, resolve } from '../js/router.js';

/* ---------- tools ---------- */
test('tools.json covers all 10 required categories with at least 3 tools each', async () => {
  const { data } = await load('tools');
  const required = ['siem', 'edr', 'ids', 'vuln', 'network', 'intel', 'forensics', 'ir', 'pentest', 'cloud'];
  assert.deepEqual(data.categories.map((c) => c.id).sort(), required.slice().sort());
  for (const c of required) assert.ok(data.tools.filter((t) => t.category === c).length >= 3, `${c} has fewer than 3 tools`);
});

test('every penetration-testing tool carries the authorised-use caution', async () => {
  const { data } = await load('tools');
  data.tools.filter((t) => t.category === 'pentest').forEach((t) => assert.ok(t.caution, `${t.id} missing caution`));
});

test('validateTools rejects bad licences, http docs and unknown workflow tools', () => {
  const v = validateTools({ categories: [{ id: 'siem' }], tools: [{ id: 'aa', category: 'nope', licence: 'gpl', url: 'http://x', description: '', useCases: [] }], workflows: [{ steps: [{ tool: 'zz' }] }] });
  for (const part of ['category unknown', 'licence invalid', 'https', 'description/useCases', 'unknown tool zz']) assert.ok(v.some((m) => m.includes(part)), `expected "${part}"`);
});

/* ---------- knowledge ---------- */
test('knowledge.json: 10 subject areas, every article cites at least one reference', async () => {
  const { data } = await load('knowledge');
  assert.equal(data.categories.length, 10);
  for (const c of data.categories) assert.ok(data.articles.some((a) => a.category === c.id), `no article for ${c.id}`);
  data.articles.forEach((a) => assert.ok(a.refs.length >= 1, `${a.id} has no references`));
});

test('validateKnowledge catches broken pathway steps and unknown references', () => {
  const v = validateKnowledge({ categories: [{ id: 'soc' }], references: {}, articles: [{ id: 'aa', category: 'soc', level: 'beginner', sections: [{}], refs: ['missing'] }],
    pathways: [{ steps: [{ type: 'article', ref: 'nope' }, { type: 'practice', href: 'https://evil.example' }] }] });
  for (const part of ['unknown reference missing', 'unknown article nope', 'in-app route']) assert.ok(v.some((m) => m.includes(part)), `expected "${part}"`);
});

test('every in-app link in tools, articles and pathways resolves to a registered route', async () => {
  const [{ data: tools }, { data: kb }, { data: mods }] = await Promise.all([load('tools'), load('knowledge'), load('modules')]);
  const routes = [{ path: '/' }, { path: '/about' }, { path: '/components' }, ...mods.modules.map((m) => ({ path: m.route })),
    ...['/threat-intel/:id', '/attacks/:id', '/incidents/:id', '/detections/:id', '/vulnerabilities/:id', '/knowledge/:id'].map((p) => ({ path: p }))];
  const hrefs = [
    ...tools.tools.filter((t) => t.practice).map((t) => t.practice.href),
    ...tools.workflows.map((w) => w.related.href),
    ...kb.articles.flatMap((a) => a.practice.map((p) => p.href)),
    ...kb.pathways.flatMap((p) => p.steps.filter((s) => s.href).map((s) => s.href))
  ];
  for (const h of hrefs) assert.ok(resolve(routes, hashToPath(h)), `unresolved in-app link ${h}`);
});

test('detail links point at items that exist', async () => {
  const [{ data: tools }, { data: kb }, { data: intel }, { data: lib }, { data: inc }, { data: det }] = await Promise.all(
    ['tools', 'knowledge', 'intel', 'attacks', 'incidents', 'detections'].map((n) => load(n)));
  const ids = { 'threat-intel': intel.profiles.map((p) => p.id), attacks: lib.attacks.map((a) => a.id), incidents: inc.incidents.map((i) => i.id),
    detections: det.rules.map((r) => r.slug), knowledge: kb.articles.map((a) => a.id) };
  const hrefs = [...tools.tools.filter((t) => t.practice).map((t) => t.practice.href), ...tools.workflows.map((w) => w.related.href),
    ...kb.articles.flatMap((a) => a.practice.map((p) => p.href)), ...kb.pathways.flatMap((p) => p.steps.filter((s) => s.href).map((s) => s.href))];
  for (const h of hrefs) {
    const [, mod, id] = hashToPath(h).split('/');
    if (id && ids[mod]) assert.ok(ids[mod].includes(id), `${h}: no ${mod} item "${id}"`);
  }
});

/* ---------- search ---------- */
const fullIndex = async () => {
  const names = ['modules', 'knowledge', 'tools', 'intel', 'attacks', 'detections', 'cves', 'incidents', 'network'];
  const d = Object.fromEntries((await Promise.all(names.map((n) => load(n)))).map((r, i) => [names[i], r.data]));
  return buildIndex({ modules: d.modules.modules, articles: d.knowledge.articles, tools: d.tools.tools, profiles: d.intel.profiles, attacks: d.attacks.attacks,
    rules: d.detections.rules, cves: d.cves.cves, incidents: d.incidents.incidents, topics: d.network.topics });
};

test('search index covers all nine content types and every item', async () => {
  const idx = await fullIndex();
  assert.deepEqual([...new Set(idx.map((e) => e.type))].sort(), ['article', 'attack', 'cve', 'incident', 'module', 'profile', 'rule', 'tool', 'topic']);
  const sizes = await Promise.all(['modules', 'knowledge', 'tools', 'intel', 'attacks', 'detections', 'cves', 'incidents', 'network'].map((n) => load(n)));
  const [m, k, t, i, a, d, c, inc, net] = sizes.map((s) => s.data);
  const expected = m.modules.length + k.articles.length + t.tools.length + i.profiles.length + a.attacks.length + d.rules.length + c.cves.length + inc.incidents.length + net.topics.length;
  assert.equal(idx.length, expected);
  assert.ok(idx.every((e) => typeof e.title === 'string' && e.title.length > 0), 'every entry has a title');
  assert.equal(idx.find((e) => e.id === 'shadow-copy-deletion').title, 'Shadow Copies Deleted via vssadmin or wmic', 'rule title read from YAML');
});

test('exact IDs rank first; all terms must match', async () => {
  const idx = await fullIndex();
  assert.equal(search(idx, 'CVE-2023-4966')[0].id, 'CVE-2023-4966');
  assert.equal(search(idx, 'ir-2026-004')[0].id, 'IR-2026-004');
  const lsass = search(idx, 'lsass');
  assert.ok(lsass.some((r) => r.type === 'rule') && lsass.some((r) => r.type === 'attack'), 'LSASS finds rules and dossiers');
  assert.equal(search(idx, 'zero trust').filter((r) => r.type === 'article')[0].id, 'zero-trust-practice');
  assert.equal(search(idx, 'lsass qwertyzzz').length, 0, 'AND semantics');
  assert.deepEqual(search(idx, '   '), []);
});

test('search input is length-capped and never treated as a pattern', async () => {
  const idx = await fullIndex();
  assert.equal(parseTerms('x'.repeat(500)).join('').length, 120);
  assert.deepEqual(search(idx, '.*'), [], 'regex syntax is literal');
  const r = search(idx, 'volt typhoon')[0];
  assert.ok(excerpt(r, 'volt typhoon').includes('volt'));
});
