import { test, assert } from './test-runner.js';
import { load, validateIntel, validateAttacks } from '../js/data-service.js';
import { ATTACK_NAMES } from '../js/utils/attack.js';
import { collectReports } from '../js/views/threat-intel.js';
import { DOSSIER_SECTIONS } from '../js/views/attacks.js';
import { formatSourceDate, dossierToMarkdown, profileToMarkdown, citedFacts } from '../js/components/intel-ui.js';

const DOC_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;

test('threat-intelligence.json loads and validates (10 profiles)', async () => {
  const { data } = await load('intel');
  assert.equal(data.profiles.length, 10);
  assert.equal(data.provenance, 'documented');
});

test('attack-library.json loads and validates (14 dossiers)', async () => {
  const { data } = await load('attacks');
  assert.equal(data.attacks.length, 14);
  const required = ['phishing', 'ransomware', 'sql-injection', 'xss', 'brute-force', 'password-spraying', 'privilege-escalation',
    'lateral-movement', 'credential-dumping', 'malware-execution', 'dns-tunnelling', 'ddos', 'supply-chain', 'exploit-known-vuln'];
  assert.deepEqual(data.attacks.map((a) => a.id).sort(), required.sort(), 'all 14 required attack types present');
});

test('every dossier has all 10 sections populated', async () => {
  const { data } = await load('attacks');
  assert.equal(DOSSIER_SECTIONS.length, 10);
  for (const a of data.attacks) {
    for (const k of ['overview']) assert.ok(a[k], `${a.id}.${k}`);
    for (const k of ['methodology', 'techniques', 'indicators', 'logSources', 'detections', 'controls', 'response', 'references']) {
      assert.ok(Array.isArray(a[k]) && a[k].length, `${a.id}.${k} empty`);
    }
    assert.ok(a.incident.facts.length >= 1 && a.incident.analysis, `${a.id} incident needs facts and labelled analysis`);
  }
});

test('every cited fact points at an existing https source with a date', async () => {
  const [{ data: intel }, { data: lib }] = await Promise.all([load('intel'), load('attacks')]);
  const check = (facts, sources, where) => {
    for (const f of facts) {
      const s = sources[f.source];
      assert.ok(s, `${where}: fact cites missing source ${f.source}`);
      assert.ok(s.url.startsWith('https://'), `${where}: non-https source`);
      assert.ok(s.date, `${where}: source without date`);
    }
  };
  intel.profiles.forEach((p) => { check(p.facts, p.sources, p.id); check(p.incidents || [], p.sources, `${p.id} incidents`); });
  lib.attacks.forEach((a) => check(a.incident.facts, a.references, a.id));
});

test('every ATT&CK ID in the intel datasets has a technique name', async () => {
  const [{ data: intel }, { data: lib }] = await Promise.all([load('intel'), load('attacks')]);
  const ids = new Set([...intel.profiles.flatMap((p) => p.techniques), ...lib.attacks.flatMap((a) => a.techniques)]);
  const missing = [...ids].filter((id) => !ATTACK_NAMES[id]);
  assert.deepEqual(missing, []);
});

test('cross-links between profiles and dossiers resolve', async () => {
  const [{ data: intel }, { data: lib }] = await Promise.all([load('intel'), load('attacks')]);
  const pIds = new Set(intel.profiles.map((p) => p.id));
  const aIds = new Set(lib.attacks.map((a) => a.id));
  intel.profiles.forEach((p) => (p.relatedAttacks || []).forEach((id) => assert.ok(aIds.has(id), `${p.id} → missing dossier ${id}`)));
  lib.attacks.forEach((a) => (a.relatedProfiles || []).forEach((id) => assert.ok(pIds.has(id), `${a.id} → missing profile ${id}`)));
});

test('IOC watchlist is simulated, uses documentation ranges, and references real sample events', async () => {
  const [{ data: intel }, { data: ev }] = await Promise.all([load('intel'), load('events')]);
  const eventIds = new Set(ev.events.map((e) => e.id));
  assert.equal(intel.iocWatchlist.provenance, 'simulated');
  for (const i of intel.iocWatchlist.items) {
    if (i.type === 'ipv4') assert.ok(DOC_IP.test(i.value), `${i.value} not RFC 5737`);
    if (i.type === 'domain') assert.ok(/\.(example|test)$/.test(i.value), `${i.value} not reserved TLD`);
    if (i.type === 'url') assert.ok(DOC_IP.test(new URL(i.value).hostname), `${i.value} host not RFC 5737`);
    i.events.forEach((id) => assert.ok(eventIds.has(id), `${i.value} references unknown ${id}`));
  }
});

test('validators reject uncited or badly sourced intelligence', () => {
  const base = { id: 'xx', name: 'X', type: 'apt', summary: 's', attribution: 'a', techniques: ['T1078'],
    sources: [{ title: 't', publisher: 'p', date: '2024-01-01', url: 'https://example.org' }], facts: [{ text: 'f', source: 0 }] };
  const ok = { provenance: 'documented', profiles: [base], iocWatchlist: { provenance: 'simulated', items: [] } };
  assert.deepEqual(validateIntel(ok), []);
  const bad = (patch) => validateIntel({ ...ok, profiles: [{ ...base, ...patch }] });
  assert.ok(bad({ facts: [{ text: 'f', source: 3 }] }).some((m) => m.includes('cites missing source')));
  assert.ok(bad({ sources: [{ ...base.sources[0], url: 'http://insecure.example' }] }).some((m) => m.includes('https')));
  assert.ok(bad({ sources: [{ ...base.sources[0], date: 'yesterday' }] }).some((m) => m.includes('date')));
  assert.ok(bad({ type: 'nation-state' }).some((m) => m.includes('type')));
  assert.ok(validateAttacks({ provenance: 'documented', attacks: [{ id: 'a', name: 'A', overview: 'o', category: 'impact', techniques: ['T1486'],
    references: base.sources, incident: { title: 'i', date: '2024', facts: [{ text: 'f', source: 0 }] }, methodology: ['m'] }] })
    .some((m) => m.includes('indicators')), 'missing dossier section detected');
});

test('collectReports de-duplicates shared advisories', async () => {
  const { data } = await load('intel');
  const reports = collectReports(data.profiles);
  const citrix = reports.find((r) => r.url.endsWith('aa23-325a'));
  assert.deepEqual(citrix.usedBy.map((u) => u.id).sort(), ['citrix-bleed', 'lockbit']);
  assert.equal(new Set(reports.map((r) => r.url)).size, reports.length);
  assert.ok(reports[0].date >= reports[reports.length - 1].date, 'newest first');
});

test('formatSourceDate handles full, partial and free-text dates', () => {
  assert.equal(formatSourceDate('2023-06-14'), '14 Jun 2023');
  assert.equal(formatSourceDate('2023-05'), 'May 2023');
  assert.equal(formatSourceDate('2021'), '2021');
  assert.equal(formatSourceDate('n.d.'), 'n.d.');
});

test('Markdown exports contain every section and escape markup', async () => {
  const [{ data: lib }, { data: intel }] = await Promise.all([load('attacks'), load('intel')]);
  const md = dossierToMarkdown(lib.attacks.find((a) => a.id === 'xss'), lib.reviewed);
  assert.equal((md.match(/^## \d+\. /gm) || []).length, 10, '10 numbered sections');
  assert.ok(md.includes('\\<script\\>'), 'angle brackets escaped');
  const pm = profileToMarkdown(intel.profiles[0], intel.reviewed);
  assert.ok(pm.includes('## Documented facts') && pm.includes('## Sources'));
});

test('citedFacts renders citation links with safe attributes', () => {
  const node = citedFacts([{ text: 'Fact <b>', source: 0 }], [{ title: 'T', publisher: 'P', date: '2024-01-01', url: 'https://example.org/a' }]);
  const a = node.querySelector('a.cite');
  assert.equal(a.getAttribute('href'), 'https://example.org/a');
  assert.equal(a.getAttribute('rel'), 'noopener noreferrer');
  assert.equal(node.querySelector('b'), null, 'fact text is not parsed as HTML');
});
