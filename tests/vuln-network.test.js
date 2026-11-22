import { test, assert } from './test-runner.js';
import { load, validateCves } from '../js/data-service.js';
import { parseCvssVector, prioritise, daysBetween } from '../js/network/cvss.js';
import { checksum16, buildPacket, verifyChecksums, encodeDnsName, SAMPLE_PACKETS, hexRows } from '../js/network/packets.js';
import { evaluateFlow, scorePolicy } from '../js/network/policy.js';

/* ---------- CVE snapshot ---------- */
test('CVE snapshot validates and records freshness for every source', async () => {
  const { data } = await load('cves');
  assert.ok(data.cves.length >= 20, 'expected at least 20 CVEs');
  for (const k of ['kev', 'nvd', 'epss']) assert.ok(!Number.isNaN(Date.parse(data.sources[k].fetchedAt)), `${k}.fetchedAt`);
  assert.ok(/^\d{4}\.\d{2}\.\d{2}$/.test(data.sources.kev.catalogVersion), 'KEV catalog version format');
  assert.ok(data.sources.epss.scoreDate, 'EPSS score date recorded');
});

test('curated CVEs referenced elsewhere in Sentinel X are present with NVD data', async () => {
  const { data } = await load('cves');
  const byId = new Map(data.cves.map((c) => [c.cveID, c]));
  for (const id of ['CVE-2023-34362', 'CVE-2023-4966', 'CVE-2021-34527', 'CVE-2017-5638', 'CVE-2017-0144']) {
    const c = byId.get(id);
    assert.ok(c, `${id} missing`);
    assert.ok(c.nvd && c.nvd.cvss && c.nvd.cvss.vector, `${id} has no CVSS vector`);
    assert.ok(c.epss && c.epss.score >= 0 && c.epss.score <= 1, `${id} EPSS`);
  }
  assert.equal(byId.get('CVE-2023-34362').vendorProject, 'Progress');
});

test('every CVE in the snapshot has a parseable CVSS vector matching its stated version', async () => {
  const { data } = await load('cves');
  for (const c of data.cves.filter((x) => x.nvd && x.nvd.cvss)) {
    const p = parseCvssVector(c.nvd.cvss.vector);
    assert.ok(p && p.metrics.length >= 6, `${c.cveID}: vector not parsed`);
    assert.equal(p.version, String(c.nvd.cvss.version), `${c.cveID}: version mismatch`);
  }
});

test('validateCves rejects malformed snapshots', () => {
  const bad = validateCves({ provenance: 'documented', generatedAt: 'x', sources: { kev: {} }, cves: [{ cveID: 'CVE-1', dateAdded: 'no', nvd: { cvss: { baseScore: 11 } }, epss: { score: 2 } }] });
  for (const part of ['generatedAt', 'catalogVersion', 'cveID', 'dateAdded', 'CVSS score', 'EPSS score']) assert.ok(bad.some((m) => m.includes(part)), `expected "${part}"`);
});

test('parseCvssVector handles v3.1, v4.0 and v2 vectors', () => {
  const v3 = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(v3.version, '3.1');
  assert.deepEqual(v3.metrics.map((m) => m.label), ['Network', 'Low', 'None', 'None', 'Unchanged', 'High', 'High', 'High']);
  const v4 = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
  assert.equal(v4.version, '4.0');
  assert.equal(v4.metrics.find((m) => m.key === 'UI').label, 'Passive');
  assert.equal(parseCvssVector('AV:N/AC:L/Au:N/C:P/I:P/A:P').metrics[2].label, 'None');
  assert.equal(parseCvssVector(''), null);
});

test('prioritisation tiers follow the published rules', () => {
  assert.equal(prioritise({ dateAdded: '2024-01-01', knownRansomwareCampaignUse: 'Known', nvd: { cvss: { baseScore: 5 } } }).tier, 'P1');
  assert.equal(prioritise({ dateAdded: '2024-01-01', knownRansomwareCampaignUse: 'Unknown', nvd: { cvss: { baseScore: 9.8 } } }).tier, 'P1');
  assert.equal(prioritise({ dateAdded: '2024-01-01', knownRansomwareCampaignUse: 'Unknown', nvd: { cvss: { baseScore: 7.5 } } }).tier, 'P2');
  assert.equal(prioritise({ epss: { score: 0.4 } }).tier, 'P3');
  assert.equal(prioritise({ nvd: { cvss: { baseScore: 5 } }, epss: { score: 0.01 } }).tier, 'P4');
  assert.equal(daysBetween('2026-11-20T23:00:00Z', '2026-11-22T01:00:00Z'), 2);
});

/* ---------- packets ---------- */
test('checksum16 matches the RFC 1071 example', () => {
  // RFC 1071 §3 example words 0001 f203 f4f5 f6f7 sum to ddf2, so the checksum is 220d
  assert.equal(checksum16([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
});

test('every sample packet has valid IPv4 and transport checksums and consistent lengths', () => {
  for (const s of SAMPLE_PACKETS) {
    const { bytes, fields } = buildPacket(s.spec);
    const ok = verifyChecksums(bytes);
    assert.ok(ok.ip, `${s.id}: IPv4 checksum`);
    assert.ok(ok.l4, `${s.id}: L4 checksum`);
    const totalLen = (bytes[16] << 8) | bytes[17];
    assert.equal(totalLen, bytes.length - 14, `${s.id}: IPv4 total length`);
    fields.forEach((f) => assert.ok(f.offset + f.length <= bytes.length, `${s.id}: field ${f.name} out of range`));
  }
});

test('changing a byte breaks the checksum (verification is real)', () => {
  const { bytes } = buildPacket(SAMPLE_PACKETS[0].spec);
  const tampered = bytes.slice(); tampered[22] ^= 0xff; // TTL
  assert.ok(!verifyChecksums(tampered).ip);
});

test('DNS name encoding and packet field values', () => {
  assert.deepEqual(encodeDnsName('a.bc'), [1, 97, 2, 98, 99, 0]);
  assert.throws(() => encodeDnsName(`${'x'.repeat(64)}.example`));
  const dns = buildPacket(SAMPLE_PACKETS.find((p) => p.id === 'dns-txt-tunnel').spec);
  assert.equal(dns.bytes[23], 17, 'IPv4 protocol = UDP');
  const qtype = dns.fields.find((f) => f.name === 'QTYPE');
  assert.equal((dns.bytes[qtype.offset] << 8) | dns.bytes[qtype.offset + 1], 16, 'TXT = 16');
  const syn = buildPacket(SAMPLE_PACKETS[0].spec);
  assert.equal(syn.bytes[14 + 20 + 13], 0x02, 'TCP flags byte = SYN');
  assert.equal(hexRows(syn.bytes)[0].bytes.length, 16);
});

/* ---------- policies ---------- */
test('network.json validates; every flow resolves to known zones', async () => {
  const { data } = await load('network');
  const zones = new Set(data.zones.map((z) => z.id));
  for (const f of data.flows) {
    const r = evaluateFlow(data.policies[0], f, data.hosts);
    assert.ok(zones.has(r.fromZone) && zones.has(r.toZone), `${f.id} zones`);
  }
});

test('policy outcomes: as-was blocks nothing, segmentation misses C2, Zero Trust blocks all without breaking business flows', async () => {
  const { data } = await load('network');
  const pol = (id) => data.policies.find((p) => p.id === id);
  const asWas = scorePolicy(pol('as-was'), data.flows, data.hosts);
  const seg = scorePolicy(pol('segmented'), data.flows, data.hosts);
  const zt = scorePolicy(pol('zero-trust'), data.flows, data.hosts);
  assert.equal(asWas.attacksBlocked, 0);
  assert.equal(seg.attacksBlocked, seg.attacksTotal - 1);
  assert.equal(seg.results.find((r) => r.flow.id === 'F04').action, 'allow', 'HTTPS C2 passes a port-based firewall');
  assert.equal(zt.attacksBlocked, zt.attacksTotal);
  for (const s of [asWas, seg, zt]) assert.equal(s.legitAllowed, s.legitTotal, 'no policy breaks legitimate flows');
});

test('Zero Trust rule requires every listed attribute', async () => {
  const { data } = await load('network');
  const zt = data.policies.find((p) => p.id === 'zero-trust');
  const admin = data.flows.find((f) => f.id === 'F10');
  assert.equal(evaluateFlow(zt, admin, data.hosts).ruleId, 'Z3');
  assert.equal(evaluateFlow(zt, { ...admin, attributes: ['mfa', 'compliant-device'] }, data.hosts).action, 'deny', 'missing privileged-access');
});

test('incident links in flows point at real cases', async () => {
  const [{ data }, { data: inc }] = await Promise.all([load('network'), load('incidents')]);
  const ids = new Set(inc.incidents.map((i) => i.id));
  data.flows.filter((f) => f.incident).forEach((f) => assert.ok(ids.has(f.incident), `${f.id} → ${f.incident}`));
});
