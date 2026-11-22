import { test, assert } from './test-runner.js';
import { load, priorityFor } from '../js/data-service.js';
import { parseLine, normalise, parseKV, processLogs, MAX_LINE } from '../js/siem/parsers.js';
import { parseQuery, runQuery } from '../js/siem/query.js';
import { correlate, enrich, ipScope, registeredDomain, RULES } from '../js/siem/correlation.js';
import { pivotQuery } from '../js/views/siem.js';
import { incidentToMarkdown } from '../js/views/incidents.js';

const processed = async () => {
  const { data } = await load('logs');
  return { data, entries: processLogs(data.logs, { year: data.syslogYear }) };
};

/* ---------- parsing ---------- */
test('every sample log parses, and the detected type matches the declared type', async () => {
  const { entries } = await processed();
  assert.ok(entries.length >= 50);
  const bad = entries.filter((e) => e.parsed.type !== e.declaredType).map((e) => `${e.id}: ${e.parsed.type} (${e.parsed.error || ''})`);
  assert.deepEqual(bad, []);
  assert.ok(entries.every((e) => e.norm && !Number.isNaN(Date.parse(e.norm['@timestamp']))), 'all have a valid timestamp');
});

test('parseKV handles quoted values with spaces and Windows paths', () => {
  const kv = parseKV('Image="C:\\Program Files\\App\\a.exe" User=CORP\\m.ito Reason="bad password." N=3');
  assert.equal(kv.Image, 'C:\\Program Files\\App\\a.exe');
  assert.equal(kv.User, 'CORP\\m.ito');
  assert.equal(kv.Reason, 'bad password.');
  assert.equal(kv.N, '3');
});

test('Windows 4625 normalises to an authentication failure', () => {
  const n = normalise(parseLine('2026-11-21T22:01:14Z WS-1 Microsoft-Windows-Security-Auditing EventID=4625 LogonType=3 TargetUserName=j.doe IpAddress=203.0.113.45 Status=0xC000006D'));
  assert.equal(n['event.category'], 'authentication');
  assert.equal(n['event.outcome'], 'failure');
  assert.equal(n['user.name'], 'j.doe');
  assert.equal(n['source.ip'], '203.0.113.45');
  assert.equal(n['winlog.logon.type'], 3);
});

test('syslog, BIND, CLF and JSON timestamps convert to UTC ISO', () => {
  assert.equal(parseLine('Nov 22 00:41:05 h sshd[1]: Failed password for root from 203.0.113.61 port 1 ssh2', { year: 2026 }).timestamp, '2026-11-22T00:41:05Z');
  assert.equal(parseLine('21-Nov-2026 23:05:41.112 queries: info: client @0x1 10.0.0.1#5 (a.example): query: a.example IN A + (10.0.0.53)').timestamp, '2026-11-21T23:05:41Z');
  assert.equal(parseLine('192.0.2.1 - - [21/Nov/2026:23:20:31 +0100] "GET / HTTP/1.1" 200 1 "-" "x"').timestamp, '2026-11-21T22:20:31Z', 'timezone offset applied');
  assert.equal(parseLine('{"ts":"2026-11-22T00:03:58Z","host":"FS-02"}').host, 'FS-02');
});

test('sshd messages map to the right outcome and invalid users are flagged', () => {
  const f = normalise(parseLine('Nov 22 00:41:15 b sshd[2]: Failed password for invalid user admin from 203.0.113.61 port 52130 ssh2', { year: 2026 }));
  assert.equal(f['event.outcome'], 'failure');
  assert.equal(f['user.invalid'], true);
  const s = normalise(parseLine('Nov 22 00:55:17 b sshd[3]: Accepted publickey for deploy from 192.0.2.10 port 40122 ssh2', { year: 2026 }));
  assert.equal(s['event.outcome'], 'success');
  assert.equal(s['ssh.method'], 'publickey');
});

test('parser rejects junk, oversize and non-object JSON safely', () => {
  assert.equal(parseLine('hello world').type, 'unknown');
  assert.equal(parseLine('').type, 'unknown');
  assert.equal(parseLine('x'.repeat(MAX_LINE + 1)).type, 'unknown');
  assert.equal(parseLine('[1,2]').type, 'unknown');
  assert.equal(parseLine('{bad json').type, 'unknown');
  assert.equal(normalise(parseLine('nope')), null);
});

/* ---------- query language ---------- */
test('parseQuery splits fields, quoted values, negation and free text', () => {
  const q = parseQuery('event.code:4625 user:"j doe" -host:DC-01 powershell -benign');
  assert.deepEqual(q.fields.map((f) => [f.key, f.value, f.neg]), [['event.code', '4625', false], ['user', 'j doe', false], ['host', 'DC-01', true]]);
  assert.deepEqual(q.terms.map((t) => [t.value, t.neg]), [['powershell', false], ['benign', true]]);
  assert.deepEqual(parseQuery('user:').errors, ['Missing value for user']);
});

test('runQuery over the dataset: fields, aliases, wildcards and negation', async () => {
  const { entries } = await processed();
  assert.equal(runQuery(entries, 'event.code:4625').results.length, 9);
  assert.equal(runQuery(entries, 'src:203.0.113.45').results.length, 6);
  assert.equal(runQuery(entries, 'domain:*cdn-sync.example').results.length, 7);
  assert.equal(runQuery(entries, 'process.parent.executable:*winword.exe').results.length, 2);
  assert.equal(runQuery(entries, 'type:web http.response.status_code:500').results.length, 2);
  assert.equal(runQuery(entries, 'host:DC-01 -code:4625').results.length, 5);
  assert.equal(runQuery(entries, 'sqlmap').results.length, 3, 'free text matches the raw line');
  assert.equal(runQuery(entries, 'ip:198.51.100.88').results.length, 3, 'alias covers source and destination');
});

test('wildcard values cannot inject regular-expression syntax', async () => {
  const { entries } = await processed();
  assert.equal(runQuery(entries, 'host:(a+)+$').results.length, 0);
  assert.equal(runQuery(entries, 'host:DC-0.').results.length, 0, '"." is literal');
});

/* ---------- enrichment & correlation ---------- */
test('ipScope and registeredDomain', () => {
  assert.equal(ipScope('10.20.0.10'), 'internal');
  assert.ok(ipScope('203.0.113.9').startsWith('external (RFC 5737'));
  assert.equal(registeredDomain('abc.def.cdn-sync.example'), 'cdn-sync.example');
});

test('enrichment adds asset context and IOC-watchlist matches', async () => {
  const [{ data, entries }, { data: intel }] = await Promise.all([processed(), load('intel')]);
  const exfil = entries.find((e) => e.id === 'LOG-043');
  const en = enrich(exfil.norm, { assets: data.assets, iocs: intel.iocWatchlist.items });
  assert.ok(en.assets.some((a) => a.host === 'FS-02' && a.criticality === 'critical'));
  assert.ok(en.iocMatches.some((i) => i.value === '203.0.113.200'));
  const dns = enrich(entries.find((e) => e.id === 'LOG-020').norm, { iocs: intel.iocWatchlist.items });
  assert.ok(dns.iocMatches.some((i) => i.value === 'cdn-sync.example'), 'subdomain matches registered-domain IOC');
});

test('default correlation produces the expected 9 alerts', async () => {
  const { entries } = await processed();
  const alerts = correlate(entries);
  const byRule = alerts.reduce((m, a) => ({ ...m, [a.ruleId]: (m[a.ruleId] || 0) + 1 }), {});
  assert.deepEqual(Object.entries(byRule).sort(), Object.entries({ 'COR-001': 1, 'COR-002': 1, 'COR-003': 2, 'COR-004': 1, 'COR-005': 1, 'COR-006': 1, 'COR-007': 1, 'COR-008': 1 }).sort());
  assert.equal(alerts.length, 9);
  const bf = alerts.find((a) => a.ruleId === 'COR-001');
  assert.equal(bf.key, '203.0.113.45');
  assert.equal(bf.evidence.length, 6);
  assert.equal(alerts.find((a) => a.ruleId === 'COR-002').key, 'adm.svc@192.0.2.77');
});

test('tuning the brute-force threshold changes the alerts', async () => {
  const { entries } = await processed();
  const at3 = correlate(entries, { enabled: ['COR-001'], params: { 'COR-001': { threshold: 3 } } });
  assert.deepEqual(at3.map((a) => a.key).sort(), ['192.0.2.77', '203.0.113.45', '203.0.113.61']);
  assert.equal(correlate(entries, { enabled: ['COR-001'], params: { 'COR-001': { threshold: 10 } } }).length, 0);
  assert.equal(RULES.length, 8);
});

test('priority matrix', () => {
  assert.equal(priorityFor(3, 3), 'P1');
  assert.equal(priorityFor(3, 2), 'P2');
  assert.equal(priorityFor(2, 2), 'P3');
  assert.equal(priorityFor(1, 2), 'P4');
});

/* ---------- incident ↔ dataset integrity ---------- */
test('incidents reference existing logs, events and dossiers; timelines are chronological', async () => {
  const [{ data: inc }, { data: logs }, { data: ev }, { data: lib }] = await Promise.all([load('incidents'), load('logs'), load('events'), load('attacks')]);
  const logIds = new Set(logs.logs.map((l) => l.id));
  const evIds = new Set(ev.events.map((e) => e.id));
  const atkIds = new Set(lib.attacks.map((a) => a.id));
  const incIds = new Set(inc.incidents.map((i) => i.id));
  assert.equal(inc.incidents.length, 6);
  for (const i of inc.incidents) {
    i.logs.forEach((id) => assert.ok(logIds.has(id), `${i.id}: unknown ${id}`));
    i.investigation.forEach((s) => s.evidence.forEach((id) => assert.ok(logIds.has(id), `${i.id}: evidence ${id}`)));
    i.relatedEvents.forEach((id) => assert.ok(evIds.has(id), `${i.id}: unknown ${id}`));
    i.relatedAttacks.forEach((id) => assert.ok(atkIds.has(id), `${i.id}: unknown dossier ${id}`));
    i.linkedIncidents.forEach((id) => assert.ok(incIds.has(id), `${i.id}: unknown incident ${id}`));
    const ts = i.timeline.map((t) => Date.parse(t.ts));
    assert.deepEqual(ts, [...ts].sort((a, b) => a - b), `${i.id} timeline out of order`);
  }
});

test('every alert pivot query finds the alert\'s own evidence', async () => {
  const { entries } = await processed();
  for (const a of correlate(entries)) {
    const ids = new Set(runQuery(entries, pivotQuery(a)).results.map((e) => e.id));
    assert.ok(a.evidence.some((id) => ids.has(id)), `${a.ruleId} pivot "${pivotQuery(a)}" misses its evidence`);
  }
});

test('incident report Markdown includes all sections and escapes content', async () => {
  const { data } = await load('incidents');
  const mdText = incidentToMarkdown(data.incidents.find((i) => i.id === 'IR-2026-004'));
  for (const h of ['## Summary', '## Alert', '## Timeline (UTC)', '## Investigation', '## Root cause', '## Evidence collected', '## Containment', '## Eradication', '## Recovery', '## Lessons learned']) {
    assert.ok(mdText.includes(h), `missing ${h}`);
  }
  assert.ok(mdText.includes('| Priority | P1'), 'priority row');
  assert.ok(mdText.includes('C:\\\\Users\\\\Public\\\\svc.exe'), 'backslashes escaped for Markdown');
});

test('each incident\'s SIEM query returns at least one of its own logs', async () => {
  const [{ data: inc }, { entries }] = await Promise.all([load('incidents'), processed()]);
  for (const i of inc.incidents) {
    const ids = new Set(runQuery(entries, i.siemQuery).results.map((e) => e.id));
    assert.ok(i.logs.some((id) => ids.has(id)), `${i.id}: query "${i.siemQuery}" finds none of its logs`);
  }
});
