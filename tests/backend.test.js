import { test, assert } from './test-runner.js';
import { classifyIndicator, refang } from '../js/shared/indicators.js';
import { handleIocRequest, PROVIDERS, ALLOWED_UPSTREAM_HOSTS, MAX_UPSTREAM_BYTES } from '../netlify/lib/ioc-core.mjs';
import { lookupIndicator, isValidBody } from '../js/components/ioc-lookup.js';

/* ---------- helpers ---------- */
const req = (value, method = 'GET') => new Request(`https://sentinel.example/api/ioc${value === undefined ? '' : `?value=${encodeURIComponent(value)}`}`, { method });
const jsonRes = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const allKeys = { ABUSEIPDB_API_KEY: 'k-abuse', VIRUSTOTAL_API_KEY: 'k-vt', OTX_API_KEY: 'k-otx' };
const envOf = (o) => (k) => o[k];

/** Fake upstream that records calls and answers per host. */
function fakeFetch(answers) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, headers: init.headers });
    const host = new URL(url).hostname;
    const a = answers[host];
    if (a instanceof Error) throw a;
    return a ? a() : jsonRes(500, {});
  };
  f.calls = calls;
  return f;
}
const goodAnswers = () => ({
  'api.abuseipdb.com': () => jsonRes(200, { data: { ipAddress: '8.8.4.4', abuseConfidenceScore: 80, totalReports: 12, lastReportedAt: '2026-11-20T10:00:00+00:00', countryCode: 'US', usageType: 'Data Center', isp: 'Example ISP' } }),
  'www.virustotal.com': () => jsonRes(200, { data: { attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 60, undetected: 20 }, reputation: -3, last_analysis_date: 1795000000 } } }),
  'otx.alienvault.com': () => jsonRes(200, { pulse_info: { count: 2, pulses: [{ name: 'Pulse A' }, { name: 'Pulse B' }] } })
});

/* ---------- classifier ---------- */
test('classifyIndicator: types, refanging and non-lookup categories', () => {
  assert.equal(classifyIndicator('8.8.4.4').type, 'ipv4');
  assert.equal(classifyIndicator('8[.]8[.]4[.]4').value, '8.8.4.4', 'refanged');
  assert.equal(refang('hxxps://bad[.]example'), 'https://bad.example');
  assert.equal(classifyIndicator('Example.ORG').value, 'example.org');
  assert.equal(classifyIndicator('d41d8cd98f00b204e9800998ecf8427e').type, 'md5');
  assert.equal(classifyIndicator('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').type, 'sha256');
  assert.equal(classifyIndicator('203.0.113.45').reason, 'documentation');
  assert.equal(classifyIndicator('10.20.5.14').reason, 'non-public');
  assert.equal(classifyIndicator('100.64.1.1').reason, 'non-public', 'CGNAT');
  assert.equal(classifyIndicator('cdn-sync.example').reason, 'reserved-tld');
  for (const bad of ['256.1.1.1', '1.2.3', 'http://x.com/a', 'a..b', '-bad.com', '', 'x'.repeat(300), '<script>']) assert.ok(!classifyIndicator(bad).ok, `${bad} should be rejected`);
});

/* ---------- proxy: request handling ---------- */
test('proxy rejects non-GET and invalid input without calling upstream', async () => {
  const f = fakeFetch(goodAnswers());
  const post = await handleIocRequest(req('8.8.4.4', 'POST'), { env: envOf(allKeys), fetch: f });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('Allow'), 'GET');
  const bad = await handleIocRequest(req('not an ip'), { env: envOf(allKeys), fetch: f });
  assert.equal(bad.status, 400);
  const missing = await handleIocRequest(req(undefined), { env: envOf(allKeys), fetch: f });
  assert.equal(missing.status, 400);
  assert.equal(f.calls.length, 0);
});

test('documentation, private and reserved indicators are never sent upstream', async () => {
  const f = fakeFetch(goodAnswers());
  for (const v of ['203.0.113.45', '192.168.1.10', 'cdn-sync.example']) {
    const body = await (await handleIocRequest(req(v), { env: envOf(allKeys), fetch: f })).json();
    assert.equal(body.lookup, false, v);
    assert.ok(body.message.length > 20);
  }
  assert.equal(f.calls.length, 0);
});

test('with no keys configured, every provider reports not-configured and nothing is fetched', async () => {
  const f = fakeFetch(goodAnswers());
  const body = await (await handleIocRequest(req('8.8.4.4'), { env: envOf({}), fetch: f })).json();
  assert.deepEqual(body.results.map((r) => r.status), ['not-configured', 'not-configured', 'not-configured']);
  assert.equal(body.configured, 0);
  assert.equal(f.calls.length, 0);
});

test('successful lookups are normalised per provider, with correct upstream URLs and auth headers', async () => {
  const f = fakeFetch(goodAnswers());
  const res = await handleIocRequest(req('8.8.4.4'), { env: envOf(allKeys), fetch: f, now: () => new Date('2026-11-22T10:00:00Z') });
  const body = await res.json();
  const by = Object.fromEntries(body.results.map((r) => [r.provider, r]));
  assert.equal(by.abuseipdb.verdict, 'malicious');
  assert.equal(by.abuseipdb.fields.totalReports, 12);
  assert.equal(by.virustotal.verdict, 'suspicious');
  assert.equal(by.virustotal.fields.lastAnalysisDate, new Date(1795000000 * 1000).toISOString());
  assert.equal(by.otx.verdict, 'referenced');
  assert.deepEqual(by.otx.fields.recentPulses, ['Pulse A', 'Pulse B']);
  assert.equal(body.indicator.display, '8[.]8[.]4[.]4', 'IP displayed defanged');
  assert.equal(body.queriedAt, '2026-11-22T10:00:00.000Z');
  const urls = f.calls.map((c) => c.url).sort();
  assert.deepEqual(urls, [
    'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.4.4&maxAgeInDays=90',
    'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.4.4/general',
    'https://www.virustotal.com/api/v3/ip_addresses/8.8.4.4'
  ]);
  const hdr = Object.fromEntries(f.calls.map((c) => [new URL(c.url).hostname, c.headers]));
  assert.equal(hdr['api.abuseipdb.com'].Key, 'k-abuse');
  assert.equal(hdr['www.virustotal.com']['x-apikey'], 'k-vt');
  assert.equal(hdr['otx.alienvault.com']['X-OTX-API-KEY'], 'k-otx');
  assert.ok(res.headers.get('Netlify-CDN-Cache-Control').includes('s-maxage=3600'), 'successful results are CDN-cacheable');
});

test('API keys never appear in the response or the log', async () => {
  const logs = [];
  const res = await handleIocRequest(req('8.8.4.4'), { env: envOf(allKeys), fetch: fakeFetch(goodAnswers()), log: (m) => logs.push(m) });
  const text = await res.text();
  for (const k of Object.values(allKeys)) {
    assert.ok(!text.includes(k), 'key leaked in response');
    assert.ok(!logs.join(' ').includes(k), 'key leaked in log');
  }
  assert.ok(!logs.join(' ').includes('8.8.4.4'), 'indicator value not logged');
  assert.ok(logs[0].startsWith('ioc lookup type=ipv4'));
});

test('upstream failures map to clear statuses and responses are not cached', async () => {
  const timeout = Object.assign(new Error('t'), { name: 'TimeoutError' });
  const f = fakeFetch({
    'api.abuseipdb.com': () => jsonRes(429, {}, { 'Retry-After': '60' }),
    'www.virustotal.com': () => jsonRes(401, {}),
    'otx.alienvault.com': timeout
  });
  const res = await handleIocRequest(req('8.8.4.4'), { env: envOf(allKeys), fetch: f });
  const by = Object.fromEntries((await res.json()).results.map((r) => [r.provider, r]));
  assert.equal(by.abuseipdb.status, 'rate-limited');
  assert.equal(by.abuseipdb.retryAfterSeconds, 60);
  assert.equal(by.virustotal.status, 'error');
  assert.ok(by.virustotal.message.includes('API key rejected'));
  assert.equal(by.otx.status, 'error');
  assert.ok(by.otx.message.includes('No response within'));
  assert.equal(res.headers.get('Cache-Control'), 'no-store');
  assert.equal(res.headers.get('Netlify-CDN-Cache-Control'), null);
});

test('404 from a provider is "not-found"; domains and hashes use the right endpoints', async () => {
  const f = fakeFetch({ 'www.virustotal.com': () => jsonRes(404, {}), 'otx.alienvault.com': () => jsonRes(200, { pulse_info: { count: 0, pulses: [] } }) });
  const body = await (await handleIocRequest(req('example.org'), { env: envOf(allKeys), fetch: f })).json();
  assert.deepEqual(body.results.map((r) => r.provider), ['virustotal', 'otx'], 'AbuseIPDB is IP-only');
  assert.equal(body.results[0].status, 'not-found');
  assert.equal(body.results[1].verdict, 'no-pulses');
  assert.ok(f.calls.some((c) => c.url === 'https://www.virustotal.com/api/v3/domains/example.org'));
  const f2 = fakeFetch(goodAnswers());
  await handleIocRequest(req('d41d8cd98f00b204e9800998ecf8427e'), { env: envOf(allKeys), fetch: f2 });
  assert.ok(f2.calls.some((c) => c.url.endsWith('/api/v3/files/d41d8cd98f00b204e9800998ecf8427e')));
  assert.ok(f2.calls.some((c) => c.url.includes('/indicators/file/d41d8cd98f00b204e9800998ecf8427e/general')));
});

test('responses carry no CORS headers and only allow-listed hosts are contacted', async () => {
  const res = await handleIocRequest(req('8.8.4.4'), { env: envOf(allKeys), fetch: fakeFetch(goodAnswers()) });
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), null);
  assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  for (const p of PROVIDERS) for (const t of p.types) assert.ok(ALLOWED_UPSTREAM_HOSTS.includes(new URL(p.request(t, 'x', 'k').url).hostname), `${p.id}/${t}`);
});

/* ---------- browser client ---------- */
test('client lookup: missing backend (404 / HTML) is reported as unavailable, not as data', async () => {
  const notFound = async () => new Response('<!doctype html>404', { status: 404, headers: { 'Content-Type': 'text/html' } });
  assert.equal((await lookupIndicator('8.8.4.4', notFound)).kind, 'unavailable');
  const html200 = async () => new Response('<html>', { status: 200, headers: { 'Content-Type': 'text/html' } });
  assert.equal((await lookupIndicator('8.8.4.4', html200)).kind, 'unavailable');
  const err = async () => { throw new TypeError('network'); };
  assert.equal((await lookupIndicator('8.8.4.4', err)).kind, 'error');
  const ok = async () => jsonRes(200, { lookup: true, results: [] });
  assert.equal((await lookupIndicator('8.8.4.4', ok)).kind, 'result');
});

test('client and function agree end-to-end through the real handler', async () => {
  const viaHandler = (url) => handleIocRequest(new Request(new URL(url, 'https://sentinel.example')), { env: envOf(allKeys), fetch: fakeFetch(goodAnswers()) });
  const r = await lookupIndicator('8[.]8[.]4[.]4', viaHandler);
  assert.equal(r.kind, 'result');
  assert.equal(r.body.results.length, 3);
});

/* ---------- Phase 10 hardening ---------- */
test('classifier treats IETF-assignment and benchmarking ranges as non-public (Phase 10)', () => {
  assert.equal(classifyIndicator('192.0.0.9').reason, 'non-public');
  assert.equal(classifyIndicator('198.18.0.1').reason, 'non-public');
  assert.equal(classifyIndicator('198.19.255.254').reason, 'non-public');
  assert.equal(classifyIndicator('198.20.0.1').lookup, true, 'just outside 198.18.0.0/15');
});

test('oversized upstream bodies are rejected, not parsed (Phase 10)', async () => {
  const big = () => new Response('{"pad":"' + 'x'.repeat(MAX_UPSTREAM_BYTES) + '"}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  const declared = () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': String(MAX_UPSTREAM_BYTES + 1) } });
  const f = fakeFetch({ 'api.abuseipdb.com': big, 'www.virustotal.com': declared, 'otx.alienvault.com': goodAnswers()['otx.alienvault.com'] });
  const body = await (await handleIocRequest(req('8.8.4.4'), { env: envOf(allKeys), fetch: f })).json();
  const by = Object.fromEntries(body.results.map((r) => [r.provider, r]));
  assert.equal(by.abuseipdb.status, 'error');
  assert.equal(by.abuseipdb.message, 'Provider response too large');
  assert.equal(by.virustotal.status, 'error', 'declared Content-Length over the cap');
  assert.equal(by.otx.status, 'ok');
});

test('client rejects malformed lookup responses instead of throwing (Phase 10)', () => {
  assert.equal(isValidBody(null), false);
  assert.equal(isValidBody({}), false);
  assert.equal(isValidBody({ indicator: { display: 'x' }, lookup: true, results: [{ name: 'A', status: 'ok' }] }), false, 'ok without verdict');
  assert.equal(isValidBody({ indicator: { display: 'x' }, lookup: true, results: [{ name: 'A', status: 'ok', verdict: 'malicious', fields: {} }] }), true);
  assert.equal(isValidBody({ indicator: { display: 'x' }, lookup: false, message: 'm' }), true);
});