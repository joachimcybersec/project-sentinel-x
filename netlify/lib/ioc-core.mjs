/**
 * IOC lookup proxy: core logic (Tier B).
 *
 * GET /api/ioc?value=<ip|domain|hash>
 *
 * Written against the standard Fetch API (Request, Response, fetch), so it runs
 * unchanged in the Netlify Functions runtime and in the browser test suite
 * (with an injected fake `fetch` and `env`).
 *
 * Security properties:
 *  - API keys come only from environment variables and are never returned or logged.
 *  - Input is validated and refanged by the shared classifier; non-public,
 *    documentation-range and reserved-TLD indicators are never sent upstream.
 *  - Only fixed, allow-listed upstream hosts are contacted; the indicator is
 *    URL-encoded into a fixed path.
 *  - Upstream responses are reduced to a small normalised summary (data
 *    minimisation); raw upstream bodies are not proxied.
 *  - GET only; no CORS headers, so other origins cannot call it from a browser.
 *  - Successful results are cacheable at the CDN to protect free-tier quotas;
 *    errors are not cached.
 */
import { classifyIndicator, defang, NO_LOOKUP_REASON } from '../../js/shared/indicators.js';

export const UPSTREAM_TIMEOUT_MS = 8000;
/** Upstream bodies larger than this are rejected rather than parsed (memory/CPU guard). */
export const MAX_UPSTREAM_BYTES = 2 * 1024 * 1024;
const HASH_TYPES = ['md5', 'sha1', 'sha256'];

export const PROVIDERS = [
  {
    id: 'abuseipdb', name: 'AbuseIPDB', envKey: 'ABUSEIPDB_API_KEY', types: ['ipv4'],
    request: (type, v, key) => ({
      url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(v)}&maxAgeInDays=90`,
      headers: { Key: key, Accept: 'application/json' }
    }),
    link: (type, v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`,
    summarise: (json) => {
      const d = (json && json.data) || {};
      const score = Number(d.abuseConfidenceScore) || 0;
      const reports = Number(d.totalReports) || 0;
      return {
        verdict: score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : reports === 0 ? 'no-reports' : 'low-confidence',
        fields: { abuseConfidenceScore: score, totalReports: reports, lastReportedAt: d.lastReportedAt || null, countryCode: d.countryCode || null, usageType: d.usageType || null, isp: d.isp || null }
      };
    }
  },
  {
    id: 'virustotal', name: 'VirusTotal', envKey: 'VIRUSTOTAL_API_KEY', types: ['ipv4', 'domain', ...HASH_TYPES],
    request: (type, v, key) => {
      const coll = type === 'ipv4' ? 'ip_addresses' : type === 'domain' ? 'domains' : 'files';
      return { url: `https://www.virustotal.com/api/v3/${coll}/${encodeURIComponent(v)}`, headers: { 'x-apikey': key, Accept: 'application/json' } };
    },
    link: (type, v) => `https://www.virustotal.com/gui/${type === 'ipv4' ? 'ip-address' : type === 'domain' ? 'domain' : 'file'}/${encodeURIComponent(v)}`,
    summarise: (json) => {
      const a = (json && json.data && json.data.attributes) || {};
      const s = a.last_analysis_stats || {};
      const mal = Number(s.malicious) || 0, sus = Number(s.suspicious) || 0;
      return {
        verdict: mal >= 3 ? 'malicious' : mal + sus > 0 ? 'suspicious' : 'no-detections',
        fields: { malicious: mal, suspicious: sus, harmless: Number(s.harmless) || 0, undetected: Number(s.undetected) || 0,
          reputation: typeof a.reputation === 'number' ? a.reputation : null,
          lastAnalysisDate: typeof a.last_analysis_date === 'number' ? new Date(a.last_analysis_date * 1000).toISOString() : null }
      };
    }
  },
  {
    id: 'otx', name: 'AlienVault OTX', envKey: 'OTX_API_KEY', types: ['ipv4', 'domain', ...HASH_TYPES],
    request: (type, v, key) => {
      const section = type === 'ipv4' ? 'IPv4' : type === 'domain' ? 'domain' : 'file';
      return { url: `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(v)}/general`, headers: { 'X-OTX-API-KEY': key, Accept: 'application/json' } };
    },
    link: (type, v) => `https://otx.alienvault.com/indicator/${type === 'ipv4' ? 'ip' : type === 'domain' ? 'domain' : 'file'}/${encodeURIComponent(v)}`,
    summarise: (json) => {
      const p = (json && json.pulse_info) || {};
      const count = Number(p.count) || 0;
      return {
        verdict: count > 0 ? 'referenced' : 'no-pulses',
        fields: { pulseCount: count, recentPulses: Array.isArray(p.pulses) ? p.pulses.slice(0, 3).map((x) => String(x.name || '').slice(0, 120)) : [] }
      };
    }
  }
];

export const ALLOWED_UPSTREAM_HOSTS = ['api.abuseipdb.com', 'www.virustotal.com', 'otx.alienvault.com'];

const json = (status, body, extra = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', ...extra }
});

async function queryProvider(p, ind, key, doFetch) {
  const { url, headers } = p.request(ind.type, ind.value, key);
  if (!ALLOWED_UPSTREAM_HOSTS.includes(new URL(url).hostname)) return { status: 'error', message: 'Upstream host not allowed' };
  let res;
  try {
    const signal = typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) : undefined;
    res = await doFetch(url, { method: 'GET', headers, signal, redirect: 'error' });
  } catch (err) {
    const timeout = err && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return { status: 'error', message: timeout ? `No response within ${UPSTREAM_TIMEOUT_MS / 1000} s` : 'Network error contacting provider' };
  }
  if (res.status === 404) return { status: 'not-found', message: 'Provider has no record of this indicator' };
  if (res.status === 401 || res.status === 403) return { status: 'error', message: 'API key rejected by provider (check configuration)' };
  if (res.status === 429) {
    const ra = Number(res.headers.get('Retry-After'));
    return { status: 'rate-limited', message: 'Provider rate limit reached', retryAfterSeconds: Number.isFinite(ra) ? ra : null };
  }
  if (!res.ok) return { status: 'error', message: `Provider returned HTTP ${res.status}` };
  const declared = Number(res.headers.get('Content-Length'));
  if (Number.isFinite(declared) && declared > MAX_UPSTREAM_BYTES) return { status: 'error', message: 'Provider response too large' };
  let body;
  try {
    const text = await res.text();
    if (text.length > MAX_UPSTREAM_BYTES) return { status: 'error', message: 'Provider response too large' };
    body = JSON.parse(text);
  } catch { return { status: 'error', message: 'Provider returned invalid JSON' }; }
  const s = p.summarise(body);
  return { status: 'ok', verdict: s.verdict, fields: s.fields };
}

/**
 * @param {Request} request
 * @param {{ env: (name: string) => string|undefined, fetch: typeof fetch, now?: () => Date, log?: (msg: string) => void }} deps
 */
export async function handleIocRequest(request, { env, fetch: doFetch, now = () => new Date(), log = () => {} }) {
  if (request.method !== 'GET') return json(405, { error: 'Method not allowed' }, { Allow: 'GET' });
  let value;
  try { value = new URL(request.url).searchParams.get('value'); } catch { value = null; }
  const ind = classifyIndicator(value || '');
  if (!ind.ok) return json(400, { error: ind.error });

  const indicator = { type: ind.type, value: ind.value, display: ind.type === 'ipv4' || ind.type === 'domain' ? defang(ind.value) : ind.value };
  const queriedAt = now().toISOString();
  if (!ind.lookup) {
    return json(200, { indicator, queriedAt, lookup: false, reason: ind.reason, message: NO_LOOKUP_REASON[ind.reason], results: [] },
      { 'Cache-Control': 'public, max-age=86400' });
  }

  const applicable = PROVIDERS.filter((p) => p.types.includes(ind.type));
  const results = await Promise.all(applicable.map(async (p) => {
    const key = env(p.envKey);
    const base = { provider: p.id, name: p.name, link: p.link(ind.type, ind.value) };
    if (!key) return { ...base, status: 'not-configured', message: `${p.envKey} is not set on the server` };
    return { ...base, ...(await queryProvider(p, ind, key, doFetch)) };
  }));

  // Privacy-conscious log line: indicator type and provider statuses only, never the value or keys.
  log(`ioc lookup type=${ind.type} ${results.map((r) => `${r.provider}=${r.status}`).join(' ')}`);

  const cacheable = results.every((r) => r.status === 'ok' || r.status === 'not-found');
  const cacheHeaders = cacheable
    ? { 'Cache-Control': 'public, max-age=300', 'Netlify-CDN-Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=600' }
    : { 'Cache-Control': 'no-store' };
  return json(200, { indicator, queriedAt, lookup: true, results, configured: results.filter((r) => r.status !== 'not-configured').length }, cacheHeaders);
}
