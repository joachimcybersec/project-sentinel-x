/**
 * Live IOC lookup panel (Tier B client).
 *
 * Validates locally with the same classifier as the server, never sends
 * documentation-range, private or reserved indicators, then calls the
 * same-origin serverless proxy GET /api/ioc. When the proxy is not deployed
 * (local dev server, GitHub Pages) it explains that instead of showing fake data.
 */
import { el, clear, formatUtcDateTime } from '../utils/dom.js';
import { classifyIndicator, defang, NO_LOOKUP_REASON, MAX_INDICATOR } from '../shared/indicators.js';

export const LOOKUP_TIMEOUT_MS = 15000;
const STATUS_LABEL = { ok: 'Result', 'not-found': 'No record', 'not-configured': 'Not configured', 'rate-limited': 'Rate limited', error: 'Error' };
const VERDICT_CLASS = { malicious: 'sev-critical', suspicious: 'sev-high', referenced: 'sev-medium', 'low-confidence': 'sev-low' };

/** Perform the request. Returns { kind: 'result'|'unavailable'|'error', ... }. fetchImpl is injectable for tests. */
export async function lookupIndicator(value, fetchImpl = fetch) {
  let res;
  try {
    const signal = AbortSignal.timeout ? AbortSignal.timeout(LOOKUP_TIMEOUT_MS) : undefined;
    res = await fetchImpl(`/api/ioc?value=${encodeURIComponent(value)}`, { headers: { Accept: 'application/json' }, credentials: 'same-origin', signal });
  } catch (err) {
    return { kind: 'error', message: err && err.name === 'TimeoutError' ? 'The lookup service did not respond in time.' : 'Could not reach the lookup service.' };
  }
  const type = res.headers.get('Content-Type') || '';
  if (res.status === 404 || !type.includes('application/json')) return { kind: 'unavailable' };
  let body;
  try { body = await res.json(); } catch { return { kind: 'unavailable' }; }
  if (!res.ok) return { kind: 'error', message: body && body.error ? body.error : `Lookup service returned HTTP ${res.status}` };
  return { kind: 'result', body };
}

/** Shape check before rendering, so a broken or unexpected response shows an error instead of throwing. */
export function isValidBody(b) {
  if (!b || typeof b !== 'object' || !b.indicator || typeof b.indicator.display !== 'string') return false;
  if (b.lookup === false) return typeof b.message === 'string';
  return Array.isArray(b.results) && b.results.every((p) => p && typeof p.name === 'string' && typeof p.status === 'string' &&
    (p.status !== 'ok' || (typeof p.verdict === 'string' && p.fields && typeof p.fields === 'object')));
}

export function createIocLookup() {
  const input = el('input', { class: 'input mono', type: 'search', id: 'ioc-q', maxlength: String(MAX_INDICATOR), autocomplete: 'off', spellcheck: 'false',
    placeholder: 'IPv4, domain or MD5/SHA-1/SHA-256 (defanged input like 203[.]0[.]113[.]5 is accepted)', 'aria-describedby': 'ioc-help' });
  const btn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Look up');
  const out = el('div', { class: 'stack', 'aria-live': 'polite' });

  const notice = (cls, strong, text) => el('div', { class: `notice ${cls}`, role: cls === 'is-error' ? 'alert' : 'status' },
    el('span', { 'aria-hidden': 'true' }, cls === 'is-error' ? '⚠' : 'ⓘ'), el('span', null, el('strong', null, strong), text));

  let seq = 0; // only the most recent lookup may render (rapid clicks must not interleave results)

  async function run() {
    const mine = ++seq;
    clear(out);
    const c = classifyIndicator(input.value);
    if (!c.ok) { out.append(notice('is-error', 'Invalid indicator. ', c.error)); return; }
    const shown = c.type === 'ipv4' || c.type === 'domain' ? defang(c.value) : c.value;
    if (!c.lookup) { out.append(notice('', `${shown}: not sent to any service. `, NO_LOOKUP_REASON[c.reason])); return; }
    btn.disabled = true; btn.textContent = 'Looking up…';
    const r = await lookupIndicator(c.value);
    if (mine !== seq) return;
    btn.disabled = false; btn.textContent = 'Look up';
    if (r.kind === 'result' && !isValidBody(r.body)) { out.append(notice('is-error', 'Lookup failed. ', 'The lookup service returned an unexpected response.')); return; }
    if (r.kind === 'unavailable') {
      out.append(notice('', 'Live lookups are not available on this host. ',
        'They need the Sentinel X serverless function (/api/ioc) deployed on Netlify with provider API keys. On the local dev server or static-only hosting there is no backend, so no request reached any provider and no data is shown.'));
      return;
    }
    if (r.kind === 'error') { out.append(notice('is-error', 'Lookup failed. ', r.message)); return; }
    const b = r.body;
    if (!b.lookup) { out.append(notice('', `${b.indicator.display}: not sent to any service. `, b.message)); return; }
    out.append(el('p', { class: 'kpi-sub' }, `Third-party data for ${b.indicator.display} (${b.indicator.type}), retrieved ${formatUtcDateTime(b.queriedAt)}. Verdicts are each provider's own and can disagree.`));
    if (!b.configured) out.append(notice('', 'No providers are configured. ', 'The function is running, but no API keys are set, so nothing was queried.'));
    out.append(el('div', { class: 'grid grid-3' }, b.results.map((p) => el('article', { class: 'card lookup-card' },
      el('div', { class: 'intel-card-top' }, el('h3', null, p.name), el('span', { class: `status-pill st-${p.status === 'ok' ? 'contained' : p.status === 'error' ? 'open' : 'closed'}` }, STATUS_LABEL[p.status] || p.status)),
      p.status === 'ok' ? el('p', null, 'Verdict: ', el('strong', { class: VERDICT_CLASS[p.verdict] || '' }, p.verdict.replace(/-/g, ' '))) : el('p', { class: 'kpi-sub' }, p.message),
      p.status === 'ok' ? el('dl', { class: 'dl' }, Object.entries(p.fields).flatMap(([k, v]) => [el('dt', null, k), el('dd', null, Array.isArray(v) ? (v.join('; ') || '—') : v === null ? '—' : String(v))])) : null,
      p.retryAfterSeconds ? el('p', { class: 'kpi-sub' }, `Retry after ${p.retryAfterSeconds} s`) : null,
      el('a', { class: 'btn btn-sm', href: p.link, target: '_blank' }, `Open in ${p.name} ↗`)))));
  }

  const form = el('form', { class: 'query-bar', role: 'search', 'aria-label': 'Indicator lookup' },
    el('label', { class: 'filter-label', for: 'ioc-q' }, 'Indicator'), el('div', { class: 'query-row' }, input, btn));
  form.addEventListener('submit', (e) => { e.preventDefault(); run(); });

  const examples = el('div', { class: 'btn-row' }, el('span', { class: 'filter-label' }, 'Try'),
    ['203.0.113.45', 'cdn-sync.example', '10.20.5.14', 'not an indicator'].map((v) => {
      const b = el('button', { class: 'btn btn-sm btn-ghost mono', type: 'button' }, v);
      b.addEventListener('click', () => { input.value = v; run(); });
      return b;
    }));

  return el('div', { class: 'stack' },
    el('p', { class: 'kpi-sub', id: 'ioc-help' }, 'Looks up an indicator with AbuseIPDB, VirusTotal and AlienVault OTX through a server-side proxy, so API keys never reach your browser. Private, documentation-range and reserved indicators are checked locally and never sent anywhere. Respect each provider\'s terms: do not submit confidential data.'),
    form, examples, out);
}
