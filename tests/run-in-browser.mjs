/**
 * Headless test driver for CI (Node 20 + Playwright).
 *
 *   node tests/run-in-browser.mjs [baseUrl] [browser]
 *   e.g. node tests/run-in-browser.mjs http://localhost:8080 firefox
 *
 * 1. Opens /tests/ and waits for window.__TEST_RESULTS__ from the in-browser runner.
 * 2. Smoke-tests every application route: no uncaught errors, no console errors,
 *    no error notice rendered, a page heading present, and no findings from the
 *    accessibility audit subset in tests/a11y-audit.js.
 * Exits non-zero on any failure.
 */
import { chromium, firefox, webkit } from 'playwright';

const base = (process.argv[2] || 'http://localhost:8080').replace(/\/$/, '');
const browserName = process.argv[3] || process.env.BROWSER || 'chromium';
const engines = { chromium, firefox, webkit };
if (!engines[browserName]) { console.error(`Unknown browser ${browserName}`); process.exit(2); }

const ROUTES = [
  '/', '/soc', '/threat-intel', '/threat-intel/volt-typhoon', '/attacks', '/attacks/ransomware',
  '/incidents', '/incidents/IR-2026-004', '/siem', '/siem?q=event.code%3A4625', '/detections', '/detections/lsass-memory-access',
  '/vulnerabilities', '/vulnerabilities/CVE-2023-34362', '/network', '/tools', '/knowledge', '/knowledge/ir-lifecycle',
  '/knowledge?tab=search&q=lsass', '/components', '/about'
];

const browser = await engines[browserName].launch();
const page = await browser.newPage();
const problems = [];
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });

// Poll with page.evaluate rather than page.waitForFunction: waitForFunction evaluates a string
// inside the page, which the app's CSP (no 'unsafe-eval', Trusted Types) correctly blocks.
async function waitFor(fn, timeout) {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await page.evaluate(fn).catch(() => undefined); // navigation in flight → retry
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out after ${timeout} ms`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

// 1. Unit / data / component tests
// Explicit index.html: some static servers (e.g. `serve` with cleanUrls off) list directories instead.
await page.goto(`${base}/tests/index.html`);
let results;
try {
  results = await waitFor(() => window.__TEST_RESULTS__, 90000);
} catch (err) {
  console.error(`[${browserName}] test page never reported results: ${err.message}`);
  for (const p of problems) console.error(`  ${p}`);
  console.error(`  page title: ${await page.title()}`);
  await browser.close();
  process.exit(1);
}
console.log(`[${browserName}] unit tests: ${results.passed}/${results.total} passed`);
for (const f of results.failures) console.log(`  FAIL ${f.name}: ${f.error}`);

// 2. Route smoke tests
let routeFailures = 0;
for (const r of ROUTES) {
  const before = problems.length;
  await page.goto(`${base}/#${r}`);
  // Wait for the view to hold *this* route's content: a hash-only goto returns before
  // hashchange fires, so the previous route's heading could otherwise satisfy the check.
  await waitFor(() => {
    const v = document.getElementById('view');
    return v.dataset.rendered === location.hash && !v.hasAttribute('aria-busy') && !!v.querySelector('h1');
  }, 15000).catch(() => problems.push(`timeout rendering ${r}`));
  const errorNotice = await page.$('#view .notice.is-error');
  if (errorNotice) problems.push(`error notice on ${r}: ${(await errorNotice.innerText()).slice(0, 120)}`);
  // Accessibility subset (tests/a11y-audit.js) on every tab panel: any finding fails the route.
  const a11y = await page.evaluate(async () => {
    const { audit } = await import('/tests/a11y-audit.js');
    const tabs = [...document.querySelectorAll('#view [role="tab"]')];
    const found = [];
    for (let t = 0; t < Math.max(1, tabs.length); t++) {
      if (tabs[t]) { tabs[t].click(); await new Promise((res) => setTimeout(res, 150)); }
      found.push(...audit().map((i) => `${tabs[t] ? `[${tabs[t].textContent.trim()}] ` : ''}${i.rule}: ${i.detail} @ ${i.el}`));
    }
    return [...new Set(found)];
  });
  for (const i of a11y) problems.push(`a11y ${r}: ${i}`);
  const ok = problems.length === before;
  if (!ok) routeFailures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} #${r}`);
}
for (const p of problems) console.log(`  ${p}`);
await browser.close();

const failed = results.failures.length > 0 || results.total === 0 || routeFailures > 0 || problems.length > 0;
console.log(failed ? `[${browserName}] FAILED` : `[${browserName}] all checks passed`);
process.exit(failed ? 1 : 0);
