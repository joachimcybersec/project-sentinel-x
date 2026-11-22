# Security review and QA — Phase 10 (2026-11-22)

Scope: everything in the repository: static SPA (`index.html`, `js/`, `css/`, `data/`), the serverless
IOC proxy (`netlify/`), hosting configuration (`netlify.toml`, `serve.json`, `serve.ps1`) and the GitHub
Actions workflows. Reviewer: the project author (self-review, not an independent audit or penetration test).

Method:
1. Manual code review of every DOM sink, URL sink, regex constructed from input, storage use, fetch,
   and the serverless handler.
2. Grep sweeps for dangerous APIs (`innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
   `new Function`, string timers, `setAttribute` with data, `location` writes, `postMessage`) and for
   hard-coded secrets.
3. Proof-of-concept checks in the browser for each suspected issue before fixing it, then a regression
   test.
4. Malformed and injection-style deep links on every route type.
5. Automated QA: an accessibility audit on every route and tab panel, a crawl that clicks every control,
   an internal link crawl, and responsive checks at 375 px and 768 px.

Severity is judged for this application (a static demo with no accounts or user data), not in the abstract.

## Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| SR-01 | **`safeUrl()` bypass.** Relative values were trusted by prefix (`/…`), so `/\evil.example/x` and `/<TAB>/evil.example/x` passed through and the browser resolved them to `http://evil.example/x`. Confirmed in the browser. Exploitability was low because all URLs come from curated data or NVD references, but it defeated a documented control. | Medium | ✅ Fixed: control characters are rejected and relative URLs are resolved against a placeholder origin, which they must not leave. 8 regression assertions in `tests/dom.test.js` |
| SR-02 | **No browser-enforced backstop for DOM XSS.** Safety relied entirely on the `el()` convention. | Low (hardening) | ✅ Added `require-trusted-types-for 'script'; trusted-types 'none'` to all four CSP sources. Verified in Chromium: `innerHTML` assignment throws, and no app code path triggers a violation (126 tests, 21 routes with all tabs, 400-click crawl) |
| SR-03 | **Unbounded upstream body parsing** in the IOC proxy (`res.json()` on any size). | Low | ✅ 2 MB cap on the declared `Content-Length` and on the body actually read; test added |
| SR-04 | **Special-purpose IPv4 ranges sent upstream**: `192.0.0.0/24` (IETF protocol assignments) and `198.18.0.0/15` (benchmarking) were classified as public. | Low | ✅ Added to `NON_PUBLIC_RANGES`; test added |
| SR-05 | **Lookup race in the UI**: two quick lookups could interleave results, and a malformed response body could throw during rendering. | Low (integrity of display) | ✅ Request sequence guard and response shape check (`isValidBody`); test added |
| SR-06 | Internal folders were blocked only by `/folder/*` patterns; the bare `/tests` form was not listed explicitly. | Info | ✅ Explicit rules added. `Cross-Origin-Resource-Policy: same-origin` added |
| SR-07 | Public `/api/ioc` endpoint can spend the site's provider quota. | Accepted risk | Documented in `security.md` with mitigations (CDN caching, Netlify rate limiting if abused) |
| SR-08 | GitHub Actions use version tags (`@v4`) rather than commit SHAs; `sigma-cli` is unpinned until a first green run. | Info | Accepted for now: GitHub-owned actions only, read-only permissions except the snapshot job. Pin SHAs in Phase 11 |
| SR-09 | Sigma `re` modifier compiles user-supplied patterns (ReDoS possible in the playground). | Info | Accepted: runs only in the visitor's own tab, patterns capped at 200 characters |

Checked and found sound (no change): no HTML sinks anywhere in `js/`; `el()` rejects non-allow-listed and
`on*` attributes; route params are restricted to `[\w.-]{1,80}`; query-string deep links are length-capped
and used only as text; SIEM wildcards are escaped before building a RegExp; YAML parser rejects
`__proto__`/`constructor` keys; CSV export neutralises formula prefixes; `localStorage` holds only pathway
progress; no secrets in the repository; the proxy uses fixed upstream URL templates, a host allow-list,
`redirect: 'error'`, no CORS headers and logs no indicator values; the dev server is bound to localhost
with a root-prefix path guard.

Deep-link probes (all rendered safely as a 404 view or as plain text, with no elements injected):
`#/incidents/%3Cscript%3E`, `#/attacks/..%2F..%2Fetc`, `#/siem?q=<img src=x onerror=…>`,
`#/knowledge?tab=search&q="><svg onload=…>`, `#/tools?tool="><b>`.

## QA findings (accessibility, function, layout, performance)

| ID | Finding | Status |
|---|---|---|
| QA-01 | 7 data tables had no caption or label (chart data tables, chain of custody, priority tiers, CVSS metrics, keyboard reference, coverage, SIEM tools) | ✅ Visually hidden captions |
| QA-02 | Heading levels skipped h2 on tabbed pages and card grids (h1 → h3) | ✅ Tab panels get a visually hidden h2 (in `tabs.js`, so every tabbed page benefits); attack library grid too |
| QA-03 | Targets under 24×24 px (WCAG 2.2 SC 2.5.8): sort headers, breadcrumbs, ATT&CK links, workflow tool chips, "View data table" toggles | ✅ CSS minimum sizes |
| QA-04 | Code-viewer comments at 4.16:1 contrast (found only when every tab was audited) | ✅ Now 6.12:1 |
| QA-05 | About page at 375 px: the definition-list grid squeezed descriptions to 13 px wide (one character per line) | ✅ Lists stack on narrow screens, and term columns are capped at 40 % |
| QA-06 | Wide tables (SIEM tool map, SOC chart data, network comparison) widened the page at 375 px | ✅ Scroll inside their container |
| QA-07 | Landing page downloaded every module's code (54 requests, 449 KB uncompressed) | ✅ Views load on first visit: 20 requests, 139 KB |
| QA-08 | Click crawl: 400 controls on 19 routes, every tab, 0 errors; 17 exports (download stubbed), all controls had a visible effect (the 11 jump buttons verified to move focus) | ✅ No defects |
| QA-09 | Internal link crawl: 121 unique in-app URLs discovered and visited, all render | ✅ No defects |

New tooling: `tests/a11y-audit.js` (a DOM-only WCAG subset: names, labels, duplicate ids, id references,
heading order, table captions, ARIA tab structure, contrast, target size). `tests/run-in-browser.mjs` now
runs it on every route and tab panel in Chromium, Firefox and WebKit in CI.

## Limits of this review

- Self-review, not an independent audit or penetration test. No dynamic scanner (e.g. OWASP ZAP) was run.
- Run in one Chromium-based browser. Trusted Types is enforced in Chromium-based browsers only; others
  ignore the directive and rely on the code-level controls, which are unchanged.
- The IOC function was reviewed and tested with simulated upstreams only; it has not been deployed.
- The accessibility audit is a subset. It cannot judge reading order, focus visibility, alt-text quality
  or text over images, and is not a substitute for axe-core, Lighthouse or a screen-reader pass (still to do).
- Performance figures come from the local single-threaded dev server with the browser pane hidden,
  so paint timings were not meaningful and are not reported. Lighthouse on the deployed site is in Phase 11.
