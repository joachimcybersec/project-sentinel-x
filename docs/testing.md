# Testing — Sentinel X

Only tests that were actually executed are marked ✅. Anything not yet run is marked ⏳ with the phase it belongs to.

## How to run

1. Start the dev server: `powershell -ExecutionPolicy Bypass -File .\serve.ps1`
2. Unit + data tests: open <http://localhost:8080/tests/> — the page shows `N/N passed`.
   Automation can read `window.__TEST_RESULTS__`.
3. App: open <http://localhost:8080/>.

## Phase 1 results — 2026-11-22

Environment: Windows 10, PowerShell 5.1 `serve.ps1`, Chromium-based in-app browser (Claude desktop app).

| # | Check | Result |
|---|---|---|
| 1 | Unit & data test suite (`/tests/`) | ✅ 20/20 passed |
| 2 | Landing page renders: hero canvas, KPI tiles, event replay, provenance legend, module grid | ✅ |
| 3 | Browser console errors on load and across navigation | ✅ none |
| 4 | Sidebar link navigates, sets `aria-current`, updates `document.title`, moves focus to `<main>` | ✅ |
| 5 | All 10 module routes + `#/about` resolve (13 unique in-app links found on landing) | ✅ |
| 6 | Unknown route `#/does-not-exist` shows 404 view | ✅ |
| 7 | Replay Pause/Resume: label + `aria-pressed` toggle, feed frozen while paused (3 s check) | ✅ |
| 8 | Skip link focuses `<main>` without changing the route | ✅ (bug found and fixed during testing — it previously routed to 404) |
| 9 | Mobile 375×812: no horizontal scroll, drawer opens, focus moves into nav, Escape closes and returns focus to toggle, link click closes drawer and navigates | ✅ |
| 10 | Hero text legibility over animation | ✅ after adding readability gradient (issue found during testing) |
| 11 | Dev server sends CSP / nosniff headers | ✅ |
| 12 | Path traversal `/..%2f..%2f..%2fWindows/win.ini` | ✅ rejected (HTTP 403 from Windows HTTP.sys before reaching the script's own root-prefix guard) |
| 13 | Non-GET method (POST) | ✅ 405 |

## Phase 2 results — 2026-11-22 (UI component kit)

| # | Check | Result |
|---|---|---|
| 14 | Full test suite (Phase 1 + 12 component tests) | ✅ 32/32 passed |
| 15 | `#/components` renders with no console errors from the app | ✅ |
| 16 | Severity chips: critical → 5, +high → 15, +status open → 9, search "FS-02" → 3 (all match a hand count of the dataset) | ✅ |
| 17 | Date range from 2026-11-22 → 12 events | ✅ |
| 18 | Reset clears chips, select, search and dates; focus returns to search | ✅ |
| 19 | Severity column sort (desc) puts all 5 critical first, `aria-sort` updates, focus stays on header | ✅ |
| 20 | Pagination: "Page 1 of 4, 1–8 of 30" → "Page 2 of 4, 9–16 of 30" | ✅ |
| 21 | Empty state: "No matching records."; export with 0 rows shows warning toast and does not download | ✅ |
| 22 | CSV export content: header + 5 critical rows, UTF-8 BOM bytes `EF BB BF` present; JSON export has `provenance: simulated`, `count: 5`, active filters | ✅ (file contents captured in-page; the browser's own save-to-disk step was not exercised) |
| 23 | Drawer: modal, focus moves to Close, Escape closes, focus returns to the row's open button; ATT&CK link `https://attack.mitre.org/techniques/T1059/001/` with `rel="noopener noreferrer"` | ✅ |
| 24 | Tabs with real keyboard input: ArrowRight ×2 selects and focuses "Sigma rule"; YAML keys and `\|contains` modifiers highlighted | ✅ |
| 25 | Mobile 375×812: no page-level horizontal scroll, table scrolls inside its own region, drawer is full width | ✅ |

Test-harness note: an early verification script tried `fetch()` on a blob URL and was correctly blocked by
`connect-src 'self'`; those console errors came from the harness, not the application.

## Phase 3 results — 2026-11-22 (Module 01 SOC dashboard)

| # | Check | Result |
|---|---|---|
| 26 | Full suite (13 new: chart maths, aggregations, telemetry integrity, filter `update()`) | ✅ 45/45 passed |
| 27 | `#/soc` loads with no new console errors; sidebar shows Module 01 as live | ✅ |
| 28 | KPI tiles 30 / 5 / 10 / 9 / 4 match dataset | ✅ |
| 29 | Critical KPI → 5 events, chip and donut synced, `aria-pressed` set, focus kept on tile after re-render; second click clears | ✅ |
| 30 | Donut legend high + medium → 19; status legend "investigating" → 6 (status select synced); "Authentication" bar → 7; technique T1110.001 → 4 (search box synced); IP 203.0.113.45 → 3 | ✅ all match hand counts |
| 31 | Date "to 2026-11-21" → 18 events; network chart limited to 22:00–23:45 (peak 52 MB); reset restores 2,412 MB peak at 00:15 | ✅ |
| 32 | Real keyboard: Enter on High tile, Tab to Medium, Space → 9 events, focus on Medium tile | ✅ |
| 33 | Reload data: timestamp updates, info toast explains the data is simulated | ✅ |
| 34 | Shift summary JSON (critical filter): totals 5, status open 3 / investigating 1 / contained 1, top techniques, auth stats, health; CSV export 5 rows | ✅ (content captured in-page, not saved to disk) |
| 35 | Drawer from endpoint feed (EVT-0020) lists 3 related FS-02 events; focus returns to the feed button on close | ✅ |
| 36 | 1366×900 layout screenshot review | ✅ after fixing a cramped donut legend and fractional y-axis ticks |
| 37 | Mobile 375×812: no element overflows the viewport; chart labels legible after enlarging SVG text; peak label stays inside the plot | ✅ (both found and fixed during testing) |
| 38 | UI kit drawer still works after extracting the shared event drawer | ✅ |

## Phase 4 results — 2026-11-22 (Modules 02 Threat Intelligence and 03 Attack Library)

### Source verification (documented content)

| # | Check | Result |
|---|---|---|
| 39 | `tools/check-links.ps1` over all 34 source URLs | ✅ 33 return 2xx; gao.gov returns 403 to scripts and was opened manually in the browser |
| 40 | Broken links found on first run, then fixed | CISA ED 21-04 (404) → current URL; NYDFS Twitter report (404) → press release + report PDF; 2 OWASP pages (308) → new hosts |
| 41 | Soft-404 found: the MSRC Midnight Blizzard URL redirected to the blog index | ✅ replaced with the article's current URL (found by the claim check, not the link check) |
| 42 | `tools/check-claims.ps1`: key phrases behind each fact present in the cited page (20 sources) | ✅ 20/20 |
| 43 | JavaScript-rendered or bot-protected sources checked manually in the browser (MSRC, justice.gov, gao.gov) | ✅ all key phrases present; GAO published 30 Aug 2018 |
| 44 | Claims corrected after reading the sources | ALPHV: affiliates *posed as* IT/helpdesk staff (not "social engineering of help desks"). Scattered Spider: current advisory (updated 29 Jul 2025) cites DragonForce, not ALPHV. Colonial Pipeline: reworded to what the CISA page states. Equifax: "at least 145.5 million individuals" per GAO. PrintNightmare: wording aligned to ED 21-04. |

Scope note: the claim check confirms that key phrases appear in each source. It does not prove every sentence of every summary. Detection, control and response guidance is general practice and is not presented as sourced fact.

### Application

| # | Check | Result |
|---|---|---|
| 45 | Full suite (12 new: dataset validation, citation integrity, ATT&CK name coverage, cross-links, IOC ranges, Markdown export) | ✅ 57/57 (one failure on first run was a test-fixture ID shorter than the validator allows; fixture corrected) |
| 46 | `#/threat-intel`: 10 cards; Ransomware chip → 3; search "T1621" → Scattered Spider; search "password spraying" (technique name) → APT29 | ✅ |
| 47 | IOC tab: 10 simulated indicators, network indicators defanged; simulated notice shown | ✅ after fixing file names being defanged |
| 48 | Source-reports tab: 14 de-duplicated reports newest first; AA23-325A credited to LockBit and Citrix Bleed; all external links `rel="noopener noreferrer"` | ✅ |
| 49 | Profile page (Scattered Spider): 3 cited facts → AA23-320A, labelled analysis, 2-entry timeline, techniques, related dossiers; sidebar keeps Module 02 active | ✅ |
| 50 | Cross-link profile → `#/attacks/phishing`: 10 numbered sections; TOC button focuses section 9 without changing the route; Markdown export has 10 sections (captured in-page) | ✅ |
| 51 | `#/attacks`: Credential access → 3; search "Equifax" → exploitation dossier; search "T1071.004" → DNS dossier | ✅ |
| 52 | Unknown IDs show "not found"; `#/threat-intel/<img src=x onerror=…>` is rejected by the router, no element injected | ✅ |
| 53 | Mobile 375×812 on a dossier and the reports tab: no overflow; tab strip scrolls inside its own frame | ✅ |
| 54 | Console errors from the app across all new routes | ✅ none |

## Phase 5 results — 2026-11-22 (Modules 04 Incident Response and 05 SIEM)

| # | Check | Result |
|---|---|---|
| 55 | Full suite (18 new: all 52 logs parse to their declared type, query language, enrichment, 9 expected correlation alerts, threshold tuning, pivot queries, incident ↔ log/event/dossier integrity, report Markdown) | ✅ 75/75 (two test-only fixes: JSON key order, fixture ID length) |
| 56 | SIEM explorer: deep link `#/siem?q=event.code:4625` → 9; quoted value + negation → 6; missing value shows an error; DNS chip → 8; example query → 3 | ✅ |
| 57 | Log drawer: raw / parsed / normalised / enrichment, including asset criticality and an IOC-watchlist match | ✅ |
| 58 | Parser lab: pasted sshd line parsed, normalised and matched to the watchlist; HTML junk rejected, nothing injected | ✅ |
| 59 | Correlation: default 9 alerts; threshold 3 → 11; disabling a rule removes its alerts; invalid parameter restores the value in use | ✅ after fixing a bug where an invalid value restored the default instead of the current value |
| 60 | Alert pivot link navigates to the explorer and closes the drawer | ✅ (navigation now closes open drawers globally) |
| 61 | Incident dashboard: KPIs 3/1/3/1/1; matrix cell I3×U3 → 3 cases, keeps focus; status and search filters | ✅ |
| 62 | Case IR-2026-004: lifecycle shows Recovery; investigation step reveal moves focus to the finding; evidence opens the log drawer; SIEM link `host:FS-02` | ✅ |
| 63 | Dev server crashed when a client disconnected mid-response | ✅ fixed (`serve.ps1` guards `Close()`); 20 aborted requests later the server still answered, but no disconnect warning was logged, so the exact failure path was not reproduced |

| 64 | New Phase 5 URLs | ✅ 6 of 9 verified: NIST SP 800-61r3 (browser: April 2025, CSF 2.0 profile), CISA playbooks page (browser; no publication date shown, so the source date is now "n.d."), Sysmon and Security Onion (browser), Wazuh, Elastic ECS and SigmaHQ (script, 200). ⚠ docs.zeek.org and docs.suricata.io returned HTTP 429 behind a Cloudflare bot challenge, which was not bypassed; both are the projects' official documentation hosts but are **not verified** here |
| 65 | Full `check-links.ps1` re-run | ⚠ Inconclusive: 35/43 timed out (status 0), including URLs that loaded in the browser at the same time. This reflects the shell's network during the run, not broken links. The previous run (#39) passed. Re-run before deployment |
| 66 | Evidence-drawer focus return with a **real** click and real Escape key | ✅ focus returns to the LOG-039 button (the earlier miss came from a scripted `.click()`, which never focuses the button) |
| 67 | Mobile 375×812: `#/incidents/IR-2026-004` and all four `#/siem` tabs | ✅ no element overflows the viewport; the tab strip scrolls inside its own frame |
| 68 | README, About, architecture and security docs updated for Phase 5 | ✅ |

## Phase 6 results — 2026-11-22 (Module 06 Detection Engineering)

| # | Check | Result |
|---|---|---|
| 69 | Full suite (12 new: YAML subset parser, condition parser, wildcard/CIDR/numeric/regex/keyword semantics, logsource mapping, validator errors and warnings) | ✅ 87/87 |
| 70 | All 16 library rules validate with **no errors and no warnings**, have unique UUIDs and status `experimental` | ✅ |
| 71 | Each rule matches **exactly** its expected sample logs (no misses, no false positives on the 52-line dataset) | ✅ 16/16 |
| 72 | Every rule ATT&CK tag maps to a named technique; related dossiers exist | ✅ |
| 73 | Evaluator modifiers checked against the Sigma specification's modifier appendix (contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte all listed) | ✅ (browser, GitHub) |
| 74 | Log-source categories and field names checked against the specification's taxonomy appendix | ✅ after switching the resolver rule from `query`/`record_type` to the taxonomy's `dns.question.name`/`dns.question.type` |
| 75 | `#/detections` library: 16 rows all ✓; Critical → 1; webserver → 2; search T1071.004 → 2; credential-access → 3 | ✅ |
| 76 | Coverage tab: per-incident evidence coverage (e.g. IR-2026-005 9/9, IR-2026-004 1/4) and 14 techniques | ✅ shows real gaps honestly (EDR JSON has no standard Sigma logsource) |
| 77 | Playground: template loads and runs; broadening the XSS rule surfaces 3 false positives; unknown identifier and tab indentation give clear errors; markup in YAML is not injected | ✅ |
| 78 | Deep link `#/detections?edit=lsass-memory-access` opens the playground with that rule | ✅ |
| 79 | Rule page: objective, log source, logic (highlighted YAML), severity, ATT&CK, false positives, investigation, remediation, live test ✓, related dossier; unknown ID → "Rule not found" | ✅ |
| 80 | Mobile 375×812: rule page and all three tabs, no overflow | ✅ |
| 81 | New reference URL (Sigma specification) | ✅ 200 |

**Not done:** validation with pySigma / `sigma check` (no Python on this machine); conversion to backend queries (Splunk/KQL/Elastic) was not attempted.

## Phase 7 results — 2026-11-22 (Modules 07 Vulnerability Intelligence and 08 Network Security)

| # | Check | Result |
|---|---|---|
| 82 | `tools/update-cve-snapshot.ps1` run against live sources | ✅ KEV catalog 2026.11.20 (1,790 entries); 29 CVEs selected (14 curated + 15 newest); NVD records 29/29; EPSS scores 29/29 (score date 2026-11-21) |
| 83 | Root cause of earlier shell timeouts found | ✅ `Invoke-WebRequest` took about 85 s per request on this machine, while `curl.exe` took about 2 s. The snapshot script and `check-links.ps1` now use curl.exe |
| 84 | Full suite (14 new: snapshot validation and freshness, curated CVEs present, every CVSS vector parsed with the right version, prioritisation rules, RFC 1071 checksum example, packet checksums and lengths, tamper detection, DNS encoding, policy outcomes, Zero Trust attribute logic, incident links) | ✅ 101/101 |
| 85 | `#/vulnerabilities`: freshness banner shows KEV version and release, NVD fetch and EPSS date; KPIs 29 / 22 P1 / 13 ransomware / 16 critical; P2 filter → 7; vendor search; ransomware filter → 13 | ✅ all counts match a manual count of the snapshot |
| 86 | CVE page (CVE-2023-34362): NVD description, CVSS 3.1 breakdown, CWE-89 link, KEV required action, EPSS 99.9%, priority reasons, auto-found CL0P profile and SQL injection dossier; unknown CVE → link to NVD | ✅ |
| 87 | Segmentation simulator: as-was 0/6 attacks blocked, segmented 5/6 (HTTPS C2 passes the port-based rule), Zero Trust 6/6; legitimate flows 6/6 in all; focus retained on re-render | ✅ |
| 88 | Diagram legibility | ✅ after moving unselected flow lines behind zones (they overlapped host labels) |
| 89 | Packet explorer: SYN 58 bytes, TTL byte 22 = 0x80, flags byte 47 = 0x02; DNS QNAME 51 bytes, packet 109 bytes; HTTP 194 bytes; all IPv4/TCP/UDP checksums valid | ✅ (hand-checked offsets) |
| 90 | Topics: 10 cards, references, buttons switch tabs and move focus | ✅ |
| 91 | Mobile 375×812: all three network tabs, vulnerability list, CVE page — no overflow | ✅ |
| 92 | Link check (curl): 182 URLs including NVD's per-CVE references → 170 OK; 6 failures and 6 × 403 were all third-party NVD references (SecurityFocus, Ars Technica, openSUSE lists…) except GAO (known bot block). The checker now skips NVD reference lists by default (`-IncludeNvdReferences` to include them) | ✅ |
| 93 | RFC 768/791/9293 returned 429 in the burst; re-checked slowly | ✅ 200 with matching titles |
| 94 | NIST/CISA network references: titles and dates confirmed | ✅ after replacing SP 800-81-2 (**withdrawn 19 Mar 2026**) with SP 800-81 Rev. 3 (March 2026) |

## Phase 8 results — 2026-11-22 (Modules 09 Tools, 10 Knowledge Centre, site-wide search)

| # | Check | Result |
|---|---|---|
| 95 | Full suite (10 new: 10 tool categories × ≥3 tools, pen-test cautions, validators, every in-app link resolves to a route and an existing item, search index covers all items and 9 types, ranking, AND semantics, input cap) | ✅ 111/111 after two fixes found by the tests: Sigma rule titles live in the YAML (search had `undefined` titles), and the tool count is 33, not 34 as first written |
| 96 | `#/tools`: 33 tools in 10 sections; Commercial → 5; search "memory" → Volatility 3; Forensics → 3; workflow button clears filters and focuses the tool card; 4 pen-test cautions; external links `noopener noreferrer` | ✅ |
| 97 | Pathways: ticking steps updates count and progress; persists after reload; Reset clears; focus kept | ✅ |
| 98 | Articles: 20; Advanced → 1; article page shows sections, practice links, references and parent pathway; unknown ID → "Article not found" | ✅ |
| 99 | Top-bar search with real keyboard input: `/` focuses it, typing "lsass" and Enter opens `#/knowledge?tab=search&q=lsass` with 4 results across rule, dossier, tool and article | ✅ (the automation's "slash" key name sends an empty key; the literal "/" key works) |
| 100 | Mobile search icon was also visible on desktop (`.icon-btn` in a later stylesheet overrode `display:none`) | ✅ fixed with a more specific selector |
| 101 | Mobile 375×812: tools, all three knowledge tabs, article page, no overflow; search box collapses to an icon | ✅ |
| 102 | Link check (curl, NVD per-CVE references excluded): 106 URLs → 102 OK; GAO and ISO 403 (bot protection) and 2 RFCs 429 (rate limit) | ✅ ISO verified in the browser (27001:2022, published 2022-10); RFCs verified earlier; the checker now retries 429 once and reports 403/429 as "verify manually", not failures |
| 103 | Final URL and title check for likely-moved links (Splunk, Elastic, NIST 800-63B, NICE, TheHive, Prowler, Greenbone, Snort, Trivy, Autopsy, MDE, Nessus, CSF, CIS, Pyramid of Pain, Kill Chain, Microsoft events, DFIR-IRIS) | ✅ Elastic moved to a new docs URL (updated). Nessus checked in the browser (JavaScript-rendered). DFIR-IRIS uses a meta refresh to `latest/` (fine) |

## Phase 9 results — 2026-11-22 (serverless proxy, automation)

| # | Check | Result |
|---|---|---|
| 104 | Full suite (11 new backend tests: classifier, 405/400 handling, no upstream calls for documentation/private/reserved indicators, not-configured with zero keys, per-provider normalisation with exact upstream URLs and auth headers, keys and indicator values absent from response and log, 429/401/timeout mapping, no caching of errors, CDN caching of successes, 404 → not-found, domain and hash endpoints, no CORS header, upstream host allow-list, client fallback when the backend is missing, client ↔ handler end-to-end) | ✅ 122/122 (first run) |
| 105 | Live lookup tab on the local server: documentation IP, private IP, reserved domain and invalid input make **0** requests; a public IP makes 1 same-origin request, gets 404 and shows "not available on this host" with no data | ✅ (the browser logs the expected 404 in the console; this only happens when a user runs a lookup without the backend) |
| 106 | Sigma export: 16 `.yml` files, UTF-8 without BOM, LF line endings | ✅ |
| 107 | Mobile 375×812: Live lookup tab, no overflow | ✅ after making the tab strip scroll the selected tab into view (it could sit off-screen; fix applies to every tabbed page) |

**Written but not executed (no Node, Netlify account, GitHub repository or API keys on this machine):**

| Item | How it will be verified |
|---|---|
| `netlify/functions/ioc.mjs` deployed on Netlify; real AbuseIPDB / VirusTotal / OTX responses | Phase 11: deploy, set keys, run the curl checks in `docs/deployment.md`, compare with each provider's web UI |
| Provider response field names (`abuseConfidenceScore`, `last_analysis_stats`, `pulse_info`) against live APIs | Phase 11, as above (the tests use documented field names, not captured live responses) |
| `ci.yml` (Chromium, Firefox, WebKit + `sigma check`) | First push to GitHub |
| `refresh-cve-snapshot.yml`, `source-checks.yml` | Manual "Run workflow" after the first push |
| `tests/run-in-browser.mjs` (Playwright driver) | Runs in CI; not run locally (no Node) |

## Phase 10 results — 2026-11-22 (security review and QA)

Full write-up, with severities: [security-review.md](security-review.md).

| # | Check | Result |
|---|---|---|
| 108 | Proof of concept: `safeUrl('/\\evil.example/x')` and `'/\t/evil.example/x'` were returned unchanged and resolved by the browser to `http://evil.example/x` | ❌ → ✅ fixed; regression test added |
| 109 | Trusted Types: `innerHTML` assignment throws (`TypeError`) with the new CSP; no violations from the app across the test suite, 21 routes with every tab, the click crawl and a cold deep-link load | ✅ (Chromium only) |
| 110 | Full suite after fixes (new tests: sanitiser bypasses, special-purpose IPv4 ranges, oversized upstream bodies, malformed lookup responses) | ✅ 126/126 |
| 111 | Deep-link probes (`<script>` in route param, `..%2F`, HTML/SVG payloads in `q=` and `tool=`) | ✅ 404 view or plain text; nothing injected |
| 112 | Accessibility audit (`tests/a11y-audit.js`), 21 routes, default tabs: 7 unlabelled tables, 5 heading skips, sub-24 px targets on 15 routes | ❌ → ✅ 0 findings after fixes |
| 113 | Accessibility audit on **every tab panel** at 375 px and 768 px | ❌ one contrast failure (code comments 4.16:1) → ✅ 0 findings |
| 114 | Click crawl: 400 buttons and toggles on 19 routes and every tab | ✅ 0 errors; every control had a visible effect (the 11 that change no DOM are jump buttons, and each one was verified to move focus) |
| 115 | Internal link crawl from every module | ✅ 121 unique in-app URLs, all render |
| 116 | Layout at 375 px with every tab and every collapsible opened | ❌ About page descriptions squeezed to 13 px; 3 wide tables widened the page → ✅ fixed, 0 overflow |
| 117 | Layout at 768 px | ✅ no overflow (an initial 15 px "overflow" was my script measuring once while a scrollbar was showing) |
| 118 | Landing page weight (local, uncompressed) | 54 requests / 449 KB → ✅ 20 requests / 139 KB after lazy-loading module views; 0 third-party requests; no long tasks; CLS 0.003 on `/soc` |
| 119 | docs.zeek.org | ⏳ Cloudflare bot check on automated access; not bypassed. Verify by hand |

## Phase 11 results — 2026-11-22 (GitHub, CI, Netlify deployment)

Live site: <https://joachimcybersec-project.netlify.app> (Netlify, deployed from `main`). No provider API keys are set, so live lookups return "not-configured".

| # | Check | Result |
|---|---|---|
| 120 | First CI run on GitHub (`ci.yml`) | ❌ pre-deploy and Sigma check passed; all three browser jobs timed out: `serve@14` showed directory listings for `/` and `/tests/` → fixed in `serve.json` (no listings, `/` → `index.html`) and the driver opens `/tests/index.html` |
| 121 | Local run of the CI driver (Playwright 1.49.1, `serve@14.2.4`) | ❌ `page.waitForFunction` evaluates a string in the page, which the CSP (`script-src 'self'`, Trusted Types) blocks → ✅ driver polls with `page.evaluate`; the CSP stays on in tests. Local runs used installed Chrome: Playwright 1.49's browser download fails under Node 26 (CI uses Node 22) |
| 122 | Intermittent target-size findings: `.th-sort` (local), `a.tech-id` (CI Chromium) measured 23.x px with `min-height: 24px` | ✅ `min-height: 28px` on `.th-sort`, `a.tech-id`, `.wf-tool` |
| 123 | CI WebKit: SIEM view rendered twice (2 h1s, duplicate ids, unlabelled controls) | ❌ real bug: a lazy view from an earlier navigation finished after a newer one had cleared `#view` → ✅ router serialises navigations (`latestOnly`, unit-tested); `#view` records `data-rendered`; a burst of 5 hash changes leaves 1 h1 and 0 duplicate ids |
| 124 | CI run on `54bd76f`: pre-deploy, Sigma check (`sigma check`), Chromium, Firefox, WebKit (127 unit tests + 21 routes with the accessibility audit on every tab) | ✅ all 5 jobs passed |
| 125 | Live response headers on `/` | ✅ CSP incl. `require-trusted-types-for 'script'`, HSTS (preload), X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP |
| 126 | Internal paths on the live site: `/tests/`, `/netlify/`, `/tools/`, `/.github/` (folders and files inside) | ✅ 404 |
| 127 | Local-development files served: `package.json`, `serve.json`, `serve.ps1` (no secrets) | ❌ 200 → ✅ 404 after adding redirect rules |
| 128 | Live `/api/ioc`: documentation IP and private IP → `lookup:false`, nothing sent upstream; `8.8.8.8`, `example.com` → each provider `not-configured`; `<script>` → 400; POST → 405; `no-store` on lookups and errors | ✅ |
| 129 | Live smoke test in Chrome: 21 routes, one h1 each, no error notices, no 4xx/5xx, no CSP violations from the app; Live lookup tab with `8.8.8.8` | ✅ |
| 130 | Console on the live site | ⚠️ one Trusted Types error from a script **Netlify injects** (`/.netlify/scripts/hud?variant=public`, the "Powered by Netlify" badge), which builds an iframe via `srcdoc`. The CSP blocks it, so the badge never renders. Turning the badge off in project settings did not remove it: the script itself says the badge cannot be hidden on the free plan. Not an application error; goes away on a paid plan or another host |
| 131 | W3C Nu validator on the live URL | ❌ 2 errors in our markup (`aria-label` on `<time>`, clock `<time>` with no valid `datetime` before boot) + redundant `role="banner"` → ✅ fixed; `index.html` revalidated by direct input: 0 errors (the only warnings are CSP `'self'` not matching when there is no origin). The live page also reports a stray `<script>` after `</html>`: Netlify's injected badge tag, not our markup |

## Phase 12 results — 2026-11-22 (portfolio presentation)

| # | Check | Result |
|---|---|---|
| 132 | Provenance audit while reviewing screenshots: detection rules carried the *Lab result* badge, but have only been tested on simulated logs (architecture.md: *LAB* only once actually performed) | ❌ → ✅ relabelled *Simulated* in data, validator, Module 06 card and rule pages |
| 133 | Demo guide: every step run against the live site (KPI filter, event drawer, incident → SIEM link, `host:FS-02` query, rule page matches exactly 1 expected log, policy simulator, packet checksums, 8 tunable correlation thresholds, KEV/NVD/EPSS freshness, CVSS breakdown, `innerHTML` → TypeError) | ✅ one link fixed: `#/network?tab=packets` does not select the tab, so the guide says to click it |
| 134 | Case study facts against the data (attack chronology from incident timelines, counts from the JSON files) | ✅ one correction: the attack order |
| 135 | About page "For reviewers" section at 1440 px and 390 px: no overflow; 5 in-app and 5 GitHub links | ✅ (the GitHub doc links resolve once pushed) |
| 136 | Release v1.0.0 (`3362de2`): CI run 45031615386 (pre-deploy, Sigma check, Chromium, Firefox, WebKit); live site redeployed; `og-image.jpg` served; rules served as `"simulated"`; live smoke test of 21 routes | ✅ all 5 CI jobs passed; no CSP violations from the app (the only console error is the Netlify badge script, #130) |

## v1.1 results — 2026-11-23 (portfolio themes and name)

Branch `feature/portfolio-themes`. Local runs used installed Chrome with Playwright 1.49.1 and `serve@14.2.4`.

| # | Check | Result |
|---|---|---|
| 137 | Full suite with the new theme tests | ✅ 135/135 |
| 138 | Accessibility audit (incl. contrast) on 21 routes × every tab × 3 themes | ✅ 0 findings |
| 139 | Theme switching via the real button: attribute, saved choice, browser UI colour, reload persistence | ✅ all three themes |
| 140 | CSP / Trusted Types violations and console errors while switching themes | ✅ none |
| 141 | Phone (390 px): menu fits the screen, no horizontal overflow; open nav drawer covers the theme button | ✅ |
| 142 | Reduced motion: background drawn once, then unchanged (sampled for 5.6 s) | ✅ one early redraw, then still |
| 143 | Desktop: theme button covered the sidebar footer text | ❌ → ✅ footer right-aligned on desktop |
| 144 | Syntax check of every changed script; pre-deploy check | ✅ (140 files) |

## Not yet performed

| Check | Phase |
|---|---|
| Verify docs.zeek.org and docs.suricata.io manually in a normal browser (automated access is challenged) | ⏳ manual |
| Scheduled regeneration of `cve-snapshot.json` (GitHub Action running `update-cve-snapshot.ps1`) | ⏳ workflow on GitHub; not yet run (manual "Run workflow" or first daily schedule) |

| Check | Phase |
|---|---|
| Reduced-motion visual check with OS setting enabled (the in-app browser cannot emulate it) | ⏳ manual |
| Real file save of CSV/JSON export (the crawl stubbed downloads: 17 export actions produced a file name with no error); opening the CSV in Excel / LibreOffice | ⏳ manual |
| Clipboard copy with a real user gesture (the crawl stubbed the clipboard) | ⏳ manual |
| Screen reader pass (NVDA / VoiceOver) | ⏳ manual |
| axe-core / Lighthouse performance and accessibility scores on the deployed site | ⏳ manual (Chrome DevTools) |
| Independent penetration test or DAST scan (e.g. OWASP ZAP baseline) | ⏳ optional, after deployment |
| Scheduled re-run of link and claim checks (advisories get updated, as AA23-320A was) | ⏳ `source-checks.yml` on GitHub; not yet run |
| Real provider responses through `/api/ioc` (needs API keys set in Netlify) | ⏳ when keys are added |
