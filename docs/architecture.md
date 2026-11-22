# PROJECT SENTINEL X — Technical Architecture

> Detect. Investigate. Understand. Defend.

Status: **Phases 1–10 complete** (this document was written in Phase 1; the roadmap table in §6 tracks what
was built). Tier B (`/api/ioc`) and the GitHub Actions are implemented and unit-tested but not yet deployed.
Anything still marked *planned* has not been built. Nothing here claims a live integration that does not exist.

---

## 1. Architecture overview

Sentinel X is a **static-first, progressively enhanced** platform built as two tiers:

| Tier | What it is | Where it runs | Required? |
|---|---|---|---|
| **Tier A — Static SPA** | HTML/CSS/vanilla ES modules, hash router, curated JSON datasets, Canvas/SVG visualisations (in-house SVG charts) | Netlify / GitHub Pages (CDN) | Yes — the whole site works with only this tier |
| **Tier B — Intel proxy** | Small serverless functions that call public threat-intel APIs with server-side keys, normalise and cache responses | Netlify Functions (AWS Lambda under the hood) + scheduled build job | Optional — enables *live* feeds |

Design principles:

1. **Works without a backend.** Every module renders from versioned JSON in `/data`. If Tier B is down or
   rate-limited, the UI falls back to the last good snapshot and *says so* (source, fetched-at timestamp).
2. **Three provenance classes, always labelled** on every card, table row and chart:
   - `SIMULATED` — synthetic demonstration telemetry generated for this project.
   - `DOCUMENTED` — real-world intelligence from a cited public source (with date + link).
   - `LAB` — results produced by the author in an isolated lab (only added once actually performed).
3. **No secrets in the browser.** API keys live only in Netlify environment variables, read by functions.
4. **No framework lock-in.** Vanilla ES modules keep the bundle tiny, show fundamentals, and need no build step.
   A build step (esbuild) can be introduced later purely for minification.
5. **Safe DOM by construction.** All rendering goes through `js/utils/dom.js` (`el()` builds nodes with
   `textContent`); `innerHTML` with data is forbidden. CSP blocks inline scripts.

## 2. System architecture diagram

```
                                   ┌──────────────────────────────────────────┐
                                   │              USER BROWSER                │
                                   │                                          │
                                   │  index.html  (CSP, semantic shell)       │
                                   │     │                                    │
                                   │  app.js ──► router.js (#/route)          │
                                   │     │          │                         │
                                   │     │          ▼                         │
                                   │     │     views/*.js  (one per module)   │
                                   │     │          │                         │
                                   │     │          ▼                         │
                                   │     │   utils/dom.js (safe rendering)    │
                                   │     │          ▲                         │
                                   │     ▼          │                         │
                                   │  data-service.js ── in-memory cache      │
                                   │     │   (fetch, validate, provenance,    │
                                   │     │    timeout, fallback)              │
                                   └─────┼────────────────────────────────────┘
                     static JSON         │          live (optional, Tier B)
                 ┌───────────────────────┴─────────────────────┐
                 ▼                                             ▼
   ┌──────────────────────────────┐          ┌──────────────────────────────────────┐
   │  NETLIFY CDN (Tier A)        │          │  NETLIFY FUNCTIONS (Tier B, Phase 9) │
   │  /data/*.json  (versioned)   │          │  /api/ioc (AbuseIPDB · VT · OTX)     │
   │   modules, sample-events,    │          │  • keys from env vars                │
   │   incidents, detections,     │          │  • allow-list of upstream hosts      │
   │   attack-library, cve-snap   │          │  • input validation, response shape  │
   │  security headers (CSP,      │          │  • Cache-Control s-maxage            │
   │   HSTS, nosniff, etc.)       │          │  • rate-limit aware, graceful errors │
   └──────────────▲───────────────┘          └───────────────┬──────────────────────┘
                  │ commit snapshot                          │ HTTPS
   ┌──────────────┴───────────────┐          ┌───────────────▼──────────────────────┐
   │  GitHub Actions (Phase 9)    │          │  PUBLIC SOURCES                      │
   │  nightly: fetch CISA KEV +   │─────────►│  CISA KEV JSON · NIST NVD 2.0 API    │
   │  NVD deltas → validate →     │          │  MITRE ATT&CK STIX (GitHub)          │
   │  write data/snapshots/*.json │          │  URLhaus · MalwareBazaar · OTX       │
   └──────────────────────────────┘          │  AbuseIPDB · VirusTotal (key/ToS)    │
                                             └──────────────────────────────────────┘
```

Why a nightly snapshot *and* functions: snapshots give fast, free, always-available data (KEV and ATT&CK
change slowly); functions are only needed for on-demand lookups (e.g. "check this IOC").

## 3. Sitemap

```
#/                    Landing — topology canvas, telemetry ticker, module launcher
#/soc                 01 Security Operations Centre dashboard
#/threat-intel        02 Threat Intelligence Centre (actors, campaigns, IOCs, reports)
#/attacks             03 Attack Intelligence Library  →  #/attacks/:id (10-section dossier)
#/incidents           04 Incident Response           →  #/incidents/:id (case investigation)
#/siem                05 SIEM & Log Analysis (search, parse, correlate)
#/detections          06 Detection Engineering        →  #/detections/:id (Sigma viewer)
#/vulnerabilities     07 Vulnerability & CVE Intelligence
#/network             08 Network Security Intelligence
#/tools               09 Security Tools Directory
#/knowledge           10 Knowledge Centre & learning paths
#/about               About This Project (engineering decisions, provenance policy)
```

Hash routing is chosen deliberately: it works on GitHub Pages and Netlify with zero rewrite rules and
every module is deep-linkable.

## 4. Technology stack

| Layer | Choice | Justification |
|---|---|---|
| Markup | Semantic HTML5, ARIA landmarks | Accessibility, SEO, recruiter-readable source |
| Styling | CSS custom properties, layered files (`main`, `components`, `responsive`) | Themeable, no preprocessor needed |
| Logic | Vanilla ES2020 modules | Zero dependencies, demonstrates fundamentals, no build step |
| Visuals | Canvas 2D (topology), inline SVG diagrams, **in-house SVG charts** (`js/components/charts.js`: stacked timeline, donut, bar list, line/area) | Decided in Phase 3 instead of Chart.js: zero third-party code, CSP stays `script-src 'self'`, every chart has a data-table fallback. Revisit if heavier charting (zoom, brushing) is needed. |
| Code display | Lightweight in-house YAML/Sigma highlighter (planned) | Avoids a heavyweight dependency |
| Data | Versioned JSON with schema-checked fields | Static-host friendly, diffable in Git |
| Serverless | Netlify Functions (Node 20) | Hides API keys; same platform as hosting |
| Automation | GitHub Actions | Nightly data snapshots, link checking, tests |
| Tests | Browser test runner (`tests/index.html`), later Playwright + html-validate in CI | Runs with no local toolchain |
| Local dev | `serve.ps1` (PowerShell HttpListener, zero install) or `npx serve` | ES modules need HTTP, not `file://` |
| Optional lab | Docker Compose: Wazuh or Elastic + Sysmon/Suricata sample data | Only cited as *LAB* once actually run |

Not chosen: React/Vue (unnecessary weight for this scope), a persistent database server (no need — data is
read-only and fits in JSON; SQLite only becomes relevant if user accounts/case notes are added).

## 5. Directory structure

```
project-sentinel-x/
├── index.html                 App shell (CSP meta, landmarks, nav)
├── netlify.toml               Publish config + security headers
├── serve.ps1                  Zero-dependency local dev server (Windows)
├── package.json               Scripts for when Node is installed
├── README.md  LICENSE
├── assets/icons/              favicon.svg
├── css/
│   ├── main.css               Design tokens, base, layout
│   ├── components.css         Cards, badges, buttons, tables
│   └── responsive.css         Breakpoints, reduced motion
├── js/
│   ├── app.js                 Bootstrap, route table
│   ├── router.js              Hash router (pure parse fn + listener)
│   ├── navigation.js          Sidebar, mobile drawer, active state, keyboard
│   ├── data-service.js        Fetch, timeout, cache, validation, provenance
│   ├── effects/topology.js    Animated network topology canvas
│   ├── utils/dom.js           Safe element builder, escaping, formatters
│   └── views/                 home.js, module-status.js, about.js, not-found.js (+1 per module later)
├── data/
│   ├── modules.json           Module registry (status, phase, description)
│   └── sample-events.json     SIMULATED telemetry seed (used by landing ticker)
├── netlify/functions/ioc.mjs  Phase 9: /api/ioc wrapper (core logic in netlify/lib/ioc-core.mjs)
├── .github/workflows/         Phase 9: ci.yml, refresh-cve-snapshot.yml, source-checks.yml
├── docs/  architecture.md deployment.md security.md testing.md
└── tests/ index.html  test-runner.js  *.test.js
```

## 6. Implementation roadmap (realistic)

Effort assumes a focused learner working part-time; each phase ends with a verification gate.

| Phase | Deliverable | Gate | Est. |
|---|---|---|---|
| 1 | Architecture + working shell, router, data-service, landing, CSP | Tests green, no console errors, mobile OK | ✅ done |
| 2 | Full UI kit (tables, filters, drawers, tabs, toasts) + style guide page | Every component keyboard-operable | ✅ done |
| 3 | SOC dashboard (Module 01) with SVG charts, filters, CSV/JSON export, shift summary | Filters change counts correctly (unit tests) | ✅ done |
| 4 | Threat Intel + Attack Library (02, 03) with ATT&CK mapping, cited sources | Every DOCUMENTED item has source/date/link | ✅ done (link + claim checks in `tools/`) |
| 5 | Incident Response + SIEM (04, 05): case studies, log search & parsing | Parsers tested on sample logs | ✅ done |
| 6 | Detection Engineering (06): Sigma library + viewer | Rules match expected sample logs (in-browser evaluator); `sigma check` in CI moved to Phase 10 | ✅ done |
| 7 | Vulnerabilities + Network (07, 08): KEV snapshot, diagrams | Snapshot freshness shown | ✅ done (KEV + NVD + EPSS snapshot script) |
| 8 | Tools + Knowledge (09, 10) + site-wide search | Link checker passes | ✅ done |
| 9 | Netlify Functions + nightly snapshot Action | Function errors degrade gracefully | ✅ code done and unit-tested with mocked upstreams; deployment and first Action runs pending (Phase 11) |
| 10 | Security review + QA (CSP audit, a11y, Lighthouse, Playwright) | Documented results | ✅ review + fixes, Trusted Types, a11y audit, click and link crawls (docs/security-review.md); Lighthouse and live Playwright runs move to Phase 11 |
| 11 | Docs + deployment + custom domain | Public HTTPS URL | 1–2 days |
| 12 | Portfolio presentation (About page, screenshots, demo script) | Walkthrough rehearsed | 1 day |

(Your original 12-phase list is preserved in spirit; UI kit is pulled earlier because every later module
depends on it.)

## 7. Open-source tools and data sources

**Data sources (planned integration method → constraints)**

| Source | Use | Access | Notes |
|---|---|---|---|
| CISA KEV | Exploited CVEs | Public JSON feed, no key | Ideal for nightly snapshot |
| NIST NVD API 2.0 | CVE details, CVSS | Public; API key raises rate limit | Must respect rate limits; key server-side only |
| MITRE ATT&CK | Technique IDs/names | STIX 2.1 JSON on GitHub (`mitre-attack/attack-stix-data`) | Snapshot, cite version |
| URLhaus / MalwareBazaar (abuse.ch) | Malicious URLs, sample hashes | API (auth key now required) | Display defanged indicators only |
| AlienVault OTX | Pulses / IOCs | Free key | Server-side |
| AbuseIPDB | IP reputation lookups | Free key, daily quota | On-demand function only |
| VirusTotal | Hash/URL reputation | Free key, strict ToS for public API | Personal/non-commercial use; low quota |
| OWASP, FIRST (CVSS/EPSS), CERT advisories, vendor blogs | Reference content | Links | Cited, not scraped |

**Tools referenced / for optional lab work:** Wazuh, Elastic Stack, Security Onion, Suricata, Zeek,
Sysmon (+ SwiftOnSecurity / Olaf Hartong configs), Sigma + pySigma, Velociraptor, osquery, YARA,
Wireshark/tshark, CyberChef, TheHive/Cortex, MISP, Atomic Red Team (lab-only validation).

## 8. Static hosting vs backend

| Capability | Static (Netlify/GH Pages) | Needs Tier B |
|---|---|---|
| All 10 modules rendering curated/simulated data | ✅ | |
| Search, filters, sorting, charts, CSV/JSON export | ✅ (client-side) | |
| Sigma rule viewer, log parsing demo | ✅ (parsing runs in the browser) | |
| KEV / ATT&CK data refreshed daily | ✅ via GitHub Action committing snapshots | |
| On-demand IOC lookup (AbuseIPDB, VT, OTX) | ❌ keys would leak | ✅ Netlify Function |
| NVD queries with API key | ❌ | ✅ Function |
| User accounts, saved case notes | ❌ | ✅ + DB (e.g. Netlify DB/Supabase) — *not planned* |
| Real Wazuh/Elastic integration | ❌ | ❌ — would need a hosted lab VM; shown only as documented lab screenshots |

Netlify static hosting does **not** run a persistent Python/Node process. Netlify Functions are short-lived,
request-scoped serverless executions — suitable for proxying, not for a SIEM.

## 9. Resource-conscious strategy

- No framework, no build step until needed → near-zero toolchain, fast loads (< 100 KB first paint target).
- Datasets loaded lazily per route and cached in memory; one module's data never blocks another.
- Canvas animation: capped node count, pauses when the tab is hidden or off-screen, disabled entirely
  under `prefers-reduced-motion`.
- Charts are in-house SVG (no charting library download); panels recompute only on filter changes.
- Free tiers only: Netlify free plan, GitHub Actions free minutes, free API keys with server-side caching
  so quotas are never hit by visitors.
- Content is written once in JSON and rendered by reusable view components (card, table, dossier),
  so adding the 14th attack is a data change, not a code change.
