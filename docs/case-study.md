# Case study: Project Sentinel X

**A security operations demonstration platform, built and verified like production software.**
Live: <https://joachimcybersec-project.netlify.app> · Source: <https://github.com/joachimcybersec/project-sentinel-x>

Every figure below comes from the repository or its test records ([testing.md](testing.md)). Nothing here
describes a real organisation, a real incident or a live integration.

## The problem

Security portfolios tend to fall into two traps: static pages describing tools the author has not built, or
dashboards full of numbers presented as if they were live. Neither shows how an analyst actually works, and
the second is quietly misleading.

The goal was a platform that **does the work instead of describing it**: parsing logs, evaluating detection
rules, scoring vulnerabilities and modelling network policy, all in code that can be read and tested. It also
had to **stay honest about what is simulated**.

## Approach

**One storyline across ten modules.** A single simulated intrusion runs through the whole platform:
failed external logons and password spraying → a phishing document launching PowerShell → lateral RDP
to a file server → DNS-based C2 → ransomware → exfiltration, over about two and a half hours.
The same hosts, users and timestamps appear in the SOC dashboard (30 events), the SIEM (52 raw log lines in 7
formats), the six incident case studies, the 16 Sigma rules and the network simulator. Tests check that every
cross-reference resolves, so a reviewer can follow one alert from the dashboard to the raw evidence, the rule
that fired, the case write-up and the control that would have stopped it.

**Three provenance labels, everywhere.** Each dataset, card and chart is marked *Simulated*, *Documented*
(a cited public source with a date) or *Lab result*. Threat-intelligence facts carry numbered citations,
and analysis is labelled separately from sourced fact. Link and claim checkers re-verify that each source
still says what the platform says it does.

**Static first, server only where it earns its place.** The site is plain HTML, CSS and ES modules, with no
framework, no build step and no runtime dependencies. The only server code is one Netlify Function (`/api/ioc`).
It exists because AbuseIPDB, VirusTotal and OTX keys must never reach the browser.

## What was built

| Component | What it does |
|---|---|
| Sigma evaluator (`js/detection/`) | Parses YAML and evaluates the supported subset of the Sigma specification; each of the 16 rules must match exactly its expected log lines |
| SIEM pipeline (`js/siem/`) | Parsers for 7 log formats, ECS-style normalisation, a query language with deep links, enrichment, 8 tunable correlation rules |
| Packet builder (`js/network/packets.js`) | Builds real Ethernet/IPv4/TCP/UDP/DNS bytes with verified checksums |
| Policy simulator (`js/network/policy.js`) | Evaluates as-was, segmented and Zero Trust policies against the attack paths and the legitimate flows |
| CVE pipeline (`tools/update-cve-snapshot.ps1`) | Joins CISA KEV, NVD CVE API 2.0 and FIRST EPSS into a dated snapshot; refreshed daily by GitHub Actions |
| IOC proxy (`netlify/lib/ioc-core.mjs`) | Validates and classifies indicators, never sends private or documentation addresses upstream, allow-lists provider hosts, caps response size, normalises output |
| Test harness (`tests/`) | 127 in-browser tests, a Playwright driver and a DOM-based accessibility audit run on every route and tab |

About 10,000 lines of JavaScript, CSS, PowerShell and tests.

## Security engineering

- **CSP with Trusted Types** (`require-trusted-types-for 'script'; trusted-types 'none'`): the browser itself
  refuses `innerHTML` and similar sinks. All rendering goes through one safe-DOM helper with an attribute
  allow-list.
- **A sanitiser bypass, found and fixed.** The Phase 10 review found that `safeUrl` passed
  `/\evil.example/x` and a TAB variant unchanged; browsers resolve both off-site. The rewrite resolves every
  URL against a sentinel origin, and regression tests cover the cases
  ([security-review.md](security-review.md), SR-01).
- **Proxy hardening**: input classification before any network call, RFC 5737/1918 and other special-purpose
  ranges kept local, no CORS header, a 2 MB cap on upstream responses, `no-store` on errors, and keys and
  indicator values kept out of logs. All of this is covered by tests.
- **Deployment controls in version control**: security headers, 404 rules for internal folders, and GitHub
  Actions pinned to commit SHAs.

## Verification, and what it caught

The rule was that nothing counts as done until it has been run. Several real defects only surfaced because
the checks were actually executed:

| Found by | Defect | Fix |
|---|---|---|
| Security review | Link sanitiser bypass (backslash and TAB URLs) | URL resolution against a sentinel origin; regression tests |
| CI on WebKit | Navigation race: a slow lazy-loaded view finished after a newer navigation, so the page showed two views (two h1s, duplicate IDs) | Router serialises navigations (`latestOnly`), with a unit test |
| Running the CI driver locally | Playwright's `waitForFunction` evaluates strings in the page, which the strict CSP correctly blocks | Driver polls with `page.evaluate`; the CSP stays on during tests |
| Accessibility audit | Touch targets at exactly 24 px measured 23.x px mid-layout and failed intermittently | 28 px minimum, giving headroom |
| Live-site checks | Development files (`package.json`, `serve.*`) were publicly served | 404 rules in `netlify.toml` |
| W3C validator | Invalid attributes on the clock's `<time>` element | Valid `datetime`, visually hidden label |

End state: **127/127 tests and 21/21 routes pass in Chromium, Firefox and WebKit** on GitHub Actions.
The accessibility audit reports zero findings on every tab panel, and the live site's headers and API
behaviour match the documentation.

## Trade-offs

- **No framework.** More hand-written plumbing (router, tabs, tables), in exchange for zero runtime
  dependencies and a codebase that can be reviewed line by line. The cost showed up as the navigation race
  above, which a framework router would have handled; it was found by tests and fixed.
- **Simulated data.** Synthetic telemetry allows a coherent storyline and safe sharing, but it proves the
  logic, not field performance. The *Lab result* label is reserved for data captured in an isolated,
  authorised lab, and none has been published yet.
- **A Sigma subset.** Implementing the full specification (aggregations, all modifiers) was out of scope.
  The subset is documented, and pySigma's `sigma check` runs in CI as an independent check.

## Limitations and next steps

Live IOC lookups need provider keys, so they have not yet returned real data. A screen-reader pass and
Lighthouse scores are still to do. The next step that would add the most credibility is lab results: running
the Sigma rules against Sysmon telemetry from an isolated test VM and publishing those events as *Lab
result* data. See the README's limitations and future improvements.
