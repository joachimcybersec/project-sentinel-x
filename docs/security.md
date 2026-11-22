# Security — Sentinel X

Phase 10 review findings, severities and fixes: [security-review.md](security-review.md).

## Threat model (Phase 1)

A static site with no user accounts, no forms and no third-party scripts. Main risks: DOM XSS via
dataset content or URL hash, clickjacking, dependency compromise, and (later) API key exposure.

## Controls implemented

| Control | Where |
|---|---|
| Content Security Policy: `script-src 'self'`, no inline script, no `unsafe-eval`, `object-src 'none'`, `frame-ancestors 'none'` | `netlify.toml`, `<meta>` fallback in `index.html`, `serve.ps1` |
| Safe DOM: all rendering through `el()` using text nodes; attribute allow-list; `on*` attributes throw; URL scheme allow-list (`http`, `https`, `mailto`, relative) | `js/utils/dom.js` (unit-tested) |
| Route params restricted to `[\w.-]{1,80}`; malformed URI escapes rejected | `js/router.js` (unit-tested) |
| Dataset schema validation before rendering | `js/data-service.js` (unit-tested) |
| Same-origin data only (`connect-src 'self'`), fetch timeout, typed errors, visible error state | `js/data-service.js`, `js/app.js` |
| HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP | `netlify.toml` |
| `target=_blank` links forced to `rel="noopener noreferrer"` | `js/utils/dom.js` |
| CSV export neutralises formula injection (`=`, `+`, `-`, `@`, TAB, CR prefixed with `'`); export filenames restricted to `[\w.-]` | `js/components/export.js` (unit-tested) |
| Code viewer tokenises into text nodes, so rule/log content cannot inject markup | `js/components/code-block.js` (unit-tested) |
| Search input length-capped (200 chars) and treated as plain substring, not regex | `js/components/filter-bar.js` |
| Network indicators are always displayed and exported defanged (`hxxp`, `[.]`); no real IOCs are published | `js/views/threat-intel.js`, `defang()` |
| Every external source link must be https (validator) and opens with `rel="noopener noreferrer"` | `js/data-service.js`, `js/utils/dom.js` |
| Markdown exports escape Markdown/HTML metacharacters in content | `js/components/intel-ui.js` (unit-tested) |
| Log parser: input capped at 4,000 chars, anchored regexes only, JSON.parse in try/catch, output rendered as text | `js/siem/parsers.js` (unit-tested with junk and oversize input) |
| Query language: user wildcards are escaped before building a RegExp (no user-controlled regex, no ReDoS); query capped at 300 chars | `js/siem/query.js` (unit-tested) |
| Deep-link query (`#/siem?q=`) is length-capped and only ever used as search text | `js/views/siem.js` |
| Correlation parameters accept positive integers only | `js/views/siem.js` |
| Dev server survives client disconnects (response close guarded) | `serve.ps1` |
| YAML parser: 20,000-char cap, no anchors/aliases/tags (no alias expansion attacks), rejects `__proto__`/`constructor` keys (no prototype pollution) | `js/detection/yaml.js` (unit-tested) |
| Sigma `re` modifier: patterns capped at 200 chars and compiled in try/catch; evaluation stays in the viewer's own browser | `js/detection/sigma.js` |
| CVE snapshot script: optional `NVD_API_KEY` read from the environment, sent only as a request header and never written to output; public rate limit respected (6.5 s between NVD calls) | `tools/update-cve-snapshot.ps1` |
| Third-party reference URLs from NVD are rendered through the safe-URL helper and labelled as unchecked | `js/views/vulnerabilities.js` |
| Site search: query capped at 120 chars, plain substring matching (no user regex), results rendered as text | `js/search/search.js` (unit-tested) |
| Pathway progress uses localStorage only for a per-viewer convenience, wrapped in try/catch; no personal data | `js/views/knowledge.js` |
| Pathway "practice" links must be in-app routes (validator rejects external URLs) | `js/data-service.js` (unit-tested) |
| Trusted Types enforced by CSP (`require-trusted-types-for 'script'; trusted-types 'none'`): the browser blocks `innerHTML` and other HTML/script sinks outright (Chromium-based browsers) | all CSP sources (Phase 10) |
| `safeUrl` resolves relative URLs against a placeholder origin and rejects any that leave it; control characters rejected (fixes backslash/TAB bypass SR-01) | `js/utils/dom.js` (unit-tested) |
| `Cross-Origin-Resource-Policy: same-origin` | `netlify.toml` |
| Module views load on demand (`import()` with static specifiers, same origin) | `js/app.js` |
| Zero runtime dependencies | — |
| Sample data uses RFC 5737 IPs and reserved TLDs; indicators displayed defanged | `data/`, `defang()` |
| Dev server bound to `localhost` only, GET/HEAD only, root-prefix path guard | `serve.ps1` |

## Tier B: IOC lookup function (Phase 9)

Implemented in `netlify/lib/ioc-core.mjs` (wrapper `netlify/functions/ioc.mjs`) and unit-tested with
mocked upstreams (`tests/backend.test.js`). Not yet deployed.

| Control | Detail |
|---|---|
| Secrets | Provider keys only in Netlify environment variables; never in the repo, the response or logs (test asserts this) |
| Input validation | Shared classifier (`js/shared/indicators.js`): IPv4, domain (RFC 1123 labels), MD5/SHA-1/SHA-256; 253-char cap; refangs `[.]`/`hxxp` |
| No internal leakage | Private, loopback, link-local, CGNAT, multicast, RFC 5737 documentation addresses and reserved TLDs are never sent upstream (checked client- and server-side) |
| SSRF resistance | Fixed upstream URL templates and a host allow-list; the indicator is URL-encoded into a fixed path; `redirect: 'error'` |
| Data minimisation | Only a small normalised summary is returned; raw upstream bodies are not proxied |
| Abuse and quota protection | GET only (405 otherwise); successful results CDN-cached for 1 h; errors not cached; 8 s upstream timeout; upstream bodies over 2 MB rejected unparsed |
| Client robustness | Only the latest lookup may render; responses are shape-checked before display |
| Cross-origin | No CORS headers, so other sites cannot call the API from a browser |
| Logging | One line per request: indicator type and provider statuses only, never the value or keys |

Residual risk: the endpoint is public, so anyone can spend the site's provider quota by calling it
directly. CDN caching limits repeat cost. If abuse occurs, add Netlify rate limiting rules or require a
lightweight token. Per-instance in-memory rate limiting is not reliable in serverless environments, so it
was not implemented.

## Automation (Phase 9)

- `refresh-cve-snapshot.yml` has `contents: write` only; other workflows are read-only.
- Third-party actions are limited to GitHub's own (`actions/checkout`, `setup-node`, `setup-python`).
- Exported Sigma rules are validated with the official `sigma check` in CI.
- CI tool versions are pinned (`serve@14.2.4`, `playwright@1.49.1`).

## Other notes

- Charts are built in-house (Phase 3), so no third-party charting script is loaded.
- Programmatic filter updates (`filterBar.update`) accept only known option values, so chart clicks cannot inject arbitrary filter state.
- Planned: Dependabot + `npm audit` in CI once `package.json` gains runtime dependencies.

## Ethics

All attack content is educational and defensive. No exploit code, malware or live offensive tooling is
hosted. Lab demonstrations are performed only in isolated environments the author owns.
