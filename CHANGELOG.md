# Changelog

Versions follow the build phases. Dates are UTC.

## 0.11.0 — 2026-11-22 · Phase 11: documentation and deployment
- Deployed to Netlify (<https://joachimcybersec-project.netlify.app>) from GitHub; CI green on Chromium,
  Firefox and WebKit
- Router serialises navigations, so a slow lazy view can no longer render on top of a newer one (found by
  CI on WebKit)
- CI fixes: `serve.json` serves `index.html` instead of directory listings; the test driver polls with
  `page.evaluate` (the CSP blocks `waitForFunction`)
- 28 px minimum height on sort buttons, technique links and tool links (24 px measured 23.x intermittently)
- 404 for `package.json`, `serve.json`, `serve.ps1` on the live site; W3C validator fixes in `index.html`
- `tools/predeploy-check.ps1`: JSON validity, no BOMs, secret patterns, module imports, HTML asset paths,
  CSP essentials, function entry point, file sizes. Runs locally and as a CI job
- GitHub Actions pinned to commit SHAs (checkout v7.0.1, setup-node v7.1.0, setup-python v7.1.0); CI on
  Node 22 LTS and Ubuntu 24.04
- `SECURITY.md` (private vulnerability reporting), this changelog, expanded `.gitignore`
- Deployment guide rewritten for a first-time setup (Git or Netlify CLI)

## 0.10.0 — 2026-11-22 · Phase 10: security review and QA
- Fixed a `safeUrl` bypass (backslash and TAB URLs resolved off-site)
- Trusted Types enforced in every CSP; `Cross-Origin-Resource-Policy` header
- IOC proxy: 2 MB upstream body cap, more special-purpose IPv4 ranges kept local, lookup race fixed
- Accessibility audit (`tests/a11y-audit.js`) added to CI; table captions, heading order, 24 px targets,
  code-comment contrast fixed
- Mobile layout fixes (definition lists, wide tables); module views load on demand (landing page 449 KB → 139 KB)

## 0.9.0 — 2026-11-22 · Phase 9: backend and automation
- `/api/ioc` Netlify Function (AbuseIPDB, VirusTotal, OTX) and the Live lookup tab
- CI (Chromium, Firefox, WebKit, `sigma check`), daily CVE snapshot refresh, weekly source checks
- Sigma rules exported to `rules/`

## 0.8.0 · Phase 8: Tools Directory, Knowledge Centre, site-wide search
## 0.7.0 · Phase 7: Vulnerability & CVE Intelligence, Network Security
## 0.6.0 · Phase 6: Detection Engineering (Sigma)
## 0.5.0 · Phase 5: Incident Response, SIEM & Log Analysis
## 0.4.0 · Phase 4: Threat Intelligence Centre, Attack Library
## 0.3.0 · Phase 3: SOC dashboard
## 0.2.0 · Phase 2: UI component kit
## 0.1.0 · Phase 1: architecture, app shell, router, data service
