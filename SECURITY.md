# Security policy

Sentinel X is a demonstration platform. It has no user accounts and stores no personal data. The only
server-side component is a read-only indicator lookup proxy (`/api/ioc`).

## Reporting a vulnerability

Please report security issues privately through GitHub: **Security → Report a vulnerability** on this
repository (GitHub private vulnerability reporting). Do not open a public issue for a vulnerability.

Include the affected URL or file, steps to reproduce, and the impact you expect. You should receive an
acknowledgement within 7 days.

## In scope

- DOM-based XSS or HTML injection in the site
- Bypasses of the URL sanitiser, Content Security Policy or Trusted Types enforcement
- The `/api/ioc` function: SSRF, key disclosure, sending private or reserved indicators upstream
- Misconfigured security headers on the deployed site

## Out of scope

- Using up the lookup quota by calling `/api/ioc` (documented accepted risk; see `docs/security.md`)
- Findings that require a modified browser or a compromised device
- Automated scanner output without a demonstrated impact
- Content accuracy (please open a normal issue for that)

## Testing rules

Test only against your own local copy (`serve.ps1`) or the public demo at a gentle request rate. Do not
run denial-of-service tests, do not submit real confidential indicators to the lookup tool, and do not
attempt to access the hosting accounts behind the site.

The design and review history are in [docs/security.md](docs/security.md) and
[docs/security-review.md](docs/security-review.md).
