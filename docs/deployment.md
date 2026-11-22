# Deployment — Sentinel X

| Tier | What | Where | Required? |
|---|---|---|---|
| A — static site | `index.html`, `css/`, `js/`, `data/`, `assets/` | Netlify CDN (or GitHub Pages) | Yes |
| B — serverless | `netlify/functions/ioc.mjs` → `GET /api/ioc` (live IOC lookups) | Netlify Functions | Optional |
| Automation | `.github/workflows/*.yml` (CI, daily CVE refresh, weekly source checks) | GitHub Actions | Recommended |

No build step: the repository root is the publish directory. Netlify bundles the function with esbuild.

There are two routes. **Route 1 (GitHub + Netlify)** is recommended: every push runs CI and redeploys, and the
daily CVE refresh keeps data current. **Route 2 (Netlify CLI only)** deploys from this folder without GitHub.

Live deployment results are recorded in `docs/testing.md` (Phase 11).

## 0. Before every deploy

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\predeploy-check.ps1
```

Then open <http://localhost:8080/tests/> with `serve.ps1` running and confirm `N/N passed`.

## 1. One-time tools (Windows)

```powershell
winget install --id Git.Git -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id GitHub.cli -e
```

Open a new terminal afterwards so the tools are on `PATH`. Then set your Git identity (the name and email
recorded in commits; use a GitHub `noreply` address if you don't want your email public):

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@users.noreply.github.com"
```

## Route 1 — GitHub + Netlify

### 1a. Push to GitHub

```powershell
gh auth login                 # sign in through the browser; you approve this yourself
cd project-sentinel-x
git init -b main
git add .
git commit -m "Sentinel X 0.11.0: phases 1-11"
gh repo create project-sentinel-x --public --source . --push
```

`gh repo create` makes the repository and pushes in one step. Use `--private` if you prefer; GitHub Actions
minutes are free for public repositories and limited for private ones.

### 1b. Repository settings (github.com → the repo → Settings)

| Setting | Value | Why |
|---|---|---|
| Actions → General → Workflow permissions | **Read and write** | the daily CVE workflow commits the refreshed snapshot |
| Secrets and variables → Actions → `NVD_API_KEY` | optional | higher NVD rate limit ([request a key](https://nvd.nist.gov/developers/request-an-api-key)) |
| Code security → Private vulnerability reporting | **Enable** | `SECURITY.md` points reporters there |
| Branches → protect `main` → require the CI checks | recommended | blocks merges that fail tests |

Check the first CI run under the **Actions** tab. Then start the other two workflows manually once
(**Run workflow**) to confirm they work.

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to main, pull requests | Pre-deploy checks; test suite, route smoke tests and accessibility audit in Chromium, Firefox and WebKit; `sigma check` |
| `refresh-cve-snapshot.yml` | daily 06:17 UTC, manual | Rebuilds `data/cve-snapshot.json` from CISA KEV, NVD and EPSS and commits it if it changed |
| `source-checks.yml` | Mondays 07:41 UTC, manual | Re-checks every source link and quoted claim |

### 1c. Connect Netlify

1. app.netlify.com → **Add new project → Import an existing project → GitHub** → choose the repository.
2. Leave the build command empty; publish directory `.`; functions directory `netlify/functions`
   (already set in `netlify.toml`).
3. Deploy. The site is at `https://<name>.netlify.app` (rename it under Project configuration).

Each push to `main` redeploys, including the daily snapshot commits.

## Route 2 — Netlify CLI only (no GitHub)

```powershell
cd project-sentinel-x
npx --yes netlify-cli@latest login        # browser sign-in; you approve it
npx --yes netlify-cli@latest init --manual # or: sites:create
npx --yes netlify-cli@latest deploy                # draft URL to check first
npx --yes netlify-cli@latest deploy --prod         # publish
```

This deploys the site and the function, but there is no CI and the CVE snapshot is not refreshed
automatically. Run `tools\update-cve-snapshot.ps1` and redeploy when you need fresh data.

## 2. Enable live IOC lookups (optional)

Project configuration → **Environment variables** (scope: Functions). Each key is optional; providers
without a key show as "not configured". Redeploy after adding keys.

| Variable | Provider |
|---|---|
| `ABUSEIPDB_API_KEY` | AbuseIPDB (IP reputation) |
| `VIRUSTOTAL_API_KEY` | VirusTotal (IP, domain, file hash) |
| `OTX_API_KEY` | AlienVault OTX (pulses) |

Read each provider's terms first: free tiers are usually for non-commercial use with low request rates.
Successful results are cached at the CDN for one hour and errors are not cached. The function is a
short-lived, per-request execution; Netlify does not run a persistent server, and Sentinel X does not need one.

## 3. Verify the live site

```powershell
$site = "https://<name>.netlify.app"
curl.exe -sI "$site/"                                   # expect 200 + content-security-policy (with trusted-types), strict-transport-security, x-frame-options, cross-origin-resource-policy
curl.exe -s -o NUL -w "%{http_code}`n" "$site/tests/"   # expect 404 (same for /netlify/, /tools/, /.github/)
curl.exe -s "$site/api/ioc?value=203.0.113.45"          # documentation range → "lookup":false, nothing sent upstream
curl.exe -s "$site/api/ioc?value=10.0.0.1"              # private → "lookup":false
curl.exe -s -o NUL -w "%{http_code}`n" -X POST "$site/api/ioc"   # expect 405
curl.exe -s "$site/api/ioc?value=8.8.8.8"               # with keys set: provider results; without: "not-configured"
```

On the free Netlify plan, Netlify injects `/.netlify/scripts/hud?variant=public` (the "Powered by Netlify"
badge) into every page, and the project setting does not remove it. The script builds an iframe via `srcdoc`, which
the Trusted Types policy blocks, so the badge does not render and one console error appears. This is expected and
not an application error; do not weaken the CSP to allow it.

Then in a browser:
- Open the site, visit each module, and check the console stays free of errors.
- Threat Intelligence → **Live lookup** → try `8.8.8.8`.
- Run Lighthouse (Chrome DevTools) on `/`, `#/soc` and `#/vulnerabilities`, and the W3C validator
  (<https://validator.w3.org/nu/>) on the site URL.

## 4. GitHub Pages (static only, not recommended)

Settings → Pages → Deploy from branch → `main` / root. There are no custom headers (only the `<meta>` CSP
applies: no HSTS, `frame-ancestors` or CORP), no `/api/ioc` (the Live lookup tab says it is unavailable), and
`tests/`, `tools/` and `netlify/` are publicly readable.

## 5. Custom domain

Netlify → Domain management → Add a domain → follow the DNS instructions. Netlify provisions a Let's Encrypt
certificate automatically; turn on **Force HTTPS**.

## 6. Local development

```powershell
powershell -ExecutionPolicy Bypass -File .\serve.ps1     # static site on http://localhost:8080
npx --yes netlify-cli@latest dev                         # site + functions on http://localhost:8888 (Node required)
```

Run the same headless checks CI runs (Node required):

```powershell
npm install --no-save playwright@1.49.1
npx playwright install chromium
node tests/run-in-browser.mjs http://localhost:8080 chromium
```

## 7. Rollback

Netlify keeps every deploy: **Deploys → pick an earlier deploy → Publish deploy**. With Git, use
`git revert <commit>` and push.
