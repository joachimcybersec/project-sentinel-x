# Demo walkthrough

A script for presenting Sentinel X live: a **5-minute** path for a screening call, and a **15-minute** path
for a technical interview. Links go to the live site.

Base URL: <https://joachimcybersec-project.netlify.app>

## Before you present

- Open the site once to warm the CDN, and keep DevTools closed unless you plan to show the security demo.
- Check the CVE snapshot date on `#/vulnerabilities`. The page warns when it is more than 7 days old; the
  daily GitHub workflow normally keeps it fresh.
- Know your one-line framing: *"A security operations platform where one simulated intrusion runs through
  every module, and every piece of data is labelled simulated, documented or lab result."*
- Live IOC lookups say "not configured" until provider keys are added. Say so rather than demoing it as live.

## 5-minute path: follow one alert end to end

| Step | Open | Show | Say |
|---|---|---|---|
| 1 | [Overview](https://joachimcybersec-project.netlify.app/#/) | The provenance legend (Simulated / Documented / Lab result) | "Nothing here pretends to be live. Every number says where it came from." |
| 2 | [SOC dashboard](https://joachimcybersec-project.netlify.app/#/soc) | Click the **Critical** KPI tile, then open an event in the drawer | "Tiles, legends and bars are all filters; the charts are hand-written SVG with data tables behind them." |
| 3 | [IR-2026-004 ransomware](https://joachimcybersec-project.netlify.app/#/incidents/IR-2026-004) | Lifecycle tracker, alert (COR-007), timeline; click **Open in SIEM: host:FS-02** | "The case is tied to raw evidence, not just narrated." |
| 4 | [SIEM, host:FS-02](https://joachimcybersec-project.netlify.app/#/siem?q=host%3AFS-02) | The `vssadmin delete shadows` line; expand it to show the parsed, normalised fields | "These are raw lines in seven formats, parsed and normalised in the browser." |
| 5 | [Shadow-copy deletion rule](https://joachimcybersec-project.netlify.app/#/detections/shadow-copy-deletion) | The Sigma YAML and the logs it matches | "The rule actually runs against the same logs. Tests require each rule to match exactly its expected lines, and `sigma check` runs in CI." |

Close with: *"127 tests pass in Chromium, Firefox and WebKit on every push, and the docs list what hasn't been
verified yet."*

## 15-minute path: the 5-minute path, plus

| Step | Open | Show | Say |
|---|---|---|---|
| 6 | [Network](https://joachimcybersec-project.netlify.app/#/network) | Switch between **As-was**, **Segmented** and **Zero Trust**; watch *attack steps blocked* versus *legitimate flows working* | "A control only counts if business traffic still works, so the simulator scores both." |
| 7 | [Network](https://joachimcybersec-project.netlify.app/#/network) → **Packet explorer** tab | Choose **DNS TXT query: tunnelling pattern**; point at *checksum valid ✓*, then click a header field to highlight its bytes | "Real bytes with computed and verified checksums, not a picture of Wireshark." |
| 8 | [SIEM correlation rules](https://joachimcybersec-project.netlify.app/#/siem) | Correlation rules tab; change a threshold and watch the matches update | "Tuning trades noise against missed detections, and you can see that trade here." |
| 9 | [Volt Typhoon profile](https://joachimcybersec-project.netlify.app/#/threat-intel/volt-typhoon) | Numbered citations with dates; the *Analysis* box kept separate from sourced facts | "Fact and interpretation are kept apart, and a scheduled job re-checks the sources." |
| 10 | [Vulnerabilities](https://joachimcybersec-project.netlify.app/#/vulnerabilities) | KEV, NVD and EPSS freshness; a CVE page with the CVSS breakdown | "Priority is explained, not a black box, and it's labelled a teaching model." |
| 11 | DevTools console on any page | Run `document.body.innerHTML = 'x'` and show the TypeError | "Trusted Types: the browser itself refuses HTML injection sinks. That's enforced by the CSP, not by convention." |
| 12 | [About](https://joachimcybersec-project.netlify.app/#/about) and the GitHub repo | Design decisions; the Actions tab with green runs; `docs/testing.md` | "Every test claim links to a record of what was run, including what failed first." |

If you're short of time, pick steps 6, 11 and 12. They show the deepest engineering in the least time.

Every step above was checked against the live site on 2026-11-22. For example, the as-was policy blocks
0 of 6 attack steps, while the segmented and Zero Trust policies each block 5 of 6 with all 6 legitimate flows
still working. The remaining step is worth discussing: ask which control would close it.

## Questions to expect, with honest answers

- **Is it connected to a real SIEM or EDR?** No. It demonstrates SIEM concepts (parsing, normalisation,
  querying, correlation) in the browser over simulated logs. The tools page maps real products to each stage
  and marks them as not integrated.
- **What's real and what's simulated?** Telemetry, logs and incidents are simulated. Threat profiles, attack
  dossiers and CVE data are documented from cited public sources with dates. No *Lab result* data has been
  published yet.
- **Why no framework?** Zero runtime dependencies and a codebase small enough to review line by line. The
  cost is hand-written plumbing: a navigation race in the router was found by CI on WebKit and fixed
  (see [case-study.md](case-study.md)).
- **How do you know the detection rules work?** Each rule is evaluated by the in-browser Sigma evaluator, and
  tests require it to match exactly its expected log lines. pySigma's `sigma check` validates the syntax in CI.
  They have not been tested against real enterprise telemetry, which is why they're marked `experimental`.
- **How are the API keys protected?** They live only in Netlify environment variables. The browser calls
  `/api/ioc`, a serverless function that validates input, never forwards private or documentation-range
  addresses, and talks only to allow-listed provider hosts.
- **What would you do next?** Capture lab telemetry from an isolated, authorised test VM and publish it as
  *Lab result* data; export the rules to a SIEM back end with pySigma; complete a screen-reader pass.
