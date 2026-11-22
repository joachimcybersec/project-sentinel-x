/**
 * About This Project — engineering decisions, provenance policy, roadmap.
 * Content is factual about what exists today; nothing is claimed that is not built.
 */
import { el, provenanceBadge, PROVENANCE_HELP } from '../utils/dom.js';

const DECISIONS = [
  ['Static-first, two-tier architecture', 'The full site runs from a CDN with curated JSON. Live indicator lookups go through one serverless function, so API keys never reach the browser, and the site still works when that function is absent.'],
  ['Vanilla ES modules, no framework', 'Keeps the payload small, needs no build step, and keeps the source readable for reviewers. Each module\'s code loads on first visit, so the landing page fetches about a third of the bytes. A minifier can be added without changing code structure.'],
  ['Security reviewed and enforced by the browser', 'Phase 10 added Trusted Types to the Content Security Policy, so the browser itself refuses HTML injection sinks such as innerHTML. A review also found and fixed a link-sanitiser bypass (backslash URLs), with regression tests.'],
  ['Hash-based routing', 'Works on GitHub Pages and Netlify without rewrite rules, and makes every module deep-linkable.'],
  ['Safe DOM by construction', 'All rendering goes through one helper that uses textContent and an attribute allow-list. innerHTML is not used with data, and the Content Security Policy forbids inline script.'],
  ['Validated datasets', 'Each JSON dataset is schema-checked before a view renders it; invalid data produces a visible error instead of a broken page.'],
  ['Every documented fact is cited and checked', 'Threat profiles and attack dossiers attach a numbered source (publisher, date, link) to each fact and keep analysis visually separate. Two scripts check that every link resolves and that each source still contains the phrases a fact relies on. Advisories change; the 2025 update to AA23-320A is an example.'],
  ['No real IOCs typed from memory', 'Indicator values are easy to get wrong and dangerous to publish wrongly. The watchlist uses simulated documentation-range indicators; real ones are linked in the official advisories.'],
  ['One simulated intrusion across modules', 'SOC events, raw logs and incident case studies describe the same fictitious attack, so a reviewer can follow an alert from the dashboard to raw evidence in the SIEM and to the case write-up. Tests check that every cross-reference resolves.'],
  ['SIEM concepts in the browser, not a fake integration', 'Parsing, normalisation, enrichment and correlation run as small pure functions over simulated logs. Real tools (Wazuh, Elastic, Zeek, Suricata) are mapped to each stage and labelled "not integrated".'],
  ['Detections are tested, not just displayed', 'Sigma rules run through a small in-browser evaluator against the sample logs, and the test suite fails if any rule misses an expected event or matches an unexpected one. Rules stay "experimental" because they have not been validated with pySigma or production data.'],
  ['Real vulnerability data, generated not typed', 'The CVE module reads a snapshot produced by a script from CISA KEV, the NVD API and FIRST EPSS, with each source\'s fetch time shown. No CVE detail is entered by hand, and the page warns when the snapshot is stale.'],
  ['In-house SVG charts instead of Chart.js', 'The dashboard needs four chart types. Building them as small SVG components keeps third-party code at zero, keeps the strict CSP, and gives every chart a keyboard-reachable data table.'],
  ['Motion with restraint', 'The topology animation pauses off-screen and in background tabs, and is replaced by a static frame when the visitor prefers reduced motion.']
];

const PHASES = [
  ['1', 'Architecture, app shell, router, data service, landing page', 'Complete'],
  ['2', 'UI component kit (tables, filters, drawers, tabs, toasts, export)', 'Complete'],
  ['3', 'Module 01 — SOC dashboard with charts and filters', 'Complete'],
  ['4', 'Modules 02–03 — Threat intelligence and attack library', 'Complete'],
  ['5', 'Modules 04–05 — Incident response and SIEM log analysis', 'Complete'],
  ['6', 'Module 06 — Detection engineering (Sigma)', 'Complete'],
  ['7', 'Modules 07–08 — CVE intelligence and network security', 'Complete'],
  ['8', 'Modules 09–10 — Tools directory, knowledge centre and site-wide search', 'Complete'],
  ['9', 'Serverless IOC proxy and GitHub Actions automation', 'Complete (not yet deployed)'],
  ['10', 'Security review and QA (Trusted Types, accessibility audit, click-through crawl)', 'Complete'],
  ['11', 'Documentation and deployment (GitHub, Netlify, CI)', 'In progress'],
  ['12', 'Portfolio presentation', 'Planned']
];

export function renderAbout(view) {
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'About this project'),
      el('h1', null, 'Engineering Sentinel X'),
      el('p', { class: 'lede' }, 'Sentinel X is a portfolio project that demonstrates security operations, threat intelligence, incident response and detection engineering concepts through a working web platform. It is a demonstration, not a production SOC: it does not ingest live telemetry from any organisation.')
    ),
    el('section', { class: 'card', 'aria-labelledby': 'dec-h' },
      el('h2', { id: 'dec-h' }, 'Key engineering decisions'),
      el('dl', { class: 'dl' }, ...DECISIONS.flatMap(([k, v]) => [el('dt', null, k), el('dd', null, v)]))
    ),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'prov-h2' },
        el('h2', { id: 'prov-h2' }, 'Provenance labels'),
        el('dl', { class: 'dl' },
          ...['simulated', 'documented', 'lab'].flatMap((k) => [el('dt', null, provenanceBadge(k)), el('dd', null, PROVENANCE_HELP[k])])
        ),
        el('p', { class: 'kpi-sub' }, 'Sample data uses RFC 5737 documentation IP ranges and reserved .example/.test domains, so no real organisation or address is implicated.')
      ),
      el('section', { class: 'card', 'aria-labelledby': 'road-h' },
        el('h2', { id: 'road-h' }, 'Development roadmap'),
        el('dl', { class: 'dl' },
          ...PHASES.flatMap(([n, what, state]) => [
            el('dt', null, `Phase ${n}`),
            el('dd', null, what, ' — ', el('strong', null, state))
          ])
        )
      )
    )
  );
}
