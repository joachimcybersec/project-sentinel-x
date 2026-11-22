/**
 * Landing / overview view.
 * - Animated topology hero
 * - KPI tiles computed from the SIMULATED sample-events dataset
 * - Event replay feed (pause/resume) — replays the dataset, not live data
 * - Module launcher grid driven by data/modules.json
 */
import { el, formatNumber, formatUtcTime, severityBadge, provenanceBadge, PROVENANCE_HELP } from '../utils/dom.js';
import { load, severityCounts } from '../data-service.js';
import { mountTopology } from '../effects/topology.js';

const REPLAY_INTERVAL_MS = 2400;
const FEED_LENGTH = 8;

export async function renderHome(view, { reducedMotion }) {
  const [{ data: modulesData }, { data: eventsData }] = await Promise.all([load('modules'), load('events')]);
  const events = [...eventsData.events].sort((a, b) => a.ts.localeCompare(b.ts));
  const counts = severityCounts(events);
  const active = events.filter((e) => e.status === 'open' || e.status === 'investigating').length;

  /* ---------------- Hero ---------------- */
  const canvas = el('canvas', { 'aria-hidden': 'true' });
  const modulesSection = el('section', { id: 'modules', 'aria-labelledby': 'modules-h', tabindex: '-1' });
  const exploreBtn = el('button', { class: 'btn btn-primary', type: 'button' }, 'Explore the modules');
  exploreBtn.addEventListener('click', () => {
    modulesSection.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
    modulesSection.focus({ preventScroll: true });
  });

  const hero = el('section', { class: 'hero', 'aria-labelledby': 'hero-h' },
    canvas,
    reducedMotion ? null : el('div', { class: 'hero-scan', 'aria-hidden': 'true' }),
    el('div', { class: 'hero-content' },
      el('span', { class: 'eyebrow' }, "Joachim's Sentinel X"),
      el('h1', { id: 'hero-h' }, 'Cybersecurity Intelligence & ', el('span', { class: 'accent' }, 'Security Operations'), ' Platform'),
      el('p', { class: 'tagline' }, 'Detect. Investigate. Understand. Defend.'),
      el('p', null, 'A demonstration platform showing how SOC analysts monitor telemetry, investigate incidents, engineer detections and act on threat intelligence — with every dataset clearly labelled as simulated, documented or lab-produced.'),
      el('div', { class: 'hero-actions' },
        exploreBtn,
        el('a', { class: 'btn', href: '#/about' }, 'How it was built')
      )
    )
  );

  /* ---------------- KPI tiles ---------------- */
  const total = events.length;
  const kpi = (label, value, sub, sevClass, ratio) =>
    el('div', { class: `card kpi ${sevClass || ''}` },
      el('div', { class: 'kpi-label' }, label),
      el('div', { class: 'kpi-value' }, formatNumber(value)),
      el('div', { class: 'kpi-sub' }, sub),
      el('div', { class: 'kpi-bar', 'aria-hidden': 'true' }, barFill(ratio))
    );

  const kpis = el('section', { 'aria-labelledby': 'kpi-h', class: 'stack' },
    el('div', { class: 'meta-row' },
      el('h2', { id: 'kpi-h' }, 'Telemetry snapshot'),
      provenanceBadge('simulated'),
      el('span', { class: 'kpi-sub' }, `${total} events · dataset generated ${eventsData.generated}`)
    ),
    el('div', { class: 'grid grid-4' },
      kpi('Total events', total, 'In demo dataset', 'status-live', 1),
      kpi('Critical', counts.critical, 'Immediate response', 'sev-critical', counts.critical / total),
      kpi('High', counts.high, 'Triage within 1h (demo SLA)', 'sev-high', counts.high / total),
      kpi('Active', active, 'Open or investigating', 'sev-medium', active / total)
    )
  );

  /* ---------------- Event replay feed ---------------- */
  const feed = el('ul', { class: 'feed', 'aria-label': 'Simulated event replay' });
  const pauseBtn = el('button', { class: 'btn', type: 'button', 'aria-pressed': 'false' }, 'Pause replay');
  let cursor = 0;
  let paused = reducedMotion; // no auto-advancing content under reduced motion
  let timer = 0;

  const pushEvent = (e, animate) => {
    const li = el('li', { class: animate ? 'is-new' : null },
      el('time', { datetime: e.ts }, formatUtcTime(e.ts)),
      severityBadge(e.severity),
      el('span', { class: 'feed-msg' }, `${e.host} · ${e.source} — ${e.message}`)
    );
    feed.prepend(li);
    while (feed.children.length > FEED_LENGTH) feed.lastElementChild.remove();
  };
  // Seed with the first N events so the feed is never empty.
  for (; cursor < Math.min(FEED_LENGTH, events.length); cursor++) pushEvent(events[cursor], false);

  const tick = () => {
    pushEvent(events[cursor % events.length], true);
    cursor += 1;
  };
  const startReplay = () => { stopReplay(); timer = window.setInterval(tick, REPLAY_INTERVAL_MS); };
  const stopReplay = () => window.clearInterval(timer);
  const syncPauseBtn = () => {
    pauseBtn.textContent = paused ? 'Resume replay' : 'Pause replay';
    pauseBtn.setAttribute('aria-pressed', String(paused));
  };
  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    paused ? stopReplay() : startReplay();
    syncPauseBtn();
  });
  syncPauseBtn();
  if (!paused) startReplay();

  const feedCard = el('section', { class: 'card', 'aria-labelledby': 'feed-h' },
    el('div', { class: 'card-title' },
      el('h2', { id: 'feed-h' }, 'Event replay'),
      provenanceBadge('simulated')
    ),
    el('p', { class: 'kpi-sub' }, 'Replays the synthetic dataset in a loop to illustrate a SOC event stream. This is not live telemetry.'),
    feed,
    el('div', { class: 'hero-actions' }, pauseBtn)
  );

  /* ---------------- Provenance legend ---------------- */
  const legend = el('section', { class: 'card', 'aria-labelledby': 'prov-h' },
    el('h2', { id: 'prov-h' }, 'Data provenance policy'),
    el('p', null, 'Every card, table and chart on this platform carries one of three labels:'),
    el('dl', { class: 'dl' },
      ...['simulated', 'documented', 'lab'].flatMap((k) => [el('dt', null, provenanceBadge(k)), el('dd', null, PROVENANCE_HELP[k])])
    )
  );

  /* ---------------- Modules grid ---------------- */
  modulesSection.append(
    el('div', { class: 'meta-row' }, el('h2', { id: 'modules-h' }, 'Platform modules')),
    el('div', { class: 'grid grid-3' },
      ...modulesData.modules.map((m) =>
        el('a', { class: 'card module-tile', href: '#' + m.route },
          el('span', { class: 'num' }, `MODULE ${m.num}`),
          el('h3', null, m.title),
          el('p', null, m.summary),
          el('div', { class: 'tile-foot' },
            el('span', { class: `badge status-${m.status}` }, m.status === 'live' ? 'Available' : `Planned · phase ${m.phase}`),
            ...m.provenance.map(provenanceBadge)
          )
        )
      )
    )
  );

  view.append(hero, kpis, el('div', { class: 'grid grid-2' }, feedCard, legend), modulesSection);
  view.classList.add('stack'); // vertical rhythm between sections

  const destroyTopology = mountTopology(canvas, { reducedMotion });
  return () => { stopReplay(); destroyTopology(); view.classList.remove('stack'); };
}

function barFill(ratio) {
  const span = el('span');
  span.style.width = `${Math.max(0, Math.min(1, ratio || 0)) * 100}%`; // CSSOM — allowed under CSP
  return span;
}
