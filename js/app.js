/**
 * Sentinel X — application bootstrap.
 * Wires the route table, navigation, view lifecycle and global error display.
 */
import { createRouter } from './router.js';
import { initNavigation } from './navigation.js';
import { load, DataError } from './data-service.js';
import { el, clear, formatUtcTime } from './utils/dom.js';
import { renderHome } from './views/home.js';
import { renderModuleStatus } from './views/module-status.js';
import { closeDrawer } from './components/drawer.js';
import { mountThemeSwitcher } from './components/theme-switcher.js';

/**
 * Module views are loaded on first visit (dynamic import), so the landing page does not
 * download every module's code and its engines (SIEM parsers, Sigma evaluator, packet builder…).
 * Specifiers are static strings, so bundlers and CSP 'self' both handle them.
 */
const lazy = (load, name) => async (target, ctx) => (await load())[name](target, ctx);
const V = {
  about: () => import('./views/about.js'),
  components: () => import('./views/components.js'),
  soc: () => import('./views/soc.js'),
  siem: () => import('./views/siem.js'),
  incidents: () => import('./views/incidents.js'),
  detections: () => import('./views/detections.js'),
  vulnerabilities: () => import('./views/vulnerabilities.js'),
  network: () => import('./views/network.js'),
  tools: () => import('./views/tools.js'),
  knowledge: () => import('./views/knowledge.js'),
  threatIntel: () => import('./views/threat-intel.js'),
  attacks: () => import('./views/attacks.js')
};

/** Modules that have shipped their own view; everything else shows the status page. */
const MODULE_VIEWS = {
  soc: lazy(V.soc, 'renderSoc'), 'threat-intel': lazy(V.threatIntel, 'renderThreatIntel'), attacks: lazy(V.attacks, 'renderAttacks'),
  incidents: lazy(V.incidents, 'renderIncidents'), siem: lazy(V.siem, 'renderSiem'), detections: lazy(V.detections, 'renderDetections'),
  vulnerabilities: lazy(V.vulnerabilities, 'renderVulnerabilities'), network: lazy(V.network, 'renderNetwork'),
  tools: lazy(V.tools, 'renderTools'), knowledge: lazy(V.knowledge, 'renderKnowledge')
};

/** Detail routes for live modules. */
const DETAIL_ROUTES = [
  { path: '/incidents/:id', title: 'Incident', render: lazy(V.incidents, 'renderIncident') },
  { path: '/detections/:id', title: 'Detection rule', render: lazy(V.detections, 'renderDetection') },
  { path: '/vulnerabilities/:id', title: 'CVE', render: lazy(V.vulnerabilities, 'renderVulnerability') },
  { path: '/knowledge/:id', title: 'Article', render: lazy(V.knowledge, 'renderArticle') },
  { path: '/threat-intel/:id', title: 'Threat profile', render: lazy(V.threatIntel, 'renderThreatProfile') },
  { path: '/attacks/:id', title: 'Attack dossier', render: lazy(V.attacks, 'renderAttackDossier') }
];

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const view = document.getElementById('view');
const main = document.getElementById('main');
let cleanup = null;

function renderNotFound(target, { path }) {
  target.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, '404'),
      el('h1', null, 'Route not found'),
      el('p', { class: 'lede' }, `Nothing is registered at “${path}”.`)
    ),
    el('a', { class: 'btn btn-primary', href: '#/' }, 'Back to overview')
  );
}

function renderError(target, err) {
  const detail = err instanceof DataError ? err.message : 'An unexpected error occurred while rendering this view.';
  target.append(
    el('div', { class: 'notice is-error', role: 'alert' },
      el('span', { 'aria-hidden': 'true' }, '⚠'),
      el('span', null, el('strong', null, 'Unable to display this page. '), detail)
    ),
    el('p', null),
    el('button', { class: 'btn', type: 'button', id: 'retry-btn' }, 'Retry')
  );
  target.querySelector('#retry-btn').addEventListener('click', () => window.dispatchEvent(new HashChangeEvent('hashchange')));
}

function startClock() {
  const clock = document.getElementById('utc-clock');
  const tick = () => {
    const now = new Date();
    clock.textContent = `${formatUtcTime(now)} UTC`;
    clock.setAttribute('datetime', now.toISOString());
  };
  tick();
  window.setInterval(tick, 1000);
}

/** The animated background loads after first paint (idle time), so content always wins. */
function startAmbientBackground() {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const go = () => import('./effects/background.js')
    .then((m) => m.startBackground(canvas, { reducedMotion }))
    .catch((err) => console.error(err)); // decorative: a failure must never affect the app
  if ('requestIdleCallback' in window) window.requestIdleCallback(go, { timeout: 600 });
  else window.setTimeout(go, 200);
}

async function boot() {
  startClock();
  mountThemeSwitcher();
  startAmbientBackground();

  // Site-wide search: submit opens the Knowledge Centre search tab; "/" focuses the box.
  const siteSearch = document.getElementById('site-search');
  const siteQ = document.getElementById('site-q');
  siteSearch.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = siteQ.value.trim().slice(0, 120);
    location.hash = `#/knowledge?tab=search${q ? `&q=${encodeURIComponent(q)}` : ''}`;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if (getComputedStyle(siteSearch).display === 'none') return;
    e.preventDefault();
    siteQ.focus();
    siteQ.select();
  });

  // The skip link must not change the hash, or the router would treat "#main" as a route.
  document.querySelector('.skip-link').addEventListener('click', (e) => {
    e.preventDefault();
    main.focus();
  });

  let modules = [];
  try {
    ({ data: { modules } } = await load('modules'));
  } catch (err) {
    console.error(err);
    renderError(view, err);
    return;
  }
  const nav = initNavigation(modules);

  const routes = [
    { path: '/', title: 'Overview', render: (t) => renderHome(t, { reducedMotion }) },
    { path: '/about', title: 'About this project', render: lazy(V.about, 'renderAbout') },
    { path: '/components', title: 'UI component kit', render: lazy(V.components, 'renderComponents') },
    ...modules.map((m) => ({
      path: m.route,
      title: m.title,
      render: m.status === 'live' && MODULE_VIEWS[m.id] ? MODULE_VIEWS[m.id] : (t) => renderModuleStatus(t, { moduleId: m.id })
    })),
    ...DETAIL_ROUTES
  ];
  const notFound = { path: '*', title: 'Not found', render: (t, ctx) => renderNotFound(t, ctx) };
  let firstRender = true;

  const router = createRouter({
    routes,
    notFound,
    async onNavigate({ route, params }, path) {
      closeDrawer(); // a drawer opened on the previous page must not float over the next one
      if (typeof cleanup === 'function') { try { cleanup(); } catch (e) { console.error(e); } }
      cleanup = null;
      const hash = window.location.hash;
      delete view.dataset.rendered;
      clear(view);
      view.classList.remove('is-entering');
      view.setAttribute('aria-busy', 'true');
      nav.setActive(path);
      document.title = `${route.title} · Joachim's Sentinel X`;

      try {
        cleanup = await route.render(view, { params, path });
      } catch (err) {
        console.error(err);
        clear(view);
        renderError(view, err);
      }
      view.removeAttribute('aria-busy');
      view.dataset.rendered = hash; // which location this content belongs to (used by the browser test driver)
      if (!reducedMotion) { void view.offsetWidth; view.classList.add('is-entering'); }
      window.scrollTo(0, 0);
      // Move focus to main content on navigation (not on first load) for screen-reader users.
      if (!firstRender) main.focus({ preventScroll: true });
      firstRender = false;
    }
  });

  await router.start();
}

boot();
