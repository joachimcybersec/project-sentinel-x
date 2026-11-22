/**
 * Minimal hash router.
 *
 * Hash routing works on any static host (GitHub Pages, Netlify) without
 * rewrite rules and keeps every module deep-linkable: #/attacks/phishing
 *
 * Route patterns support named params: '/incidents/:id'
 */

/** Normalise a location hash to a path: '#/soc?x=1' -> '/soc' */
export function hashToPath(hash) {
  let h = typeof hash === 'string' ? hash : '';
  if (h.startsWith('#')) h = h.slice(1);
  h = h.split('?')[0];
  if (!h.startsWith('/')) h = '/' + h;
  if (h.length > 1 && h.endsWith('/')) h = h.slice(0, -1);
  return h;
}

/** Match '/incidents/:id' against '/incidents/IR-3' -> { id: 'IR-3' } | null */
export function matchRoute(pattern, path) {
  const ps = pattern.split('/').filter(Boolean);
  const xs = path.split('/').filter(Boolean);
  if (ps.length !== xs.length) return null;
  const params = {};
  for (let i = 0; i < ps.length; i++) {
    if (ps[i].startsWith(':')) {
      let value;
      try { value = decodeURIComponent(xs[i]); } catch { return null; }
      // Params are identifiers, never markup or paths.
      if (!/^[\w.-]{1,80}$/.test(value)) return null;
      params[ps[i].slice(1)] = value;
    } else if (ps[i] !== xs[i]) {
      return null;
    }
  }
  return params;
}

/** Resolve a path against a route table. Returns { route, params } or null. */
export function resolve(routes, path) {
  for (const route of routes) {
    const params = matchRoute(route.path, path);
    if (params) return { route, params };
  }
  return null;
}

/**
 * Wrap an async task so runs never overlap. A call made while a run is in flight
 * schedules exactly one more run after it; any further calls fold into that one.
 * The router uses this so a slow (lazy-loaded) view can't finish rendering into
 * the container after a newer navigation has already cleared and filled it.
 */
export function latestOnly(task) {
  let running = null;
  let again = false;
  return function run() {
    if (running) { again = true; return running; }
    running = (async () => {
      try {
        do { again = false; await task(); } while (again);
      } finally { running = null; }
    })();
    return running;
  };
}

export function createRouter({ routes, onNavigate, notFound }) {
  // Each run reads the hash afresh, so the last navigation always wins.
  const handle = latestOnly(async () => {
    const path = hashToPath(window.location.hash);
    const hit = resolve(routes, path);
    await onNavigate(hit ? hit : { route: notFound, params: {} }, path);
  });
  window.addEventListener('hashchange', handle);
  return {
    start: handle,
    navigate(path) { window.location.hash = '#' + path; }
  };
}
