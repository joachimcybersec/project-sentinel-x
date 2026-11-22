/**
 * Theme state: Original (default), Dark and Gold Luxury, from Joachim's portfolio.
 * The choice is a per-visitor convenience kept in localStorage; every read and
 * write is guarded so the site works when storage is blocked.
 * js/theme-init.js applies the saved theme before CSS loads; keep both in sync.
 */
export const THEME_KEY = 'sx-theme';
export const THEME_EVENT = 'sx-themechange';

export const THEMES = [
  { id: 'original', label: 'Original', tagline: 'Red team energy', themeColor: '#160202' },
  { id: 'dark', label: 'Dark', tagline: 'Blue team precision', themeColor: '#0b0f19' },
  { id: 'gold', label: 'Gold Luxury', tagline: 'The gold standard', themeColor: '#050505' }
];

const IDS = new Set(THEMES.map((t) => t.id));

/** Any unknown or missing value falls back to the default theme. */
export function normalizeTheme(value) {
  return typeof value === 'string' && IDS.has(value) ? value : 'original';
}

export function currentTheme(root = document.documentElement) {
  return normalizeTheme(root.getAttribute('data-theme'));
}

export function readSavedTheme(storage = safeStorage()) {
  try { return normalizeTheme(storage ? storage.getItem(THEME_KEY) : null); } catch { return 'original'; }
}

/** Apply a theme: DOM attribute, browser UI colour, saved choice, and a change event. */
export function applyTheme(value, { root = document.documentElement, storage = safeStorage(), animate = false } = {}) {
  const id = normalizeTheme(value);
  if (animate) {
    root.classList.add('theme-anim');
    setTimeout(() => root.classList.remove('theme-anim'), 400);
  }
  if (id === 'original') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', id);
  const meta = document.querySelector('meta[name="theme-color"]');
  const theme = THEMES.find((t) => t.id === id);
  if (meta && theme) meta.setAttribute('content', theme.themeColor);
  try { if (storage) storage.setItem(THEME_KEY, id); } catch { /* storage blocked: still applied for this visit */ }
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: id }));
  return id;
}

function safeStorage() {
  try { return window.localStorage; } catch { return null; }
}
