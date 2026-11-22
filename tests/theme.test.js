import { test, assert } from './test-runner.js';
import { THEMES, THEME_KEY, THEME_EVENT, normalizeTheme, readSavedTheme, applyTheme, currentTheme } from '../js/theme.js';
import { mountThemeSwitcher } from '../js/components/theme-switcher.js';
import { BACKGROUND_THEMES } from '../js/effects/background.js';
import { contrastRatio } from './a11y-audit.js';

const IDS = THEMES.map((t) => t.id);

function memoryStorage(initial = {}) {
  const m = new Map(Object.entries(initial));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), _m: m };
}
const throwingStorage = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };

/* ---------- theme state ---------- */
test('themes: exactly Original, Dark and Gold Luxury, Original first (default)', () => {
  assert.deepEqual(IDS, ['original', 'dark', 'gold']);
  assert.deepEqual(THEMES.map((t) => t.label), ['Original', 'Dark', 'Gold Luxury']);
});

test('normalizeTheme falls back to original for anything unknown', () => {
  for (const id of IDS) assert.equal(normalizeTheme(id), id);
  for (const bad of [null, undefined, '', 'light', 'DARK', '<script>', 42, {}]) assert.equal(normalizeTheme(bad), 'original');
});

test('readSavedTheme tolerates missing, invalid and blocked storage', () => {
  assert.equal(readSavedTheme(memoryStorage({ [THEME_KEY]: 'gold' })), 'gold');
  assert.equal(readSavedTheme(memoryStorage({ [THEME_KEY]: 'neon' })), 'original');
  assert.equal(readSavedTheme(memoryStorage()), 'original');
  assert.equal(readSavedTheme(throwingStorage), 'original');
  assert.equal(readSavedTheme(null), 'original');
});

test('applyTheme sets the attribute (none for original), saves, and fires the change event', () => {
  const root = document.createElement('div');
  const storage = memoryStorage();
  const seen = [];
  const on = (e) => seen.push(e.detail);
  window.addEventListener(THEME_EVENT, on);
  try {
    assert.equal(applyTheme('dark', { root, storage }), 'dark');
    assert.equal(root.getAttribute('data-theme'), 'dark');
    assert.equal(storage.getItem(THEME_KEY), 'dark');
    applyTheme('original', { root, storage });
    assert.equal(root.hasAttribute('data-theme'), false, 'original is the attribute-free default');
    assert.equal(applyTheme('bogus', { root, storage }), 'original');
    applyTheme('gold', { root, storage: throwingStorage }); // blocked storage must not throw
    assert.equal(currentTheme(root), 'gold');
    assert.deepEqual(seen, ['dark', 'original', 'original', 'gold']);
  } finally {
    window.removeEventListener(THEME_EVENT, on);
  }
});

test('theme-init.js (runs before CSS) uses the same storage key and theme names', async () => {
  const src = await (await fetch('../js/theme-init.js')).text();
  assert.ok(src.includes(`'${THEME_KEY}'`), 'storage key matches js/theme.js');
  for (const id of ['dark', 'gold']) assert.ok(src.includes(`'${id}'`), `knows ${id}`);
  assert.ok(!/innerHTML|eval\(|document\.write/.test(src), 'no injection sinks');
});

test('background engine has a palette for every theme', () => {
  assert.deepEqual([...BACKGROUND_THEMES].sort(), [...IDS].sort());
});

/* ---------- switcher ---------- */
test('theme switcher: opens, reflects the current theme, applies a choice by click and by keyboard', () => {
  const root = document.documentElement;
  const before = root.getAttribute('data-theme');
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* storage blocked */ }
  const host = document.createElement('div');
  document.body.append(host);
  try {
    root.removeAttribute('data-theme');
    const { fab, menu } = mountThemeSwitcher(host);
    const opts = [...menu.querySelectorAll('[role="radio"]')];
    assert.equal(menu.getAttribute('role'), 'radiogroup');
    assert.equal(opts.length, 3);
    assert.equal(menu.hidden, true);
    assert.equal(fab.getAttribute('aria-expanded'), 'false');

    fab.click();
    assert.equal(menu.hidden, false);
    assert.equal(fab.getAttribute('aria-expanded'), 'true');
    assert.deepEqual(opts.map((o) => o.getAttribute('aria-checked')), ['true', 'false', 'false']);
    assert.equal(document.activeElement, opts[0], 'focus moves to the selected theme');

    opts[2].click();
    assert.equal(root.getAttribute('data-theme'), 'gold');
    assert.equal(menu.hidden, true, 'menu closes after a choice');
    assert.equal(document.activeElement, fab, 'focus returns to the button');

    fab.click();
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    assert.equal(root.hasAttribute('data-theme'), false, 'ArrowDown wraps gold → original');
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    assert.equal(root.getAttribute('data-theme'), 'gold');
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
    assert.equal(root.hasAttribute('data-theme'), false);
    assert.deepEqual(opts.map((o) => o.tabIndex), [0, -1, -1], 'roving tabindex follows the selection');
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    assert.equal(menu.hidden, true);
  } finally {
    host.remove();
    if (before) root.setAttribute('data-theme', before); else root.removeAttribute('data-theme');
    try { if (saved === null) localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, saved); } catch { /* ignore */ }
  }
});

/* ---------- contrast of every theme's tokens (read from the real CSS) ---------- */
function tokens(block) {
  const out = {};
  for (const m of block.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\b/g)) out[m[1]] = m[2];
  return out;
}
const hex = (h) => ({ r: parseInt(h.slice(1, 3), 16), g: parseInt(h.slice(3, 5), 16), b: parseInt(h.slice(5, 7), 16), a: 1 });

test('every theme: text, links and button labels meet WCAG AA contrast', async () => {
  const main = await (await fetch('../css/main.css')).text();
  const themes = await (await fetch('../css/themes.css')).text();
  const rootBlock = main.slice(main.indexOf(':root {'), main.indexOf('}', main.indexOf(':root {')));
  const base = tokens(rootBlock);
  const sets = { original: base };
  for (const id of ['dark', 'gold']) {
    const start = themes.indexOf(`html[data-theme="${id}"] {`);
    assert.ok(start >= 0, `themes.css defines ${id}`);
    sets[id] = { ...base, ...tokens(themes.slice(start, themes.indexOf('}', start))) };
  }
  const pairs = [
    ['text-1', 'bg-0', 4.5], ['text-1', 'bg-3', 4.5], ['text-2', 'bg-2', 4.5], ['text-3', 'bg-1', 4.5], ['text-3', 'bg-2', 4.5],
    ['cyan', 'bg-1', 4.5], ['cyan', 'bg-2', 4.5],      // accent used as link / label text
    ['on-accent', 'cyan', 4.5], ['on-accent', 'accent-lo', 4.5] // text on accent-filled buttons and chips
  ];
  const fails = [];
  for (const [id, t] of Object.entries(sets)) {
    for (const [fg, bg, need] of pairs) {
      assert.ok(t[fg] && t[bg], `${id}: --${fg} and --${bg} defined as hex`);
      const r = contrastRatio(hex(t[fg]), hex(t[bg]));
      if (r < need) fails.push(`${id}: --${fg} on --${bg} = ${r.toFixed(2)}:1 (needs ${need}:1)`);
    }
  }
  assert.deepEqual(fails, []);
});
