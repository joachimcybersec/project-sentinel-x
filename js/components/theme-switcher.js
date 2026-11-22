/**
 * Floating theme switcher (bottom-left), modelled on Joachim's portfolio:
 * a palette button opens a radio group of the three themes.
 *
 * Accessibility: the button reports aria-expanded; the menu is a radiogroup
 * whose options use aria-checked; Arrow keys move and select (radio pattern),
 * Home/End jump, Escape or a click outside closes and returns focus.
 */
import { el } from '../utils/dom.js';
import { THEMES, currentTheme, applyTheme } from '../theme.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

function paletteIcon() {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', 'M12 2a10 10 0 0 0 0 20c1.1 0 2-.9 2-2 0-.55-.22-1.05-.59-1.41-.36-.36-.58-.86-.58-1.42 0-1.1.9-2 2-2h2.17A5 5 0 0 0 22 10.5C22 5.8 17.5 2 12 2z');
  svg.append(path);
  for (const [cx, cy] of [[6.5, 11.5], [9.5, 7], [14.5, 7]]) {
    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('cx', String(cx));
    c.setAttribute('cy', String(cy));
    c.setAttribute('r', '1.2');
    c.setAttribute('fill', 'currentColor');
    c.setAttribute('stroke', 'none');
    svg.append(c);
  }
  return svg;
}

export function mountThemeSwitcher(parent = document.body) {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const fab = el('button', {
    class: 'theme-fab', id: 'theme-fab', type: 'button',
    'aria-haspopup': 'true', 'aria-expanded': 'false', 'aria-controls': 'theme-menu',
    'aria-label': 'Change theme', title: 'Change theme'
  }, paletteIcon());

  const options = THEMES.map((t) => el('button', {
    class: 'theme-option', type: 'button', role: 'radio', 'aria-checked': 'false', 'data-theme-choice': t.id
  },
  el('span', { class: `theme-dot theme-dot-${t.id}`, 'aria-hidden': 'true' }),
  el('span', { class: 'theme-option-text' }, t.label, el('small', null, t.tagline))));

  const menu = el('div', { class: 'theme-menu', id: 'theme-menu', role: 'radiogroup', 'aria-labelledby': 'theme-menu-label', hidden: true },
    el('p', { class: 'theme-menu-label', id: 'theme-menu-label' }, 'Theme'),
    ...options);

  function reflect() {
    const id = currentTheme();
    for (const btn of options) {
      const on = btn.getAttribute('data-theme-choice') === id;
      btn.setAttribute('aria-checked', String(on));
      btn.tabIndex = on ? 0 : -1; // roving tabindex: Tab lands on the selected theme
    }
  }

  function open() {
    menu.hidden = false;
    fab.setAttribute('aria-expanded', 'true');
    (options.find((b) => b.getAttribute('aria-checked') === 'true') || options[0]).focus();
  }
  function close({ focusFab = true } = {}) {
    if (menu.hidden) return;
    menu.hidden = true;
    fab.setAttribute('aria-expanded', 'false');
    if (focusFab) fab.focus();
  }
  function choose(btn) {
    applyTheme(btn.getAttribute('data-theme-choice'), { animate: !reduceMotion });
    reflect();
  }

  fab.addEventListener('click', (e) => {
    e.stopPropagation();
    if (menu.hidden) open(); else close();
  });
  menu.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-theme-choice]');
    if (!btn) return;
    choose(btn);
    close();
  });
  menu.addEventListener('keydown', (e) => {
    const i = options.indexOf(document.activeElement);
    let next = -1;
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') next = (i + 1) % options.length;
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') next = (i - 1 + options.length) % options.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = options.length - 1;
    else if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    else if (e.key === 'Tab') { close({ focusFab: false }); return; }
    if (next < 0) return;
    e.preventDefault();
    options[next].focus();
    choose(options[next]);
  });
  document.addEventListener('click', (e) => {
    if (!menu.hidden && !menu.contains(e.target) && e.target !== fab) close({ focusFab: false });
  });

  reflect();
  parent.append(fab, menu);
  return { fab, menu, reflect };
}
