/**
 * Primary navigation: builds the sidebar from the module registry, tracks the
 * active route, and runs the off-canvas drawer on small screens.
 */
import { el, clear } from './utils/dom.js';

const MOBILE_QUERY = window.matchMedia('(max-width: 960px)');

export function initNavigation(modules) {
  const list = document.getElementById('nav-list');
  const sidebar = document.getElementById('sidebar');
  const toggle = document.getElementById('nav-toggle');
  const scrim = document.getElementById('scrim');

  clear(list);
  list.append(
    el('li', null, navLink('/', '◈', 'Overview', true)),
    el('li', { class: 'nav-group-label', 'aria-hidden': 'true' }, 'Modules'),
    ...modules.map((m) => el('li', null, navLink(m.route, m.num, m.title, m.status === 'live'))),
    el('li', { class: 'nav-group-label', 'aria-hidden': 'true' }, 'Project'),
    el('li', null, navLink('/components', '▦', 'UI component kit', true)),
    el('li', null, navLink('/about', 'ⓘ', 'About this project', true))
  );

  const open = () => {
    sidebar.classList.add('is-open');
    scrim.hidden = false;
    toggle.setAttribute('aria-expanded', 'true');
    toggle.setAttribute('aria-label', 'Close navigation');
    const first = sidebar.querySelector('.nav-link');
    if (first) first.focus();
  };
  const close = ({ restoreFocus = false } = {}) => {
    if (!sidebar.classList.contains('is-open')) return;
    sidebar.classList.remove('is-open');
    scrim.hidden = true;
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open navigation');
    if (restoreFocus) toggle.focus();
  };

  toggle.addEventListener('click', () => (sidebar.classList.contains('is-open') ? close({ restoreFocus: true }) : open()));
  scrim.addEventListener('click', () => close({ restoreFocus: true }));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close({ restoreFocus: true });
  });
  sidebar.addEventListener('click', (e) => {
    if (e.target.closest('.nav-link') && MOBILE_QUERY.matches) close();
  });
  // If the viewport grows past the breakpoint while open, reset drawer state.
  MOBILE_QUERY.addEventListener('change', (e) => { if (!e.matches) close(); });

  return {
    /** Mark the link for the current path (or its parent module) as current. */
    setActive(path) {
      const top = '/' + (path.split('/')[1] || '');
      for (const a of list.querySelectorAll('.nav-link')) {
        const route = a.getAttribute('href').slice(1);
        if (route === top) a.setAttribute('aria-current', 'page');
        else a.removeAttribute('aria-current');
      }
    }
  };
}

function navLink(route, num, label, live) {
  return el('a', { class: 'nav-link', href: '#' + route },
    el('span', { class: 'nav-num', 'aria-hidden': 'true' }, num),
    el('span', null, label),
    el('span', {
      class: `nav-state${live ? ' is-live' : ''}`,
      title: live ? 'Available' : 'Planned — not yet built'
    }),
    live ? null : el('span', { class: 'visually-hidden' }, ' (planned)')
  );
}
