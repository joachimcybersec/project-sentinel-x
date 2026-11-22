/**
 * Accessible tabs (WAI-ARIA Authoring Practices "Tabs with automatic activation").
 * Arrow Left/Right move and activate, Home/End jump; roving tabindex keeps a
 * single tab stop. Panels render lazily on first activation.
 *
 *   createTabs({ label: 'Event views', tabs: [{ id: 'raw', label: 'Raw', render: () => node }] })
 */
import { el } from '../utils/dom.js';

let uid = 0;

export function createTabs({ label, tabs, initial = 0 }) {
  const id = `tabs${++uid}`;
  const tablist = el('div', { class: 'tablist', role: 'tablist', 'aria-label': label });
  const panels = [];
  const buttons = [];
  const rendered = new Set();
  let active = -1;

  tabs.forEach((t, i) => {
    const tabId = `${id}-tab-${t.id}`;
    const panelId = `${id}-panel-${t.id}`;
    const btn = el('button', {
      class: 'tab', type: 'button', role: 'tab', id: tabId,
      'aria-selected': 'false', 'aria-controls': panelId, tabindex: '-1'
    }, t.label);
    const panel = el('div', { class: 'tabpanel', role: 'tabpanel', id: panelId, 'aria-labelledby': tabId, tabindex: '0', hidden: true });
    btn.addEventListener('click', () => select(i));
    buttons.push(btn);
    panels.push(panel);
    tablist.append(btn);
  });

  tablist.addEventListener('keydown', (e) => {
    const n = buttons.length;
    let next = null;
    if (e.key === 'ArrowRight') next = (active + 1) % n;
    else if (e.key === 'ArrowLeft') next = (active - 1 + n) % n;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = n - 1;
    if (next === null) return;
    e.preventDefault();
    select(next, { focus: true });
  });

  function select(i, { focus = false } = {}) {
    if (i === active) { if (focus) buttons[i].focus(); return; }
    buttons.forEach((b, j) => {
      const on = i === j;
      b.setAttribute('aria-selected', String(on));
      b.setAttribute('tabindex', on ? '0' : '-1');
      panels[j].hidden = !on;
    });
    if (!rendered.has(i)) {
      // A hidden h2 keeps the heading outline intact (h1 → h2 → card h3) and lets
      // screen-reader users jump to each panel by heading.
      panels[i].append(el('h2', { class: 'visually-hidden' }, tabs[i].heading || tabs[i].label), tabs[i].render());
      rendered.add(i);
    }
    active = i;
    // Keep the selected tab visible when the tab strip scrolls horizontally (narrow screens).
    const b = buttons[i];
    if (tablist.scrollWidth > tablist.clientWidth) {
      if (b.offsetLeft < tablist.scrollLeft) tablist.scrollLeft = b.offsetLeft;
      else if (b.offsetLeft + b.offsetWidth > tablist.scrollLeft + tablist.clientWidth) tablist.scrollLeft = b.offsetLeft + b.offsetWidth - tablist.clientWidth;
    }
    if (focus) b.focus();
  }

  select(Math.min(Math.max(0, initial), tabs.length - 1));

  return { element: el('div', { class: 'tabs' }, tablist, panels), select, get active() { return active; } };
}
