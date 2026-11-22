/**
 * MODULE 09 — Security Tools Directory (#/tools, #/tools?tool=<id> to jump to a tool).
 * Tools grouped by category with licence type, use cases, official documentation,
 * links to practice inside Sentinel X, and example multi-tool workflows.
 */
import { el, clear, provenanceBadge } from '../utils/dom.js';
import { load } from '../data-service.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { bulletList } from '../components/intel-ui.js';

export const LICENCE_LABEL = { 'open-source': 'Open source', free: 'Free (proprietary)', commercial: 'Commercial', 'cloud-service': 'Cloud service' };

function hashParam(name) {
  const i = location.hash.indexOf('?');
  if (i < 0) return '';
  try { return (new URLSearchParams(location.hash.slice(i + 1)).get(name) || '').slice(0, 60); } catch { return ''; }
}

export async function renderTools(view) {
  const { data } = await load('tools');
  const catLabel = Object.fromEntries(data.categories.map((c) => [c.id, c.label]));
  const toolById = Object.fromEntries(data.tools.map((t) => [t.id, t]));
  const rows = data.tools.map((t) => ({ ...t, _search: [t.name, t.description, catLabel[t.category], ...t.useCases].join(' ') }));
  const listSlot = el('div', { class: 'stack' });
  const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });

  const focusTool = (id) => {
    const card = view.querySelector(`#tool-${CSS.escape(id)}`);
    if (!card) return;
    card.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    card.classList.add('is-highlight');
    card.focus({ preventScroll: true });
    setTimeout(() => card.classList.remove('is-highlight'), 2000);
  };

  const card = (t) => el('article', { class: 'card tool-card', id: `tool-${t.id}`, tabindex: '-1', 'aria-labelledby': `tool-${t.id}-h` },
    el('div', { class: 'intel-card-top' },
      el('h3', { id: `tool-${t.id}-h` }, t.name),
      el('span', { class: `lic lic-${t.licence}` }, LICENCE_LABEL[t.licence])),
    el('p', null, t.description),
    t.caution ? el('p', { class: 'tool-caution' }, '⚠ Authorised testing only. Use only on systems you own or have written permission to test.') : null,
    el('h4', { class: 'chart-title' }, 'Practical use cases'), bulletList(t.useCases),
    el('div', { class: 'btn-row tool-links' },
      el('a', { class: 'btn btn-sm', href: t.url, target: '_blank' }, 'Official documentation ↗'),
      t.practice ? el('a', { class: 'btn btn-sm btn-ghost', href: t.practice.href }, `Practice: ${t.practice.label}`) : null)
  );

  const render = (s) => {
    const out = applyFilters(rows, s, { searchFields: ['_search'] });
    count.textContent = `${out.length} of ${rows.length} tools`;
    clear(listSlot);
    if (!out.length) { listSlot.append(el('p', { class: 'bar-empty' }, 'No tools match the filters.')); return; }
    for (const c of data.categories) {
      const inCat = out.filter((t) => t.category === c.id);
      if (!inCat.length) continue;
      listSlot.append(el('section', { 'aria-labelledby': `cat-${c.id}` },
        el('h2', { id: `cat-${c.id}`, class: 'cat-heading' }, c.label, el('span', { class: 'kpi-sub' }, ` ${inCat.length}`)),
        el('div', { class: 'grid grid-3' }, inCat.map(card))));
    }
  };
  const fb = createFilterBar({
    ariaLabel: 'Filter tools', searchLabel: 'Search tools', searchPlaceholder: 'Tool name, use case, e.g. memory, DNS, CI…',
    chips: [{ key: 'licence', label: 'Licence', options: Object.entries(LICENCE_LABEL).map(([v, l]) => ({ value: v, label: l })) }],
    selects: [{ key: 'category', label: 'Category', options: data.categories.map((c) => ({ value: c.id, label: c.label })) }],
    onChange: render
  });
  render(fb.getState());

  const workflows = el('section', { class: 'card', 'aria-labelledby': 'wf-h' },
    el('h2', { id: 'wf-h' }, 'Example workflows'),
    el('p', { class: 'kpi-sub' }, 'How tools combine in real tasks. Select a tool to jump to its card.'),
    el('div', { class: 'grid grid-2' }, data.workflows.map((w) => el('article', { class: 'workflow' },
      el('h3', null, w.title),
      el('p', { class: 'kpi-sub' }, w.scenario),
      el('ol', { class: 'wf-steps' }, w.steps.map((s) => {
        const t = toolById[s.tool];
        const b = el('button', { class: 'wf-tool', type: 'button' }, t.name);
        b.addEventListener('click', () => {
          fb.update({ q: '', multi: { licence: [] }, single: { category: '' } });
          requestAnimationFrame(() => focusTool(t.id));
        });
        return el('li', null, b, el('span', null, s.action));
      })),
      el('a', { class: 'btn btn-sm', href: w.related.href }, w.related.label)))));

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 09'),
      el('h1', null, 'Security Tools Directory'),
      el('p', { class: 'lede' }, `${data.tools.length} tools across ${data.categories.length} categories, from SIEM and EDR to forensics and cloud security. Each has practical use cases, a link to its official documentation and, where possible, a place to practise the concept in Sentinel X.`),
      el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'kpi-sub' }, `Reviewed ${data.reviewed}`))),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, data.note)),
    fb.element, el('div', null, count), listSlot, workflows
  );
  const jump = hashParam('tool');
  if (jump && toolById[jump]) requestAnimationFrame(() => focusTool(jump));
  return () => view.classList.remove('stack');
}
