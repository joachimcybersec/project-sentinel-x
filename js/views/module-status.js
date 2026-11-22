/**
 * Module status view — rendered for modules that are planned but not yet built.
 * It states plainly what the module will contain and when, instead of showing
 * fake controls. Each module replaces this with its own view as it ships.
 */
import { el, provenanceBadge } from '../utils/dom.js';
import { load } from '../data-service.js';

export async function renderModuleStatus(view, { moduleId }) {
  const { data } = await load('modules');
  const mods = data.modules;
  const idx = mods.findIndex((m) => m.id === moduleId);
  const m = mods[idx];
  if (!m) throw new Error(`Module "${moduleId}" not in registry`);
  const prev = mods[idx - 1];
  const next = mods[idx + 1];

  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, `Module ${m.num}`),
      el('h1', null, m.title),
      el('p', { class: 'lede' }, m.summary),
      el('div', { class: 'meta-row' },
        el('span', { class: `badge status-${m.status}` }, m.status === 'live' ? 'Available' : `Planned · phase ${m.phase}`),
        ...m.provenance.map(provenanceBadge)
      )
    ),
    el('div', { class: 'grid grid-2' },
      el('section', { class: 'card', 'aria-labelledby': 'scope-h' },
        el('h2', { id: 'scope-h' }, 'Planned scope'),
        el('ul', { class: 'checklist' }, ...m.features.map((f) => el('li', null, f)))
      ),
      el('section', { class: 'card', 'aria-labelledby': 'status-h' },
        el('h2', { id: 'status-h' }, 'Build status'),
        el('p', null, `This module is scheduled for development phase ${m.phase}. It is intentionally not mocked up with non-functional controls: when it ships, every filter, search and export on this page will work against the datasets described here.`),
        el('div', { class: 'notice' },
          el('span', { 'aria-hidden': 'true' }, 'ⓘ'),
          el('span', null, el('strong', null, 'Roadmap: '), 'see ', el('a', { href: '#/about' }, 'About this project'), ' for the full phase plan and architecture.')
        )
      )
    ),
    el('nav', { class: 'hero-actions', 'aria-label': 'Module pager' },
      prev ? el('a', { class: 'btn', href: '#' + prev.route }, `← ${prev.num} ${prev.title}`) : el('a', { class: 'btn', href: '#/' }, '← Overview'),
      next ? el('a', { class: 'btn', href: '#' + next.route }, `${next.num} ${next.title} →`) : el('a', { class: 'btn', href: '#/about' }, 'About this project →')
    )
  );
}
