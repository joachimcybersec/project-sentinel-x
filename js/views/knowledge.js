/**
 * MODULE 10 — Cybersecurity Knowledge Centre.
 *   #/knowledge                      learning pathways · article library · search everything
 *   #/knowledge?tab=search&q=<text>  site-wide search (used by the top-bar search box)
 *   #/knowledge/:id                  article page
 *
 * Pathway progress is a per-viewer convenience stored in localStorage (wrapped in
 * try/catch; the page works without it). Nothing is sent anywhere.
 */
import { el, clear, provenanceBadge } from '../utils/dom.js';
import { load } from '../data-service.js';
import { createTabs } from '../components/tabs.js';
import { createFilterBar, applyFilters } from '../components/filter-bar.js';
import { sourceList } from '../components/intel-ui.js';
import { buildIndex, search, excerpt, TYPE_LABEL, MAX_SEARCH } from '../search/search.js';

const PROGRESS_KEY = 'sx-pathway-progress';
export function readProgress() {
  try { const v = JSON.parse(localStorage.getItem(PROGRESS_KEY) || '{}'); return v && typeof v === 'object' ? v : {}; } catch { return {}; }
}
function writeProgress(p) { try { localStorage.setItem(PROGRESS_KEY, JSON.stringify(p)); } catch { /* storage unavailable: progress is not kept */ } }

export const readingMinutes = (a) => Math.max(1, Math.round(a.sections.flatMap((s) => [s.heading, ...(s.paragraphs || []), ...(s.bullets || [])]).join(' ').split(/\s+/).length / 200));

function hashParam(name) {
  const i = location.hash.indexOf('?');
  if (i < 0) return '';
  try { return (new URLSearchParams(location.hash.slice(i + 1)).get(name) || '').slice(0, MAX_SEARCH); } catch { return ''; }
}

/** Load every dataset the search index needs; missing datasets are skipped. */
async function loadSearchData() {
  const names = ['modules', 'knowledge', 'tools', 'intel', 'attacks', 'detections', 'cves', 'incidents', 'network'];
  const res = await Promise.allSettled(names.map((n) => load(n)));
  const get = (n) => { const r = res[names.indexOf(n)]; return r.status === 'fulfilled' ? r.value.data : null; };
  const k = get('knowledge');
  return buildIndex({
    modules: (get('modules') || {}).modules, articles: k ? k.articles : [], tools: (get('tools') || {}).tools,
    profiles: (get('intel') || {}).profiles, attacks: (get('attacks') || {}).attacks, rules: (get('detections') || {}).rules,
    cves: (get('cves') || {}).cves, incidents: (get('incidents') || {}).incidents, topics: (get('network') || {}).topics
  });
}

export async function renderKnowledge(view) {
  const { data } = await load('knowledge');
  const articleById = Object.fromEntries(data.articles.map((a) => [a.id, a]));
  const catLabel = Object.fromEntries(data.categories.map((c) => [c.id, c.label]));
  const wantSearch = hashParam('tab') === 'search' || !!hashParam('q');

  /* ---------- pathways ---------- */
  const pathways = () => {
    const wrap = el('div', { class: 'grid grid-2' });
    const render = () => {
      const progress = readProgress();
      clear(wrap).append(...data.pathways.map((pw) => {
        const done = new Set(progress[pw.id] || []);
        const pct = Math.round((done.size / pw.steps.length) * 100);
        return el('article', { class: 'card pathway', 'aria-labelledby': `pw-${pw.id}` },
          el('div', { class: 'intel-card-top' }, el('h3', { id: `pw-${pw.id}` }, pw.title), el('span', { class: 'kpi-sub' }, `${done.size}/${pw.steps.length} done`)),
          el('p', null, pw.summary),
          el('div', { class: 'inv-progress', role: 'progressbar', 'aria-label': `${pw.title} progress`, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) }),
          el('ol', { class: 'pw-steps' }, pw.steps.map((s, i) => {
            const id = `pw-${pw.id}-${i}`;
            const cb = el('input', { type: 'checkbox', id, checked: done.has(i) || null, 'data-focus-key': id });
            cb.addEventListener('change', () => {
              const p = readProgress();
              const set = new Set(p[pw.id] || []);
              cb.checked ? set.add(i) : set.delete(i);
              p[pw.id] = [...set].sort((a, b) => a - b);
              writeProgress(p);
              render();
              wrap.querySelector(`#${CSS.escape(id)}`)?.focus();
            });
            const a = s.type === 'article' ? articleById[s.ref] : null;
            return el('li', { class: done.has(i) ? 'is-done' : null },
              cb,
              el('label', { for: id, class: 'visually-hidden' }, `Mark step ${i + 1} done`),
              el('span', { class: `step-type type-${s.type}` }, s.type === 'article' ? 'Read' : 'Practise'),
              a ? el('a', { href: `#/knowledge/${a.id}` }, a.title, el('span', { class: 'kpi-sub' }, ` · ${readingMinutes(a)} min`)) : el('a', { href: s.href }, s.label));
          })));
      }));
      wrap.querySelectorAll('.inv-progress').forEach((bar) => bar.style.setProperty('--pct', `${bar.getAttribute('aria-valuenow')}%`));
    };
    render();
    const reset = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Reset progress');
    reset.addEventListener('click', () => { writeProgress({}); render(); });
    return el('div', { class: 'stack' },
      el('div', { class: 'section-head' }, el('p', { class: 'kpi-sub' }, 'Structured routes that mix reading with hands-on tasks in Sentinel X. Progress is saved only in this browser.'), el('div', { class: 'btn-row' }, reset)),
      wrap);
  };

  /* ---------- article library ---------- */
  const library = () => {
    const rows = data.articles.map((a) => ({ ...a, _search: [a.title, a.summary, catLabel[a.category], ...a.sections.flatMap((s) => [s.heading, ...(s.paragraphs || []), ...(s.bullets || [])])].join(' ') }));
    const grid = el('div', { class: 'grid grid-3' });
    const count = el('span', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' });
    const fb = createFilterBar({
      ariaLabel: 'Filter articles', searchLabel: 'Search articles', searchPlaceholder: 'Topic, framework, technique…',
      chips: [{ key: 'level', label: 'Level', options: ['beginner', 'intermediate', 'advanced'].map((l) => ({ value: l, label: l })) }],
      selects: [{ key: 'category', label: 'Subject', options: data.categories.map((c) => ({ value: c.id, label: c.label })) }],
      onChange: (s) => {
        const out = applyFilters(rows, s, { searchFields: ['_search'] });
        count.textContent = `${out.length} of ${rows.length} articles`;
        clear(grid).append(...(out.length ? out.map((a) => el('a', { class: 'card intel-card', href: `#/knowledge/${a.id}` },
          el('div', { class: 'intel-card-top' }, el('span', { class: 'type-pill' }, catLabel[a.category]), el('span', { class: `level level-${a.level}` }, a.level)),
          el('h3', null, a.title), el('p', null, a.summary),
          el('div', { class: 'tile-foot' }, el('span', { class: 'kpi-sub' }, `${readingMinutes(a)} min read · ${a.refs.length} reference${a.refs.length === 1 ? '' : 's'}`))))
          : [el('p', { class: 'bar-empty' }, 'No articles match the filters.')]));
      }
    });
    fb.update({});
    return el('div', { class: 'stack' }, fb.element, el('div', null, count), grid);
  };

  /* ---------- search everything ---------- */
  const searchTab = () => {
    const input = el('input', { class: 'input', type: 'search', id: 'ks-q', maxlength: String(MAX_SEARCH), autocomplete: 'off', spellcheck: 'false', placeholder: 'e.g. CVE-2023-4966, LSASS, ransomware, Zero Trust…' });
    const status = el('p', { class: 'kpi-sub', role: 'status', 'aria-live': 'polite' }, 'Building index…');
    const results = el('div', { class: 'stack' });
    let index = null;
    const run = (updateUrl = true) => {
      if (!index) return;
      const q = input.value.trim();
      clear(results);
      if (!q) { status.textContent = `${index.length} items indexed across ${Object.keys(TYPE_LABEL).length} content types. Type to search.`; return; }
      const hits = search(index, q);
      status.textContent = `${hits.length} result${hits.length === 1 ? '' : 's'} for “${q}”`;
      const types = [...new Set(hits.map((h) => h.type))];
      for (const t of types) {
        const group = hits.filter((h) => h.type === t);
        results.append(el('section', { 'aria-label': TYPE_LABEL[t] },
          el('h3', { class: 'chart-title' }, `${TYPE_LABEL[t]} (${group.length})`),
          el('ul', { class: 'search-results' }, group.map((h) => el('li', null,
            el('a', { href: h.href }, h.title),
            h.meta ? el('span', { class: 'kpi-sub' }, ` · ${h.meta}`) : null,
            el('p', { class: 'search-excerpt' }, excerpt(h, q)))))));
      }
      if (!hits.length) results.append(el('p', { class: 'bar-empty' }, 'No matches. Try fewer or different words.'));
      if (updateUrl) {
        const url = `#/knowledge?tab=search${q ? `&q=${encodeURIComponent(q)}` : ''}`;
        if (location.hash !== url) history.replaceState(null, '', url);
      }
    };
    let t = 0;
    input.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => run(), 150); });
    const form = el('form', { role: 'search', 'aria-label': 'Search everything', class: 'query-bar' },
      el('label', { class: 'filter-label', for: 'ks-q' }, 'Search all of Sentinel X'), el('div', { class: 'query-row' }, input, el('button', { class: 'btn btn-primary', type: 'submit' }, 'Search')));
    form.addEventListener('submit', (e) => { e.preventDefault(); run(); });
    input.value = hashParam('q');
    loadSearchData().then((idx) => { index = idx; run(false); if (wantSearch) input.focus({ preventScroll: true }); });
    return el('div', { class: 'stack' }, form, status, results);
  };

  const tabs = createTabs({
    label: 'Knowledge Centre views', initial: wantSearch ? 2 : 0,
    tabs: [
      { id: 'pathways', label: `Learning pathways (${data.pathways.length})`, render: pathways },
      { id: 'articles', label: `Articles (${data.articles.length})`, render: library },
      { id: 'search', label: 'Search everything', render: searchTab }
    ]
  });

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 10'),
      el('h1', null, 'Knowledge Centre'),
      el('p', { class: 'lede' }, 'Short explainers across ten subject areas, learning pathways that link reading to hands-on practice in the platform, and search across everything in Sentinel X.'),
      el('div', { class: 'meta-row' }, provenanceBadge('documented'), el('span', { class: 'kpi-sub' }, `Reviewed ${data.reviewed}`))),
    el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'), el('span', null, data.note)),
    el('section', { class: 'card' }, tabs.element)
  );
  return () => view.classList.remove('stack');
}

export async function renderArticle(view, { params }) {
  const { data } = await load('knowledge');
  const a = data.articles.find((x) => x.id === params.id);
  if (!a) {
    view.append(el('header', { class: 'page-head' }, el('span', { class: 'eyebrow' }, 'Module 10'), el('h1', null, 'Article not found'),
      el('p', { class: 'lede' }, `No article has the ID “${params.id}”.`)), el('a', { class: 'btn btn-primary', href: '#/knowledge' }, '← Knowledge Centre'));
    return;
  }
  document.title = `${a.title} · Knowledge Centre · Joachim's Sentinel X`;
  const cat = data.categories.find((c) => c.id === a.category);
  const sameCat = data.articles.filter((x) => x.category === a.category);
  const i = sameCat.indexOf(a);
  const inPathways = data.pathways.filter((p) => p.steps.some((s) => s.ref === a.id));

  view.classList.add('stack');
  view.append(
    el('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' }, el('a', { href: '#/knowledge' }, 'Knowledge Centre'), ' / ', el('span', null, cat.label), ' / ', el('span', { 'aria-current': 'page' }, a.title)),
    el('article', { class: 'card kb-article', 'aria-labelledby': 'kb-h' },
      el('header', { class: 'page-head' },
        el('span', { class: 'eyebrow' }, cat.label),
        el('h1', { id: 'kb-h' }, a.title),
        el('p', { class: 'lede' }, a.summary),
        el('div', { class: 'meta-row' }, el('span', { class: `level level-${a.level}` }, a.level), el('span', { class: 'kpi-sub' }, `${readingMinutes(a)} min read`), provenanceBadge('documented'))),
      ...a.sections.map((s) => el('section', null,
        el('h2', null, s.heading),
        ...(s.paragraphs || []).map((p) => el('p', null, p)),
        s.bullets ? el('ul', { class: 'checklist' }, s.bullets.map((b) => el('li', null, b))) : null)),
      a.practice.length ? el('section', { class: 'kb-practice' }, el('h2', null, 'Practise in Sentinel X'),
        el('div', { class: 'btn-row' }, a.practice.map((p) => el('a', { class: 'btn btn-sm', href: p.href }, p.label)))) : null,
      el('section', null, el('h2', null, 'References'), sourceList(a.refs.map((r) => data.references[r])))),
    inPathways.length ? el('section', { class: 'card', 'aria-labelledby': 'kb-pw' }, el('h2', { id: 'kb-pw' }, 'Part of these learning pathways'),
      el('div', { class: 'btn-row' }, inPathways.map((p) => el('a', { class: 'btn btn-sm', href: '#/knowledge' }, p.title)))) : null,
    el('nav', { class: 'hero-actions', 'aria-label': 'Article pager' },
      sameCat[i - 1] ? el('a', { class: 'btn', href: `#/knowledge/${sameCat[i - 1].id}` }, `← ${sameCat[i - 1].title}`) : el('a', { class: 'btn', href: '#/knowledge' }, '← Knowledge Centre'),
      sameCat[i + 1] ? el('a', { class: 'btn', href: `#/knowledge/${sameCat[i + 1].id}` }, `${sameCat[i + 1].title} →`) : null)
  );
  return () => view.classList.remove('stack');
}
