/**
 * Filter bar: free-text search, multi-select chip groups, single-select
 * dropdowns, a date range and a reset button. Emits a plain state object;
 * the filtering itself is the pure function applyFilters() so it can be
 * unit-tested and reused by every module.
 *
 * State shape:
 *   { q: 'text', multi: { severity: ['high'] }, single: { status: 'open' }, from: 'YYYY-MM-DD', to: 'YYYY-MM-DD' }
 */
import { el } from '../utils/dom.js';

const MAX_QUERY = 200;

export function emptyState(config = {}) {
  return {
    q: '',
    multi: Object.fromEntries((config.chips || []).map((c) => [c.key, []])),
    single: Object.fromEntries((config.selects || []).map((s) => [s.key, ''])),
    from: '',
    to: ''
  };
}

/**
 * Filter rows.
 *  - q: whitespace-separated terms, all must appear (case-insensitive) in any searchField
 *  - multi: empty array = no constraint; otherwise row[key] must be one of the values
 *  - single: '' = no constraint; otherwise strict equality
 *  - from/to: inclusive UTC calendar dates compared against row[dateField]
 */
export function applyFilters(rows, state, { searchFields = [], dateField = null } = {}) {
  const terms = String(state.q || '').slice(0, MAX_QUERY).toLowerCase().split(/\s+/).filter(Boolean);
  const multi = Object.entries(state.multi || {}).filter(([, v]) => v && v.length);
  const single = Object.entries(state.single || {}).filter(([, v]) => v !== '' && v != null);
  const from = state.from ? Date.parse(state.from + 'T00:00:00Z') : null;
  const to = state.to ? Date.parse(state.to + 'T23:59:59.999Z') : null;

  return rows.filter((row) => {
    for (const [k, values] of multi) if (!values.includes(row[k])) return false;
    for (const [k, value] of single) if (row[k] !== value) return false;
    if (dateField && (from !== null || to !== null)) {
      const t = Date.parse(row[dateField]);
      if (Number.isNaN(t)) return false;
      if (from !== null && !Number.isNaN(from) && t < from) return false;
      if (to !== null && !Number.isNaN(to) && t > to) return false;
    }
    if (terms.length) {
      const hay = searchFields.map((f) => String(row[f] ?? '')).join(' \u0000 ').toLowerCase();
      for (const term of terms) if (!hay.includes(term)) return false;
    }
    return true;
  });
}

/** True when the state applies no constraint at all. */
export function isEmptyState(state) {
  return !state.q && !state.from && !state.to &&
    Object.values(state.multi || {}).every((v) => !v.length) &&
    Object.values(state.single || {}).every((v) => !v);
}

let uid = 0;

/**
 * config: {
 *   searchLabel, searchPlaceholder,
 *   chips:   [{ key, label, options: [{ value, label, className }] }],
 *   selects: [{ key, label, options: [{ value, label }] }],
 *   dateRange: { label } | null,
 *   onChange(state)
 * }
 */
export function createFilterBar(config) {
  const id = `fb${++uid}`;
  let state = emptyState(config);
  let debounce = 0;
  const emit = () => config.onChange({ ...state, multi: { ...state.multi }, single: { ...state.single } });

  /* search */
  const search = el('input', {
    id: `${id}-q`, class: 'input', type: 'search', maxlength: String(MAX_QUERY),
    placeholder: config.searchPlaceholder || 'Search…', autocomplete: 'off', spellcheck: 'false'
  });
  search.addEventListener('input', () => {
    window.clearTimeout(debounce);
    debounce = window.setTimeout(() => { state.q = search.value; emit(); }, 150);
  });

  /* chip groups */
  const chipGroups = (config.chips || []).map((group) => {
    const buttons = group.options.map((opt) => {
      const b = el('button', { class: `chip ${opt.className || ''}`, type: 'button', 'aria-pressed': 'false', 'data-value': opt.value }, opt.label);
      b.addEventListener('click', () => {
        const set = new Set(state.multi[group.key]);
        set.has(opt.value) ? set.delete(opt.value) : set.add(opt.value);
        state.multi[group.key] = group.options.map((o) => o.value).filter((v) => set.has(v));
        b.setAttribute('aria-pressed', String(set.has(opt.value)));
        emit();
      });
      return b;
    });
    return { group, buttons, node: el('div', { class: 'filter-field' },
      el('span', { class: 'filter-label', id: `${id}-${group.key}-l` }, group.label),
      el('div', { class: 'chip-group', role: 'group', 'aria-labelledby': `${id}-${group.key}-l` }, buttons)
    ) };
  });

  /* selects */
  const selects = (config.selects || []).map((s) => {
    const select = el('select', { id: `${id}-${s.key}`, class: 'input' },
      el('option', { value: '' }, `All`),
      s.options.map((o) => el('option', { value: o.value }, o.label))
    );
    select.addEventListener('change', () => { state.single[s.key] = select.value; emit(); });
    return { s, select, node: el('div', { class: 'filter-field' }, el('label', { class: 'filter-label', for: select.id }, s.label), select) };
  });

  /* date range */
  let fromInput = null, toInput = null, dateNode = null;
  if (config.dateRange) {
    fromInput = el('input', { id: `${id}-from`, class: 'input', type: 'date' });
    toInput = el('input', { id: `${id}-to`, class: 'input', type: 'date' });
    const onDate = () => { state.from = fromInput.value; state.to = toInput.value; emit(); };
    fromInput.addEventListener('change', onDate);
    toInput.addEventListener('change', onDate);
    dateNode = el('div', { class: 'filter-field' },
      el('span', { class: 'filter-label' }, config.dateRange.label || 'Date (UTC)'),
      el('div', { class: 'date-range' },
        el('label', { class: 'visually-hidden', for: fromInput.id }, 'From date'), fromInput,
        el('span', { 'aria-hidden': 'true' }, '→'),
        el('label', { class: 'visually-hidden', for: toInput.id }, 'To date'), toInput
      )
    );
  }

  const reset = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Reset filters');
  reset.addEventListener('click', () => {
    state = emptyState(config);
    window.clearTimeout(debounce);
    syncControls();
    emit();
    search.focus();
  });

  const element = el('div', { class: 'filter-bar', role: 'search', 'aria-label': config.ariaLabel || 'Filters' },
    el('div', { class: 'filter-field filter-search' },
      el('label', { class: 'filter-label', for: search.id }, config.searchLabel || 'Search'),
      search
    ),
    chipGroups.map((g) => g.node),
    selects.map((s) => s.node),
    dateNode,
    el('div', { class: 'filter-field filter-actions' }, reset)
  );

  /** Sync every control to `state` (used by reset and programmatic updates). */
  function syncControls() {
    search.value = state.q;
    chipGroups.forEach((g) => g.buttons.forEach((b) =>
      b.setAttribute('aria-pressed', String((state.multi[g.group.key] || []).includes(b.dataset.value)))));
    selects.forEach((s) => { s.select.value = state.single[s.s.key] || ''; });
    if (fromInput) { fromInput.value = state.from; toInput.value = state.to; }
  }

  /**
   * Programmatically change filters, e.g. from a chart click:
   *   update({ multi: { severity: ['high'] } }), update({ single: { status: 'open' } }), update({ q: 'T1059.001' })
   * Unknown keys and option values are ignored so callers cannot inject arbitrary state.
   */
  function update(partial = {}) {
    if (typeof partial.q === 'string') state.q = partial.q.slice(0, MAX_QUERY);
    for (const g of chipGroups) {
      const v = partial.multi && partial.multi[g.group.key];
      if (Array.isArray(v)) {
        const allowed = g.group.options.map((o) => o.value);
        state.multi[g.group.key] = allowed.filter((a) => v.includes(a));
      }
    }
    for (const s of selects) {
      const v = partial.single && partial.single[s.s.key];
      if (typeof v === 'string' && (v === '' || s.s.options.some((o) => o.value === v))) state.single[s.s.key] = v;
    }
    if (fromInput) {
      if (typeof partial.from === 'string') state.from = partial.from;
      if (typeof partial.to === 'string') state.to = partial.to;
    }
    window.clearTimeout(debounce);
    syncControls();
    emit();
  }

  return { element, getState: () => state, update };
}
