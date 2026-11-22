/**
 * Sortable, paginated data table.
 *
 *   const table = createDataTable({
 *     caption: 'Security events',
 *     columns: [{ key: 'id', label: 'ID', sortable: true, render: (row) => node }],
 *     rows, pageSize: 10, initialSort: { key: 'ts', dir: 'desc' },
 *     onRowActivate: (row, triggerEl) => {...}
 *   });
 *   container.append(table.element); table.setRows(filtered);
 *
 * Accessibility: real <table> with <caption>, header sort buttons with
 * aria-sort on the <th>, a per-row "open" button (keyboard reachable),
 * pagination announced through a polite live region. Mouse users may also
 * click anywhere on a row.
 */
import { el, clear } from '../utils/dom.js';

/** Stable sort; returns a new array. getValue(row) defaults to row[key]. */
export function sortRows(rows, key, dir = 'asc', getValue) {
  const value = getValue || ((r) => r[key]);
  const factor = dir === 'desc' ? -1 : 1;
  return rows
    .map((row, i) => ({ row, i, v: value(row) }))
    .sort((a, b) => {
      const av = a.v, bv = b.v;
      let c;
      if (av == null && bv == null) c = 0;
      else if (av == null) c = 1;          // nulls always last
      else if (bv == null) c = -1;
      else if (typeof av === 'number' && typeof bv === 'number') c = (av - bv) * factor;
      else c = String(av).localeCompare(String(bv), 'en', { numeric: true, sensitivity: 'base' }) * factor;
      return c || a.i - b.i;
    })
    .map((x) => x.row);
}

/** Slice rows for a 1-based page. Clamps out-of-range pages. */
export function paginate(rows, page, size) {
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(1, page), pages);
  const start = (p - 1) * size;
  return { items: rows.slice(start, start + size), page: p, pages, total, start: total ? start + 1 : 0, end: Math.min(start + size, total) };
}

export function createDataTable({
  caption, columns, rows = [], pageSize = 10, initialSort = null,
  onRowActivate = null, rowLabel = (r) => r.id, emptyText = 'No matching records.'
}) {
  let data = rows;
  let sort = initialSort ? { ...initialSort } : null;
  let page = 1;

  const thead = el('thead');
  const tbody = el('tbody');
  const status = el('p', { class: 'table-status', role: 'status', 'aria-live': 'polite' });
  const prevBtn = el('button', { class: 'btn btn-sm', type: 'button' }, '‹ Prev');
  const nextBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Next ›');
  const pageLabel = el('span', { class: 'page-label' });

  const table = el('table', { class: 'data-table' }, el('caption', { class: 'visually-hidden' }, caption), thead, tbody);
  const wrap = el('div', { class: 'table-wrap', role: 'region', 'aria-label': caption, tabindex: '0' }, table);
  const element = el('div', { class: 'data-table-component' },
    wrap,
    el('div', { class: 'table-foot' }, status, el('div', { class: 'pager' }, prevBtn, pageLabel, nextBtn))
  );

  prevBtn.addEventListener('click', () => { page -= 1; renderBody(); });
  nextBtn.addEventListener('click', () => { page += 1; renderBody(); });

  function renderHead() {
    clear(thead);
    const tr = el('tr');
    if (onRowActivate) tr.append(el('th', { scope: 'col', class: 'col-action' }, el('span', { class: 'visually-hidden' }, 'Open')));
    for (const col of columns) {
      const isSorted = sort && sort.key === col.key;
      const ariaSort = isSorted ? (sort.dir === 'asc' ? 'ascending' : 'descending') : (col.sortable ? 'none' : null);
      const th = el('th', { scope: 'col', 'aria-sort': ariaSort, class: col.className || null });
      if (col.sortable) {
        const btn = el('button', { class: 'th-sort', type: 'button' },
          col.label,
          el('span', { class: 'sort-icon', 'aria-hidden': 'true' }, isSorted ? (sort.dir === 'asc' ? '▲' : '▼') : '↕')
        );
        btn.addEventListener('click', () => {
          sort = isSorted ? { key: col.key, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { key: col.key, dir: col.defaultDir || 'asc' };
          page = 1;
          renderHead();
          renderBody();
          // keep focus on the same header after re-render
          thead.querySelectorAll('.th-sort')[columns.filter((c) => c.sortable).indexOf(col)]?.focus();
        });
        th.append(btn);
      } else {
        th.append(col.label);
      }
      tr.append(th);
    }
    thead.append(tr);
  }

  function renderBody() {
    clear(tbody);
    let view = data;
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      view = sortRows(data, sort.key, sort.dir, col && col.sortValue);
    }
    const pg = paginate(view, page, pageSize);
    page = pg.page;

    if (!pg.total) {
      const span = columns.length + (onRowActivate ? 1 : 0);
      tbody.append(el('tr', null, el('td', { colspan: String(span), class: 'empty-cell' }, emptyText)));
    }
    for (const row of pg.items) {
      const tr = el('tr', { class: onRowActivate ? 'is-clickable' : null });
      if (onRowActivate) {
        const open = el('button', { class: 'row-open', type: 'button', 'aria-label': `Open details for ${rowLabel(row)}`, 'aria-haspopup': 'dialog' }, '›');
        open.addEventListener('click', (e) => { e.stopPropagation(); onRowActivate(row, open); });
        tr.addEventListener('click', (e) => {
          if (e.target.closest('a, button, input, select')) return;
          onRowActivate(row, open);
        });
        tr.append(el('td', { class: 'col-action' }, open));
      }
      for (const col of columns) {
        const content = col.render ? col.render(row) : row[col.key];
        tr.append(el('td', { class: col.className || null }, content ?? '—'));
      }
      tbody.append(tr);
    }

    status.textContent = pg.total ? `Showing ${pg.start}–${pg.end} of ${pg.total}` : 'No results';
    pageLabel.textContent = `Page ${pg.page} of ${pg.pages}`;
    prevBtn.disabled = pg.page <= 1;
    nextBtn.disabled = pg.page >= pg.pages;
  }

  renderHead();
  renderBody();

  return {
    element,
    setRows(next) { data = next; page = 1; renderBody(); },
    /** Rows in current sort order (all pages) — used for export. */
    getSortedRows() {
      if (!sort) return data.slice();
      const col = columns.find((c) => c.key === sort.key);
      return sortRows(data, sort.key, sort.dir, col && col.sortValue);
    }
  };
}
