/**
 * Safe DOM construction helpers.
 *
 * Security contract: data is NEVER interpreted as HTML. Text goes through
 * textContent / createTextNode, attributes are allow-listed, event-handler
 * attributes are rejected, and URLs are restricted to safe schemes.
 * Pure helpers (safeUrl, defang, formatters) have no DOM dependency so they
 * can be unit-tested in isolation.
 */

const SAFE_URL_SCHEMES = new Set(['http:', 'https:', 'mailto:']);
// Relative URLs are resolved against a placeholder origin exactly as a browser would
// resolve them; if the result leaves that origin, the "relative" URL was really an
// off-site one in disguise (e.g. "/\evil.example" or "/<TAB>/evil.example").
const RELATIVE_BASE = new URL('https://relative.invalid/');

/**
 * Return the URL if it is same-origin relative or uses an allowed scheme, otherwise '#'.
 * Blocks javascript:, data:, vbscript:, protocol-relative and backslash/whitespace tricks.
 */
export function safeUrl(value) {
  if (typeof value !== 'string') return '#';
  const v = value.trim();
  if (v === '') return '#';
  // URL parsers silently drop TAB/CR/LF, which is how scheme and host checks get bypassed.
  if (/[\u0000-\u001f\u007f]/.test(v)) return '#';
  let u;
  try { u = new URL(v, RELATIVE_BASE); } catch { return '#'; }
  if (!/^[a-z][a-z0-9+.-]*:/i.test(v)) return u.origin === RELATIVE_BASE.origin ? v : '#';
  return SAFE_URL_SCHEMES.has(u.protocol) ? u.href : '#';
}

/**
 * Defang an indicator for safe display (every dot in the host is bracketed):
 *   203.0.113.5               -> 203[.]0[.]113[.]5
 *   https://bad.example/a.php -> hxxps://bad[.]example/a.php
 */
export function defang(indicator) {
  if (typeof indicator !== 'string') return '';
  const m = indicator.trim().match(/^(https?):\/\/([^/?#]+)(.*)$/i);
  if (m) {
    const scheme = m[1].toLowerCase().replace(/^http/, 'hxxp');
    return `${scheme}://${m[2].replace(/\./g, '[.]')}${m[3]}`;
  }
  return indicator.trim().replace(/\./g, '[.]');
}

const nf = new Intl.NumberFormat('en-GB');
export const formatNumber = (n) => (Number.isFinite(n) ? nf.format(n) : '—');

/** HH:MM:SS UTC for a Date or ISO string. Returns '—' if invalid. */
export function formatUtcTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(11, 19);
}

/** YYYY-MM-DD HH:MM UTC */
export function formatUtcDateTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}

const ALLOWED_ATTRS = new Set([
  'id', 'class', 'href', 'src', 'alt', 'title', 'role', 'tabindex', 'type', 'name', 'value',
  'for', 'placeholder', 'datetime', 'width', 'height', 'hidden', 'disabled', 'target', 'rel',
  'viewBox', 'd', 'fill', 'stroke', 'stroke-width', 'aria-hidden', 'aria-label', 'aria-current',
  'aria-expanded', 'aria-controls', 'aria-pressed', 'aria-live', 'aria-describedby', 'aria-labelledby',
  // Phase 2 — tables, forms, tabs, dialogs
  'aria-sort', 'aria-selected', 'aria-modal', 'aria-haspopup', 'aria-busy', 'aria-atomic',
  'scope', 'colspan', 'maxlength', 'autocomplete', 'spellcheck', 'inputmode', 'min', 'max',
  'download', 'checked', 'selected', 'open', 'lang', 'rows',
  'aria-valuemin', 'aria-valuemax', 'aria-valuenow',
  // Phase 3 — SVG charts
  'x', 'y', 'x1', 'x2', 'y1', 'y2', 'cx', 'cy', 'r', 'rx', 'points', 'transform', 'text-anchor',
  'dominant-baseline', 'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin',
  'preserveAspectRatio', 'focusable', 'opacity'
]);
const SVG_NS = 'http://www.w3.org/2000/svg';
const SVG_TAGS = new Set(['svg', 'path', 'g', 'rect', 'circle', 'line', 'polyline', 'polygon', 'text', 'title']);
const URL_ATTRS = new Set(['href', 'src']);

/**
 * Create an element.
 *   el('a', { href: '#/soc', class: 'btn' }, 'Open SOC')
 *   el('ul', null, items.map(i => el('li', null, i.name)))
 * Children may be strings, numbers, Nodes, arrays, or null/false (skipped).
 */
export function el(tag, attrs, ...children) {
  // 'title' is only an SVG element when explicitly requested as 'svg:title'.
  const svgTag = tag.startsWith('svg:') ? tag.slice(4) : (tag !== 'title' && SVG_TAGS.has(tag) ? tag : null);
  const node = svgTag ? document.createElementNS(SVG_NS, svgTag) : document.createElement(tag);

  if (attrs) {
    for (const [key, raw] of Object.entries(attrs)) {
      if (raw === null || raw === undefined || raw === false) continue;
      if (key.startsWith('data-')) { node.setAttribute(key, String(raw)); continue; }
      if (!ALLOWED_ATTRS.has(key)) {
        throw new Error(`el(): attribute "${key}" is not allow-listed`);
      }
      const value = URL_ATTRS.has(key) ? safeUrl(String(raw)) : String(raw === true ? '' : raw);
      node.setAttribute(key, value);
    }
    if (attrs.target === '_blank') node.setAttribute('rel', 'noopener noreferrer');
  }
  append(node, children);
  return node;
}

function append(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else if (child instanceof Node) parent.appendChild(child);
    else parent.appendChild(document.createTextNode(String(child)));
  }
}

/** Remove all children. */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** Severity / provenance badge. Unknown values fall back to a neutral style. */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const PROVENANCE = ['simulated', 'documented', 'lab'];

export function severityBadge(sev) {
  const s = SEVERITIES.includes(sev) ? sev : 'info';
  return el('span', { class: `badge sev-${s}` }, s);
}

export function provenanceBadge(kind) {
  const p = PROVENANCE.includes(kind) ? kind : 'simulated';
  const label = { simulated: 'Simulated', documented: 'Documented', lab: 'Lab result' }[p];
  return el('span', { class: `badge prov-${p}`, title: PROVENANCE_HELP[p] }, label);
}

export const PROVENANCE_HELP = {
  simulated: 'Synthetic demonstration data generated for this project — not real telemetry.',
  documented: 'Real-world intelligence from a cited public source, with date and link.',
  lab: 'Produced by the author in an isolated, authorised lab environment.'
};
