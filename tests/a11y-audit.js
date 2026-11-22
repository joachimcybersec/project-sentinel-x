/**
 * Lightweight accessibility audit (Phase 10).
 *
 * Runs in the page (imported by tests/run-in-browser.mjs for every route, or from
 * the console: (await import('/tests/a11y-audit.js')).audit()). It implements a
 * focused subset of WCAG 2.2 AA checks that can be decided from the DOM alone.
 * It does NOT replace axe-core, Lighthouse or a screen-reader pass: it cannot judge
 * reading order, meaningful alt text, focus visibility or text over gradients/images.
 *
 * Returns an array of { rule, detail, el } (el is a short selector-like description).
 */

const describe = (n) => {
  if (!n || !n.tagName) return String(n);
  const id = n.id ? `#${n.id}` : '';
  const cls = typeof n.className === 'string' && n.className.trim() ? `.${n.className.trim().split(/\s+/).slice(0, 2).join('.')}` : '';
  const text = (n.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40);
  return `${n.tagName.toLowerCase()}${id}${cls}${text ? ` "${text}"` : ''}`;
};

const visible = (n) => {
  if (!(n instanceof Element)) return false;
  if (n.closest('[hidden], [aria-hidden="true"], dialog:not([open]), template')) return false;
  const s = getComputedStyle(n);
  if (s.display === 'none' || s.visibility === 'hidden') return false;
  return n.getClientRects().length > 0;
};

/** Approximate accessible name (enough for the patterns this site uses). */
export function accessibleName(n) {
  const lb = n.getAttribute('aria-labelledby');
  if (lb) return lb.split(/\s+/).map((id) => document.getElementById(id)?.textContent || '').join(' ').trim();
  const al = n.getAttribute('aria-label');
  if (al && al.trim()) return al.trim();
  if (n.labels && n.labels.length) return [...n.labels].map((l) => l.textContent).join(' ').trim();
  if (n.tagName === 'IMG') return (n.getAttribute('alt') || '').trim();
  if (n.tagName === 'INPUT' && ['submit', 'button', 'reset'].includes(n.type)) return n.value;
  const svgTitle = n.querySelector(':scope > title');
  if (n instanceof SVGElement && svgTitle) return svgTitle.textContent.trim();
  // Text content, excluding aria-hidden descendants.
  let out = '';
  const walk = (x) => {
    for (const c of x.childNodes) {
      if (c.nodeType === 3) out += c.textContent;
      else if (c.nodeType === 1 && c.getAttribute('aria-hidden') !== 'true') {
        if (c.tagName === 'IMG') out += c.getAttribute('alt') || '';
        else walk(c);
      }
    }
  };
  walk(n);
  return out.replace(/\s+/g, ' ').trim() || (n.getAttribute('title') || '').trim();
}

/* ---------- colour contrast ---------- */
function parseColor(c) {
  const m = c.match(/rgba?\(([^)]+)\)/);
  if (!m) return null;
  const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
  return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
}
const blend = (fg, bg) => ({ r: fg.r * fg.a + bg.r * (1 - fg.a), g: fg.g * fg.a + bg.g * (1 - fg.a), b: fg.b * fg.a + bg.b * (1 - fg.a), a: 1 });
const lum = ({ r, g, b }) => {
  const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};
export const contrastRatio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

/** Effective background: blend translucent layers up the tree. Returns null if an image/gradient is in the way. */
function effectiveBg(n) {
  const layers = [];
  for (let x = n; x; x = x.parentElement) {
    const s = getComputedStyle(x);
    if (s.backgroundImage && s.backgroundImage !== 'none') return null;
    const c = parseColor(s.backgroundColor);
    if (c && c.a > 0) { layers.push(c); if (c.a >= 1) break; }
  }
  let bg = { r: 255, g: 255, b: 255, a: 1 };
  for (let i = layers.length - 1; i >= 0; i--) bg = blend(layers[i], bg);
  return bg;
}

export function audit(root = document) {
  const issues = [];
  const add = (rule, detail, n) => issues.push({ rule, detail, el: describe(n) });
  const all = [...root.querySelectorAll('*')];

  // Duplicate ids
  const seen = new Map();
  for (const n of root.querySelectorAll('[id]')) seen.set(n.id, (seen.get(n.id) || 0) + 1);
  for (const [id, c] of seen) if (c > 1) add('duplicate-id', `id "${id}" used ${c} times`, document.getElementById(id));

  // ID references resolve
  for (const n of root.querySelectorAll('[aria-labelledby], [aria-describedby], [aria-controls], label[for]')) {
    for (const attr of ['aria-labelledby', 'aria-describedby', 'aria-controls', 'for']) {
      const v = n.getAttribute(attr);
      if (!v || (attr === 'for' && n.tagName !== 'LABEL')) continue;
      for (const id of v.split(/\s+/)) if (!document.getElementById(id)) add('broken-idref', `${attr}="${id}" has no target`, n);
    }
  }

  // Images and SVGs
  for (const n of root.querySelectorAll('img')) if (!n.hasAttribute('alt')) add('img-alt', 'img without alt attribute', n);
  for (const n of root.querySelectorAll('svg')) {
    if (n.closest('[aria-hidden="true"]') || !visible(n)) continue;
    const role = n.getAttribute('role');
    const named = accessibleName(n);
    if (n.parentElement && n.parentElement.closest('svg')) continue;
    if (!role && !named && !n.closest('button, a')) add('svg-name', 'visible SVG with no role/name and not aria-hidden', n);
    if (role === 'img' && !named) add('svg-name', 'role="img" SVG without a name', n);
  }

  // Interactive elements have names
  const interactive = root.querySelectorAll('a[href], button, [role="button"], [role="tab"], [role="link"], input:not([type="hidden"]), select, textarea, summary');
  for (const n of interactive) {
    if (!visible(n)) continue;
    if (!accessibleName(n) && !(n.tagName === 'INPUT' && n.placeholder && n.getAttribute('aria-label'))) add('control-name', 'interactive element without accessible name', n);
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(n.tagName) && !['submit', 'button', 'reset'].includes(n.type)) {
      if (!(n.labels && n.labels.length) && !n.getAttribute('aria-label') && !n.getAttribute('aria-labelledby')) add('form-label', 'form control without a label', n);
    }
  }

  // Nested interactive content
  for (const n of root.querySelectorAll('a[href] a[href], a[href] button, button a[href], button button')) add('nested-interactive', 'interactive element inside another', n);

  // Positive tabindex
  for (const n of root.querySelectorAll('[tabindex]')) if (Number(n.getAttribute('tabindex')) > 0) add('tabindex-positive', `tabindex=${n.getAttribute('tabindex')}`, n);

  // ARIA tab structure
  for (const n of root.querySelectorAll('[role="tab"]')) if (!n.closest('[role="tablist"]')) add('aria-structure', 'role=tab outside a tablist', n);
  for (const n of root.querySelectorAll('[role="tab"][aria-controls]')) {
    const p = document.getElementById(n.getAttribute('aria-controls'));
    if (p && p.getAttribute('role') !== 'tabpanel') add('aria-structure', 'tab controls an element that is not role=tabpanel', n);
  }

  // Headings: exactly one visible h1 in the view, no skipped levels
  const view = document.getElementById('view') || root;
  const heads = [...view.querySelectorAll('h1, h2, h3, h4, h5, h6')].filter(visible);
  const h1s = heads.filter((h) => h.tagName === 'H1');
  if (h1s.length !== 1) add('heading-h1', `${h1s.length} visible h1 elements in the view`, view);
  let prev = 1;
  for (const h of heads) {
    const lvl = Number(h.tagName[1]);
    if (lvl > prev + 1) add('heading-order', `h${prev} followed by h${lvl}`, h);
    prev = lvl;
    if (!h.textContent.trim()) add('heading-empty', 'empty heading', h);
  }

  // Landmarks
  if (!document.querySelector('main')) add('landmark', 'no <main> landmark', document.body);
  if (!document.documentElement.lang) add('lang', '<html> has no lang', document.documentElement);
  if (!document.title.trim()) add('title', 'document has no title', document.documentElement);

  // Tables
  for (const t of root.querySelectorAll('table')) {
    if (!visible(t)) continue;
    if (!t.querySelector('th')) add('table-headers', 'data table without th cells', t);
    if (!t.querySelector('caption') && !t.getAttribute('aria-label') && !t.getAttribute('aria-labelledby')) add('table-name', 'table without caption or label', t);
  }

  // Text contrast (direct text only; skips text over images/gradients, which needs a manual check)
  const checked = new Set();
  for (const n of all) {
    if (!visible(n) || checked.has(n)) continue;
    const hasText = [...n.childNodes].some((c) => c.nodeType === 3 && c.textContent.trim());
    if (!hasText || n.closest('svg')) continue;
    checked.add(n);
    const s = getComputedStyle(n);
    const fg = parseColor(s.color);
    const bg = effectiveBg(n);
    if (!fg || !bg) continue;
    const opacity = Number(s.opacity);
    const ratio = contrastRatio(blend({ ...fg, a: fg.a * (opacity || 1) }, bg), bg);
    const size = parseFloat(s.fontSize);
    const large = size >= 24 || (size >= 18.66 && Number(s.fontWeight) >= 700);
    const need = large ? 3 : 4.5;
    if (n.closest('button:disabled, [aria-disabled="true"]')) continue; // inactive controls are exempt (WCAG 1.4.3)
    if (ratio + 0.005 < need) add('contrast', `${ratio.toFixed(2)}:1 (needs ${need}:1) ${s.color} on rgb(${Math.round(bg.r)}, ${Math.round(bg.g)}, ${Math.round(bg.b)})`, n);
  }

  // Touch target size (WCAG 2.2 SC 2.5.8 minimum 24x24 CSS px; inline links in text are exempt)
  for (const n of interactive) {
    if (!visible(n) || (n.tagName === 'A' && n.closest('p, li, dd, td') && getComputedStyle(n).display === 'inline')) continue;
    if (n.tagName === 'INPUT' && (n.type === 'checkbox' || n.type === 'radio')) continue;
    const r = n.getBoundingClientRect();
    if (r.width > 0 && (r.width < 24 || r.height < 24)) add('target-size', `${Math.round(r.width)}x${Math.round(r.height)} px`, n);
  }

  return issues;
}
