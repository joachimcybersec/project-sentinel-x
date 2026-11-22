/**
 * Toast notifications.
 * A single polite live region announces messages; error toasts use role="alert".
 * Auto-dismiss pauses while the toast is hovered or focused; every toast has a
 * dismiss button so nothing disappears before a keyboard user can read it.
 */
import { el } from '../utils/dom.js';

const VARIANTS = new Set(['info', 'success', 'warning', 'error']);
let region = null;

function getRegion() {
  if (region && document.body.contains(region)) return region;
  region = el('div', { class: 'toast-region', 'aria-live': 'polite', 'aria-atomic': 'false' });
  document.body.append(region);
  return region;
}

export function toast(message, { variant = 'info', timeout = 4500 } = {}) {
  const v = VARIANTS.has(variant) ? variant : 'info';
  const dismiss = el('button', { class: 'toast-dismiss', type: 'button', 'aria-label': 'Dismiss notification' }, '✕');
  const node = el('div', { class: `toast toast-${v}`, role: v === 'error' ? 'alert' : 'status' },
    el('span', { class: 'toast-msg' }, message),
    dismiss
  );

  let timer = 0;
  const remove = () => {
    window.clearTimeout(timer);
    node.classList.add('is-leaving');
    window.setTimeout(() => node.remove(), 200);
  };
  const arm = () => { if (timeout > 0) timer = window.setTimeout(remove, timeout); };
  const disarm = () => window.clearTimeout(timer);

  dismiss.addEventListener('click', remove);
  node.addEventListener('mouseenter', disarm);
  node.addEventListener('mouseleave', arm);
  node.addEventListener('focusin', disarm);
  node.addEventListener('focusout', arm);

  const r = getRegion();
  r.append(node);
  while (r.children.length > 4) r.firstElementChild.remove();
  arm();
  return { dismiss: remove, node };
}
