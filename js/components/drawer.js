/**
 * Side drawer built on the native <dialog> element.
 * showModal() gives us a focus trap, inert background and Escape-to-close for
 * free; we add a backdrop click, a close button, and explicit focus return.
 * Only one drawer is open at a time.
 */
import { el } from '../utils/dom.js';

let current = null;
let uid = 0;

export function openDrawer({ title, subtitle = null, content, actions = [], returnFocus = document.activeElement, onClose = null }) {
  if (current) current.close();

  const titleId = `drawer-title-${++uid}`;
  const closeBtn = el('button', { class: 'icon-btn drawer-close', type: 'button', 'aria-label': 'Close panel' }, '✕');
  const dialog = el('dialog', { class: 'drawer', 'aria-labelledby': titleId },
    el('header', { class: 'drawer-head' },
      el('div', null,
        subtitle ? el('span', { class: 'eyebrow' }, subtitle) : null,
        el('h2', { id: titleId }, title)
      ),
      closeBtn
    ),
    el('div', { class: 'drawer-body' }, content),
    actions.length ? el('footer', { class: 'drawer-foot' }, actions) : null
  );

  const close = () => { if (dialog.open) dialog.close(); };
  closeBtn.addEventListener('click', close);
  // Click on the backdrop (the dialog element itself, outside its content box) closes.
  dialog.addEventListener('click', (e) => {
    if (e.target !== dialog) return;
    const r = dialog.getBoundingClientRect();
    const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
    if (!inside) close();
  });
  dialog.addEventListener('close', () => {
    dialog.remove();
    if (current && current.dialog === dialog) current = null;
    if (returnFocus && typeof returnFocus.focus === 'function' && document.contains(returnFocus)) returnFocus.focus();
    if (onClose) onClose();
  });

  document.body.append(dialog);
  dialog.showModal();
  closeBtn.focus();

  current = { dialog, close };
  return current;
}

export function closeDrawer() { if (current) current.close(); }
