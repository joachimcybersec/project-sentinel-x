/**
 * Security-event detail drawer, shared by the SOC dashboard and the UI kit.
 */
import { el, formatUtcDateTime, severityBadge, provenanceBadge } from '../utils/dom.js';
import { mitreUrl } from '../data-service.js';
import { openDrawer } from './drawer.js';
import { toast } from './toast.js';
import { createCodeBlock } from './code-block.js';

const title = (s) => s.charAt(0).toUpperCase() + s.slice(1).replace(/-/g, ' ');

export function openEventDrawer(row, trigger, { related = [] } = {}) {
  const url = mitreUrl(row.mitre);
  const copyBtn = el('button', { class: 'btn btn-sm', type: 'button' }, 'Copy event JSON');
  copyBtn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(row, null, 2)); toast(`${row.id} copied`, { variant: 'success' }); }
    catch { toast('Clipboard unavailable in this context.', { variant: 'warning' }); }
  });
  const closeBtn = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Close');

  const drawer = openDrawer({
    title: row.message,
    subtitle: row.id,
    returnFocus: trigger,
    content: [
      el('div', { class: 'meta-row' }, severityBadge(row.severity), provenanceBadge('simulated'), el('span', { class: 'badge status-planned' }, row.status)),
      el('section', { class: 'drawer-section' },
        el('h3', null, 'Event details'),
        el('dl', { class: 'dl' },
          el('dt', null, 'Timestamp'), el('dd', null, formatUtcDateTime(row.ts)),
          el('dt', null, 'Host'), el('dd', null, row.host),
          el('dt', null, 'User'), el('dd', null, row.user),
          el('dt', null, 'Log source'), el('dd', null, row.source),
          el('dt', null, 'Category'), el('dd', null, title(row.category)),
          el('dt', null, 'ATT&CK'), el('dd', null, url ? el('a', { href: url, target: '_blank' }, `${row.mitre} ↗`) : 'Not mapped')
        )
      ),
      related.length ? el('section', { class: 'drawer-section' },
        el('h3', null, `Related activity on ${row.host}`),
        el('ul', { class: 'mini-feed' }, related.map((r) => el('li', null,
          el('time', { datetime: r.ts }, formatUtcDateTime(r.ts).slice(11)), ' ', severityBadge(r.severity), ' ', r.message)))
      ) : null,
      el('section', { class: 'drawer-section' },
        el('h3', null, 'Raw record'),
        createCodeBlock({ code: JSON.stringify(row, null, 2), language: 'json', title: `${row.id}.json` })
      ),
      el('section', { class: 'drawer-section' },
        el('div', { class: 'notice' }, el('span', { 'aria-hidden': 'true' }, 'ⓘ'),
          el('span', null, 'Investigation playbooks for this event type arrive with the Incident Response module (Phase 5).'))
      )
    ],
    actions: [copyBtn, closeBtn]
  });
  closeBtn.addEventListener('click', drawer.close);
  return drawer;
}
