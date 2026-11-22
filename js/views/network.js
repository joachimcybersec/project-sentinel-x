/**
 * MODULE 08 — Network Security Intelligence (#/network).
 *   Segmentation & Zero Trust · compare three policy sets against the incident's attack paths
 *   Packet explorer            · real header bytes with verified checksums, field-by-field
 *   Topics                     · TCP/IP, DNS, traffic analysis, firewalls, IDS/IPS, VPN, VLANs, NIDS, packets, ZTA
 */
import { el, clear, provenanceBadge } from '../utils/dom.js';
import { load } from '../data-service.js';
import { createTabs } from '../components/tabs.js';
import { evaluateFlow, scorePolicy } from '../network/policy.js';
import { SAMPLE_PACKETS, buildPacket, verifyChecksums, hexRows } from '../network/packets.js';
import { bulletList, sourceList } from '../components/intel-ui.js';

export async function renderNetwork(view) {
  const { data } = await load('network');
  let tabs;

  /* ================= Segmentation & Zero Trust ================= */
  const segmentation = () => {
    let policy = data.policies[0];
    let selected = data.flows.find((f) => f.kind === 'attack');
    const policyBar = el('div', { class: 'seg-control', role: 'group', 'aria-label': 'Network policy' });
    const scoreSlot = el('div', { class: 'grid grid-2 seg-scores' });
    const diagram = el('div', { class: 'net-diagram' });
    const flowList = el('ul', { class: 'flow-list' });
    const detail = el('div', { class: 'flow-detail', 'aria-live': 'polite' });
    const compare = el('div');

    const zoneById = Object.fromEntries(data.zones.map((z) => [z.id, z]));
    const center = (z, k = 0) => ({ x: z.x + z.w / 2 + ((k % 3) - 1) * 14, y: z.y + z.h / 2 + ((k % 2) ? 10 : -10) });

    function drawDiagram(results) {
      const svg = el('svg', { viewBox: '0 0 680 500', class: 'chart-svg', role: 'img', focusable: 'false',
        'aria-label': `Network zones with ${results.length} flows under the ${policy.label} policy; ${results.filter((r) => r.action === 'deny').length} blocked.` });
      // Paint order: unselected flows, then zones (which cover them inside the boxes), then the selected flow on top.
      const line = (r, k) => {
        const a = center(zoneById[r.fromZone], k), b = center(zoneById[r.toZone], k + 1);
        const isSel = r.flow.id === selected.id;
        const cls = `flow-line ${r.action === 'allow' ? 'is-allow' : 'is-deny'} ${isSel ? 'is-selected' : ''}`;
        return { a, b, isSel, node: el('line', { class: cls, x1: a.x.toFixed(1), y1: a.y.toFixed(1), x2: b.x.toFixed(1), y2: b.y.toFixed(1) }, el('svg:title', null, `${r.flow.id} ${r.flow.label}: ${r.action}`)) };
      };
      const lines = results.map((r, k) => ({ r, ...line(r, k) }));
      lines.filter((l) => !l.isSel).forEach((l) => svg.append(l.node));
      for (const z of data.zones) {
        const hosts = data.hosts.filter((h) => h.zone === z.id).map((h) => h.name);
        if (z.id === 'internet') hosts.push('external hosts');
        svg.append(
          el('rect', { class: `zone zone-${z.id}`, x: z.x, y: z.y, width: z.w, height: z.h, rx: '10' }),
          el('text', { class: 'zone-label', x: z.x + 10, y: z.y + 20 }, z.label.toUpperCase()),
          ...hosts.map((h, i) => el('text', { class: 'zone-host', x: z.x + 10, y: z.y + 40 + i * 16 }, h))
        );
      }
      lines.filter((l) => l.isSel).forEach(({ r, a, b, node, isSel }) => {
        svg.append(node);
        if (isSel) {
          const ang = Math.atan2(b.y - a.y, b.x - a.x), s = 12;
          const p = (dx) => `${(b.x - Math.cos(ang) * s + Math.cos(ang + Math.PI / 2) * dx).toFixed(1)},${(b.y - Math.sin(ang) * s + Math.sin(ang + Math.PI / 2) * dx).toFixed(1)}`;
          svg.append(el('polygon', { class: `flow-arrow ${r.action === 'allow' ? 'is-allow' : 'is-deny'}`, points: `${b.x.toFixed(1)},${b.y.toFixed(1)} ${p(6)} ${p(-6)}` }));
          if (r.action === 'deny') {
            const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
            svg.append(el('circle', { class: 'deny-mark', cx: mx.toFixed(1), cy: my.toFixed(1), r: '11' }), el('text', { class: 'deny-x', x: mx.toFixed(1), y: (my + 4).toFixed(1), 'text-anchor': 'middle' }, '✕'));
          }
        }
      });
      clear(diagram).append(svg);
    }

    function render(focusKey) {
      const score = scorePolicy(policy, data.flows, data.hosts);
      clear(policyBar).append(...data.policies.map((p) => {
        const b = el('button', { class: 'seg-btn', type: 'button', 'aria-pressed': String(p.id === policy.id), 'data-focus-key': `pol-${p.id}` }, p.label);
        b.addEventListener('click', () => { policy = p; render(`pol-${p.id}`); });
        return b;
      }));
      clear(scoreSlot).append(
        el('div', { class: `card kpi ${score.attacksBlocked === score.attacksTotal ? 'status-live' : 'sev-critical'}` },
          el('span', { class: 'kpi-label' }, 'Attack steps blocked'), el('span', { class: 'kpi-value' }, `${score.attacksBlocked} / ${score.attacksTotal}`), el('span', { class: 'kpi-sub' }, 'Paths used in the six incidents')),
        el('div', { class: `card kpi ${score.legitAllowed === score.legitTotal ? 'status-live' : 'sev-high'}` },
          el('span', { class: 'kpi-label' }, 'Legitimate flows working'), el('span', { class: 'kpi-value' }, `${score.legitAllowed} / ${score.legitTotal}`), el('span', { class: 'kpi-sub' }, 'Business traffic that must keep flowing')));
      drawDiagram(score.results);
      clear(flowList).append(...score.results.map((r) => {
        const b = el('button', { class: 'flow-btn', type: 'button', 'aria-pressed': String(r.flow.id === selected.id), 'data-focus-key': `flow-${r.flow.id}` },
          el('span', { class: `flow-kind kind-${r.flow.kind}` }, r.flow.kind === 'attack' ? 'Attack' : 'Legit'),
          el('span', { class: 'flow-label' }, r.flow.label),
          el('span', { class: `flow-result ${r.action === 'allow' ? 'is-allow' : 'is-deny'}` }, r.action === 'allow' ? 'Allowed' : 'Blocked'));
        b.addEventListener('click', () => { selected = r.flow; render(`flow-${r.flow.id}`); });
        return el('li', null, b);
      }));
      const d = evaluateFlow(policy, selected, data.hosts);
      const good = (selected.kind === 'attack') === (d.action === 'deny');
      clear(detail).append(
        el('h3', null, `${selected.id}: ${selected.label}`),
        el('dl', { class: 'dl' },
          el('dt', null, 'Path'), el('dd', { class: 'mono' }, `${selected.from} (${d.fromZone}) → ${selected.to} (${d.toZone}) ${selected.proto.toUpperCase()}/${selected.port}`),
          el('dt', null, 'Context'), el('dd', null, selected.attributes.length ? selected.attributes.join(', ') : 'none (no verified user, device or destination signals)'),
          el('dt', null, 'Decision'), el('dd', null, el('strong', { class: d.action === 'allow' ? 'test-pass' : 'test-fail' }, d.action.toUpperCase()), ` by rule ${d.ruleId}: ${d.reason}`),
          el('dt', null, 'Outcome'), el('dd', null, good ? (selected.kind === 'attack' ? '✓ Attack step stopped' : '✓ Business flow works') : (selected.kind === 'attack' ? '✗ Attack step succeeds under this policy' : '✗ Policy breaks a legitimate flow'))),
        selected.incident ? el('a', { class: 'btn btn-sm', href: `#/incidents/${selected.incident}` }, `Open ${selected.incident}`) : null);
      clear(compare).append(el('table', { class: 'kbd-table compare-table' },
        el('caption', { class: 'visually-hidden' }, 'Flow decisions by policy'),
        el('thead', null, el('tr', null, el('th', { scope: 'col' }, 'Flow'), ...data.policies.map((p) => el('th', { scope: 'col' }, p.label)))),
        el('tbody', null, data.flows.map((f) => el('tr', null,
          el('th', { scope: 'row' }, el('span', { class: `flow-kind kind-${f.kind}` }, f.kind === 'attack' ? 'Attack' : 'Legit'), ` ${f.label}`),
          ...data.policies.map((p) => { const r = evaluateFlow(p, f, data.hosts); const ok = (f.kind === 'attack') === (r.action === 'deny'); return el('td', { class: ok ? 'test-pass' : 'test-fail', title: `${r.ruleId}: ${r.reason}` }, `${r.action === 'allow' ? 'Allowed' : 'Blocked'} ${ok ? '✓' : '✗'}`); }))))));
      if (focusKey) view.querySelector(`[data-focus-key="${focusKey}"]`)?.focus({ preventScroll: true });
    }
    render();
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub' }, 'Compare how three network designs handle the attack paths from the incident case studies, and check they still allow normal business traffic. Select a policy, then select a flow to see which rule decides it.'),
      policyBar,
      scoreSlot,
      el('div', { class: 'seg-layout' }, el('div', { class: 'card' }, diagram), el('div', { class: 'stack' }, flowList, el('div', { class: 'card' }, detail))),
      el('details', { class: 'chart-data' }, el('summary', null, 'All flows × all policies'), compare),
      el('p', { class: 'kpi-sub' }, data.note));
  };

  /* ================= Packet explorer ================= */
  const packets = () => {
    let current = SAMPLE_PACKETS[0];
    let active = null;
    const picker = el('div', { class: 'seg-control', role: 'group', 'aria-label': 'Sample packet' });
    const info = el('div');
    const fieldsSlot = el('div');
    const hexSlot = el('div', { class: 'hexdump', 'aria-hidden': 'true' });

    function highlight(field) {
      active = field;
      hexSlot.querySelectorAll('.hx').forEach((s) => {
        const i = Number(s.dataset.i);
        s.classList.toggle('is-active', !!field && i >= field.offset && i < field.offset + field.length);
      });
      fieldsSlot.querySelectorAll('.field-row').forEach((r) => r.setAttribute('aria-pressed', String(!!field && r.dataset.key === `${field.layer}-${field.name}`)));
    }
    function render() {
      const { bytes, fields } = buildPacket(current.spec);
      const ok = verifyChecksums(bytes);
      clear(picker).append(...SAMPLE_PACKETS.map((p) => {
        const b = el('button', { class: 'seg-btn', type: 'button', 'aria-pressed': String(p.id === current.id) }, p.title);
        b.addEventListener('click', () => { current = p; active = null; render(); b.focus(); });
        return b;
      }));
      clear(info).append(
        el('p', null, current.context),
        el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, `${bytes.length} bytes`),
          el('span', { class: ok.ip ? 'test-pass' : 'test-fail' }, `IPv4 checksum ${ok.ip ? 'valid ✓' : 'invalid ✗'}`),
          el('span', { class: ok.l4 ? 'test-pass' : 'test-fail' }, `${current.spec.tcp ? 'TCP' : 'UDP'} checksum ${ok.l4 ? 'valid ✓' : 'invalid ✗'}`)));
      const layers = [...new Set(fields.map((f) => f.layer))];
      clear(fieldsSlot).append(...layers.map((layer) => el('section', { class: 'layer-block' },
        el('h3', { class: 'chart-title' }, layer),
        el('ul', { class: 'field-rows' }, fields.filter((f) => f.layer === layer).map((f) => {
          const b = el('button', { class: 'field-row', type: 'button', 'aria-pressed': 'false', 'data-key': `${f.layer}-${f.name}` },
            el('span', { class: 'field-name' }, f.name),
            el('span', { class: 'field-value mono' }, f.value),
            el('span', { class: 'field-off mono' }, `bytes ${f.offset}–${f.offset + f.length - 1}`),
            f.note ? el('span', { class: 'field-note' }, f.note) : null);
          b.addEventListener('click', () => highlight(active === f ? null : f));
          b.addEventListener('focus', () => highlight(f));
          return el('li', null, b);
        })))));
      clear(hexSlot).append(...hexRows(bytes).map((row) => el('div', { class: 'hx-row' },
        el('span', { class: 'hx-off' }, row.offset.toString(16).padStart(4, '0')),
        el('span', { class: 'hx-bytes' }, row.bytes.map((b) => {
          const s = el('span', { class: 'hx', 'data-i': String(b.i) }, b.value.toString(16).padStart(2, '0'));
          s.addEventListener('mouseenter', () => { const f = fields.find((x) => b.i >= x.offset && b.i < x.offset + x.length); if (f) highlight(f); });
          return s;
        })),
        el('span', { class: 'hx-ascii' }, row.ascii))));
    }
    render();
    return el('div', { class: 'stack' },
      el('p', { class: 'kpi-sub' }, 'Each packet is built byte by byte from the RFC header layouts, and its IPv4, TCP and UDP checksums are computed and then verified. Select a field to highlight its bytes, or hover over the hex dump.'),
      picker, info,
      el('div', { class: 'packet-layout' }, el('div', { class: 'card' }, fieldsSlot), el('div', { class: 'card hex-card' }, el('h3', { class: 'chart-title' }, 'Hex dump'), hexSlot)));
  };

  /* ================= Topics ================= */
  const topics = () => el('div', { class: 'grid grid-2' }, data.topics.map((t) => el('article', { class: 'card topic-card', id: `topic-${t.id}` },
    el('h3', null, t.title),
    el('p', null, t.summary),
    el('h4', { class: 'chart-title' }, 'Key points'), bulletList(t.keyPoints),
    el('h4', { class: 'chart-title' }, 'Defensive checks'), bulletList(t.defensiveChecks),
    t.related.length ? el('div', { class: 'btn-row' }, t.related.map((r) => {
      if (r.href) return el('a', { class: 'btn btn-sm', href: r.href }, r.label);
      const b = el('button', { class: 'btn btn-sm', type: 'button' }, r.label);
      b.addEventListener('click', () => tabs.select(r.tab === 'packets' ? 1 : 0, { focus: true }));
      return b;
    })) : null,
    t.refs.length ? el('details', { class: 'chart-data' }, el('summary', null, `References (${t.refs.length})`), sourceList(t.refs.map((i) => data.references[i])))
      : el('p', { class: 'kpi-sub' }, 'General practice; no single authoritative reference.'))));

  tabs = createTabs({
    label: 'Network security views',
    tabs: [
      { id: 'segmentation', label: 'Segmentation & Zero Trust', render: segmentation },
      { id: 'packets', label: 'Packet explorer', render: packets },
      { id: 'topics', label: `Topics (${data.topics.length})`, render: topics }
    ]
  });

  view.classList.add('stack');
  view.append(
    el('header', { class: 'page-head' },
      el('span', { class: 'eyebrow' }, 'Module 08'),
      el('h1', null, 'Network Security Intelligence'),
      el('p', { class: 'lede' }, 'Segmentation, Zero Trust and packet-level analysis, tied to the attack paths from the incident case studies.'),
      el('div', { class: 'meta-row' }, provenanceBadge('simulated'), el('span', { class: 'kpi-sub' }, 'Topic references: NIST, CISA, IETF RFCs'))),
    el('section', { class: 'card' }, tabs.element),
    el('section', { class: 'card', 'aria-labelledby': 'net-refs' }, el('h2', { id: 'net-refs' }, 'References'), sourceList(data.references))
  );
  return () => view.classList.remove('stack');
}
