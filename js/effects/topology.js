/**
 * Animated network topology for the landing hero (Canvas 2D).
 *
 * A stylised enterprise network: Internet → edge firewall → DMZ / core →
 * server and endpoint tiers. Benign packets (cyan) flow along links; hostile
 * packets (red) originate on the Internet side and are dropped at the edge
 * firewall, which flashes. This is decorative, simulated motion only.
 *
 * Performance: fixed node count, one rAF loop, paused when the hero is off
 * screen or the tab is hidden, static single frame under reduced motion.
 * Returns a destroy() function so the view can clean up on navigation.
 */

const COLORS = {
  link: 'rgba(96, 165, 250, 0.18)',
  node: '#60a5fa',
  nodeCore: '#22d3ee',
  internet: '#94a3b8',
  packet: '#22d3ee',
  threat: '#f43f5e',
  label: 'rgba(169, 182, 204, 0.75)'
};

// Normalised layout (x, y in 0..1). Tier drives colour/size.
const NODES = [
  { id: 'inet1', x: 0.06, y: 0.18, tier: 'internet' },
  { id: 'inet2', x: 0.06, y: 0.50, tier: 'internet', label: 'INTERNET' },
  { id: 'inet3', x: 0.06, y: 0.82, tier: 'internet' },
  { id: 'fw',    x: 0.24, y: 0.50, tier: 'core', label: 'EDGE FW' },
  { id: 'dmz',   x: 0.42, y: 0.20, tier: 'node', label: 'DMZ' },
  { id: 'core',  x: 0.44, y: 0.56, tier: 'core', label: 'CORE' },
  { id: 'siem',  x: 0.62, y: 0.86, tier: 'core', label: 'SIEM' },
  { id: 'web',   x: 0.62, y: 0.12, tier: 'node' },
  { id: 'dc',    x: 0.66, y: 0.42, tier: 'node', label: 'DC' },
  { id: 'fs',    x: 0.70, y: 0.64, tier: 'node' },
  { id: 'e1',    x: 0.86, y: 0.22, tier: 'node' },
  { id: 'e2',    x: 0.90, y: 0.42, tier: 'node' },
  { id: 'e3',    x: 0.86, y: 0.62, tier: 'node' },
  { id: 'e4',    x: 0.92, y: 0.82, tier: 'node' }
];
const LINKS = [
  ['inet1', 'fw'], ['inet2', 'fw'], ['inet3', 'fw'],
  ['fw', 'dmz'], ['fw', 'core'], ['dmz', 'web'], ['dmz', 'core'],
  ['core', 'dc'], ['core', 'fs'], ['core', 'siem'],
  ['dc', 'e1'], ['dc', 'e2'], ['fs', 'e3'], ['fs', 'e4'], ['dc', 'fs'],
  ['web', 'siem'], ['dc', 'siem'], ['fs', 'siem']
];

export function mountTopology(canvas, { reducedMotion = false } = {}) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  const byId = Object.fromEntries(NODES.map((n) => [n.id, n]));
  const links = LINKS.map(([a, b]) => [byId[a], byId[b]]);
  const packets = [];
  let w = 0, h = 0, dpr = 1, raf = 0, running = false, last = 0, spawnAcc = 0, fwFlash = 0;

  function resize() {
    const rect = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = Math.max(1, rect.width);
    h = Math.max(1, rect.height);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  // On narrow screens the left of the hero holds text; bias nodes rightwards.
  const px = (n) => (w < 640 ? 0.25 + n.x * 0.75 : 0.35 + n.x * 0.65) * w;
  const py = (n) => (0.08 + n.y * 0.84) * h;

  function spawn() {
    const hostile = Math.random() < 0.22;
    if (hostile) {
      const src = byId[['inet1', 'inet2', 'inet3'][Math.floor(Math.random() * 3)]];
      packets.push({ a: src, b: byId.fw, t: 0, speed: 0.45 + Math.random() * 0.3, hostile: true });
    } else {
      const [a, b] = links[Math.floor(Math.random() * links.length)];
      const flip = Math.random() < 0.5;
      packets.push({ a: flip ? b : a, b: flip ? a : b, t: 0, speed: 0.25 + Math.random() * 0.35, hostile: false });
    }
    if (packets.length > 40) packets.shift();
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    // links
    ctx.lineWidth = 1;
    ctx.strokeStyle = COLORS.link;
    ctx.beginPath();
    for (const [a, b] of links) { ctx.moveTo(px(a), py(a)); ctx.lineTo(px(b), py(b)); }
    ctx.stroke();

    // packets
    for (const p of packets) {
      const x = px(p.a) + (px(p.b) - px(p.a)) * p.t;
      const y = py(p.a) + (py(p.b) - py(p.a)) * p.t;
      ctx.fillStyle = p.hostile ? COLORS.threat : COLORS.packet;
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = 8;
      ctx.beginPath(); ctx.arc(x, y, p.hostile ? 2.6 : 2, 0, Math.PI * 2); ctx.fill();
    }
    ctx.shadowBlur = 0;

    // nodes
    ctx.font = '600 10px ui-monospace, Consolas, monospace';
    ctx.textAlign = 'center';
    for (const n of NODES) {
      const x = px(n), y = py(n);
      const core = n.tier === 'core';
      const r = core ? 6 : n.tier === 'internet' ? 4 : 4.5;
      let color = n.tier === 'internet' ? COLORS.internet : core ? COLORS.nodeCore : COLORS.node;
      if (n.id === 'fw' && fwFlash > 0) color = COLORS.threat;

      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.25;
      ctx.beginPath(); ctx.arc(x, y, r + 6, 0, Math.PI * 2); ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
      if (n.label) { ctx.fillStyle = COLORS.label; ctx.fillText(n.label, x, y - r - 9); }
    }
  }

  function step(now) {
    const dt = Math.min(0.05, (now - last) / 1000 || 0);
    last = now;
    spawnAcc += dt;
    while (spawnAcc > 0.18) { spawn(); spawnAcc -= 0.18; }
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      p.t += p.speed * dt;
      if (p.t >= 1) {
        if (p.hostile) fwFlash = 0.25; // dropped at the firewall
        packets.splice(i, 1);
      }
    }
    fwFlash = Math.max(0, fwFlash - dt);
    draw();
    if (running) raf = requestAnimationFrame(step);
  }

  function start() {
    if (running || reducedMotion) return;
    running = true;
    last = performance.now();
    raf = requestAnimationFrame(step);
  }
  function stop() { running = false; cancelAnimationFrame(raf); }

  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  const io = new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop()));
  io.observe(canvas);
  const onVis = () => (document.hidden ? stop() : start());
  document.addEventListener('visibilitychange', onVis);

  // Reduced motion: seed a few packets so the static frame still reads as a network.
  if (reducedMotion) { for (let i = 0; i < 12; i++) { spawn(); packets[packets.length - 1].t = Math.random(); } }
  resize();

  return function destroy() {
    stop();
    ro.disconnect();
    io.disconnect();
    document.removeEventListener('visibilitychange', onVis);
  };
}
