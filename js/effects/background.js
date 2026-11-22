/**
 * Full-page animated background (Canvas 2D), ported from Joachim's portfolio.
 *
 * One engine, three theme palettes (Original / Dark / Gold Luxury). Switching
 * theme swaps the palette, rebuilds the two cached static layers and crossfades;
 * particles and nodes are never rebuilt. Purely decorative: aria-hidden canvas,
 * no pointer events.
 *
 * Performance (as in the portfolio): cached atmosphere and hex-grid layers,
 * spatial hashing for node links, frame-rate cap, an adaptive quality governor
 * that drops the costliest layers on slow devices, a locked light mode for
 * data-saver / low-end hardware (html.perf-lite), and a pause while the tab is
 * hidden. Under prefers-reduced-motion it draws a single still frame instead.
 *
 * Differences from the portfolio version: an ES module loaded from 'self'
 * (the CSP forbids inline scripts), fades via a CSS class, and returns a
 * destroy() function.
 */
import { THEME_EVENT, currentTheme } from '../theme.js';

const ENGINE_THEMES = {
  original: {
    atmo: [
      { x: 0.5, y: 0.8, r: 0.65, c: [[0, 'rgba(100,4,4,0.22)'], [0.5, 'rgba(50,2,2,0.10)'], [1, 'transparent']] },
      { x: 0.92, y: 0.08, r: 0.3, c: [[0, 'rgba(212,175,55,0.10)'], [0.6, 'rgba(212,175,55,0.03)'], [1, 'transparent']] },
      { x: 0.08, y: 0.92, r: 0.25, c: [[0, 'rgba(212,175,55,0.08)'], [1, 'transparent']] }
    ],
    hexHot: '212,175,55', hexDim: '120,10,6',
    scan: '212,175,55',
    rainHead: '255,215,80', rainHalo: '212,175,55', rainTail: '180,14,6',
    streamA: '212,175,55', streamB: '160,12,6',
    streamHeadA: '255,215,80', streamHeadB: '255,60,20',
    ringA: '212,175,55', ringB: '160,12,6',
    linkAA: '212,175,55', linkAB: '200,140,30', linkBB: '160,12,6',
    nodeA: '212,175,55', nodeB: '200,20,8',
    haloA: '212,175,55', haloB: '200,30,8',
    labelA: '255,215,80', labelB: '255,80,20',
    dot: '255,215,80', dotHalo: '212,175,55',
    layers: { rain: true, streams: true, vscan: false, circuits: false, wave: true, rings: false, particles: true }
  },
  dark: {
    atmo: [
      { x: 0.5, y: 0.85, r: 0.7, c: [[0, 'rgba(23,44,92,0.30)'], [0.5, 'rgba(10,20,46,0.14)'], [1, 'transparent']] },
      { x: 0.9, y: 0.06, r: 0.32, c: [[0, 'rgba(56,189,248,0.11)'], [0.6, 'rgba(56,189,248,0.03)'], [1, 'transparent']] },
      { x: 0.06, y: 0.94, r: 0.26, c: [[0, 'rgba(59,130,246,0.10)'], [1, 'transparent']] }
    ],
    hexHot: '103,232,249', hexDim: '37,72,150',
    scan: '103,232,249',
    rainHead: '165,243,252', rainHalo: '56,189,248', rainTail: '37,99,235',
    streamA: '56,189,248', streamB: '59,130,246',
    streamHeadA: '165,243,252', streamHeadB: '147,197,253',
    ringA: '103,232,249', ringB: '59,130,246',
    linkAA: '56,189,248', linkAB: '80,150,240', linkBB: '40,84,180',
    nodeA: '56,189,248', nodeB: '59,130,246',
    haloA: '56,189,248', haloB: '59,130,246',
    labelA: '165,243,252', labelB: '147,197,253',
    dot: '165,243,252', dotHalo: '56,189,248',
    layers: { rain: true, streams: true, vscan: true, circuits: false, wave: false, rings: true, particles: true }
  },
  gold: {
    atmo: [
      { x: 0.5, y: 0.85, r: 0.7, c: [[0, 'rgba(60,48,12,0.26)'], [0.5, 'rgba(30,24,6,0.12)'], [1, 'transparent']] },
      { x: 0.9, y: 0.06, r: 0.32, c: [[0, 'rgba(212,175,55,0.12)'], [0.6, 'rgba(212,175,55,0.03)'], [1, 'transparent']] },
      { x: 0.06, y: 0.94, r: 0.26, c: [[0, 'rgba(255,217,102,0.09)'], [1, 'transparent']] }
    ],
    hexHot: '255,217,102', hexDim: '110,90,26',
    scan: '212,175,55',
    rainHead: '255,217,102', rainHalo: '212,175,55', rainTail: '140,112,32',
    streamA: '212,175,55', streamB: '176,141,40',
    streamHeadA: '255,217,102', streamHeadB: '255,217,102',
    ringA: '255,217,102', ringB: '176,141,40',
    linkAA: '212,175,55', linkAB: '190,155,48', linkBB: '140,112,32',
    nodeA: '212,175,55', nodeB: '176,141,40',
    haloA: '212,175,55', haloB: '176,141,40',
    labelA: '255,217,102', labelB: '230,190,90',
    dot: '255,217,102', dotHalo: '212,175,55',
    layers: { rain: false, streams: true, vscan: false, circuits: true, wave: true, rings: false, particles: true }
  }
};

export const BACKGROUND_THEMES = Object.keys(ENGINE_THEMES);

const LABELS = ['0x4F', 'AES', 'RSA', 'SHA', 'PKI', 'TLS', 'VPN', 'IDS', 'FW', 'SOC', 'XSS', 'CVE'];
const RAIN = ['0', '1', 'A', 'F', 'E', 'B', 'C', 'D', 'X', '%', '#'];

export function startBackground(canvas, { reducedMotion = false } = {}) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  const calm = reducedMotion;
  const lite = document.documentElement.classList.contains('perf-lite');
  const SPD = calm ? 0.35 : 1;
  let P = ENGINE_THEMES[currentTheme()] || ENGINE_THEMES.original;

  let W = 0, H = 0, DPR = 1;
  let nodes = [], binCols = [], hexCells = [], pulses = [], dataStreams = [], motes = [];
  let scanY = 0, tick = 0;
  let atmoLayer = null, hexLayer = null, liveHexes = [], circuitPaths = [];
  let hexBreath = 0, ringT = 0, vScanX = 0, wavePhase = 0, parT = 0;
  const par = { x: 0, y: 0, tx: 0, ty: 0, auto: true };

  const isMobile = () => W < 600;
  const isTablet = () => W >= 600 && W < 1024;
  const rand = (a, b) => a + Math.random() * (b - a);
  const randInt = (a, b) => Math.floor(rand(a, b + 1));
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 1.5); // soft background: 1.5x is indistinguishable from 2x
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.round(W * DPR);
    canvas.height = Math.round(H * DPR);
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    init();
    buildStaticLayers();
    if (calm) drawFrame();
  }

  function buildStaticLayers() {
    atmoLayer = document.createElement('canvas');
    atmoLayer.width = Math.round(W * DPR); atmoLayer.height = Math.round(H * DPR);
    const a = atmoLayer.getContext('2d');
    a.setTransform(DPR, 0, 0, DPR, 0, 0);
    for (const spec of P.atmo) {
      const g = a.createRadialGradient(W * spec.x, H * spec.y, 0, W * spec.x, H * spec.y, W * spec.r);
      for (const [stop, color] of spec.c) g.addColorStop(stop, color);
      a.fillStyle = g; a.fillRect(0, 0, W, H);
    }

    // Hex grid, with 20 px overscan on each side so the cached layer can drift without edge gaps.
    hexLayer = document.createElement('canvas');
    hexLayer.width = Math.round((W + 40) * DPR); hexLayer.height = Math.round((H + 40) * DPR);
    const h = hexLayer.getContext('2d');
    h.setTransform(DPR, 0, 0, DPR, 20 * DPR, 20 * DPR);
    for (const cell of hexCells) {
      hexPath(h, cell);
      h.strokeStyle = cell.gold ? `rgba(${P.hexHot},${cell.alpha * 1.4})` : `rgba(${P.hexDim},${cell.alpha})`;
      h.lineWidth = cell.gold ? 0.7 : 0.4;
      h.stroke();
    }
    if (P.layers.circuits) buildCircuits(h); else circuitPaths = [];
    liveHexes = hexCells.filter((c) => c.gold).slice(0, 6);
  }

  function hexPath(c2, cell) {
    c2.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i - Math.PI / 6;
      const px = cell.cx + cell.r * Math.cos(angle);
      const py = cell.cy + cell.r * Math.sin(angle);
      if (i === 0) c2.moveTo(px, py); else c2.lineTo(px, py);
    }
    c2.closePath();
  }

  function init() {
    const mobile = isMobile();
    const tablet = isTablet();
    hexCells = [];
    const hexR = mobile ? 28 : 42;
    const hexW = hexR * 2;
    const hexH = Math.sqrt(3) * hexR;
    for (let row = -1; row < H / hexH + 2; row++) {
      for (let col = -1; col < W / (hexW * 0.75) + 2; col++) {
        const xOff = row % 2 === 0 ? 0 : hexW * 0.375;
        hexCells.push({
          cx: col * hexW * 0.75 + xOff, cy: row * hexH, r: hexR,
          alpha: rand(0.04, 0.14), pulsePhase: rand(0, Math.PI * 2), pulseSpeed: rand(0.008, 0.022),
          gold: Math.random() < 0.08
        });
      }
    }
    let nodeCount = mobile ? 22 : tablet ? 38 : 58;
    if (calm || lite) nodeCount = Math.round(nodeCount / 2);
    nodes = Array.from({ length: nodeCount }, makeNode);
    const colW = mobile ? 14 : 18;
    binCols = Array.from({ length: Math.ceil(W / colW) }, (_, i) => makeBinCol(i * colW));
    pulses = Array.from({ length: mobile ? 2 : 4 }, () => makePulse(true));
    dataStreams = Array.from({ length: mobile ? 3 : 6 }, makeStream);
    let n = mobile ? 18 : 45;
    if (calm) n = Math.round(n / 2);
    motes = Array.from({ length: n }, () => ({
      x: rand(0, W), y: rand(0, H), r: rand(0.6, 1.8),
      vx: rand(-0.16, 0.16) * SPD, vy: rand(-0.1, 0.04) * SPD,
      tw: rand(0, Math.PI * 2), twSpd: rand(0.01, 0.03), depth: rand(0.4, 1)
    }));
    scanY = 0;
  }

  function makeNode() {
    return {
      x: rand(0, W), y: rand(0, H), r: rand(2, isMobile() ? 4 : 5.5),
      vx: rand(-0.22, 0.22) * SPD, vy: rand(-0.22, 0.22) * SPD,
      alpha: rand(0.4, 0.9), alphaDir: Math.random() < 0.5 ? 1 : -1, alphaSpd: rand(0.004, 0.012),
      gold: Math.random() < 0.25,
      connDist: rand(isMobile() ? 90 : 120, isMobile() ? 140 : 190),
      type: pick(['circle', 'diamond', 'square', 'tri']), rot: rand(0, Math.PI), rotSpd: rand(-0.005, 0.005),
      label: Math.random() < 0.18 ? pick(LABELS) : null
    };
  }
  function makeBinCol(x) {
    const fontSize = isMobile() ? 9 : 11;
    return {
      x, y: rand(-H, 0), fontSize, speed: rand(0.4, 1.1), chars: Math.ceil(H / (fontSize + 3)),
      alpha: rand(0.04, 0.13), goldRow: randInt(0, 20),
      content: Array.from({ length: 40 }, () => pick(RAIN)), tick: 0, refreshRate: randInt(18, 55)
    };
  }
  function makePulse(spread = false) {
    return {
      x: rand(W * 0.1, W * 0.9), y: rand(H * 0.1, H * 0.9),
      r: spread ? rand(0, 200) : 0, maxR: rand(isMobile() ? 80 : 140, isMobile() ? 160 : 280),
      speed: rand(0.5, 1.1), alpha: spread ? rand(0.1, 0.4) : rand(0.25, 0.55),
      gold: Math.random() < 0.4, lineW: rand(0.5, 1.5)
    };
  }
  function makeStream() {
    return {
      y: rand(0, H), x: rand(-200, -20), speed: rand(1.2, 3.0),
      len: randInt(isMobile() ? 40 : 80, isMobile() ? 100 : 220), alpha: rand(0.06, 0.18),
      gold: Math.random() < 0.3,
      chars: Array.from({ length: 20 }, () => pick(['0', '1', 'A', 'F', 'E', 'B', 'C', 'D', '>', '/', '\\', '#', '%'])),
      charTick: 0
    };
  }

  // ── Layers ──────────────────────────────────────────────────────
  function drawHexGrid() {
    if (hexLayer) {
      hexBreath += 0.012 * SPD;
      const dx = Math.sin(hexBreath * 0.7) * 10 + par.x * 6;
      const dy = Math.cos(hexBreath * 0.5) * 7 + par.y * 6;
      ctx.globalAlpha = 0.82 + Math.sin(hexBreath) * 0.18;
      ctx.drawImage(hexLayer, -20 + dx, -20 + dy, W + 40, H + 40);
      ctx.globalAlpha = 1;
    }
    for (const cell of liveHexes) {
      cell.pulsePhase += cell.pulseSpeed;
      const pulse = (Math.sin(cell.pulsePhase) + 1) / 2;
      const alpha = cell.alpha + pulse * 0.08;
      hexPath(ctx, cell);
      ctx.strokeStyle = `rgba(${P.hexHot},${alpha * 1.4})`;
      ctx.lineWidth = 0.7;
      ctx.stroke();
      if (pulse > 0.85) { ctx.fillStyle = `rgba(${P.hexHot},${(pulse - 0.85) * 0.18})`; ctx.fill(); }
    }
  }

  function drawScanLine() {
    const grad = ctx.createLinearGradient(0, scanY - 8, 0, scanY + 8);
    grad.addColorStop(0, 'transparent');
    grad.addColorStop(0.5, `rgba(${P.scan},0.06)`);
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.fillRect(0, scanY - 8, W, 16);
    ctx.beginPath(); ctx.moveTo(0, scanY); ctx.lineTo(W, scanY);
    ctx.strokeStyle = `rgba(${P.scan},0.07)`; ctx.lineWidth = 0.5; ctx.stroke();
    scanY += (isMobile() ? 1.0 : 1.5) * SPD;
    if (scanY > H) scanY = 0;
  }

  function onPointer(e) {
    par.auto = false;
    par.tx = (e.clientX / W - 0.5) * 2;
    par.ty = (e.clientY / H - 0.5) * 2;
  }
  function updateParallax() {
    if (par.auto) { parT += 0.004; par.tx = Math.sin(parT) * 0.5; par.ty = Math.cos(parT * 0.8) * 0.5; }
    par.x += (par.tx - par.x) * 0.04;
    par.y += (par.ty - par.y) * 0.04;
  }

  function drawMotes() {
    const ox = par.x * 14, oy = par.y * 14;
    for (const m of motes) {
      m.x += m.vx; m.y += m.vy; m.tw += m.twSpd;
      if (m.x < -4) m.x = W + 4; else if (m.x > W + 4) m.x = -4;
      if (m.y < -4) m.y = H + 4; else if (m.y > H + 4) m.y = -4;
      const a = (0.10 + (Math.sin(m.tw) + 1) * 0.10) * m.depth;
      ctx.beginPath();
      ctx.arc(m.x + ox * m.depth, m.y + oy * m.depth, m.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${P.dot},${a})`;
      ctx.fill();
    }
  }

  function drawDataRings() {
    ringT += SPD;
    const centers = [
      { x: W * 0.16, y: H * 0.24, r: isMobile() ? 60 : 110 },
      { x: W * 0.84, y: H * 0.68, r: isMobile() ? 80 : 150 },
      { x: W * 0.55, y: H * 0.12, r: isMobile() ? 44 : 80 }
    ];
    ctx.setLineDash([10, 16]);
    centers.forEach((c, i) => {
      ctx.lineDashOffset = (i % 2 ? -1 : 1) * ringT * 0.35;
      ctx.beginPath(); ctx.arc(c.x + par.x * 8, c.y + par.y * 8, c.r, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${P.hexHot},0.10)`; ctx.lineWidth = 1; ctx.stroke();
      ctx.lineDashOffset = (i % 2 ? 1 : -1) * ringT * 0.22;
      ctx.beginPath(); ctx.arc(c.x + par.x * 8, c.y + par.y * 8, c.r * 0.72, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${P.hexHot},0.07)`; ctx.stroke();
    });
    ctx.setLineDash([]);
    ctx.lineDashOffset = 0;
  }

  function drawVScan() {
    const grad = ctx.createLinearGradient(vScanX - 30, 0, vScanX + 30, 0);
    grad.addColorStop(0, 'transparent');
    grad.addColorStop(0.5, `rgba(${P.scan},0.045)`);
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.fillRect(vScanX - 30, 0, 60, H);
    ctx.beginPath(); ctx.moveTo(vScanX, 0); ctx.lineTo(vScanX, H);
    ctx.strokeStyle = `rgba(${P.scan},0.08)`; ctx.lineWidth = 0.5; ctx.stroke();
    vScanX += (isMobile() ? 0.6 : 0.9) * SPD;
    if (vScanX > W) vScanX = 0;
  }

  // Gold theme: Manhattan circuit traces baked into the cached layer; only the pulses animate.
  function buildCircuits(h) {
    circuitPaths = [];
    const count = isMobile() ? 5 : 9;
    for (let i = 0; i < count; i++) {
      const pts = [];
      let x = rand(0, W), y = rand(0, H);
      pts.push({ x, y });
      const segs = randInt(4, 7);
      let horiz = Math.random() < 0.5;
      for (let s = 0; s < segs; s++) {
        const len = rand(60, isMobile() ? 140 : 220) * (Math.random() < 0.5 ? -1 : 1);
        if (horiz) x = Math.max(0, Math.min(W, x + len)); else y = Math.max(0, Math.min(H, y + len));
        pts.push({ x, y });
        horiz = !horiz;
      }
      h.beginPath();
      pts.forEach((p2, idx) => (idx === 0 ? h.moveTo(p2.x, p2.y) : h.lineTo(p2.x, p2.y)));
      h.strokeStyle = `rgba(${P.hexHot},0.10)`; h.lineWidth = 1; h.stroke();
      for (const p2 of pts) {
        h.beginPath(); h.arc(p2.x, p2.y, 1.6, 0, Math.PI * 2);
        h.fillStyle = `rgba(${P.hexHot},0.22)`; h.fill();
      }
      let total = 0;
      const lens = [];
      for (let s = 1; s < pts.length; s++) {
        const L = Math.abs(pts[s].x - pts[s - 1].x) + Math.abs(pts[s].y - pts[s - 1].y);
        lens.push(L); total += L;
      }
      circuitPaths.push({ pts, lens, total, t: rand(0, 1), speed: rand(0.0018, 0.004) * SPD });
    }
  }
  function drawCircuitPulses() {
    for (const c of circuitPaths) {
      c.t += c.speed;
      if (c.t > 1) c.t = 0;
      let d = c.t * c.total, x = c.pts[0].x, y = c.pts[0].y;
      for (let s = 0; s < c.lens.length; s++) {
        if (d <= c.lens[s]) {
          const a2 = c.pts[s], b2 = c.pts[s + 1], f = c.lens[s] ? d / c.lens[s] : 0;
          x = a2.x + (b2.x - a2.x) * f;
          y = a2.y + (b2.y - a2.y) * f;
          break;
        }
        d -= c.lens[s];
      }
      ctx.beginPath(); ctx.arc(x, y, 3.4, 0, Math.PI * 2); ctx.fillStyle = `rgba(${P.dotHalo},0.22)`; ctx.fill();
      ctx.beginPath(); ctx.arc(x, y, 1.4, 0, Math.PI * 2); ctx.fillStyle = `rgba(${P.dot},0.9)`; ctx.fill();
    }
  }

  function drawWave() {
    wavePhase += 0.016 * SPD;
    const bands = [
      { y0: H * 0.32, amp: 16, wl: W / 2.6, ph: wavePhase, aSoft: 0.05, aCore: 0.10 },
      { y0: H * 0.72, amp: 22, wl: W / 3.2, ph: -wavePhase * 0.7, aSoft: 0.04, aCore: 0.08 }
    ];
    const step = Math.max(18, W / 48);
    for (const b of bands) {
      ctx.beginPath();
      for (let x = 0; x <= W + step; x += step) {
        const y = b.y0 + Math.sin((x / b.wl) * Math.PI * 2 + b.ph) * b.amp;
        if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = `rgba(${P.hexHot},${b.aSoft})`; ctx.lineWidth = 22; ctx.stroke();
      ctx.strokeStyle = `rgba(${P.dot},${b.aCore})`; ctx.lineWidth = 1; ctx.stroke();
    }
  }

  function drawBinaryRain() {
    for (const col of binCols) {
      col.y += col.speed;
      col.tick++;
      if (col.tick >= col.refreshRate) {
        col.tick = 0;
        for (let i = 0; i < 3; i++) col.content[randInt(0, col.content.length - 1)] = pick([...RAIN, '>', '<']);
        col.goldRow = randInt(0, col.chars - 1);
      }
      if (col.y > H + col.chars * (col.fontSize + 3)) {
        col.y = rand(-200, -50); col.alpha = rand(0.04, 0.13); col.speed = rand(0.6, 1.5);
      }
      ctx.font = `${col.fontSize}px "Courier New", monospace`;
      for (let i = 0; i < col.chars; i++) {
        const cy = col.y + i * (col.fontSize + 3);
        if (cy < -col.fontSize || cy > H + col.fontSize) continue;
        const ch = col.content[i % col.content.length];
        if (i === col.goldRow) {
          ctx.fillStyle = `rgba(${P.rainHalo},${col.alpha * 2.2})`;
          ctx.fillText(ch, col.x - 0.6, cy + 0.6);
          ctx.fillStyle = `rgba(${P.rainHead},${col.alpha * 5.5})`;
        } else {
          const fade = Math.max(0, 1 - i / col.chars);
          ctx.fillStyle = `rgba(${P.rainTail},${col.alpha * (0.3 + fade * 1.2)})`;
        }
        ctx.fillText(ch, col.x, cy);
      }
    }
  }

  function drawDataStreams() {
    for (const s of dataStreams) {
      s.x += s.speed;
      if (++s.charTick > 8) { s.charTick = 0; s.chars.push(pick(['0', '1', 'A', 'F', 'B', 'E', '>', '/', '#'])); s.chars.shift(); }
      if (s.x > W + 50) {
        s.x = rand(-200, -20); s.y = rand(0, H); s.speed = rand(1.2, 3.0); s.alpha = rand(0.06, 0.18); s.gold = Math.random() < 0.3;
      }
      const gl = ctx.createLinearGradient(s.x, s.y, s.x + s.len, s.y);
      const base = s.gold ? P.streamA : P.streamB;
      gl.addColorStop(0, `rgba(${base},0)`);
      gl.addColorStop(0.6, `rgba(${base},${s.alpha})`);
      gl.addColorStop(1, `rgba(${base},0)`);
      ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(s.x + s.len, s.y);
      ctx.strokeStyle = gl; ctx.lineWidth = s.gold ? 1.2 : 0.8; ctx.stroke();
      ctx.font = '9px "Courier New", monospace';
      ctx.fillStyle = s.gold ? `rgba(${P.streamHeadA},${s.alpha * 3})` : `rgba(${P.streamHeadB},${s.alpha * 3})`;
      ctx.fillText(s.chars[s.chars.length - 1], s.x + s.len, s.y + 3);
    }
  }

  function drawPulseRings() {
    pulses.forEach((p, idx) => {
      p.r += p.speed;
      p.alpha -= 0.0018;
      if (p.r > p.maxR || p.alpha <= 0) { pulses[idx] = makePulse(); return; }
      const rgb = p.gold ? P.ringA : P.ringB;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${rgb},${p.alpha * 0.3})`; ctx.lineWidth = p.lineW + 3; ctx.stroke();
      ctx.strokeStyle = `rgba(${rgb},${p.alpha})`; ctx.lineWidth = p.lineW; ctx.stroke();
      if (p.r > 20) {
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r * 0.6, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${rgb},${p.alpha * 0.4})`; ctx.lineWidth = 0.4; ctx.stroke();
      }
    });
    if (pulses.length > 12) pulses.splice(0, pulses.length - 12);
  }

  // Network: spatial hash so each node only checks its 3x3 neighbourhood.
  const CELL = 190;
  const buckets = new Map();
  function drawNetwork() {
    buckets.clear();
    nodes.forEach((n, i) => {
      const key = ((n.x / CELL) | 0) * 4096 + ((n.y / CELL) | 0);
      let arr = buckets.get(key);
      if (!arr) { arr = []; buckets.set(key, arr); }
      arr.push(i);
    });
    ctx.save();
    ctx.translate(par.x * 10, par.y * 10);
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      const cx = (a.x / CELL) | 0, cy = (a.y / CELL) | 0;
      for (let gx = cx - 1; gx <= cx + 1; gx++) {
        for (let gy = cy - 1; gy <= cy + 1; gy++) {
          const cell = buckets.get(gx * 4096 + gy);
          if (!cell) continue;
          for (const j of cell) {
            if (j <= i) continue;
            const b = nodes[j];
            const dx = b.x - a.x, dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const maxD = Math.min(a.connDist, b.connDist);
            if (dist >= maxD) continue;
            const t = 1 - dist / maxD;
            const bothGold = a.gold && b.gold;
            const rgb = bothGold ? P.linkAA : a.gold || b.gold ? P.linkAB : P.linkBB;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.setLineDash(bothGold ? [4, 6] : []);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(${rgb},${t * 0.28 * Math.min(a.alpha, b.alpha)})`;
            ctx.lineWidth = bothGold ? 0.9 : 0.5;
            ctx.stroke();
            ctx.setLineDash([]);
            if (bothGold && Math.random() < 0.003) {
              const mid = 0.3 + Math.random() * 0.4;
              ctx.beginPath(); ctx.arc(a.x + dx * mid, a.y + dy * mid, 3.2, 0, Math.PI * 2);
              ctx.fillStyle = `rgba(${P.dotHalo},0.35)`; ctx.fill();
              ctx.beginPath(); ctx.arc(a.x + dx * mid, a.y + dy * mid, 1.5, 0, Math.PI * 2);
              ctx.fillStyle = `rgba(${P.dot},0.85)`; ctx.fill();
            }
          }
        }
      }
    }
    for (const n of nodes) {
      const rgb = n.gold ? P.nodeA : P.nodeB;
      ctx.save();
      ctx.translate(n.x, n.y);
      ctx.rotate(n.rot);
      ctx.beginPath(); ctx.arc(0, 0, n.r * 2.1, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${n.gold ? P.haloA : P.haloB},${n.alpha * 0.10})`; ctx.fill();
      ctx.fillStyle = `rgba(${rgb},${n.alpha})`;
      ctx.strokeStyle = `rgba(${rgb},${n.alpha * 0.6})`;
      ctx.lineWidth = 0.8;
      if (n.type === 'diamond') {
        ctx.beginPath(); ctx.moveTo(0, -n.r); ctx.lineTo(n.r, 0); ctx.lineTo(0, n.r); ctx.lineTo(-n.r, 0); ctx.closePath();
        ctx.fill(); ctx.stroke();
      } else if (n.type === 'square') {
        const s = n.r * 0.85;
        ctx.fillRect(-s, -s, s * 2, s * 2); ctx.strokeRect(-s, -s, s * 2, s * 2);
      } else if (n.type === 'tri') {
        const s = n.r;
        ctx.beginPath(); ctx.moveTo(0, -s); ctx.lineTo(s * 0.866, s * 0.5); ctx.lineTo(-s * 0.866, s * 0.5); ctx.closePath();
        ctx.fill(); ctx.stroke();
      } else {
        ctx.beginPath(); ctx.arc(0, 0, n.r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      }
      ctx.restore();
      if (n.label) {
        ctx.font = `bold ${isMobile() ? 7 : 9}px "Courier New", monospace`;
        ctx.fillStyle = n.gold ? `rgba(${P.labelA},${n.alpha * 0.9})` : `rgba(${P.labelB},${n.alpha * 0.8})`;
        ctx.fillText(n.label, n.x + n.r + 2, n.y - n.r - 2);
      }
    }
    ctx.restore();
  }

  function update() {
    tick++;
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy; n.rot += n.rotSpd;
      n.alpha += n.alphaDir * n.alphaSpd;
      if (n.alpha > 0.92 || n.alpha < 0.25) n.alphaDir *= -1;
      if (n.x < -20) n.vx = Math.abs(n.vx);
      if (n.x > W + 20) n.vx = -Math.abs(n.vx);
      if (n.y < -20) n.vy = Math.abs(n.vy);
      if (n.y > H + 20) n.vy = -Math.abs(n.vy);
    }
    if (tick % (isMobile() ? 280 : 190) === 0) pulses.push(makePulse());
  }

  // ── Frame + loop ────────────────────────────────────────────────
  let lowMode = true;            // every device starts light and must earn full quality
  let frameEMA = 30;
  const lowLock = lite;          // data-saver / low-end never upgrades

  function drawFrame() {
    ctx.clearRect(0, 0, W, H);
    updateParallax();
    if (atmoLayer) ctx.drawImage(atmoLayer, 0, 0, W, H);
    drawHexGrid();
    drawScanLine();
    if (P.layers.vscan) drawVScan();
    if (P.layers.rings) drawDataRings();
    if (P.layers.wave) drawWave();
    if (P.layers.rain && !lowMode && !calm) drawBinaryRain();
    if (P.layers.streams && !lowMode && !calm) drawDataStreams();
    if (P.layers.circuits) drawCircuitPulses();
    if (P.layers.particles) drawMotes();
    drawPulseRings();
    drawNetwork();
  }

  const frameBudget = () => (lowMode ? 1000 / 24 : isMobile() ? 1000 / 32 : 1000 / 45);
  let raf = 0, last = 0, running = false;
  function loop(now) {
    raf = requestAnimationFrame(loop);
    if (now - last < frameBudget()) return;
    last = now;
    const t0 = performance.now();
    drawFrame();
    update();
    const cost = performance.now() - t0;
    frameEMA = frameEMA * 0.9 + cost * 0.1;
    if (!lowMode && frameEMA > 26) lowMode = true;
    else if (lowMode && !lowLock && frameEMA < 13) lowMode = false;
  }
  function start() {
    if (running || calm) return;
    running = true;
    last = 0;
    raf = requestAnimationFrame(loop);
  }
  function stop() { running = false; cancelAnimationFrame(raf); }

  // ── Events ──────────────────────────────────────────────────────
  let fadeTimer = 0;
  function onTheme(e) {
    const next = ENGINE_THEMES[e.detail] || ENGINE_THEMES.original;
    if (next === P) return;
    canvas.classList.remove('is-on');                 // crossfade out, swap, fade in
    clearTimeout(fadeTimer);
    fadeTimer = setTimeout(() => {
      P = next;
      buildStaticLayers();
      if (calm) drawFrame();
      canvas.classList.add('is-on');
    }, calm ? 0 : 380);
  }
  const onVisibility = () => (document.hidden ? stop() : start());
  let resizeTimer = 0, lastW = window.innerWidth;
  function onResize() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (window.innerWidth !== lastW) { lastW = window.innerWidth; resize(); return; }
      // Height-only change (mobile URL bar): resync the buffer, keep the scene.
      H = window.innerHeight;
      canvas.height = Math.round(H * DPR);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      if (atmoLayer) buildStaticLayers();
      if (calm) drawFrame();
    }, 120);
  }

  window.addEventListener(THEME_EVENT, onTheme);
  window.addEventListener('resize', onResize);
  window.addEventListener('pointermove', onPointer, { passive: true });
  document.addEventListener('visibilitychange', onVisibility);

  resize();
  requestAnimationFrame(() => canvas.classList.add('is-on'));
  if (!document.hidden) start();

  return function destroy() {
    stop();
    clearTimeout(fadeTimer);
    clearTimeout(resizeTimer);
    window.removeEventListener(THEME_EVENT, onTheme);
    window.removeEventListener('resize', onResize);
    window.removeEventListener('pointermove', onPointer);
    document.removeEventListener('visibilitychange', onVisibility);
    canvas.classList.remove('is-on');
  };
}
