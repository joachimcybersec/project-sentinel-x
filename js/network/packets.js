/**
 * Packet builder for the packet explorer (pure functions, no DOM).
 *
 * Builds real byte sequences for Ethernet II / IPv4 (RFC 791) / TCP (RFC 9293) /
 * UDP (RFC 768) / DNS (RFC 1035) with correctly computed IPv4 header, TCP and
 * UDP checksums, and returns a field map (layer, name, byte offset, length,
 * value, explanation) so the UI can highlight bytes for each field.
 *
 * Sample packets are SIMULATED and mirror events in the Sentinel X dataset.
 * MAC addresses are locally administered (02:…) and IPs use RFC 1918 / 5737 ranges.
 */

export const ipToBytes = (ip) => {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) throw new Error(`Invalid IPv4 address ${ip}`);
  return p;
};
const macToBytes = (mac) => mac.split(':').map((h) => parseInt(h, 16));
const u16 = (n) => [(n >>> 8) & 0xff, n & 0xff];
const u32 = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0) & 0x7f);
const hex = (n, w = 2) => `0x${n.toString(16).padStart(w, '0')}`;

/** Internet checksum (RFC 1071): one's-complement of the one's-complement sum of 16-bit words. */
export function checksum16(bytes) {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (i + 1 < bytes.length ? bytes[i + 1] : 0);
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

function pseudoHeader(src, dst, proto, length) {
  return [...ipToBytes(src), ...ipToBytes(dst), 0, proto, ...u16(length)];
}

/** Encode a DNS name as length-prefixed labels (RFC 1035 §3.1). */
export function encodeDnsName(name) {
  const out = [];
  for (const label of String(name).replace(/\.$/, '').split('.')) {
    if (!label || label.length > 63) throw new Error(`Invalid DNS label "${label}"`);
    out.push(label.length, ...ascii(label));
  }
  out.push(0);
  if (out.length > 255) throw new Error('DNS name longer than 255 bytes');
  return out;
}

const TCP_FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20 };
const PROTO_NAME = { 6: 'TCP', 17: 'UDP' };
const QTYPE = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

/**
 * spec: { eth: {src, dst}, ip: {src, dst, ttl, id}, tcp?: {...}, udp?: {...}, dns?: {...}, payload?: string, notes: {...} }
 * Returns { bytes: number[], fields: [{ layer, name, offset, length, value, note }] }
 */
export function buildPacket(spec) {
  const fields = [];
  const add = (layer, name, offset, length, value, note = '') => fields.push({ layer, name, offset, length, value, note });
  const n = spec.notes || {};

  /* --- application / transport payload first, so lengths are known --- */
  let l4 = [];
  let l4Fields = [];
  const proto = spec.tcp ? 6 : 17;
  if (spec.tcp) {
    const t = spec.tcp;
    const options = t.mss ? [0x02, 0x04, ...u16(t.mss)] : [];
    const payload = spec.payload ? ascii(spec.payload) : [];
    const hdrLen = 20 + options.length;
    const flags = t.flags.reduce((acc, f) => acc | TCP_FLAGS[f], 0);
    const header = [...u16(t.srcPort), ...u16(t.dstPort), ...u32(t.seq), ...u32(t.ack || 0), (hdrLen / 4) << 4, flags, ...u16(t.window), 0, 0, 0, 0, ...options];
    const seg = [...header, ...payload];
    const cs = checksum16([...pseudoHeader(spec.ip.src, spec.ip.dst, 6, seg.length), ...seg]);
    seg[16] = cs >>> 8; seg[17] = cs & 0xff;
    l4 = seg;
    l4Fields = [
      ['TCP', 'Source port', 0, 2, String(t.srcPort), n.srcPort || 'Ephemeral client port chosen by the operating system.'],
      ['TCP', 'Destination port', 2, 2, String(t.dstPort), n.dstPort || ''],
      ['TCP', 'Sequence number', 4, 4, String(t.seq >>> 0), 'Initial sequence numbers should be unpredictable to prevent session hijacking.'],
      ['TCP', 'Acknowledgment number', 8, 4, String(t.ack || 0), t.flags.includes('ACK') ? 'Next byte expected from the peer.' : 'Unused when the ACK flag is not set.'],
      ['TCP', 'Data offset', 12, 1, `${hdrLen / 4} (${hdrLen} bytes)`, 'TCP header length in 32-bit words, including options.'],
      ['TCP', 'Flags', 13, 1, `${t.flags.join(', ')} (${hex(flags)})`, n.flags || ''],
      ['TCP', 'Window size', 14, 2, String(t.window), 'Receive window; initial values can help fingerprint the OS.'],
      ['TCP', 'Checksum', 16, 2, hex(cs, 4), 'Covers a pseudo-header (IPs, protocol, length) plus the whole segment.'],
      ['TCP', 'Urgent pointer', 18, 2, '0', 'Rarely used.']
    ];
    if (options.length) l4Fields.push(['TCP', 'Option: MSS', 20, 4, String(t.mss), 'Maximum segment size the sender can receive.']);
    if (payload.length) l4Fields.push(['Application', 'HTTP request', hdrLen, payload.length, spec.payload.split('\r\n')[0], n.payload || '']);
  } else {
    const u = spec.udp;
    let payload = [];
    const appFields = [];
    if (spec.dns) {
      const d = spec.dns;
      const qname = encodeDnsName(d.name);
      payload = [...u16(d.id), ...u16(d.flags), ...u16(1), 0, 0, 0, 0, 0, 0, ...qname, ...u16(QTYPE[d.qtype]), ...u16(1)];
      const firstLabel = d.name.split('.')[0];
      appFields.push(
        ['DNS', 'Transaction ID', 0, 2, hex(d.id, 4), 'Matches responses to queries; should be random to resist cache poisoning.'],
        ['DNS', 'Flags', 2, 2, `${hex(d.flags, 4)} (standard query, recursion desired)`, ''],
        ['DNS', 'Question count', 4, 2, '1', ''],
        ['DNS', 'Answer / authority / additional counts', 6, 6, '0 / 0 / 0', ''],
        ['DNS', 'QNAME', 12, qname.length, d.name, n.qname || `First label is ${firstLabel.length} characters (maximum 63).`],
        ['DNS', 'QTYPE', 12 + qname.length, 2, `${d.qtype} (${QTYPE[d.qtype]})`, n.qtype || ''],
        ['DNS', 'QCLASS', 14 + qname.length, 2, 'IN (1)', 'Internet class.']
      );
    }
    const len = 8 + payload.length;
    const dgram = [...u16(u.srcPort), ...u16(u.dstPort), ...u16(len), 0, 0, ...payload];
    let cs = checksum16([...pseudoHeader(spec.ip.src, spec.ip.dst, 17, len), ...dgram]);
    if (cs === 0) cs = 0xffff; // RFC 768: a computed zero is transmitted as all ones
    dgram[6] = cs >>> 8; dgram[7] = cs & 0xff;
    l4 = dgram;
    l4Fields = [
      ['UDP', 'Source port', 0, 2, String(u.srcPort), 'Ephemeral client port.'],
      ['UDP', 'Destination port', 2, 2, String(u.dstPort), n.dstPort || ''],
      ['UDP', 'Length', 4, 2, `${len} bytes`, 'UDP header (8 bytes) plus payload.'],
      ['UDP', 'Checksum', 6, 2, hex(cs, 4), 'Optional in IPv4 but computed here over the pseudo-header and datagram.'],
      ...appFields.map(([l, nm, o, ln, v, note]) => [l, nm, 8 + o, ln, v, note])
    ];
  }

  /* --- IPv4 --- */
  const ip = spec.ip;
  const totalLen = 20 + l4.length;
  const iph = [0x45, 0, ...u16(totalLen), ...u16(ip.id), 0x40, 0x00, ip.ttl, proto, 0, 0, ...ipToBytes(ip.src), ...ipToBytes(ip.dst)];
  const ipcs = checksum16(iph);
  iph[10] = ipcs >>> 8; iph[11] = ipcs & 0xff;

  /* --- Ethernet II --- */
  const eth = [...macToBytes(spec.eth.dst), ...macToBytes(spec.eth.src), 0x08, 0x00];

  const bytes = [...eth, ...iph, ...l4];
  add('Ethernet', 'Destination MAC', 0, 6, spec.eth.dst, 'Next-hop MAC on the local segment (often the default gateway).');
  add('Ethernet', 'Source MAC', 6, 6, spec.eth.src, 'Locally administered example address. Real MACs reveal the NIC vendor (OUI).');
  add('Ethernet', 'EtherType', 12, 2, '0x0800 (IPv4)', '');
  const o = 14;
  add('IPv4', 'Version / IHL', o, 1, '4 / 5 (20-byte header)', '');
  add('IPv4', 'DSCP / ECN', o + 1, 1, '0', '');
  add('IPv4', 'Total length', o + 2, 2, `${totalLen} bytes`, '');
  add('IPv4', 'Identification', o + 4, 2, hex(ip.id, 4), 'Used to reassemble fragments.');
  add('IPv4', 'Flags / fragment offset', o + 6, 2, "Don't Fragment, offset 0", '');
  add('IPv4', 'TTL', o + 8, 1, String(ip.ttl), n.ttl || 'Default initial TTL hints at the sender OS (Windows typically 128, Linux 64).');
  add('IPv4', 'Protocol', o + 9, 1, `${proto} (${PROTO_NAME[proto]})`, '');
  add('IPv4', 'Header checksum', o + 10, 2, hex(ipcs, 4), 'Covers the IPv4 header only; recomputed by every router because TTL changes.');
  add('IPv4', 'Source address', o + 12, 4, ip.src, n.src || '');
  add('IPv4', 'Destination address', o + 16, 4, ip.dst, n.dst || '');
  const l4o = 14 + 20;
  for (const [layer, name, off, len, value, note] of l4Fields) add(layer, name, l4o + off, len, value, note);
  return { bytes, fields };
}

/** Verify checksums of a built packet: returns { ip, l4 } booleans. */
export function verifyChecksums(bytes) {
  const ipHdr = bytes.slice(14, 34);
  const proto = ipHdr[9];
  const src = ipHdr.slice(12, 16).join('.'), dst = ipHdr.slice(16, 20).join('.');
  const l4 = bytes.slice(34);
  return { ip: checksum16(ipHdr) === 0, l4: checksum16([...pseudoHeader(src, dst, proto, l4.length), ...l4]) === 0 };
}

/* ---------------- sample packets (simulated) ---------------- */

export const SAMPLE_PACKETS = [
  {
    id: 'tcp-syn-c2',
    title: 'TCP SYN: first connection to a C2 server',
    context: 'WS-HR-022 opens a TLS connection to 198.51.100.88:443 seconds after the PowerShell download cradle (IR-2026-003, LOG-015).',
    spec: {
      eth: { src: '02:00:00:20:04:22', dst: '02:00:00:20:00:01' },
      ip: { src: '10.20.4.22', dst: '198.51.100.88', ttl: 128, id: 0x5a3c },
      tcp: { srcPort: 52019, dstPort: 443, seq: 0x1a2b3c4d, ack: 0, flags: ['SYN'], window: 64240, mss: 1460 },
      notes: {
        flags: 'SYN only: the first step of the three-way handshake. A burst of SYNs to many ports would indicate scanning.',
        dstPort: '443 (HTTPS). Encrypted C2 blends into normal web traffic, so look at destination reputation, first-seen and beacon timing instead.',
        dst: 'External destination never contacted before by this host, which makes it a first-seen indicator.',
        ttl: '128 suggests a Windows sender (consistent with an internal workstation).'
      }
    }
  },
  {
    id: 'dns-txt-tunnel',
    title: 'DNS TXT query: tunnelling pattern',
    context: 'WS-ENG-031 queries a 32-character base32-like label under cdn-sync.example (IR-2026-005, LOG-020).',
    spec: {
      eth: { src: '02:00:00:20:08:31', dst: '02:00:00:20:00:01' },
      ip: { src: '10.20.8.31', dst: '10.20.0.53', ttl: 128, id: 0x7710 },
      udp: { srcPort: 53122, dstPort: 53 },
      dns: { id: 0x4f1a, flags: 0x0100, name: 'mzxw6ytboi2dsnrrgezdgnbvgy3tqojq.cdn-sync.example', qtype: 'TXT' },
      notes: {
        qname: 'A 32-character label drawn from the base32 alphabet. Long, high-entropy labels are a classic DNS tunnelling indicator.',
        qtype: 'TXT records can carry arbitrary text back to the client, which is ideal for C2 responses.',
        dstPort: '53 to the internal resolver (good). Direct queries to external resolvers would bypass DNS logging.'
      }
    }
  },
  {
    id: 'http-sqli',
    title: 'HTTP GET carrying a SQL injection probe',
    context: 'An external client sends a URL-encoded SQL injection attempt to web-01 (LOG-034). Cleartext HTTP is shown so the payload is visible; with TLS, only the web server, a TLS-terminating WAF or the access log can see it.',
    spec: {
      eth: { src: '02:00:00:30:00:fe', dst: '02:00:00:30:00:05' },
      ip: { src: '198.51.100.14', dst: '10.30.0.5', ttl: 52, id: 0x0c41 },
      tcp: { srcPort: 51515, dstPort: 80, seq: 0x00a1b2c3, ack: 0x5f6e7d8c, flags: ['PSH', 'ACK'], window: 502 },
      payload: "GET /products.php?id=1%27%20OR%201%3D1-- HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\nAccept: */*\r\n\r\n",
      notes: {
        payload: '%27 decodes to a single quote and %3D to "=", so the parameter becomes 1\' OR 1=1--. The User-Agent identifies the sqlmap tool.',
        flags: 'PSH, ACK: data segment inside an established connection.',
        ttl: 'TTL 52 means the packet crossed several hops from an initial 64, so it arrived from the internet (through edge NAT).',
        dstPort: '80 (HTTP). An IDS such as Suricata can inspect this cleartext payload; TLS would hide it from network sensors.'
      }
    }
  }
];

/** Hex dump rows: [{ offset, bytes: [{i, value}] , ascii }] */
export function hexRows(bytes, width = 16) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += width) {
    const chunk = bytes.slice(i, i + width);
    rows.push({ offset: i, bytes: chunk.map((v, k) => ({ i: i + k, value: v })), ascii: chunk.map((v) => (v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : '.')).join('') });
  }
  return rows;
}
