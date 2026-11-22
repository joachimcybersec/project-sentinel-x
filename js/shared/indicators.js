/**
 * Indicator classification and validation, shared by the browser UI and the
 * Netlify Function (netlify/lib/ioc-core.mjs). Pure functions, no DOM,
 * no Node APIs, so the same rules apply on both sides.
 */

export const MAX_INDICATOR = 253;

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const HASH = { md5: /^[a-f0-9]{32}$/, sha1: /^[a-f0-9]{40}$/, sha256: /^[a-f0-9]{64}$/ };

/** Undo common defanging ("hxxp", "[.]", "(.)", "[:]") so analysts can paste indicators from reports. */
export function refang(v) {
  return String(v).trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':');
}

export function defang(v) {
  const s = String(v);
  const m = s.match(/^(https?):\/\/([^/?#]+)(.*)$/i);
  if (m) return `${m[1].toLowerCase().replace(/^http/, 'hxxp')}://${m[2].replace(/\./g, '[.]')}${m[3]}`;
  return s.replace(/\./g, '[.]');
}

const toInt = (ip) => ip.split('.').reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0;
const inRange = (ip, cidr) => {
  const [net, bits] = cidr.split('/');
  const mask = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return ((toInt(ip) & mask) >>> 0) === ((toInt(net) & mask) >>> 0);
};

/** RFC 5737 documentation ranges, used throughout Sentinel X's simulated data. */
export const DOCUMENTATION_RANGES = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'];
/** Private, loopback, link-local, CGNAT, IETF protocol assignments, benchmarking (RFC 2544), multicast and
 *  reserved ranges (IANA IPv4 Special-Purpose Address Registry): never sent to external services. */
export const NON_PUBLIC_RANGES = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4'];
const RESERVED_TLDS = ['example', 'test', 'invalid', 'localhost', 'local', 'internal'];

/**
 * Classify a pasted indicator.
 * Returns { ok: true, type: 'ipv4'|'domain'|'md5'|'sha1'|'sha256', value, lookup: true|false, reason? }
 *      or { ok: false, error }.
 * lookup=false means "valid, but must not or need not be sent to external services".
 */
export function classifyIndicator(input) {
  if (typeof input !== 'string') return { ok: false, error: 'Indicator must be text.' };
  const raw = refang(input);
  if (!raw) return { ok: false, error: 'Enter an IP address, domain or file hash.' };
  if (raw.length > MAX_INDICATOR) return { ok: false, error: `Indicator longer than ${MAX_INDICATOR} characters.` };
  const v = raw.toLowerCase();

  if (IPV4.test(v)) {
    if (DOCUMENTATION_RANGES.some((r) => inRange(v, r))) return { ok: true, type: 'ipv4', value: v, lookup: false, reason: 'documentation' };
    if (NON_PUBLIC_RANGES.some((r) => inRange(v, r))) return { ok: true, type: 'ipv4', value: v, lookup: false, reason: 'non-public' };
    return { ok: true, type: 'ipv4', value: v, lookup: true };
  }
  for (const [type, re] of Object.entries(HASH)) if (re.test(v)) return { ok: true, type, value: v, lookup: true };
  if (/^https?:\/\//.test(v)) return { ok: false, error: 'Full URLs are not supported; look up the domain instead.' };
  const host = v.replace(/\.$/, '');
  if (DOMAIN.test(host)) {
    const tld = host.split('.').pop();
    if (RESERVED_TLDS.includes(tld)) return { ok: true, type: 'domain', value: host, lookup: false, reason: 'reserved-tld' };
    return { ok: true, type: 'domain', value: host, lookup: true };
  }
  return { ok: false, error: 'Not a valid IPv4 address, domain name or MD5/SHA-1/SHA-256 hash. (IPv6 is not supported yet.)' };
}

export const NO_LOOKUP_REASON = {
  documentation: 'This address is in an RFC 5737 documentation range (used by Sentinel X\'s simulated data). It is not real infrastructure, so there is nothing to look up.',
  'non-public': 'This is a private, loopback, link-local or otherwise non-public address. Internal addresses are never sent to external services.',
  'reserved-tld': 'This domain uses a reserved top-level domain (such as .example or .test) that does not exist on the public internet.'
};
