/**
 * CVSS vector parsing and the Sentinel X prioritisation model (pure functions).
 * Metric names and values follow the FIRST CVSS v2, v3.x and v4.0 specifications.
 */

const V3 = {
  AV: ['Attack Vector', { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }],
  AC: ['Attack Complexity', { L: 'Low', H: 'High' }],
  PR: ['Privileges Required', { N: 'None', L: 'Low', H: 'High' }],
  UI: ['User Interaction', { N: 'None', R: 'Required' }],
  S: ['Scope', { U: 'Unchanged', C: 'Changed' }],
  C: ['Confidentiality', { H: 'High', L: 'Low', N: 'None' }],
  I: ['Integrity', { H: 'High', L: 'Low', N: 'None' }],
  A: ['Availability', { H: 'High', L: 'Low', N: 'None' }]
};
const HLN = { H: 'High', L: 'Low', N: 'None' };
const V4 = {
  AV: ['Attack Vector', { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }],
  AC: ['Attack Complexity', { L: 'Low', H: 'High' }],
  AT: ['Attack Requirements', { N: 'None', P: 'Present' }],
  PR: ['Privileges Required', { N: 'None', L: 'Low', H: 'High' }],
  UI: ['User Interaction', { N: 'None', P: 'Passive', A: 'Active' }],
  VC: ['Vulnerable System Confidentiality', HLN], VI: ['Vulnerable System Integrity', HLN], VA: ['Vulnerable System Availability', HLN],
  SC: ['Subsequent System Confidentiality', HLN], SI: ['Subsequent System Integrity', HLN], SA: ['Subsequent System Availability', HLN]
};
const V2 = {
  AV: ['Access Vector', { L: 'Local', A: 'Adjacent Network', N: 'Network' }],
  AC: ['Access Complexity', { H: 'High', M: 'Medium', L: 'Low' }],
  Au: ['Authentication', { M: 'Multiple', S: 'Single', N: 'None' }],
  C: ['Confidentiality', { N: 'None', P: 'Partial', C: 'Complete' }],
  I: ['Integrity', { N: 'None', P: 'Partial', C: 'Complete' }],
  A: ['Availability', { N: 'None', P: 'Partial', C: 'Complete' }]
};

/** Parse a CVSS vector into { version, metrics: [{ key, name, value, label }] }. Unknown parts are kept raw. */
export function parseCvssVector(vector) {
  if (typeof vector !== 'string' || !vector) return null;
  const parts = vector.split('/');
  let version = '2.0';
  let table = V2;
  if (/^CVSS:3\.[01]$/.test(parts[0])) { version = parts[0].slice(5); table = V3; parts.shift(); }
  else if (parts[0] === 'CVSS:4.0') { version = '4.0'; table = V4; parts.shift(); }
  const metrics = [];
  for (const p of parts) {
    const [key, value] = p.split(':');
    const def = table[key];
    if (!def) continue; // temporal/environmental/threat metrics are not shown
    metrics.push({ key, name: def[0], value, label: def[1][value] || value });
  }
  return { version, metrics };
}

/**
 * Sentinel X prioritisation (a transparent teaching model, not an industry standard):
 *   P1 Act now   KEV-listed AND (known ransomware use OR CVSS ≥ 9.0)
 *   P2 Urgent    KEV-listed
 *   P3 Elevated  EPSS ≥ 0.10 OR CVSS ≥ 9.0
 *   P4 Routine   everything else
 */
export function prioritise(c) {
  const kev = !!c.dateAdded;
  const score = c.nvd && c.nvd.cvss ? Number(c.nvd.cvss.baseScore) : null;
  const epss = c.epss ? Number(c.epss.score) : null;
  const ransomware = c.knownRansomwareCampaignUse === 'Known';
  const reasons = [];
  if (kev) reasons.push('listed in CISA KEV (exploited in the wild)');
  if (ransomware) reasons.push('known use in ransomware campaigns');
  if (score !== null && score >= 9) reasons.push(`CVSS ${score.toFixed(1)} (critical)`);
  if (epss !== null && epss >= 0.1) reasons.push(`EPSS ${(epss * 100).toFixed(1)}%`);
  let tier = 'P4';
  if (kev && (ransomware || (score !== null && score >= 9))) tier = 'P1';
  else if (kev) tier = 'P2';
  else if ((epss !== null && epss >= 0.1) || (score !== null && score >= 9)) tier = 'P3';
  return { tier, reasons };
}

export const TIER_LABEL = { P1: 'Act now', P2: 'Urgent', P3: 'Elevated', P4: 'Routine' };

/** Days between two dates (UTC calendar days, b − a). */
export function daysBetween(a, b) {
  const d = (x) => Date.UTC(x.getUTCFullYear(), x.getUTCMonth(), x.getUTCDate());
  return Math.round((d(new Date(b)) - d(new Date(a))) / 86400000);
}
