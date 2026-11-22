/**
 * Enrichment and correlation rules (pure functions).
 *
 * Rules run over normalised entries ({ id, norm }) and return alerts:
 *   { ruleId, ruleName, severity, mitre, ts, key, summary, evidence: [logIds] }
 *
 * The rules are deliberately simple and readable. They show how SIEM correlation
 * works (thresholds, time windows, grouping, sequences), not production-tuned
 * content. Phase 6 expresses detections as Sigma rules.
 */

/* ---------------- enrichment ---------------- */

const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./];
const DOC_RANGES = [/^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./];

export function ipScope(ip) {
  if (!ip) return null;
  if (PRIVATE.some((r) => r.test(ip))) return 'internal';
  if (DOC_RANGES.some((r) => r.test(ip))) return 'external (RFC 5737 documentation range, simulated)';
  return 'external';
}
export const isExternal = (ip) => !!ip && !PRIVATE.some((r) => r.test(ip));

/** Last two labels — a simplification; production code should use the Public Suffix List. */
export const registeredDomain = (name) => String(name || '').toLowerCase().split('.').filter(Boolean).slice(-2).join('.');

/**
 * Add asset context and IOC-watchlist matches.
 * assets: [{ ip, host, role, criticality }], iocs: [{ type, value, role }]
 */
export function enrich(norm, { assets = [], iocs = [] } = {}) {
  if (!norm) return { assets: [], iocMatches: [], scopes: {} };
  const byIp = new Map(assets.map((a) => [a.ip, a]));
  const byHost = new Map(assets.map((a) => [a.host.toLowerCase(), a]));
  const found = [];
  for (const k of ['source.ip', 'destination.ip']) if (byIp.has(norm[k])) found.push({ field: k, ...byIp.get(norm[k]) });
  if (norm['host.name'] && byHost.has(String(norm['host.name']).toLowerCase())) found.push({ field: 'host.name', ...byHost.get(String(norm['host.name']).toLowerCase()) });

  const observables = [norm['source.ip'], norm['destination.ip'], norm['dns.question.name'], norm['url.original'], norm['powershell.file.script_block_text']]
    .filter(Boolean).map((v) => String(v).toLowerCase());
  const iocMatches = iocs.filter((i) => {
    const v = String(i.value).toLowerCase();
    return observables.some((o) => o === v || (i.type === 'domain' && registeredDomain(o) === v) || ((i.type === 'url' || i.type === 'ipv4') && o.includes(v)));
  });
  const scopes = {};
  for (const k of ['source.ip', 'destination.ip']) if (norm[k]) scopes[k] = ipScope(norm[k]);
  return { assets: found, iocMatches, scopes };
}

/* ---------------- helpers ---------------- */

const t = (e) => Date.parse(e.norm['@timestamp']);
const byTime = (a, b) => t(a) - t(b);

/** Group entries by key, then find clusters of >= threshold within windowMs. One alert per cluster. */
function thresholdClusters(entries, keyFn, threshold, windowMs) {
  const groups = new Map();
  for (const e of entries) { const k = keyFn(e); if (k) (groups.get(k) || groups.set(k, []).get(k)).push(e); }
  const clusters = [];
  for (const [key, list] of groups) {
    list.sort(byTime);
    let i = 0;
    while (i < list.length) {
      let j = i;
      while (j + 1 < list.length && t(list[j + 1]) - t(list[i]) <= windowMs) j++;
      const size = j - i + 1;
      if (size >= threshold) { clusters.push({ key, items: list.slice(i, j + 1) }); i = j + 1; } else i++;
    }
  }
  return clusters;
}

const exe = (p) => String(p || '').toLowerCase().split('\\').pop();
const OFFICE = new Set(['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']);
const INTERPRETERS = new Set(['powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe']);
const RECOVERY_INHIBIT = /(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit(\.exe)?\s+.*recoveryenabled\s+no)/i;

/* ---------------- rules ---------------- */

export const RULES = [
  {
    id: 'COR-001', name: 'Brute-force: repeated authentication failures', severity: 'high', mitre: 'T1110.001',
    params: { threshold: 5, windowMin: 5 },
    logic: 'Count authentication failures (Windows 4625, sshd "Failed password") per source IP. Alert when the count reaches the threshold within the time window.',
    falsePositives: 'Misconfigured services retrying old credentials; users with a changed password on several devices.',
    run(entries, p) {
      const fails = entries.filter((e) => e.norm && e.norm['event.category'] === 'authentication' && e.norm['event.outcome'] === 'failure');
      return thresholdClusters(fails, (e) => e.norm['source.ip'], p.threshold, p.windowMin * 60000).map((c) => ({
        key: c.key, ts: c.items[c.items.length - 1].norm['@timestamp'], evidence: c.items.map((e) => e.id),
        summary: `${c.items.length} failed logons from ${c.key} in ${Math.round((t(c.items[c.items.length - 1]) - t(c.items[0])) / 1000)} s (users: ${[...new Set(c.items.map((e) => e.norm['user.name']))].join(', ')})`
      }));
    }
  },
  {
    id: 'COR-002', name: 'Successful logon after repeated failures', severity: 'critical', mitre: 'T1078',
    params: { minFailures: 3, windowMin: 10 },
    logic: 'For each successful logon, look back over the window for failures on the same account from the same source IP. Alert when at least the minimum number of failures preceded the success.',
    falsePositives: 'A user who mistyped their password a few times before getting it right, especially after a password change.',
    run(entries, p) {
      const auth = entries.filter((e) => e.norm && e.norm['event.category'] === 'authentication').sort(byTime);
      const out = [];
      for (const s of auth.filter((e) => e.norm['event.outcome'] === 'success')) {
        const prior = auth.filter((f) => f.norm['event.outcome'] === 'failure' && f.norm['user.name'] === s.norm['user.name'] &&
          f.norm['source.ip'] === s.norm['source.ip'] && t(f) <= t(s) && t(s) - t(f) <= p.windowMin * 60000);
        if (prior.length >= p.minFailures) out.push({ key: `${s.norm['user.name']}@${s.norm['source.ip']}`, ts: s.norm['@timestamp'],
          evidence: [...prior.map((e) => e.id), s.id], summary: `${s.norm['user.name']} logged on from ${s.norm['source.ip']} after ${prior.length} failures` });
      }
      return out;
    }
  },
  {
    id: 'COR-003', name: 'Office application spawned a script interpreter', severity: 'high', mitre: 'T1204.002',
    params: {},
    logic: 'Sysmon process creation (event 1) where the parent is an Office binary and the child is a script interpreter or LOLBin (PowerShell, cmd, wscript, mshta, rundll32, regsvr32).',
    falsePositives: 'Legitimate macros or add-ins that call scripts; document management integrations.',
    run(entries) {
      return entries.filter((e) => e.norm && e.norm['log.type'] === 'sysmon' && e.norm['event.code'] === '1' &&
        OFFICE.has(exe(e.norm['process.parent.executable'])) && INTERPRETERS.has(exe(e.norm['process.executable'])))
        .map((e) => ({ key: e.norm['host.name'], ts: e.norm['@timestamp'], evidence: [e.id],
          summary: `${exe(e.norm['process.parent.executable'])} → ${exe(e.norm['process.executable'])} on ${e.norm['host.name']} (${e.norm['user.name'] || 'unknown user'})` }));
    }
  },
  {
    id: 'COR-004', name: 'LSASS memory access', severity: 'critical', mitre: 'T1003.001',
    params: {},
    logic: 'Sysmon process access (event 10) where the target is lsass.exe and the source is not on an allow-list of expected security tools.',
    falsePositives: 'EDR, antivirus and backup agents legitimately open LSASS; maintain an allow-list.',
    run(entries) {
      const allow = new Set(['msmpeng.exe', 'csrss.exe', 'wininit.exe']);
      return entries.filter((e) => e.norm && e.norm['log.type'] === 'sysmon' && e.norm['event.code'] === '10' &&
        exe(e.norm['process.target.executable']) === 'lsass.exe' && !allow.has(exe(e.norm['process.executable'])))
        .map((e) => ({ key: e.norm['host.name'], ts: e.norm['@timestamp'], evidence: [e.id],
          summary: `${exe(e.norm['process.executable'])} opened lsass.exe (access ${e.norm['winlog.event_data.GrantedAccess']}) on ${e.norm['host.name']}` }));
    }
  },
  {
    id: 'COR-005', name: 'Possible DNS tunnelling', severity: 'high', mitre: 'T1071.004',
    params: { threshold: 5, windowMin: 10, minLabel: 25 },
    logic: 'Group DNS queries by registered domain. Alert when at least the threshold number of queries with a first label of at least the minimum length occur within the window.',
    falsePositives: 'CDNs and security products that encode identifiers in subdomains; allow-list known services.',
    run(entries, p) {
      const q = entries.filter((e) => e.norm && e.norm['dns.question.name'] && e.norm['dns.question.name'].split('.')[0].length >= p.minLabel);
      return thresholdClusters(q, (e) => registeredDomain(e.norm['dns.question.name']), p.threshold, p.windowMin * 60000).map((c) => ({
        key: c.key, ts: c.items[c.items.length - 1].norm['@timestamp'], evidence: c.items.map((e) => e.id),
        summary: `${c.items.length} long-label queries to ${c.key} from ${[...new Set(c.items.map((e) => e.norm['source.ip'] || e.norm['host.name']))].join(', ')}`
      }));
    }
  },
  {
    id: 'COR-006', name: 'Large outbound transfer to external host', severity: 'high', mitre: 'T1048',
    params: { thresholdMB: 500 },
    logic: 'Firewall session records where bytes sent from an internal host to an external destination exceed the threshold.',
    falsePositives: 'Backups to cloud storage, software distribution, large legitimate uploads; baseline per host.',
    run(entries, p) {
      return entries.filter((e) => e.norm && e.norm['log.type'] === 'firewall' && (e.norm['source.bytes'] || 0) >= p.thresholdMB * 1048576 &&
        !isExternal(e.norm['source.ip']) && isExternal(e.norm['destination.ip']))
        .map((e) => ({ key: `${e.norm['source.ip']}→${e.norm['destination.ip']}`, ts: e.norm['@timestamp'], evidence: [e.id],
          summary: `${(e.norm['source.bytes'] / 1073741824).toFixed(2)} GiB from ${e.norm['source.ip']} to ${e.norm['destination.ip']}:${e.norm['destination.port']} in ${e.norm['event.duration_s']} s` }));
    }
  },
  {
    id: 'COR-007', name: 'System recovery inhibited', severity: 'critical', mitre: 'T1490',
    params: {},
    logic: 'Process command lines that delete shadow copies or backup catalogs, or disable boot recovery (vssadmin, wmic shadowcopy, wbadmin, bcdedit).',
    falsePositives: 'Rare. Some backup software rotates shadow copies; confirm the parent process.',
    run(entries) {
      return entries.filter((e) => e.norm && RECOVERY_INHIBIT.test(e.norm['process.command_line'] || ''))
        .map((e) => ({ key: e.norm['host.name'], ts: e.norm['@timestamp'], evidence: [e.id],
          summary: `"${e.norm['process.command_line']}" on ${e.norm['host.name']} (parent ${exe(e.norm['process.parent.executable'])})` }));
    }
  },
  {
    id: 'COR-008', name: 'Security audit log cleared', severity: 'high', mitre: 'T1070.001',
    params: {},
    logic: 'Windows event 1102 (the audit log was cleared).',
    falsePositives: 'Documented maintenance on test systems. Unexpected on domain controllers.',
    run(entries) {
      return entries.filter((e) => e.norm && e.norm['log.type'] === 'windows' && e.norm['event.code'] === '1102')
        .map((e) => ({ key: e.norm['host.name'], ts: e.norm['@timestamp'], evidence: [e.id], summary: `Audit log cleared on ${e.norm['host.name']} by ${e.norm['user.name']}` }));
    }
  }
];

/** Run enabled rules with optional parameter overrides: { 'COR-001': { threshold: 3 } }. */
export function correlate(entries, { enabled = RULES.map((r) => r.id), params = {} } = {}) {
  const alerts = [];
  for (const rule of RULES) {
    if (!enabled.includes(rule.id)) continue;
    const p = { ...rule.params, ...(params[rule.id] || {}) };
    for (const a of rule.run(entries, p)) alerts.push({ ruleId: rule.id, ruleName: rule.name, severity: rule.severity, mitre: rule.mitre, ...a });
  }
  return alerts.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
}
