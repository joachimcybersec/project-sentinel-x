/**
 * Log parsing and normalisation (pure functions, no DOM).
 *
 * parseLine(raw)   -> { type, format, timestamp, host, fields } | { type: 'unknown', error }
 * normalise(parsed)-> flat object with ECS-style field names (@timestamp, host.name,
 *                     event.code, event.category, event.outcome, source.ip, user.name, …)
 *
 * Supported formats (representative, not byte-exact vendor exports):
 *   windows / sysmon / powershell  "<ISO ts> <host> <Provider> EventID=<n> key=value …"
 *   linux-auth                     RFC 3164 syslog from sshd
 *   firewall                       "<ISO ts> <device> action=… key=value …"
 *   dns                            BIND 9 query log
 *   web                            Apache/Nginx Combined Log Format
 *   edr                            flat JSON object
 *
 * Input is length-capped and only ever matched with anchored regular expressions;
 * nothing is evaluated.
 */

export const MAX_LINE = 4000;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** Parse `key=value key="quoted value"` pairs. Backslashes inside values are kept literally. */
export function parseKV(str) {
  const out = {};
  const re = /([A-Za-z_][\w.]*)=("([^"]*)"|\S*)/g;
  let m;
  while ((m = re.exec(str)) !== null) out[m[1]] = m[3] !== undefined ? m[3] : m[2];
  return out;
}

const WIN = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+) (Microsoft-Windows-[\w-]+) EventID=(\d{1,5})(?: (.*))?$/;
const SYSLOG = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([\w./-]+)(?:\[(\d+)\])?: (.*)$/;
const FW = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) (\S+) (action=.*)$/;
const BIND = /^(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? queries: info: client (?:@0x[0-9a-f]+ )?([0-9a-fA-F.:]+)#(\d+) \([^)]*\): query: (\S+) IN (\w+) ([+-]\S*) \(([^)]+)\)$/;
const CLF = /^(\S+) \S+ (\S+) \[(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-])(\d{2})(\d{2})\] "(\S+) (\S+) ([^"]+)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?$/;

const PROVIDER_TYPE = {
  'Microsoft-Windows-Security-Auditing': 'windows',
  'Microsoft-Windows-Eventlog': 'windows',
  'Microsoft-Windows-Sysmon': 'sysmon',
  'Microsoft-Windows-PowerShell': 'powershell'
};

const iso = (d) => (Number.isNaN(d.getTime()) ? null : d.toISOString().replace('.000Z', 'Z'));

export function parseLine(raw, { year = new Date().getUTCFullYear() } = {}) {
  if (typeof raw !== 'string') return { type: 'unknown', error: 'Input is not text' };
  const line = raw.trim();
  if (!line) return { type: 'unknown', error: 'Empty line' };
  if (line.length > MAX_LINE) return { type: 'unknown', error: `Line longer than ${MAX_LINE} characters` };

  let m;
  if ((m = line.match(WIN))) {
    const type = PROVIDER_TYPE[m[3]];
    if (!type) return { type: 'unknown', error: `Unsupported Windows provider ${m[3]}` };
    return { type, format: 'Windows event (key=value)', timestamp: m[1], host: m[2], fields: { Provider: m[3], EventID: m[4], ...parseKV(m[5] || '') } };
  }
  if ((m = line.match(FW))) {
    return { type: 'firewall', format: 'Firewall (key=value)', timestamp: m[1], host: m[2], fields: parseKV(m[3]) };
  }
  if ((m = line.match(BIND))) {
    const ts = iso(new Date(Date.UTC(+m[3], MONTHS[m[2]], +m[1], ...m[4].split(':').map(Number))));
    return { type: 'dns', format: 'BIND 9 query log', timestamp: ts, host: m[10], fields: { client: m[5], clientPort: m[6], query: m[7], qtype: m[8], flags: m[9], server: m[10] } };
  }
  if ((m = line.match(CLF))) {
    const [hh, mm, ss] = m[6].split(':').map(Number);
    const offsetMin = (m[7] === '-' ? -1 : 1) * (+m[8] * 60 + +m[9]);
    const ts = iso(new Date(Date.UTC(+m[5], MONTHS[m[4]], +m[3], hh, mm, ss) - offsetMin * 60000));
    return { type: 'web', format: 'Combined Log Format', timestamp: ts, host: null,
      fields: { clientIp: m[1], user: m[2], method: m[10], path: m[11], protocol: m[12], status: m[13], bytes: m[14], referrer: m[15] ?? '', userAgent: m[16] ?? '' } };
  }
  if ((m = line.match(SYSLOG))) {
    if (!(m[1] in MONTHS)) return { type: 'unknown', error: 'Unrecognised syslog month' };
    const ts = iso(new Date(Date.UTC(year, MONTHS[m[1]], +m[2], ...m[3].split(':').map(Number))));
    return { type: 'linux-auth', format: 'Syslog (RFC 3164)', timestamp: ts, host: m[4], fields: { program: m[5], pid: m[6] ?? '', message: m[7] } };
  }
  if (line.startsWith('{')) {
    let obj;
    try { obj = JSON.parse(line); } catch { return { type: 'unknown', error: 'Invalid JSON' }; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { type: 'unknown', error: 'JSON is not an object' };
    const flat = {};
    for (const [k, v] of Object.entries(obj)) if (v === null || ['string', 'number', 'boolean'].includes(typeof v)) flat[k] = v;
    return { type: 'edr', format: 'EDR JSON', timestamp: typeof flat.ts === 'string' ? flat.ts : null, host: flat.host ?? null, fields: flat };
  }
  return { type: 'unknown', error: 'No parser matched this line' };
}

/* ------------------------------------------------------------------ */
/* Normalisation                                                       */
/* ------------------------------------------------------------------ */

function splitUser(u) {
  if (!u || u === '-') return {};
  const i = u.lastIndexOf('\\');
  return i >= 0 ? { 'user.domain': u.slice(0, i), 'user.name': u.slice(i + 1) } : { 'user.name': u };
}

const WIN_CODES = {
  4624: { category: 'authentication', action: 'logon', outcome: 'success' },
  4625: { category: 'authentication', action: 'logon-failed', outcome: 'failure' },
  4672: { category: 'iam', action: 'special-privileges-assigned' },
  4688: { category: 'process', action: 'process-created' },
  4698: { category: 'configuration', action: 'scheduled-task-created' },
  4720: { category: 'iam', action: 'user-account-created' },
  4740: { category: 'iam', action: 'account-locked-out' },
  1102: { category: 'configuration', action: 'audit-log-cleared' }
};
const SYSMON_CODES = {
  1: { category: 'process', action: 'process-created' },
  3: { category: 'network', action: 'network-connection' },
  10: { category: 'process', action: 'process-accessed' },
  11: { category: 'file', action: 'file-created' },
  13: { category: 'registry', action: 'registry-value-set' },
  22: { category: 'network', action: 'dns-query' }
};

export function normalise(p) {
  if (!p || p.type === 'unknown') return null;
  const f = p.fields;
  const n = { '@timestamp': p.timestamp, 'log.type': p.type, 'host.name': p.host || null };

  if (p.type === 'windows' || p.type === 'sysmon' || p.type === 'powershell') {
    const code = Number(f.EventID);
    const meta = (p.type === 'sysmon' ? SYSMON_CODES : p.type === 'powershell' ? { 4104: { category: 'process', action: 'script-block-logged' } } : WIN_CODES)[code] || {};
    Object.assign(n, { 'event.code': String(code), 'event.provider': f.Provider, 'event.category': meta.category || 'other', 'event.action': meta.action || `event-${code}` });
    if (meta.outcome) n['event.outcome'] = meta.outcome;
    if (f.TargetUserName && (code === 4624 || code === 4625 || code === 4740)) Object.assign(n, { 'user.name': f.TargetUserName, 'user.domain': f.TargetDomainName });
    if (f.SubjectUserName) Object.assign(n, { 'user.name': f.SubjectUserName, 'user.domain': f.SubjectDomainName });
    if (code === 4720) n['user.target.name'] = f.TargetUserName;
    if (f.IpAddress && f.IpAddress !== '-') n['source.ip'] = f.IpAddress;
    if (f.IpPort) n['source.port'] = Number(f.IpPort);
    if (f.LogonType) n['winlog.logon.type'] = Number(f.LogonType);
    if (f.Status) n['winlog.event_data.Status'] = f.Status;
    if (f.SubStatus) n['winlog.event_data.SubStatus'] = f.SubStatus;
    if (f.PrivilegeList) n['winlog.event_data.PrivilegeList'] = f.PrivilegeList;
    if (f.TaskName) n['winlog.event_data.TaskName'] = f.TaskName;
    if (f.Image) n['process.executable'] = f.Image;
    if (f.SourceImage) n['process.executable'] = f.SourceImage;
    if (f.CommandLine) n['process.command_line'] = f.CommandLine;
    if (f.ParentImage) n['process.parent.executable'] = f.ParentImage;
    if (f.TargetImage) n['process.target.executable'] = f.TargetImage;
    if (f.GrantedAccess) n['winlog.event_data.GrantedAccess'] = f.GrantedAccess;
    if (f.TargetFilename) n['file.path'] = f.TargetFilename;
    if (f.TargetObject) n['registry.path'] = f.TargetObject;
    if (f.Details) n['registry.data.strings'] = f.Details;
    if (f.QueryName) n['dns.question.name'] = f.QueryName;
    if (f.DestinationIp) n['destination.ip'] = f.DestinationIp;
    if (f.DestinationPort) n['destination.port'] = Number(f.DestinationPort);
    if (f.SourceIp) n['source.ip'] = f.SourceIp;
    if (f.Protocol) n['network.transport'] = f.Protocol;
    if (f.ScriptBlockText) n['powershell.file.script_block_text'] = f.ScriptBlockText;
    if (f.User) Object.assign(n, splitUser(f.User));
  } else if (p.type === 'linux-auth') {
    Object.assign(n, { 'process.name': f.program, 'event.category': 'authentication' });
    if (f.pid) n['process.pid'] = Number(f.pid);
    let m;
    if ((m = f.message.match(/^Failed password for (invalid user )?(\S+) from ([0-9a-fA-F.:]+) port (\d+)/))) {
      Object.assign(n, { 'event.action': 'ssh-login-failed', 'event.outcome': 'failure', 'user.name': m[2], 'source.ip': m[3], 'source.port': Number(m[4]) });
      if (m[1]) n['user.invalid'] = true;
    } else if ((m = f.message.match(/^Accepted (\S+) for (\S+) from ([0-9a-fA-F.:]+) port (\d+)/))) {
      Object.assign(n, { 'event.action': 'ssh-login', 'event.outcome': 'success', 'user.name': m[2], 'source.ip': m[3], 'source.port': Number(m[4]), 'ssh.method': m[1] });
    } else if ((m = f.message.match(/^Invalid user (\S+) from ([0-9a-fA-F.:]+)(?: port (\d+))?/))) {
      Object.assign(n, { 'event.action': 'ssh-invalid-user', 'event.outcome': 'unknown', 'user.name': m[1], 'source.ip': m[2] });
      if (m[3]) n['source.port'] = Number(m[3]);
    } else {
      n['event.action'] = 'syslog-message';
    }
    n.message = f.message;
  } else if (p.type === 'firewall') {
    Object.assign(n, { 'event.category': 'network', 'event.action': `firewall-${f.action || 'unknown'}`, 'event.outcome': f.action === 'allow' ? 'success' : 'failure',
      'source.ip': f.src, 'destination.ip': f.dst, 'network.transport': f.proto, 'rule.name': f.rule });
    if (f.spt) n['source.port'] = Number(f.spt);
    if (f.dpt) n['destination.port'] = Number(f.dpt);
    if (f.bytes_out) n['source.bytes'] = Number(f.bytes_out);
    if (f.bytes_in) n['destination.bytes'] = Number(f.bytes_in);
    if (f.duration) n['event.duration_s'] = Number(f.duration);
  } else if (p.type === 'dns') {
    Object.assign(n, { 'event.category': 'network', 'event.action': 'dns-query', 'source.ip': f.client, 'source.port': Number(f.clientPort),
      'dns.question.name': f.query, 'dns.question.type': f.qtype, 'server.ip': f.server });
  } else if (p.type === 'web') {
    Object.assign(n, { 'event.category': 'web', 'event.action': 'http-request', 'source.ip': f.clientIp, 'http.request.method': f.method,
      'url.original': f.path, 'http.version': f.protocol.replace('HTTP/', ''), 'http.response.status_code': Number(f.status),
      'http.response.bytes': f.bytes === '-' ? 0 : Number(f.bytes), 'user_agent.original': f.userAgent });
    n['event.outcome'] = Number(f.status) < 400 ? 'success' : 'failure';
  } else if (p.type === 'edr') {
    Object.assign(n, { 'event.category': 'malware', 'event.action': f.action, 'rule.name': f.detection, 'observer.vendor': f.vendor, 'event.severity_label': f.severity });
    if (f.process && f.process !== '-') n['process.executable'] = f.process;
    if (f.files_affected !== undefined) n['file.count'] = f.files_affected;
    if (f.isolation_status) n['edr.isolation_status'] = f.isolation_status;
  }
  for (const k of Object.keys(n)) if (n[k] === undefined || n[k] === '') delete n[k];
  return n;
}

/** One-line human summary for tables. */
export function summarise(n) {
  if (!n) return 'Unparsed line';
  const who = n['user.name'] ? ` ${n['user.name']}` : '';
  const src = n['source.ip'] ? ` from ${n['source.ip']}` : '';
  switch (n['log.type']) {
    case 'dns': return `${n['source.ip']} queried ${n['dns.question.name']} (${n['dns.question.type']})`;
    case 'web': return `${n['http.request.method']} ${n['url.original']} → ${n['http.response.status_code']}${src}`;
    case 'firewall': return `${n['event.action'].replace('firewall-', '').toUpperCase()} ${n['network.transport']} ${n['source.ip']} → ${n['destination.ip']}:${n['destination.port']}${n['source.bytes'] ? ` (${(n['source.bytes'] / 1048576).toFixed(0)} MiB out)` : ''}`;
    case 'edr': return `${n['rule.name']} (${n['event.action']})`;
    default: {
      const proc = n['process.executable'] ? ` ${n['process.executable'].split('\\').pop()}` : '';
      return `${n['event.action'] || 'event'}${who}${src}${proc}`;
    }
  }
}

/** Parse + normalise a dataset of { id, raw } entries. */
export function processLogs(logs, opts) {
  return logs.map((l) => {
    const parsed = parseLine(l.raw, opts);
    const norm = normalise(parsed);
    return { id: l.id, declaredType: l.type, raw: l.raw, parsed, norm, summary: summarise(norm) };
  });
}
