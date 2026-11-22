import { test, assert } from './test-runner.js';
import { load } from '../js/data-service.js';
import { parseYaml } from '../js/detection/yaml.js';
import { validateSigma, runSigma, parseCondition, sigmaPattern, inCidr, toSigmaEvent, logsourceMatches } from '../js/detection/sigma.js';
import { processLogs } from '../js/siem/parsers.js';
import { ATTACK_NAMES } from '../js/utils/attack.js';

const logs = async () => { const { data } = await load('logs'); return processLogs(data.logs, { year: data.syslogYear }); };
const ruleText = (r) => r.yaml.join('\n');

/* ---------- YAML subset ---------- */
test('parseYaml: maps, nested maps, lists, flow lists, quoting, comments', () => {
  const y = parseYaml([
    'title: Test  # comment',
    'tags: [attack.execution, "attack.t1059"]',
    'detection:',
    '  sel:',
    "    Image|endswith: '\\\\cmd.exe'",
    '    Values:',
    "      - 'it''s'",
    '      - "q\\"x"',
    '      - 4688',
    '  condition: sel',
    'empty:',
    'list_same_indent:',
    '- a',
    '- b'
  ].join('\n'));
  assert.equal(y.title, 'Test');
  assert.deepEqual(y.tags, ['attack.execution', 'attack.t1059']);
  assert.equal(y.detection.sel['Image|endswith'], '\\\\cmd.exe', 'single quotes keep backslashes literally');
  assert.deepEqual(y.detection.sel.Values, ["it's", 'q"x', 4688]);
  assert.equal(y.empty, null);
  assert.deepEqual(y.list_same_indent, ['a', 'b']);
});

test('parseYaml: list of mappings', () => {
  const y = parseYaml('sel:\n  - Image: a.exe\n    User: x\n  - Image: b.exe');
  assert.deepEqual(y.sel, [{ Image: 'a.exe', User: 'x' }, { Image: 'b.exe' }]);
});

test('parseYaml rejects unsupported or dangerous input with line numbers', () => {
  const err = (t) => { try { parseYaml(t); return null; } catch (e) { return e.message; } };
  assert.ok(err('a:\n\tb: 1').includes('Tabs'));
  assert.ok(err('a: |\n  text').includes('Block scalars'));
  assert.ok(err('a: &x 1').includes('Anchors'));
  assert.ok(err('a: 1\na: 2').includes('Duplicate key'));
  assert.ok(err('__proto__: 1').includes('not allowed'));
  assert.ok(err("a: 'open").includes('Line 1'));
  assert.ok(err('x'.repeat(20001)).includes('longer than'));
});

/* ---------- Sigma primitives ---------- */
test('condition parser: precedence, parentheses, "of" quantifiers', () => {
  assert.deepEqual(parseCondition('a or b and not c'), { op: 'or', a: { op: 'id', name: 'a' }, b: { op: 'and', a: { op: 'id', name: 'b' }, b: { op: 'not', a: { op: 'id', name: 'c' } } } });
  assert.equal(parseCondition('(a or b) and c').op, 'and');
  assert.deepEqual(parseCondition('1 of sel_*'), { op: 'of', quant: 'any', pattern: 'sel_*' });
  assert.deepEqual(parseCondition('all of them'), { op: 'of', quant: 'all', pattern: 'them' });
  assert.throws(() => parseCondition('a and'));
  assert.throws(() => parseCondition('(a or b'));
  assert.throws(() => parseCondition('sel | count() > 5'));
});

test('sigmaPattern: wildcards, escapes, case-insensitivity, literal backslashes', () => {
  assert.ok(sigmaPattern('*\\WINWORD.EXE').test('C:\\Office\\winword.exe'));
  assert.ok(sigmaPattern('a?c').test('abc'));
  assert.ok(!sigmaPattern('a\\*c').test('abc'), '\\* is a literal star');
  assert.ok(sigmaPattern('a\\*c').test('a*c'));
  assert.ok(sigmaPattern('x.y').test('X.Y') && !sigmaPattern('x.y').test('xzy'), '. is literal');
});

test('inCidr', () => {
  assert.ok(inCidr('10.20.5.14', '10.0.0.0/8'));
  assert.ok(inCidr('172.31.0.1', '172.16.0.0/12'));
  assert.ok(!inCidr('172.32.0.1', '172.16.0.0/12'));
  assert.ok(!inCidr('203.0.113.200', '10.0.0.0/8'));
  assert.ok(!inCidr('not-an-ip', '10.0.0.0/8'));
});

test('logsource mapping for each log type', async () => {
  const entries = await logs();
  const ev = (id) => toSigmaEvent(entries.find((e) => e.id === id));
  assert.ok(logsourceMatches({ product: 'windows', category: 'process_creation' }, ev('LOG-012').tags));
  assert.ok(logsourceMatches({ product: 'windows', category: 'ps_script' }, ev('LOG-013').tags));
  assert.ok(logsourceMatches({ product: 'windows', service: 'security' }, ev('LOG-041').tags));
  assert.ok(logsourceMatches({ product: 'linux', service: 'sshd' }, ev('LOG-045').tags));
  assert.ok(logsourceMatches({ category: 'webserver' }, ev('LOG-034').tags));
  assert.equal(ev('LOG-034').fields['cs-uri-query'], 'id=1%27%20OR%201%3D1--');
  assert.ok(!logsourceMatches({ product: 'windows', category: 'process_creation' }, ev('LOG-017').tags), 'process_access is not process_creation');
  assert.ok(!logsourceMatches({}, ev('LOG-012').tags), 'empty logsource matches nothing');
});

/* ---------- validator ---------- */
test('validateSigma reports missing fields, bad references and unsupported features', () => {
  const v = validateSigma('title: x\nid: nope\nstatus: draft\nlevel: severe\nlogsource:\n  foo: bar\ndetection:\n  sel:\n    A|base64: x\n  condition: sel and missing');
  const msg = v.errors.join(' | ');
  for (const part of ['id must be a UUID', 'status must be', 'level must be', 'logsource needs', 'unknown identifier "missing"', 'Unsupported modifier "base64"']) assert.ok(msg.includes(part), `expected "${part}" in ${msg}`);
  const w = validateSigma('title: x\nid: 7c1e4a92-3b5d-4f08-9a6e-2d4b8c0f1a37\nstatus: test\nlevel: low\nlogsource:\n  category: dns\ndetection:\n  a:\n    query: x\n  b:\n    query: y\n  condition: a');
  assert.deepEqual(w.errors, []);
  assert.ok(w.warnings.some((x) => x.includes('"b" is not used')));
  assert.ok(validateSigma('x: [').errors[0].includes('Line 1'));
});

test('evaluator semantics: all, null, keywords, numeric and regex modifiers', async () => {
  const entries = await logs();
  const head = 'title: t\nid: 7c1e4a92-3b5d-4f08-9a6e-2d4b8c0f1a37\nstatus: test\nlevel: low\n';
  const run = (body) => runSigma(head + body, entries);
  assert.deepEqual(run("logsource:\n  product: windows\n  service: security\ndetection:\n  s:\n    EventID: 4624\n    LogonType: 10\n  condition: s").matches, ['LOG-010', 'LOG-018']);
  assert.deepEqual(run("logsource:\n  category: firewall\ndetection:\n  s:\n    dst_port|gte: 8000\n    action: allow\n  condition: s").matches, ['LOG-043']);
  assert.deepEqual(run("logsource:\n  category: webserver\ndetection:\n  s:\n    cs-user-agent|contains|all:\n      - sqlmap\n      - stable\n  condition: s").matches, ['LOG-032', 'LOG-033', 'LOG-034']);
  assert.deepEqual(run("logsource:\n  category: webserver\ndetection:\n  s:\n    cs-referrer: null\n  condition: s").matches.length, 0, 'CLF "-" referrer is not null');
  assert.deepEqual(run("logsource:\n  product: linux\n  service: sshd\ndetection:\n  k:\n    - 'accepted publickey'\n  condition: k").matches, ['LOG-049'], 'keywords are case-insensitive');
  assert.ok(run("logsource:\n  category: dns\ndetection:\n  s:\n    query|re: '('\n  condition: s").errors[0].includes('Invalid regular expression'));
});

/* ---------- the rule library ---------- */
test('every library rule is valid Sigma (no errors) with ATT&CK tags', async () => {
  const { data } = await load('detections');
  assert.equal(data.rules.length, 16);
  const ids = new Set();
  for (const r of data.rules) {
    const v = validateSigma(ruleText(r));
    assert.deepEqual(v.errors, [], `${r.slug}: ${v.errors.join('; ')}`);
    assert.deepEqual(v.warnings, [], `${r.slug} warnings: ${v.warnings.join('; ')}`);
    assert.ok(!ids.has(v.rule.id), `${r.slug}: duplicate UUID`);
    ids.add(v.rule.id);
    assert.equal(v.rule.status, 'experimental', 'untested-in-production rules stay experimental');
  }
});

test('every rule matches exactly its expected sample logs (no misses, no false positives)', async () => {
  const [{ data }, entries] = await Promise.all([load('detections'), logs()]);
  for (const r of data.rules) {
    const res = runSigma(ruleText(r), entries);
    assert.deepEqual(res.matches, r.expectedMatches, `${r.slug}: got ${res.matches.join(',')}`);
    assert.ok(res.considered > 0, `${r.slug}: no logs of its logsource`);
  }
});

test('rule ATT&CK tags map to known techniques; related dossiers exist', async () => {
  const [{ data }, { data: lib }] = await Promise.all([load('detections'), load('attacks')]);
  const atk = new Set(lib.attacks.map((a) => a.id));
  for (const r of data.rules) {
    const tags = parseYaml(ruleText(r)).tags.filter((t) => /^attack\.t\d/.test(t)).map((t) => t.replace('attack.t', 'T').toUpperCase());
    tags.forEach((t) => assert.ok(ATTACK_NAMES[t], `${r.slug}: ${t} has no name`));
    r.relatedAttacks.forEach((a) => assert.ok(atk.has(a), `${r.slug}: unknown dossier ${a}`));
  }
});
