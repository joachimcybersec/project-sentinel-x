import { test, assert } from './test-runner.js';
import { safeUrl, defang, el, formatUtcTime, formatNumber, severityBadge } from '../js/utils/dom.js';

test('safeUrl allows https and in-app hash routes', () => {
  assert.equal(safeUrl('https://attack.mitre.org/'), 'https://attack.mitre.org/');
  assert.equal(safeUrl('#/soc'), '#/soc');
  assert.equal(safeUrl('docs/architecture.md'), 'docs/architecture.md');
});

test('safeUrl blocks script-capable and protocol-relative URLs', () => {
  assert.equal(safeUrl('javascript:alert(1)'), '#');
  assert.equal(safeUrl('  JaVaScRiPt:alert(1)'), '#');
  assert.equal(safeUrl('data:text/html,<script>alert(1)</script>'), '#');
  assert.equal(safeUrl('vbscript:msgbox(1)'), '#');
  assert.equal(safeUrl('//evil.example/x'), '#');
  assert.equal(safeUrl(null), '#');
});

test('safeUrl blocks backslash and whitespace tricks that resolve off-site (Phase 10 finding)', () => {
  assert.equal(safeUrl('/\\evil.example/x'), '#');
  assert.equal(safeUrl('/\t/evil.example/x'), '#');
  assert.equal(safeUrl('\\\\evil.example'), '#');
  assert.equal(safeUrl('java\tscript:alert(1)'), '#');
  assert.equal(safeUrl('java\nscript:alert(1)'), '#');
  assert.equal(safeUrl('/rules/a.yml'), '/rules/a.yml');
  assert.equal(safeUrl('../x'), '../x');
  assert.equal(safeUrl('mailto:soc@example.org'), 'mailto:soc@example.org');
});

test('defang brackets every host dot and neuters the scheme', () => {
  assert.equal(defang('203.0.113.5'), '203[.]0[.]113[.]5');
  assert.equal(defang('https://bad.example/a.php'), 'hxxps://bad[.]example/a.php');
  assert.equal(defang('http://x.test'), 'hxxp://x[.]test');
});

test('el() renders data as text, never HTML', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const node = el('p', null, payload);
  assert.equal(node.textContent, payload);
  assert.equal(node.querySelector('img'), null, 'payload must not create elements');
});

test('el() rejects event-handler and non-allow-listed attributes', () => {
  assert.throws(() => el('a', { onclick: 'alert(1)' }));
  assert.throws(() => el('div', { style: 'color:red' }));
});

test('el() sanitises dangerous href values', () => {
  const a = el('a', { href: 'javascript:alert(1)' }, 'x');
  assert.equal(a.getAttribute('href'), '#');
});

test('el() adds rel=noopener to target=_blank links', () => {
  const a = el('a', { href: 'https://www.cisa.gov/', target: '_blank' }, 'CISA');
  assert.equal(a.getAttribute('rel'), 'noopener noreferrer');
});

test('formatters handle valid and invalid input', () => {
  assert.equal(formatUtcTime('2026-11-21T22:01:14Z'), '22:01:14');
  assert.equal(formatUtcTime('not a date'), '—');
  assert.equal(formatNumber(1240), '1,240');
  assert.equal(formatNumber(NaN), '—');
});

test('severityBadge falls back to info for unknown values', () => {
  assert.ok(severityBadge('critical').classList.contains('sev-critical'));
  assert.ok(severityBadge('<script>').classList.contains('sev-info'));
});
