/**
 * Minimal YAML-subset parser for Sigma rules (pure, no dependencies).
 *
 * Supported: block mappings, block sequences (of scalars or of mappings),
 * flow sequences of scalars ([a, b]), plain / 'single' / "double" quoted
 * scalars, comments, null/~, true/false, decimal integers.
 * Not supported (rejected with an error): tabs for indentation, anchors and
 * aliases, block scalars (| and >), flow mappings, multi-document streams.
 *
 * This is deliberately small: it exists so rules can be edited and tested in
 * the browser without loading a third-party YAML library.
 */

export class YamlError extends Error {
  constructor(message, line) { super(line ? `Line ${line}: ${message}` : message); this.name = 'YamlError'; this.line = line; }
}

export const MAX_YAML = 20000;

/** Remove a trailing comment that is not inside quotes. */
function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } q = null; } else if (c === '\\' && q === '"') i++; continue; }
    if (c === "'" || c === '"') q = c;
    else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}

export function parseScalar(raw, line) {
  const s = raw.trim();
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2) throw new YamlError('Unterminated single-quoted string', line);
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) throw new YamlError('Unterminated double-quoted string', line);
    return s.slice(1, -1).replace(/\\(["\\nt])/g, (_, c) => ({ n: '\n', t: '\t', '"': '"', '\\': '\\' })[c]);
  }
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new YamlError('Unterminated flow sequence', line);
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitFlow(inner, line).map((x) => parseScalar(x, line));
  }
  if (s.startsWith('{')) throw new YamlError('Flow mappings are not supported', line);
  if (/^[&*!]/.test(s)) throw new YamlError('Anchors, aliases and tags are not supported', line);
  if (s === '|' || s === '>' || /^[|>][+-]?$/.test(s)) throw new YamlError('Block scalars (| and >) are not supported', line);
  if (s === 'true' || s === 'True') return true;
  if (s === 'false' || s === 'False') return false;
  if (/^-?(0|[1-9]\d{0,15})$/.test(s)) return Number(s);
  return s;
}

function splitFlow(inner, line) {
  const out = []; let cur = ''; let q = null;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === '[' || c === '{') throw new YamlError('Nested flow collections are not supported', line);
    if (c === ',') { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (q) throw new YamlError('Unterminated quote in flow sequence', line);
  out.push(cur);
  return out.map((x) => x.trim()).filter((x) => x !== '');
}

const KEY = /^((?:'[^']*')|(?:"[^"]*")|[^\s'"#:][^:]*?)\s*:(?:\s+(.*)|\s*)$/;

function tokenize(text) {
  if (typeof text !== 'string') throw new YamlError('Input must be text');
  if (text.length > MAX_YAML) throw new YamlError(`Rule text longer than ${MAX_YAML} characters`);
  const lines = [];
  text.replace(/\r\n?/g, '\n').split('\n').forEach((rawLine, idx) => {
    const n = idx + 1;
    if (/^\s*---\s*$/.test(rawLine) && lines.length) throw new YamlError('Multiple YAML documents are not supported', n);
    if (/^\s*---\s*$/.test(rawLine) || /^\s*\.\.\.\s*$/.test(rawLine)) return;
    const lead = rawLine.match(/^[ \t]*/)[0];
    if (lead.includes('\t')) throw new YamlError('Tabs are not allowed for indentation', n);
    const content = stripComment(rawLine).replace(/\s+$/, '');
    if (!content.trim()) return;
    lines.push({ n, indent: lead.length, text: content.slice(lead.length) });
  });
  return lines;
}

function parseKey(k) { return k.startsWith("'") || k.startsWith('"') ? parseScalar(k) : k; }

function parseBlock(lines, i, indent) {
  if (i >= lines.length) return [null, i];
  const first = lines[i];
  if (first.indent !== indent) throw new YamlError('Unexpected indentation', first.n);
  if (first.text === '-' || first.text.startsWith('- ')) return parseSeq(lines, i, indent);
  return parseMap(lines, i, indent);
}

function parseMap(lines, i, indent) {
  const obj = {};
  while (i < lines.length && lines[i].indent === indent) {
    const ln = lines[i];
    if (ln.text.startsWith('- ') || ln.text === '-') throw new YamlError('Sequence item where a mapping key was expected', ln.n);
    const m = ln.text.match(KEY);
    if (!m) throw new YamlError(`Expected "key: value", got "${ln.text.slice(0, 40)}"`, ln.n);
    const key = parseKey(m[1]);
    if (Object.prototype.hasOwnProperty.call(obj, key)) throw new YamlError(`Duplicate key "${key}"`, ln.n);
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') throw new YamlError(`Key "${key}" is not allowed`, ln.n);
    i++;
    if (m[2] !== undefined && m[2] !== '') {
      obj[key] = parseScalar(m[2], ln.n);
    } else if (i < lines.length && lines[i].indent > indent) {
      [obj[key], i] = parseBlock(lines, i, lines[i].indent);
    } else if (i < lines.length && lines[i].indent === indent && (lines[i].text.startsWith('- ') || lines[i].text === '-')) {
      // YAML allows a sequence at the same indent as its parent key
      [obj[key], i] = parseSeq(lines, i, indent);
    } else {
      obj[key] = null;
    }
  }
  if (i < lines.length && lines[i].indent > indent) throw new YamlError('Unexpected indentation', lines[i].n);
  return [obj, i];
}

function parseSeq(lines, i, indent) {
  const arr = [];
  while (i < lines.length && lines[i].indent === indent && (lines[i].text.startsWith('- ') || lines[i].text === '-')) {
    const ln = lines[i];
    const rest = ln.text === '-' ? '' : ln.text.slice(2);
    i++;
    if (rest === '') {
      if (i < lines.length && lines[i].indent > indent) [arr[arr.length], i] = parseBlock(lines, i, lines[i].indent);
      else arr.push(null);
    } else if (/^(?:'[^']*'|"[^"]*")\s*:(?:\s|$)/.test(rest) || (!/^['"]/.test(rest) && KEY.test(rest))) {
      // "- key: value" starts a mapping item; further keys are indented to align with "key"
      const childIndent = indent + 2 + (rest.length - rest.trimStart().length);
      const synthetic = [{ n: ln.n, indent: childIndent, text: rest.trimStart() }];
      let j = i;
      while (j < lines.length && lines[j].indent >= childIndent) synthetic.push(lines[j++]);
      const [obj] = parseMap(synthetic, 0, childIndent);
      arr.push(obj);
      i = j;
    } else {
      arr.push(parseScalar(rest, ln.n));
    }
  }
  return [arr, i];
}

/** Parse YAML text into plain objects. Throws YamlError with a line number. */
export function parseYaml(text) {
  const lines = tokenize(text);
  if (!lines.length) return null;
  const [value, i] = parseBlock(lines, 0, lines[0].indent);
  if (i < lines.length) throw new YamlError('Unexpected content', lines[i].n);
  return value;
}
