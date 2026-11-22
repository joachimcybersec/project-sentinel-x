/**
 * Code / log viewer with a lightweight YAML (Sigma) highlighter and copy button.
 * The tokenizer is pure and returns { type, text } tokens; rendering wraps each
 * token in a <span> via textContent — no HTML strings, so rule content can never
 * inject markup.
 */
import { el } from '../utils/dom.js';
import { toast } from './toast.js';

const KEYWORDS = /^(true|false|null|yes|no|and|or|not|of|all|them|1)$/i;

/** Split a quoted string / comment-aware value part of a YAML line. */
function tokenizeValue(text) {
  const out = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '#' && (i === 0 || /\s/.test(text[i - 1]))) { out.push({ type: 'comment', text: text.slice(i) }); break; }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== ch) j += text[j] === '\\' && ch === '"' ? 2 : 1;
      out.push({ type: 'string', text: text.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    const m = text.slice(i).match(/^[^\s'"#]+/);
    if (m) {
      const w = m[0];
      out.push({ type: /^-?\d+(\.\d+)?$/.test(w) ? 'number' : KEYWORDS.test(w) ? 'keyword' : 'plain', text: w });
      i += w.length;
      continue;
    }
    out.push({ type: 'plain', text: ch });
    i += 1;
  }
  return out;
}

/** Tokenize YAML into lines of tokens. */
export function highlightYaml(code) {
  return String(code).replace(/\r\n?/g, '\n').split('\n').map((line) => {
    const tokens = [];
    const indent = line.match(/^\s*/)[0];
    if (indent) tokens.push({ type: 'plain', text: indent });
    let rest = line.slice(indent.length);
    if (rest.startsWith('#')) return [...tokens, { type: 'comment', text: rest }];
    const dash = rest.match(/^-\s+/);
    if (dash) { tokens.push({ type: 'punct', text: dash[0] }); rest = rest.slice(dash[0].length); }
    const key = rest.match(/^([\w.\-]+)((?:\|[\w]+)*)(:)(?=\s|$)/);
    if (key) {
      tokens.push({ type: 'key', text: key[1] });
      if (key[2]) tokens.push({ type: 'modifier', text: key[2] });
      tokens.push({ type: 'punct', text: ':' });
      rest = rest.slice(key[0].length);
    }
    return [...tokens, ...tokenizeValue(rest)];
  });
}

export function createCodeBlock({ code, language = 'text', title = null }) {
  const pre = el('pre', { class: `code code-${language}`, tabindex: '0' });
  const codeEl = el('code');
  if (language === 'yaml') {
    highlightYaml(code).forEach((tokens, i, all) => {
      for (const t of tokens) codeEl.append(t.type === 'plain' ? t.text : el('span', { class: `tok-${t.type}` }, t.text));
      if (i < all.length - 1) codeEl.append('\n');
    });
  } else {
    codeEl.textContent = code;
  }
  pre.append(codeEl);
  if (title) pre.setAttribute('aria-label', title);

  const copy = el('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Copy');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code);
      toast(`${title || 'Code'} copied to clipboard`, { variant: 'success' });
    } catch {
      toast('Clipboard unavailable — select the text and copy manually.', { variant: 'warning' });
    }
  });

  return el('figure', { class: 'code-block' },
    el('figcaption', { class: 'code-head' },
      el('span', null, title || language.toUpperCase()),
      el('span', { class: 'code-lang' }, language),
      copy
    ),
    pre
  );
}
