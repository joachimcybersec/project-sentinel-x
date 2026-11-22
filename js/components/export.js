/**
 * Report export (CSV / JSON), generated entirely client-side.
 *
 * CSV injection defence: cells that begin with = + - @ TAB or CR are prefixed
 * with a single quote so spreadsheet apps treat them as text, not formulas
 * (OWASP "CSV Injection"). Numbers are left untouched.
 */

const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  let s = Array.isArray(value) ? value.join('; ') : String(value);
  if (FORMULA_START.test(s)) s = "'" + s;
  if (/[",\r\n]/.test(s) || s !== s.trim()) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/** columns: [{ key, label, value?(row) }] */
export function toCSV(rows, columns) {
  const header = columns.map((c) => csvCell(c.label)).join(',');
  const lines = rows.map((r) => columns.map((c) => csvCell(c.value ? c.value(r) : r[c.key])).join(','));
  return [header, ...lines].join('\r\n') + '\r\n';
}

/** Restrict filenames to a safe character set. */
export function safeFilename(name) {
  const cleaned = String(name || 'export').replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  return cleaned || 'export';
}

export function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeFilename(filename);
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function exportCSV(filename, rows, columns) {
  // UTF-8 BOM so Excel detects the encoding.
  downloadFile(filename, '﻿' + toCSV(rows, columns), 'text/csv;charset=utf-8');
}

export function exportJSON(filename, payload) {
  downloadFile(filename, JSON.stringify(payload, null, 2) + '\n', 'application/json');
}

/** Timestamp suffix for export filenames: 20261122-0130Z */
export function stamp(d = new Date()) {
  return d.toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-') + 'Z';
}
