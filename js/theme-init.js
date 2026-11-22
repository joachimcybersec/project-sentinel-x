/*
 * Theme restore: a classic (non-module) script loaded in <head> BEFORE the
 * stylesheets, so a returning visitor never sees a flash of the wrong theme.
 * External file (not inline) because the CSP allows scripts from 'self' only.
 * Keep the key and theme names in sync with js/theme.js.
 */
(function () {
  'use strict';
  var root = document.documentElement;
  try {
    var t = window.localStorage.getItem('sx-theme');
    if (t === 'dark' || t === 'gold') {
      root.setAttribute('data-theme', t);
      var meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', t === 'dark' ? '#0b0f19' : '#050505');
    }
  } catch (e) { /* storage blocked (private mode): default Original theme */ }
  // Data-saver or very low-end hardware: the background engine stays in its light mode.
  try {
    var lite = (navigator.connection && navigator.connection.saveData) ||
               (navigator.hardwareConcurrency || 8) <= 3 ||
               (navigator.deviceMemory || 8) <= 2;
    if (lite) root.classList.add('perf-lite');
  } catch (e) { /* ignore */ }
})();
