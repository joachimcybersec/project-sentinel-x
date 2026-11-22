/**
 * Tiny dependency-free browser test runner.
 * Serve the project, open /tests/ — results render on the page and
 * window.__TEST_RESULTS__ is set for automation (e.g. Playwright in CI).
 */
const tests = [];
export function test(name, fn) { tests.push({ name, fn }); }

export const assert = {
  ok(v, msg = 'expected truthy') { if (!v) throw new Error(msg); },
  equal(a, b, msg) { if (a !== b) throw new Error(msg || `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); },
  deepEqual(a, b, msg) {
    const sa = JSON.stringify(a), sb = JSON.stringify(b);
    if (sa !== sb) throw new Error(msg || `expected ${sb}, got ${sa}`);
  },
  throws(fn, msg = 'expected function to throw') {
    let threw = false;
    try { fn(); } catch { threw = true; }
    if (!threw) throw new Error(msg);
  }
};

async function run() {
  await import('./dom.test.js');
  await import('./router.test.js');
  await import('./data.test.js');
  await import('./components.test.js');
  await import('./soc.test.js');
  await import('./intel.test.js');
  await import('./siem.test.js');
  await import('./detection.test.js');
  await import('./vuln-network.test.js');
  await import('./kb.test.js');
  await import('./backend.test.js');

  const list = document.getElementById('results');
  const summary = document.getElementById('summary');
  let passed = 0;
  const failures = [];

  for (const t of tests) {
    const li = document.createElement('li');
    try {
      await t.fn();
      passed++;
      li.className = 'pass';
      li.textContent = `✔ ${t.name}`;
    } catch (err) {
      failures.push({ name: t.name, error: String(err && err.message) });
      li.className = 'fail';
      li.textContent = `✘ ${t.name}`;
      const e = document.createElement('span');
      e.className = 'err';
      e.textContent = String(err && err.message);
      li.appendChild(e);
    }
    list.appendChild(li);
  }

  const total = tests.length;
  summary.textContent = `${passed}/${total} passed${failures.length ? ` — ${failures.length} failed` : ''}`;
  summary.className = failures.length ? 'fail' : 'pass';
  window.__TEST_RESULTS__ = { total, passed, failures };
}

run().catch((err) => {
  document.getElementById('summary').textContent = `Runner error: ${err.message}`;
  window.__TEST_RESULTS__ = { total: 0, passed: 0, failures: [{ name: 'runner', error: err.message }] };
});
