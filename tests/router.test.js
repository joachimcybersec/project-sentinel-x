import { test, assert } from './test-runner.js';
import { hashToPath, matchRoute, resolve } from '../js/router.js';

test('hashToPath normalises hashes', () => {
  assert.equal(hashToPath(''), '/');
  assert.equal(hashToPath('#'), '/');
  assert.equal(hashToPath('#/soc'), '/soc');
  assert.equal(hashToPath('#/soc/'), '/soc');
  assert.equal(hashToPath('#/soc?sev=high'), '/soc');
  assert.equal(hashToPath('#soc'), '/soc');
});

test('matchRoute extracts named params', () => {
  assert.deepEqual(matchRoute('/incidents/:id', '/incidents/IR-003'), { id: 'IR-003' });
  assert.deepEqual(matchRoute('/', '/'), {});
  assert.equal(matchRoute('/incidents/:id', '/incidents'), null);
  assert.equal(matchRoute('/soc', '/siem'), null);
});

test('matchRoute rejects markup or malformed params', () => {
  assert.equal(matchRoute('/x/:id', '/x/%3Cscript%3E'), null);
  assert.equal(matchRoute('/x/:id', '/x/%E0%A4%A'), null); // malformed URI escape
});

test('resolve returns the first matching route', () => {
  const routes = [{ path: '/' }, { path: '/about' }, { path: '/attacks/:id' }];
  assert.equal(resolve(routes, '/about').route.path, '/about');
  assert.equal(resolve(routes, '/attacks/phishing').params.id, 'phishing');
  assert.equal(resolve(routes, '/nope'), null);
});
