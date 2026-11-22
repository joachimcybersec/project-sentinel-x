/**
 * Netlify Function (Functions API v2): GET /api/ioc?value=<indicator>
 *
 * Thin wrapper around ../lib/ioc-core.mjs (kept outside the functions directory
 * so Netlify does not treat it as a separate function). Configure provider keys as Netlify
 * environment variables (Site configuration → Environment variables):
 *   ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, OTX_API_KEY
 * Any provider without a key is reported as "not-configured"; the function
 * still works with zero keys.
 *
 * Status: written and unit-tested with mocked upstreams in the browser test
 * suite (tests/backend.test.js). Not yet deployed or exercised against live
 * provider APIs.
 */
import { handleIocRequest } from '../lib/ioc-core.mjs';

const readEnv = (name) => {
  const viaNetlify = globalThis.Netlify && globalThis.Netlify.env && globalThis.Netlify.env.get(name);
  return viaNetlify || (typeof process !== 'undefined' ? process.env[name] : undefined);
};

export default async (request) => handleIocRequest(request, {
  env: readEnv,
  fetch: globalThis.fetch,
  log: (msg) => console.log(msg)
});

export const config = { path: '/api/ioc' };
