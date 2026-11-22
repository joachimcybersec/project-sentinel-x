/**
 * Network policy evaluator (pure functions).
 *
 * A policy is an ordered rule list; the first matching rule decides, otherwise
 * the policy default applies. Rules match on source/destination zone (or "*"),
 * destination port list (or "*"), and optional conditions describing the flow
 * (e.g. requires: ["mfa", "compliant-device"] for Zero Trust rules).
 *
 *   evaluateFlow(policy, flow, zoneOf) -> { action: 'allow'|'deny', ruleId, reason }
 */

export function zoneOf(hosts, name) {
  const h = hosts.find((x) => x.name === name);
  return h ? h.zone : 'internet';
}

function ruleMatches(rule, flow, fromZone, toZone) {
  const zoneOk = (want, actual) => want === '*' || want === actual || (Array.isArray(want) && want.includes(actual));
  if (!zoneOk(rule.from, fromZone) || !zoneOk(rule.to, toZone)) return false;
  if (rule.fromHost && rule.fromHost !== flow.from) return false;
  if (rule.toHost && rule.toHost !== flow.to) return false;
  if (rule.ports !== '*' && !rule.ports.includes(flow.port)) return false;
  if (rule.proto && rule.proto !== flow.proto) return false;
  if (rule.requires) {
    const has = new Set(flow.attributes || []);
    if (!rule.requires.every((r) => has.has(r))) return false;
  }
  if (rule.unless) {
    const has = new Set(flow.attributes || []);
    if (rule.unless.some((r) => has.has(r))) return false;
  }
  return true;
}

export function evaluateFlow(policy, flow, hosts) {
  const fromZone = zoneOf(hosts, flow.from);
  const toZone = zoneOf(hosts, flow.to);
  for (const rule of policy.rules) {
    if (ruleMatches(rule, flow, fromZone, toZone)) return { action: rule.action, ruleId: rule.id, reason: rule.reason, fromZone, toZone };
  }
  return { action: policy.default, ruleId: 'default', reason: `No rule matched; policy default is ${policy.default}.`, fromZone, toZone };
}

/** Summarise a policy: how many attack steps it blocks and whether any legitimate flow breaks. */
export function scorePolicy(policy, flows, hosts) {
  const results = flows.map((f) => ({ flow: f, ...evaluateFlow(policy, f, hosts) }));
  const attacks = results.filter((r) => r.flow.kind === 'attack');
  const legit = results.filter((r) => r.flow.kind === 'legitimate');
  return {
    results,
    attacksBlocked: attacks.filter((r) => r.action === 'deny').length,
    attacksTotal: attacks.length,
    legitAllowed: legit.filter((r) => r.action === 'allow').length,
    legitTotal: legit.length
  };
}
