// Voan Firewall — runtime guard for AI agents (JS/TS SDK).
// The Node port of the Python `voan` package — regex policy tier only for now
// (the LLM judge is Python-only; JS judge is on the roadmap). Requires Node
// >=22.6 for native TypeScript. Not yet published to npm — consume it locally:
//
//   import { guardTools } from "./src/index.ts";   // from inside this repo
//   const tools = guardTools({ runCommand, sendEmail });
//
export { Decision, BlockedAction } from "./schema.ts";
export type { Action, Verdict, DecisionType } from "./schema.ts";
export { PolicyEngine } from "./policy.ts";
export { DEFAULT_RULES, ruleMatches } from "./rules.ts";
export type { Rule } from "./rules.ts";
export { AuditLog } from "./audit.ts";
export type { AuditEvent } from "./audit.ts";
export { Firewall, guard, guardTools } from "./hook.ts";
export type { FirewallOpts } from "./hook.ts";

export const VERSION = "0.1.0";
