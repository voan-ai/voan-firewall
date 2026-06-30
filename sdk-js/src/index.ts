// Voan Firewall — runtime guard for AI agents (JS/TS SDK).
// The Node twin of the Python `voanfw` package. One line to protect an agent:
//
//   import { guardTools } from "voanfw";
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
