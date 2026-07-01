// Voan Firewall — runtime guard for AI agents (JS/TS SDK).
// The Node port of the Python `voan` package — full three-tier parity: the
// hardened regex rules, the egress allowlist, and the LLM "intent vs. hijack"
// judge. Requires Node >=22.6 for native TypeScript. Not yet published to npm —
// consume it locally:
//
//   import { guardTools } from "./src/index.ts";   // from inside this repo
//   const tools = guardTools({ runCommand, sendEmail });
//
export { Decision, BlockedAction } from "./schema.ts";
export type { Action, Verdict, DecisionType } from "./schema.ts";
export { PolicyEngine } from "./policy.ts";
export { DEFAULT_RULES, ruleMatches, egressViolation } from "./rules.ts";
export type { Rule } from "./rules.ts";
export { AuditLog } from "./audit.ts";
export type { AuditEvent } from "./audit.ts";
export { Firewall, guard, guardTools } from "./hook.ts";
export type { FirewallOpts } from "./hook.ts";
export { LLMJudge, openaiLlm, ollamaLlm } from "./judge.ts";
export type { LLM, JudgeOpts } from "./judge.ts";
export { guardAiSdkTools, guardOpenAIDispatch, guardCallables } from "./adapters.ts";
export { Plan, PlanStep } from "./plan.ts";
export type { PlanStepSpec } from "./plan.ts";
export { AutoGuard, guardLangchainAuto, isSideEffect } from "./auto.ts";
export { Capsule, CapabilityEngine, Denied, TRUSTED, UNTRUSTED, ANY } from "./capability.ts";
export { RuleOfTwo, EXTERNAL, SENSITIVE } from "./rule_of_two.ts";
export { TaintTracker } from "./taint.ts";
export { FlowMonitor } from "./flow.ts";
export { quarantinedLlm } from "./quarantine.ts";
export { derivePlan, deriveCapabilityProgram } from "./planner.ts";

export const VERSION = "0.1.11";  // tracks the Python package (repo-local, unpublished)
