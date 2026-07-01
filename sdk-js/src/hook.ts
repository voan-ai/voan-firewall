// The in-process hook — the sensor that sits inline on every tool call.
// Mirror of voan/hook.py. `guard()` wraps a tool function; the wrapper runs
// the policy before the real call: ALLOW -> run, ASK -> onAsk() must approve,
// BLOCK -> throw BlockedAction so the real tool never runs. In "monitor" mode
// nothing is blocked — every decision is still logged.
import { AuditLog } from "./audit.ts";
import type { LLMJudge } from "./judge.ts";
import { Plan, type PlanStepSpec } from "./plan.ts";
import { PolicyEngine } from "./policy.ts";
import { egressViolation } from "./rules.ts";
import { type Action, BlockedAction, Decision, type Verdict } from "./schema.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Fn = (...args: any[]) => any;

export interface FirewallOpts {
  policy?: PolicyEngine;
  audit?: AuditLog;
  agent?: string;
  onAsk?: (action: Action, verdict: Verdict) => boolean;
  mode?: "enforce" | "monitor";
  egressAllowlist?: string[];
  judge?: LLMJudge;
  judgeFailClosed?: boolean;
}

export class Firewall {
  policy: PolicyEngine;
  audit: AuditLog;
  agent: string;
  onAsk?: (action: Action, verdict: Verdict) => boolean;
  mode: "enforce" | "monitor";
  egressAllowlist?: string[];
  judge?: LLMJudge;
  judgeFailClosed: boolean;
  goal?: string;
  plan?: Plan;
  private trace: string[] = [];

  constructor(opts: FirewallOpts = {}) {
    this.policy = opts.policy ?? new PolicyEngine();
    this.audit = opts.audit ?? new AuditLog();
    this.agent = opts.agent ?? "agent";
    this.onAsk = opts.onAsk;
    this.mode = opts.mode ?? "enforce";
    this.egressAllowlist = opts.egressAllowlist;
    this.judge = opts.judge;
    this.judgeFailClosed = opts.judgeFailClosed ?? false;
  }

  /** Tell the firewall what the user actually asked for, so the LLM judge can
   *  spot actions that drift from it (hijacks). Resets the trace. */
  setGoal(goal: string): this {
    this.goal = goal;
    this.trace = [];
    return this;
  }

  /** Commit the actions the agent intends to take BEFORE it reads untrusted data.
   *  Voan then allows only these (each once, args optionally pinned) and blocks
   *  anything an injection adds or alters. Pass null to clear. Mirror of
   *  voan/hook.py set_plan; see plan.ts. */
  setPlan(steps: PlanStepSpec[] | null): this {
    this.plan = steps ? new Plan(steps) : undefined;
    return this;
  }

  check(tool: string, args: Record<string, unknown>): Verdict {
    return this.policy.evaluate({ tool, args, agent: this.agent, ts: now() });
  }

  /** Run the full pipeline (rules -> egress -> judge) for an explicit tool call,
   *  record it, and gate it (throws BlockedAction on block/denied-ask). Used by
   *  framework adapters that already know the tool name and its args object, so
   *  the action's args stay clean/named instead of positional. */
  async guardArgs(tool: string, args: Record<string, unknown>): Promise<void> {
    const action: Action = { tool, args, agent: this.agent, ts: now() };
    let verdict = this.egress(action, this.policy.evaluate(action));
    verdict = await this.judgeStep(action, verdict);
    this.audit.record(action, verdict);
    this.gate(action, verdict);
  }

  /** Feed a tool result into the judge's untrusted-context window. */
  observe(tool: string, result: unknown): void {
    this.trace.push(`${tool}: ${asText(result)}`);
  }

  guard<T extends Fn>(fn: T, name?: string): T {
    const tool = name ?? fn.name ?? "tool";
    const self = this;
    // With a judge configured the wrapper is async (the LLM call is awaited);
    // without one it stays sync so existing rule-only usage is unchanged.
    if (this.judge) {
      const wrapped = async function (this: unknown, ...args: unknown[]) {
        const action: Action = { tool, args: bindArgs(args), agent: self.agent, ts: now() };
        const base = self.egress(action, self.policy.evaluate(action));
        let verdict: Verdict;
        if (self.plan) {
          // plan-then-execute; off-plan actions fall to the judge backstop
          verdict = self.planTier(action, base);
          if (verdict.rule === "off-plan") verdict = await self.judgeStep(action, base);
        } else {
          verdict = await self.judgeStep(action, base);
        }
        self.audit.record(action, verdict);
        self.gate(action, verdict);
        const result = await fn.apply(this, args as never);
        self.observe(tool, result);  // feeds the judge's context
        return result;
      };
      return wrapped as unknown as T;
    }
    const wrapped = function (this: unknown, ...args: unknown[]) {
      const action: Action = { tool, args: bindArgs(args), agent: self.agent, ts: now() };
      let verdict = self.egress(action, self.policy.evaluate(action));
      if (self.plan) verdict = self.planTier(action, verdict);  // no judge -> hard-block off-plan
      self.audit.record(action, verdict);
      self.gate(action, verdict);
      return fn.apply(this, args as never);
    };
    return wrapped as unknown as T;
  }

  // Plan-then-execute tier: allow only actions in the committed plan (consuming
  // the step); anything an injection added or altered is off-plan and blocked.
  private planTier(action: Action, verdict: Verdict): Verdict {
    if (verdict.decision === Decision.BLOCK || !this.plan) return verdict;
    if (this.plan.allows(action)) return verdict;
    return { decision: Decision.BLOCK, rule: "off-plan", code: "AGT",
      severity: "High", reason: "action was not in the committed plan" };
  }

  guardTools<M extends Record<string, Fn>>(tools: M): M {
    const out: Record<string, Fn> = {};
    for (const [name, fn] of Object.entries(tools)) out[name] = this.guard(fn, name);
    return out as M;
  }

  private egress(action: Action, verdict: Verdict): Verdict {
    if (!this.egressAllowlist || verdict.decision === "block") return verdict;
    const bad = egressViolation(action.args, this.egressAllowlist);
    if (bad) {
      return { decision: "block", rule: "egress-allowlist", code: "AEX",
        severity: "High", reason: `egress to non-allowlisted '${bad}'` };
    }
    return verdict;
  }

  // Second tier: the LLM judge may ESCALATE a rule verdict to BLOCK when an
  // action drifts from the user's goal, but never loosens it.
  private async judgeStep(action: Action, verdict: Verdict): Promise<Verdict> {
    if (!this.judge || verdict.decision === Decision.BLOCK) return verdict;
    const jv = await this.judge.evaluate(this.goal, action, this.trace);
    if (jv === null && this.judgeFailClosed && this.goal && this.judge.available) {
      // judge was supposed to run but the backend failed -> don't fail open
      return { decision: Decision.BLOCK, rule: "judge-fail-closed", code: "AID",
        severity: "High", reason: "judge backend unavailable; failing closed" };
    }
    return jv && jv.decision === Decision.BLOCK ? jv : verdict;
  }

  private gate(action: Action, verdict: Verdict): void {
    if (this.mode === "monitor") return;
    if (verdict.decision === "block") throw new BlockedAction(action, verdict);
    if (verdict.decision === "ask") {
      const ok = this.onAsk ? this.onAsk(action, verdict) : false;
      if (!ok) throw new BlockedAction(action, verdict, true);
    }
  }
}

function now(): number {
  return Date.now() / 1000;
}

// JS agent frameworks call a tool with a single params object; use it directly.
// Otherwise capture positional args so rule patterns still see the values.
function bindArgs(args: unknown[]): Record<string, unknown> {
  if (args.length === 1 && isPlainObject(args[0])) return args[0] as Record<string, unknown>;
  return Object.fromEntries(args.map((v, i) => [`arg${i}`, v]));
}

function isPlainObject(v: unknown): boolean {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Compact a tool result into trace text for the judge's untrusted-context window.
function asText(v: unknown): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return (s ?? "").slice(0, 500);
}

export function guard<T extends Fn>(fn: T, opts?: FirewallOpts): T {
  return new Firewall(opts).guard(fn);
}

export function guardTools<M extends Record<string, Fn>>(tools: M, opts?: FirewallOpts): M {
  return new Firewall(opts).guardTools(tools);
}
