// Core types for the Voan Firewall (JS/TS SDK) — the Node twin of voanfw/schema.py.
// An Action is one attempted tool call; a Verdict is the policy ruling; a
// BlockedAction is thrown in-process when an action is denied, so the dangerous
// call never reaches the real tool.

export type DecisionType = "allow" | "ask" | "block";

export const Decision = {
  ALLOW: "allow",
  ASK: "ask",
  BLOCK: "block",
} as const;

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

export interface Action {
  tool: string;
  args: Record<string, unknown>;
  agent: string;
  ts: number;
}

export interface Verdict {
  decision: DecisionType;
  rule: string;
  code: string;
  severity: string;
  reason: string;
}

export class BlockedAction extends Error {
  action: Action;
  verdict: Verdict;
  deniedByUser: boolean;

  constructor(action: Action, verdict: Verdict, deniedByUser = false) {
    const who = deniedByUser ? "user" : `rule ${verdict.rule}`;
    super(
      `\u{1f6d1} Voan blocked ${action.tool}() — ${verdict.reason} ` +
        `[${verdict.severity}, ${who}]`,
    );
    this.name = "BlockedAction";
    this.action = action;
    this.verdict = verdict;
    this.deniedByUser = deniedByUser;
  }
}
