// Plan-then-execute — the architectural tier that beats in-domain hijacks.
// Mirror of voan/plan.py. The agent commits the actions it INTENDS to take before
// it reads untrusted data; Voan then allows ONLY those (each consumed once, args
// optionally pinned), so an injection can't add a new action or swap a planned
// one's recipient. Deterministic — no LLM. (Design Patterns for Securing LLM
// Agents against Prompt Injections, Beurer-Kellner 2025.)
import type { Action } from "./schema.ts";

export interface PlanStepInit {
  tool: string;
  pins?: Record<string, unknown>;
  [arg: string]: unknown; // bare pins: { tool: "send_money", recipient: "GB.." }
}

export type PlanStepSpec = string | PlanStepInit | [string, Record<string, unknown>?];

export class PlanStep {
  tool: string;
  pins: Record<string, unknown>;
  used = false;

  constructor(tool: string, pins?: Record<string, unknown>) {
    this.tool = tool;
    this.pins = pins ?? {};
  }

  matches(action: Action): boolean {
    if (this.used || this.tool !== action.tool) return false;
    const args = (action.args && typeof action.args === "object") ? action.args : {};
    return Object.entries(this.pins).every(([k, v]) => eq((args as Record<string, unknown>)[k], v));
  }
}

export class Plan {
  steps: PlanStep[];
  constructor(steps: PlanStepSpec[]) {
    this.steps = steps.map(toStep);
  }

  /** True (and consume the step) if `action` was planned; else false. */
  allows(action: Action): boolean {
    for (const s of this.steps) {
      if (s.matches(action)) { s.used = true; return true; }
    }
    return false;
  }

  reset(): this {
    for (const s of this.steps) s.used = false;
    return this;
  }
}

function toStep(s: PlanStepSpec): PlanStep {
  if (typeof s === "string") return new PlanStep(s);
  if (Array.isArray(s)) return new PlanStep(s[0], s[1]);
  const { tool, pins, ...rest } = s;
  return new PlanStep(tool, pins ?? (Object.keys(rest).length ? rest : undefined));
}

function eq(a: unknown, b: unknown): boolean {
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}
