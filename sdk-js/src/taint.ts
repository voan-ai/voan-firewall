// Taint tracking — integrity provenance (CaMeL-lite). JS port of voan/taint.py.
// A side-effect target that came from (untrusted) tool output and wasn't named in
// the goal is flagged — the classic poisoned-output→payout exfil, caught with no LLM.
import { isSideEffect } from "./auto.ts";
import type { Action } from "./schema.ts";

const TARGET_KEYS = ["recipient", "receiver", "payee", "to", "dest", "destination",
  "address", "account", "iban", "email", "channel", "phone", "url", "user",
  "member", "guest", "participant", "contact"];

export class TaintTracker {
  private corpus: string[] = [];

  observe(output: unknown): void {
    const s = String(output).trim().toLowerCase();
    if (s) this.corpus.push(s);
  }

  reset(): this { this.corpus = []; return this; }

  private tainted(value: unknown): boolean {
    const v = String(value).trim().toLowerCase();
    return v.length >= 4 && this.corpus.some((c) => c.includes(v));
  }

  /** First data-derived, not-in-goal target of a side-effect action, else null. */
  badTarget(action: Action, goal: string): string | null {
    if (!isSideEffect(action.tool)) return null;
    const args = (action.args && typeof action.args === "object") ? action.args : {};
    const g = String(goal ?? "").toLowerCase();
    for (const [k, v] of Object.entries(args)) {
      if ((typeof v === "string" || typeof v === "number") &&
          TARGET_KEYS.some((t) => k.toLowerCase().includes(t))) {
        const s = String(v).trim();
        if (s.length >= 4 && !g.includes(s.toLowerCase()) && this.tainted(s)) return s;
      }
    }
    return null;
  }
}
