// Information-flow monitor — the confidentiality half of FIDES-style labels. JS port
// of voan/flow.py. Data from a declared confidential-source tool must not leave via
// an external sink, whatever the destination. Deterministic.
import { isSideEffect } from "./auto.ts";
import type { Action } from "./schema.ts";

const TOKEN = /[A-Za-z0-9@._+-]{4,}/g;
const STOP = new Set(["true", "false", "null", "none", "http", "https", "message",
  "status", "amount", "date", "name", "type", "value", "sent", "from", "with", "this"]);

function tokens(output: unknown): Set<string> {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  return new Set((text.match(TOKEN) ?? []).map((t) => t.toLowerCase())
    .filter((t) => !STOP.has(t) && t.length >= 4));
}

export class FlowMonitor {
  private confTools: Set<string>;
  private secrets = new Set<string>();

  constructor(confidentialTools: Iterable<string> = []) {
    this.confTools = new Set(confidentialTools);
  }

  reset(): this { this.secrets = new Set(); return this; }

  observe(tool: string, output: unknown): void {
    if (this.confTools.has(tool)) for (const t of tokens(output)) this.secrets.add(t);
  }

  /** First confidential value carried by an external side-effect's args, else null. */
  leaks(action: Action): string | null {
    if (!isSideEffect(action.tool) || !this.secrets.size) return null;
    const args = (action.args && typeof action.args === "object") ? action.args : {};
    for (const tok of tokens(args)) if (this.secrets.has(tok)) return tok;
    return null;
  }
}
