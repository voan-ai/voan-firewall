// Agents Rule of Two — the 2026 capability constraint. JS port of voan/rule_of_two.py.
// A session should hold at most two of {untrusted input, sensitive data, external
// action}; all three is the exfil path. Deterministic — no prompt can argue away a
// capability count.
import { isSideEffect } from "./auto.ts";
import type { Action } from "./schema.ts";

export const UNTRUSTED = "untrusted";
export const SENSITIVE = "sensitive";
export const EXTERNAL = "external";

const EXT = ["send", "pay", "transfer", "post", "share", "delete", "charge", "payout",
  "write_", "create_", "update_", "schedule", "invite", "grant", "publish", "email",
  "message", "notify", "upload", "move_"];
const UNTRUSTED_SRC = ["read_", "get_webpage", "fetch", "search", "browse", "web",
  "review", "inbox", "channel", "get_emails", "get_messages", "get_file", "read_file", "list_"];
const SENSITIVE_SRC = ["balance", "transaction", "account", "iban", "payment", "password",
  "secret", "key", "credential", "ssn", "card", "health", "salary", "scheduled",
  "contact", "calendar", "private", "get_file", "read_file"];

function defaultCaps(tool: string): Set<string> {
  const t = tool.toLowerCase();
  const caps = new Set<string>();
  if (EXT.some((k) => t.includes(k))) caps.add(EXTERNAL);
  if (UNTRUSTED_SRC.some((k) => t.includes(k))) caps.add(UNTRUSTED);
  if (SENSITIVE_SRC.some((k) => t.includes(k))) caps.add(SENSITIVE);
  return caps;
}

export class RuleOfTwo {
  private declared: Record<string, Set<string>>;
  active = new Set<string>();

  constructor(caps: Record<string, Iterable<string>> = {}) {
    this.declared = Object.fromEntries(Object.entries(caps).map(([t, c]) => [t, new Set(c)]));
  }

  reset(): this { this.active = new Set(); return this; }

  capsOf(action: Action): Set<string> {
    return this.declared[action.tool] ?? defaultCaps(action.tool);
  }

  /** True if this EXTERNAL action would make the session hold all three. */
  violates(action: Action): boolean {
    const c = this.capsOf(action);
    return c.has(EXTERNAL) && this.active.has(UNTRUSTED) && this.active.has(SENSITIVE);
  }

  observe(action: Action): void {
    for (const cap of this.capsOf(action)) this.active.add(cap);
  }
}

export { isSideEffect };
