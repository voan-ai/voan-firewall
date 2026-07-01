// Auto-instrumentation — mechanical, zero-config provenance guard (JS port of
// voan/auto.py). Voan classifies each tool itself (untrusted source vs. side-effect
// sink) and enforces two DETERMINISTIC rules — no model in the decision, 0% by
// construction, unevadable: (a) grounding — a recipient the user didn't name in the
// goal is HELD for confirmation; (b) Rule of Two — a side effect with no user-named
// target, once the session has read untrusted + sensitive data, is held (the exfil
// path). An injection can't win: it can't put the attacker's account into the user's
// own words, and there is no LLM gate to fool.

const READ = ["get_", "read_", "list_", "search_", "find_", "retrieve", "view_",
  "check_", "fetch_", "lookup"];
const SOURCE_HINTS = ["read", "fetch", "search", "list", "email", "web", "file",
  "inbox", "message", "review", "lookup", "load", "browse", "get", "retrieve",
  "scrape", "content", "doc", "page", "mail", "calendar", "note"];
const SENSITIVE_HINTS = ["balance", "transaction", "account", "payment", "secret",
  "password", "private", "salary", "ssn", "card", "health", "scheduled",
  "statement", "credential", "iban", "contact"];
const TARGET_KEYS = ["recipient", "receiver", "payee", "to", "dest", "destination",
  "address", "account", "iban", "email", "channel", "url", "user", "member",
  "guest", "participant", "contact"];
const TOKEN = /[A-Za-z0-9@._+-]{4,}/g;

export function isSideEffect(tool: string): boolean {
  const t = String(tool).toLowerCase();
  return !READ.some((r) => t.startsWith(r) || t.includes(r));
}

function tokens(v: unknown): Set<string> {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return new Set((s.match(TOKEN) ?? []).map((t) => t.toLowerCase()).filter((t) => t.length >= 4));
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Fn = (...a: any[]) => any;

/** One call for the full, PROVABLE CaMeL loop (JS port of voan.capability_agent):
 *  derive the program from the trusted goal, auto-classify tools, and run it through
 *  the capability interpreter so no untrusted value can reach a sink. Returns the
 *  interpreter env; throws Denied on a violation. */
export async function capabilityAgent(
  goal: string, tools: Record<string, Fn>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  llm: (s: string, u: string) => Promise<string>,
  sinkClass?: Record<string, string>, sources?: Set<string>,
): Promise<Record<string, unknown>> {
  const { CapabilityEngine } = await import("./capability.ts");
  const { deriveCapabilityProgram } = await import("./planner.ts");
  const names = Object.keys(tools);
  const sinks = new Set(names.filter(isSideEffect));
  const sc = sinkClass ?? Object.fromEntries([...sinks].map((n) => [n, "external"]));
  const srcs = sources ?? new Set(names.filter((n) => !sinks.has(n)));
  const program = await deriveCapabilityProgram(goal, names, llm);
  return new CapabilityEngine(sc).run(program as never, tools, srcs);
}

export class AutoGuard {
  goal: string;
  private caps = new Set<string>();

  constructor(goal = "") {
    this.goal = String(goal).toLowerCase();
  }

  setGoal(goal: string): this {
    this.goal = String(goal).toLowerCase();
    this.caps = new Set();
    return this;
  }

  isSource(name: string, desc = ""): boolean {
    if (!isSideEffect(name)) return true;
    const t = `${name} ${desc}`.toLowerCase();
    return SOURCE_HINTS.some((h) => t.includes(h));
  }

  /** An ungrounded destination arg (one the user didn't name) — held mechanically. */
  violation(args: Record<string, unknown>): string | null {
    if (!args || typeof args !== "object") return null;
    for (const [k, v] of Object.entries(args)) {
      if (!TARGET_KEYS.some((t) => k.toLowerCase().includes(t))) continue;
      const ungrounded = [...tokens(v)].filter((t) => !this.goal.includes(t));
      if (ungrounded.length) return String(v);
    }
    return null;
  }

  private ruleOfTwo(args: Record<string, unknown>): boolean {
    const hasTarget = args && typeof args === "object" &&
      Object.keys(args).some((k) => TARGET_KEYS.some((t) => k.toLowerCase().includes(t)));
    return !hasTarget && this.caps.has("untrusted") && this.caps.has("sensitive");
  }

  wrap<T extends Fn>(fn: T, name: string, desc = "", source?: boolean, sink?: boolean): T {
    const src = source === undefined ? this.isSource(name, desc) : source;
    const snk = sink === undefined ? isSideEffect(name) : sink;
    const sensitive = SENSITIVE_HINTS.some((h) => `${name} ${desc}`.toLowerCase().includes(h));
    const self = this;
    const wrapped = function (this: unknown, ...a: unknown[]) {
      const args = (a.length === 1 && a[0] && typeof a[0] === "object")
        ? a[0] as Record<string, unknown>
        : Object.fromEntries(a.map((v, i) => [`a${i}`, v]));
      if (snk) {
        const bad = self.violation(args);
        const reason = bad ? `the destination '${bad}' is not one the user named`
          : (self.ruleOfTwo(args) ? "this action can send data out after the session read "
             + "untrusted content and sensitive data" : null);
        if (reason) {
          return `\u{1f6d1} Voan held ${name}: ${reason}, so it can't be authorized `
            + `automatically (possible injected action). Ask the user to confirm.`;
        }
      }
      const result = fn.apply(this, a as never);
      if (src) {
        self.caps.add("untrusted");
        if (sensitive) self.caps.add("sensitive");
      }
      if (snk) self.caps.add("external");
      return result;
    };
    return wrapped as unknown as T;
  }
}

/** Auto-instrument a LangChain-style tool set ({ name, description, execute/func }).
 *  Voan classifies each tool and shares one guard, no manual wiring. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function guardLangchainAuto(tools: any[], goal = ""): [any[], AutoGuard] {
  const g = new AutoGuard(goal);
  for (const t of tools) {
    const name = t.name ?? t.constructor?.name ?? "tool";
    const desc = t.description ?? "";
    if (typeof t.func === "function") t.func = g.wrap(t.func.bind(t), name, desc);
    else if (typeof t.execute === "function") t.execute = g.wrap(t.execute.bind(t), name, desc);
  }
  return [tools, g];
}
