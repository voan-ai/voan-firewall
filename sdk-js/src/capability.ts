// Capability engine — per-value provenance, the CaMeL/FIDES core. JS port of
// voan/capability.py. Every value carries an integrity label (was it derived only
// from trusted input, or did untrusted data touch it?) and a confidentiality label
// (which sink classes may receive it); labels propagate through operations. Two
// invariants are enforced per value, deterministically, with no model in the gate:
//   integrity  — an untrusted value may not be a control-sensitive arg of a sink;
//   confidentiality — a value may only reach a sink whose class is in its readers.

export const TRUSTED = "trusted";
export const UNTRUSTED = "untrusted";
export const ANY = "*";

const SENSITIVE_PARAMS = ["recipient", "receiver", "payee", "to", "dest",
  "destination", "address", "account", "iban", "url", "command", "cmd", "path",
  "channel", "user", "query"];

export class Denied extends Error {
  reason: string;
  constructor(reason: string) { super(reason); this.name = "Denied"; this.reason = reason; }
}

function intersect(a: Set<string>, b: Set<string>): Set<string> {
  if (a.has(ANY)) return new Set(b);
  if (b.has(ANY)) return new Set(a);
  return new Set([...a].filter((x) => b.has(x)));
}

export class Capsule {
  value: unknown;
  integrity: string;
  readers: Set<string>;
  source: string | null;

  constructor(value: unknown, integrity: string = TRUSTED,
              readers: Set<string> = new Set([ANY]), source: string | null = null) {
    this.value = value;
    this.integrity = integrity;
    this.readers = readers;
    this.source = source;
  }

  /** A value extracted or computed FROM this one inherits its capability. */
  derive(newValue: unknown, source?: string): Capsule {
    return new Capsule(newValue, this.integrity, new Set(this.readers), source ?? this.source);
  }

  /** Capability of a value computed from several: untrusted if any input is;
   *  readers = intersection (only sinks all inputs permit). */
  static combine(newValue: unknown, capsules: unknown[], source: string | null = null): Capsule {
    const caps = capsules.filter((c): c is Capsule => c instanceof Capsule);
    if (!caps.length) return new Capsule(newValue, TRUSTED, new Set([ANY]), source);
    const integrity = caps.every((c) => c.integrity === TRUSTED) ? TRUSTED : UNTRUSTED;
    let readers = caps[0].readers;
    for (const c of caps.slice(1)) readers = intersect(readers, c.readers);
    return new Capsule(newValue, integrity, readers, source);
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Fn = (...a: any[]) => any;
interface Step { tool: string; args?: Record<string, unknown>; var?: string }

export class CapabilityEngine {
  sinkClass: Record<string, string>;
  private sensitive: string[];

  constructor(sinkClass: Record<string, string> = {}, sensitive: string[] = SENSITIVE_PARAMS) {
    this.sinkClass = sinkClass;
    this.sensitive = sensitive;
  }

  trusted(value: unknown): Capsule {
    return new Capsule(value, TRUSTED, new Set([ANY]), "user");
  }

  source(tool: string, untrusted = true, readers = new Set([ANY])): Capsule {
    return new Capsule(null, untrusted ? UNTRUSTED : TRUSTED, readers, tool);
  }

  private isSensitive(key: string): boolean {
    return this.sensitive.some((s) => key.toLowerCase().includes(s));
  }

  /** Throw Denied if any Capsule arg violates an invariant, else true. */
  checkCall(tool: string, args: Record<string, unknown>): boolean {
    const cls = this.sinkClass[tool];
    for (const [k, v] of Object.entries(args ?? {})) {
      if (!(v instanceof Capsule)) continue;
      if (v.integrity === UNTRUSTED && this.isSensitive(k)) {
        throw new Denied(`untrusted value steers '${k}' of ${tool} (provenance: ${v.source}) — hijack`);
      }
      if (cls !== undefined && !v.readers.has(ANY) && !v.readers.has(cls)) {
        throw new Denied(`confidential value (readers=${[...v.readers]}) may not reach '${cls}' sink ${tool} — exfiltration`);
      }
    }
    return true;
  }

  private tagOutput(tool: string, args: Record<string, unknown>, result: unknown,
                    untrusted: boolean, readers: Set<string>): Capsule {
    const inCaps = Object.values(args).filter((v) => v instanceof Capsule);
    const combined = Capsule.combine(result, inCaps, tool);
    const integ = (untrusted || combined.integrity === UNTRUSTED) ? UNTRUSTED : TRUSTED;
    const rd = readers.has(ANY) && readers.size === 1 ? combined.readers : intersect(combined.readers, readers);
    return new Capsule(result, integ, rd, tool);
  }

  /** Interpret a capability-tracked PROGRAM (the CaMeL execution model). Each step
   *  {tool, args, var?}; an arg "$name" resolves to a prior step's capsule. */
  run(program: Step[], tools: Record<string, Fn>, sources?: Set<string>,
      confidential: Record<string, Set<string>> = {}, env: Record<string, unknown> = {}): Record<string, unknown> {
    const e = { ...env };
    const srcs = sources ?? new Set(Object.keys(tools));
    for (const step of program) {
      const args = Object.fromEntries(Object.entries(step.args ?? {}).map(
        ([k, v]) => [k, resolve(v, e)]));
      this.checkCall(step.tool, args);
      const raw = Object.fromEntries(Object.entries(args).map(
        ([k, v]) => [k, v instanceof Capsule ? v.value : v]));
      const out = this.tagOutput(step.tool, args, tools[step.tool](raw),
        srcs.has(step.tool), confidential[step.tool] ?? new Set([ANY]));
      if (step.var) e[step.var] = out;
    }
    return e;
  }
}

function resolve(value: unknown, env: Record<string, unknown>): unknown {
  if (typeof value === "string" && value.startsWith("$")) {
    const [base, field] = value.slice(1).split(".");
    const cap = env[base];
    if (cap === undefined) return value;
    if (field && cap instanceof Capsule && cap.value && typeof cap.value === "object") {
      return cap.derive((cap.value as Record<string, unknown>)[field] ?? "");
    }
    return cap;
  }
  return value;
}
