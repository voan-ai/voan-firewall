// Framework adapters — drop the firewall into JS agents you did NOT build.
// JS port of voan/adapters.py. The core guard() wraps plain functions; real
// agents wrap their tools in framework objects (a Vercel AI SDK tool, an OpenAI
// tool-dispatch table). These adapters reach inside those objects and guard the
// underlying callable, so interception happens INSIDE the framework's own
// execution path — not a toy loop. Everything is duck-typed: no framework is a
// hard dependency.
//
// Framework agents expect a tool to RETURN an observation, not throw. So unlike
// the bare guard() (which throws BlockedAction), these adapters catch the block
// and return it as a string result — the dangerous tool still never runs, but
// the agent receives "Voan blocked …" and can defer to the user instead of
// crashing.
import { Firewall } from "./hook.ts";
import { BlockedAction } from "./schema.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Fn = (...args: any[]) => any;

function fwOf(firewall?: Firewall): Firewall {
  return firewall ?? new Firewall();
}

function blockMsg(e: BlockedAction): string {
  return `\u{1f6d1} Voan blocked this action: ${e.verdict.reason} ` +
    `[${e.verdict.code} ${e.verdict.severity}]. Do not retry it; tell the user ` +
    `it was blocked by policy.`;
}

/** Wrap a guarded callable so a block returns a tool-observation string instead
 *  of throwing (the real tool still never runs on a block). Always async — the
 *  judge tier awaits an LLM call. */
function soft<T extends Fn>(fn: T): (...args: Parameters<T>) => Promise<unknown> {
  return async (...args: Parameters<T>) => {
    try { return await fn(...args); }
    catch (e) {
      if (e instanceof BlockedAction) return blockMsg(e);
      throw e;
    }
  };
}

// A Vercel AI SDK tool: { description?, parameters/inputSchema?, execute(args, opts) }.
interface AiTool { execute?: (args: Record<string, unknown>, opts?: unknown) => unknown }

/** Guard a Vercel AI SDK tool set ({ name: tool({ execute }) }). Replaces each
 *  tool's `execute` with a guarded version keyed on the tool name, so every call
 *  the model makes flows through the policy first. The args object the model
 *  produces is checked verbatim (clean/named action args). Mutates in place. */
export function guardAiSdkTools<M extends Record<string, AiTool>>(
  tools: M, firewall?: Firewall,
): M {
  const fw = fwOf(firewall);
  for (const [name, t] of Object.entries(tools)) {
    if (typeof t.execute !== "function") continue;
    const orig = t.execute.bind(t);
    t.execute = async (args: Record<string, unknown>, opts?: unknown) => {
      try { await fw.guardArgs(name, args ?? {}); }
      catch (e) {
        if (e instanceof BlockedAction) return blockMsg(e);
        throw e;
      }
      const result = await orig(args, opts);
      fw.observe(name, result);
      return result;
    };
  }
  return tools;
}

/** Guard an OpenAI tool-calling dispatch table ({ name: fn }). In an OpenAI
 *  function-calling loop you read `tool_calls` from the model and look the name
 *  up in this dict; wrap it once and every call is checked before it runs. */
export function guardOpenAIDispatch<M extends Record<string, Fn>>(
  dispatch: M, firewall?: Firewall,
): Record<string, (...a: unknown[]) => Promise<unknown>> {
  const fw = fwOf(firewall);
  const out: Record<string, (...a: unknown[]) => Promise<unknown>> = {};
  for (const [name, fn] of Object.entries(dispatch)) out[name] = soft(fw.guard(fn, name));
  return out;
}

/** Guard a plain list of callables, preserving order (block -> string result). */
export function guardCallables(fns: Fn[], firewall?: Firewall): Array<(...a: unknown[]) => Promise<unknown>> {
  const fw = fwOf(firewall);
  return fns.map((f) => soft(fw.guard(f)));
}
