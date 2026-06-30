// Parity check for the JS LLM judge (no network — uses a stub backend).
// Mirrors the Python judge semantics: escalate-only, scope-aware, fail-closed,
// redaction before the backend sees the prompt. Run: node sdk-js/judge_verify.ts
import { Firewall, LLMJudge, BlockedAction } from "./src/index.ts";

let ok = true;
function chk(label: string, cond: boolean) {
  if (!cond) ok = false;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
}

// A stub LLM that records the last user prompt and replies with a fixed verdict.
function stub(reply: string) {
  const calls: string[] = [];
  const llm = async (_sys: string, user: string) => { calls.push(user); return reply; };
  return { llm, calls };
}

// 1) Judge ESCALATES a benign-looking action to BLOCK when it drifts from goal.
{
  const s = stub('{"decision":"block","reason":"exfiltrates to a third party"}');
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: s.llm }) });
  fw.setGoal("Check the status of order ORD-1001.");
  let blocked = false;
  const sendEmail = fw.guard(async (to: string) => `sent to ${to}`, "send_email");
  try { await sendEmail("data-broker@example.com"); }
  catch (e) { blocked = e instanceof BlockedAction; }
  chk("judge escalates benign-looking action to BLOCK", blocked);
}

// 2) Judge ALLOWS an on-goal action.
{
  const s = stub('{"decision":"allow","reason":"fulfills the goal"}');
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: s.llm }) });
  fw.setGoal("Check the status of order ORD-1001.");
  const lookup = fw.guard(async (id: string) => `status of ${id}`, "lookup_order");
  const out = await lookup("ORD-1001");
  chk("judge allows on-goal action", out === "status of ORD-1001");
}

// 3) No goal set -> judge is a no-op; rule verdict (ALLOW here) stands.
{
  const s = stub('{"decision":"block","reason":"should not even be asked"}');
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: s.llm }) });
  const lookup = fw.guard(async (id: string) => `ok ${id}`, "lookup_order");
  const out = await lookup("X");
  chk("no goal -> judge skipped, action runs", out === "ok X" && s.calls.length === 0);
}

// 4) Judge only ESCALATES: a hard rule BLOCK is never loosened, even if the
//    judge says allow (it isn't even consulted on an already-blocked verdict).
{
  const s = stub('{"decision":"allow","reason":"looks fine to me"}');
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: s.llm }) });
  fw.setGoal("Clean up temp files.");
  let blocked = false;
  const run = fw.guard(async (command: string) => `ran ${command}`, "run_command");
  try { await run("rm -rf /"); }
  catch (e) { blocked = e instanceof BlockedAction; }
  chk("judge cannot loosen a hard rule BLOCK", blocked && s.calls.length === 0);
}

// 5) Fail-closed: a backend that throws BLOCKS when judgeFailClosed is set.
{
  const llm = async () => { throw new Error("backend down"); };
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm }), judgeFailClosed: true });
  fw.setGoal("Check order status.");
  let blocked = false;
  const sendEmail = fw.guard(async (to: string) => `sent ${to}`, "send_email");
  try { await sendEmail("ok@acme.com"); }
  catch (e) { blocked = e instanceof BlockedAction; }
  chk("judgeFailClosed blocks on backend error", blocked);
}

// 6) Redaction: secrets/card numbers are masked before the prompt reaches the
//    backend. Use a non-mail tool so the rule tier doesn't hard-block first —
//    we're checking what the *judge* sees.
{
  const s = stub('{"decision":"allow","reason":"ok"}');
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: s.llm }) });
  fw.setGoal("Save the receipt note.");
  const save = fw.guard(async (_note: string, _key: string) => "done", "save_note");
  await save("card 4111 1111 1111 1111", "api_key=sk-abcdef123456");
  const sentPrompt = s.calls[0] ?? "";
  chk("secret + card redacted before backend",
    !sentPrompt.includes("sk-abcdef123456") && sentPrompt.includes("[REDACTED-SECRET]")
    && !sentPrompt.includes("4111 1111 1111 1111") && sentPrompt.includes("[REDACTED-NUM]"));
}

// 7) No backend -> judge is available:false and a no-op (rule verdict stands).
{
  const fw = new Firewall({ agent: "t", judge: new LLMJudge({ llm: null }) });
  fw.setGoal("Look something up.");
  const lookup = fw.guard(async (id: string) => `ok ${id}`, "lookup_order");
  const out = await lookup("Z");
  chk("no-backend judge is a no-op", out === "ok Z");
}

console.log(`\n  ${ok ? "ALL PASS" : "FAILED"}`);
if (!ok) process.exit(1);
