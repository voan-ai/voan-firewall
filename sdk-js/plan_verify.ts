// Plan-then-execute parity check (deterministic, no LLM). Mirrors tests/test_plan.py.
// Run: node sdk-js/plan_verify.ts
import { Firewall, BlockedAction, Plan } from "./src/index.ts";

let ok = true;
function chk(label: string, cond: boolean) {
  if (!cond) ok = false;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
}

// on-plan runs
{
  const fw = new Firewall({ agent: "t" }).setPlan(["read_file", "send_money"]);
  const read = fw.guard((_a: Record<string, unknown>) => "bill", "read_file");
  const pay = fw.guard((_a: Record<string, unknown>) => "paid", "send_money");
  chk("on-plan read runs", read({ file_path: "b.txt" }) === "bill");
  chk("on-plan send runs", pay({ recipient: "GB123", amount: 10 }) === "paid");
}

// off-plan blocked
{
  const fw = new Firewall({ agent: "t" }).setPlan(["read_file"]);
  const pay = fw.guard((_a: Record<string, unknown>) => "paid", "send_money");
  let blocked = false;
  try { pay({ recipient: "US133" }); } catch (e) { blocked = e instanceof BlockedAction; }
  chk("off-plan action blocked", blocked);
}

// extra call of a planned tool blocked (multiset consume)
{
  const fw = new Firewall({ agent: "t" }).setPlan(["send_money"]);
  const pay = fw.guard((_a: Record<string, unknown>) => "ok", "send_money");
  chk("first planned send runs", pay({ recipient: "GB123" }) === "ok");
  let blocked = false;
  try { pay({ recipient: "US133" }); } catch (e) { blocked = e instanceof BlockedAction; }
  chk("injected extra send blocked", blocked);
}

// pinned recipient: swap blocked, match allowed
{
  const fw = new Firewall({ agent: "t" }).setPlan([{ tool: "send_money", recipient: "GB29NWBK" }]);
  const pay = fw.guard((a: { recipient: string }) => "ok", "send_money");
  let blocked = false;
  try { pay({ recipient: "US133000" }); } catch (e) { blocked = e instanceof BlockedAction; }
  chk("pinned recipient swap blocked", blocked);

  const fw2 = new Firewall({ agent: "t" }).setPlan([{ tool: "send_money", recipient: "GB29NWBK" }]);
  const pay2 = fw2.guard((a: { recipient: string }) => "ok", "send_money");
  chk("pinned recipient match allowed", pay2({ recipient: "GB29NWBK" }) === "ok");
}

// consume in order
{
  const p = new Plan(["a", "a"]);
  const act = (tool: string) => ({ tool, args: {}, agent: "t", ts: 0 });
  chk("plan consumes N steps then stops",
    p.allows(act("a")) && p.allows(act("a")) && !p.allows(act("a")));
}

// hard rule still blocks even if planned
{
  const fw = new Firewall({ agent: "t" }).setPlan(["run_command"]);
  const run = fw.guard((_a: { command: string }) => "ran", "run_command");
  let blocked = false;
  try { run({ command: "rm -rf /" }); } catch (e) { blocked = e instanceof BlockedAction; }
  chk("hard rule blocks even a planned tool", blocked);
}

console.log(`\n  ${ok ? "ALL PASS" : "FAILED"}`);
if (!ok) process.exit(1);
