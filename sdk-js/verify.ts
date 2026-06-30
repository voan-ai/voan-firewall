// Quick parity check for the JS SDK: hardened destructive rules + egress allowlist.
// Run: node sdk-js/verify.ts
import { Firewall, BlockedAction } from "./src/index.ts";
import { egressViolation } from "./src/rules.ts";

let ok = true;
function chk(label: string, cond: boolean) {
  if (!cond) ok = false;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
}

// 1) hardened destructive-command rule (flag reorder + new commands)
const fw = new Firewall({ agent: "t" });
const rm = (cmd: string) => fw.check("run_command", { command: cmd }).decision === "block";
chk("rm -fr / blocked", rm("rm -fr /"));
chk("rm -r -f / blocked", rm("rm -r -f /"));
chk("find / -delete blocked", rm("find / -delete"));
chk("dd of=/dev/sda blocked", rm("dd of=/dev/sda if=/dev/zero"));
chk("Remove-Item -Recurse -Force blocked", rm("Remove-Item -Recurse -Force C:\\"));
chk("benign: chmod -R 755 allowed", !rm("chmod -R 755 ./build"));
chk("benign: rm tempfile allowed", !rm("rm tempfile.txt"));

// 2) egress allowlist (domain + encoded IP, fail-closed dest fields)
const A = ["acme.com"];
chk("lookalike domain blocked", egressViolation({ dest: "acme-backups.net" }, A) !== null);
chk("decimal IP blocked", egressViolation({ url: "http://2852039166/x" }, A) !== null);
chk("ipv6 blocked", egressViolation({ url: "http://[fd00::1]/x" }, A) !== null);
chk("legit subdomain allowed", egressViolation({ dest: "backups.acme.com" }, A) === null);
chk("no FP on order id", egressViolation({ order_id: "ORD-1001", amount: "50" }, A) === null);

// 3) egress wired into the Firewall
const fw2 = new Firewall({ agent: "t", egressAllowlist: ["acme.com"], onAsk: () => false });
let blocked = false;
const exportData = fw2.guard((dest: string) => `exported to ${dest}`, "export_data");
try { exportData("https://exfil.evil-collector.net/leak"); }
catch (e) { blocked = e instanceof BlockedAction; }
chk("Firewall egress blocks exfil dest", blocked);

console.log(`\n  ${ok ? "ALL PASS" : "FAILED"}`);
if (!ok) process.exit(1);
