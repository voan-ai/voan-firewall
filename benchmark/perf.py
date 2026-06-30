"""Performance characterization of the deterministic tiers and the firewall's own
per-call overhead. The judge tier's latency is whatever your LLM backend takes
(network-bound, ~100ms-2s) — measured separately with a near-zero stub so the
number reflects VOAN's overhead, not the model's. Run: python benchmark/perf.py
"""
import os
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from voan import Firewall, LLMJudge
from voan.audit import AuditLog
from voan.policy import PolicyEngine
from voan.rules import egress_violation
from voan.schema import Action

N = 50_000


def bench(label, fn, n=N):
    fn()  # warm up
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    dt = time.perf_counter() - t0
    per_us = dt / n * 1e6
    print(f"  {label:<34} {per_us:8.2f} µs/call   {n/dt:>12,.0f} calls/s")
    return per_us


def main():
    print(f"\n  Voan performance ({N:,} iterations each)\n")
    pol = PolicyEngine()
    benign = Action(tool="get_weather", args={"city": "Seoul"}, agent="t")
    danger = Action(tool="run_command", args={"command": "rm -rf /"}, agent="t")
    big = Action(tool="export_data",
                 args={"dataset": "x", "rows": list(range(50)),
                       "dest": "https://acme.com/in", "meta": {"a": 1, "b": "c"}}, agent="t")

    print("  policy.evaluate (regex tier):")
    bench("  benign (no rule matches)", lambda: pol.evaluate(benign))
    bench("  danger (first rule blocks)", lambda: pol.evaluate(danger))
    bench("  nested/large args", lambda: pol.evaluate(big))

    print("\n  egress_violation (allowlist tier):")
    al = ["acme.com"]
    bench("  clean dest", lambda: egress_violation({"dest": "https://acme.com/x"}, al))
    bench("  exfil dest (walks all args)",
          lambda: egress_violation({"dest": "http://evil.net", "rows": list(range(50))}, al))

    print("\n  full Firewall.guard wrapper overhead (rules+egress+audit+gate):")
    # audit -> os.devnull, dashboard emit off: measure Voan's logic + JSON
    # serialization, not disk-write variance or the dashboard POST thread.
    fw = Firewall(egress_allowlist=["acme.com"],
                  audit=AuditLog(path=os.devnull, emit=False))
    tool = fw.guard(lambda command: "ok", name="run_command")
    bench("  allowed call (end to end)", lambda: tool("echo hi"))

    print("\n  judge overhead with a ZERO-latency stub (isolates Voan's cost,\n"
          "  not the model's — real judge latency = your backend's round-trip):")
    j = LLMJudge(llm=lambda s, u: '{"decision":"allow"}')
    fwj = Firewall(judge=j)
    fwj.set_goal("do the task")
    jt = fwj.guard(lambda x: "ok", name="lookup")
    bench("  guarded call + stub judge", lambda: jt("x"), n=20_000)

    print("\n  Takeaway: the deterministic tiers add single-digit microseconds per\n"
          "  tool call (sub-millisecond, local). The judge adds one LLM round-trip,\n"
          "  so enable it only for gray-zone tools — the rules run on the hot path.\n")


if __name__ == "__main__":
    main()
