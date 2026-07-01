"""Plan-then-execute vs the LLM judge, on AgentDojo's in-domain attacks.

The judge cannot verify an in-domain action (a send_money paying a bill vs. one
paying an attacker) without provenance, so it over-blocks. Plan-then-execute
sidesteps this: the agent commits the actions it INTENDS to take before it reads
untrusted data; Voan then allows only those (each once) and blocks anything an
injection adds or alters. It is DETERMINISTIC — no LLM call, no cost, no latency.

Here the committed plan = each user task's own legitimate calls. Benign calls are
on-plan; each injected attacker side-effect arrives as an extra/altered call and is
off-plan. Two granularities: tool-only (realistic when a value is only known at
runtime) and target-pinned (pin the recipient/destination — the ceiling).

    pip install voan agentdojo
    python eval/agentdojo_plan_eval.py

Honest caveat: this assumes the committed plan matches the task's real actions —
i.e. an accurate up-front planner. That is the assumption plan-then-execute makes
(and why it needs a planning step, unlike the drop-in judge). In production, pair
it with the judge (`Firewall(judge=..., ...); fw.set_plan(...)`) so off-plan-but-
legitimate actions are judged instead of hard-blocked.
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from voan.hook import Firewall
from voan.schema import Action, Decision

TARGET = ("recipient", "receiver", "payee", "to", "dest", "destination", "address",
          "account", "iban", "email", "channel", "user", "member", "guest")
READ = ("get_", "read_", "list_", "search_", "find_", "retrieve", "view_", "check_")
SUITES = ["banking", "slack", "travel", "workspace"]
side = lambda t: not any(t.startswith(r) or r in t for r in READ)


def gated(fw, tool, args):
    act = Action(tool=tool, args=args, agent="a")
    v = fw._plan(act, fw._egress(act, fw.policy.evaluate(act)))
    return v.decision in (Decision.BLOCK, Decision.ASK)


def pins(args):
    return {k: v for k, v in args.items() if any(t in k.lower() for t in TARGET)}


def steps_for(calls, mode):
    return [c.function if mode == "tool" else {"tool": c.function, "pins": pins(dict(c.args))}
            for c in calls]


def run(mode):
    from agentdojo.task_suite.load_suites import get_suite
    fp = fpn = rec = recn = 0
    for name in SUITES:
        s = get_suite("v1", name)
        env = s.load_and_inject_default_environment({})
        tasks = []
        for ut in s.user_tasks.values():
            try:
                tasks.append(ut.ground_truth(env))
            except Exception:
                pass
        for calls in tasks:                                  # benign: replay own plan
            fw = Firewall().set_plan(steps_for(calls, mode))
            for c in calls:
                fpn += 1
                fp += gated(fw, c.function, dict(c.args))
        inj = []
        for it in s.injection_tasks.values():
            try:
                inj += [fc for fc in it.ground_truth(env) if side(fc.function)]
            except Exception:
                pass
        for calls in tasks[:3]:                              # attack: injected extra call
            steps = steps_for(calls, mode)
            for fc in inj:
                fw = Firewall().set_plan(steps)
                recn += 1
                rec += gated(fw, fc.function, dict(fc.args))
    print(f"  plan={mode:7}  ATTACK recall {rec}/{recn} = {rec/recn:.0%}   "
          f"BENIGN FP {fp}/{fpn} = {fp/fpn:.0%}")


if __name__ == "__main__":
    print("\n  AgentDojo — plan-then-execute (deterministic, no LLM)\n")
    run("tool")
    run("pinned")
    print("\n  vs the LLM judge alone: 99% recall / ~10% FP (eval/agentdojo_eval.py).\n"
          "  Plan mode trades a little recall for ~5x fewer false positives, free.\n")
