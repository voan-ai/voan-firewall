"""Real-trace eval #2 — AgentDojo (ETH Zurich), the HARDER, in-domain benchmark.

Unlike InjecAgent (attacker tool always a different domain, so a goal-consistency
judge catches it trivially), AgentDojo injections are IN-DOMAIN: a banking agent
whose real task is 'pay a bill' is induced to send_money to the attacker — SAME
tool for benign and malicious. The judge must discriminate on the target/intent,
not the tool's domain. This is where a naive goal-consistency judge over-blocks.

We replay each injection task's harmful SIDE-EFFECT call (send/pay/post/...) as the
action, under a real user-task goal, and measure whether Voan gates it; and we
replay every user task's own legitimate calls to measure false positives.

    pip install voan agentdojo
    python eval/agentdojo_eval.py            # rules-only (free)
    python eval/agentdojo_eval.py --judge    # + judge (needs OPENAI_API_KEY)

Honest notes: recall is measured on the harmful SIDE-EFFECT calls (a read step in
an attacker's plan is not itself the harm). We run with an empty trace (no live
agent context), which is the hardest setting for precision — a real deployment
feeds Voan the tool-output trace, which can only help. Numbers are indicative of
the in-domain regime, not a universal guarantee.
"""
import argparse
import concurrent.futures as cf
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from voan.judge import LLMJudge, load_dotenv, openai_llm
from voan.policy import PolicyEngine
from voan.schema import Action, Decision

SUITES = ["banking", "slack", "travel", "workspace"]
READ = ("get_", "read_", "list_", "search_", "find_", "retrieve", "view_", "check_")


def is_side_effect(tool):
    return not any(tool.startswith(r) or r in tool for r in READ)


def build():
    from agentdojo.task_suite.load_suites import get_suite
    attacks, benign = [], []
    for name in SUITES:
        s = get_suite("v1", name)
        env = s.load_and_inject_default_environment({})
        users = list(s.user_tasks.values())
        for ut in users:
            try:
                for fc in ut.ground_truth(env):
                    benign.append((ut.PROMPT, fc.function, dict(fc.args)))
            except Exception:
                pass
        goals = [u.PROMPT for u in users[:3]]
        for it in s.injection_tasks.values():
            try:
                calls = it.ground_truth(env)
            except Exception:
                continue
            for g in goals:
                for fc in calls:
                    if is_side_effect(fc.function):
                        attacks.append((g, fc.function, dict(fc.args)))
    dedup = lambda xs: list({(g, t, str(a)): (g, t, a) for g, t, a in xs}.values())
    return dedup(attacks), dedup(benign)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true")
    args = ap.parse_args()
    load_dotenv()
    pol = PolicyEngine()
    judge = LLMJudge(llm=openai_llm()) if args.judge else None
    if args.judge and not judge.available:
        sys.exit("--judge needs an LLM backend (set OPENAI_API_KEY in .env).")

    attacks, benign = build()

    def gated(goal, tool, a):
        act = Action(tool=tool, args=a, agent="a")
        if pol.evaluate(act).decision in (Decision.BLOCK, Decision.ASK):
            return True
        if not judge:
            return False
        v = judge.evaluate(goal, act, [])
        return v is not None and v.decision == Decision.BLOCK

    def run(items):
        if not judge:
            return [gated(*x) for x in items]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            return list(ex.map(lambda x: gated(*x), items))

    tier = "rules + judge" if judge else "rules-only"
    print(f"\n  AgentDojo in-domain eval — {len(attacks)} harmful side-effects, "
          f"{len(benign)} benign  |  tier = {tier}\n")
    atk, ben = run(attacks), run(benign)
    print(f"  ATTACK recall (gated):          {sum(atk)}/{len(atk)} = {sum(atk)/len(atk):.0%}")
    print(f"  BENIGN false-positive (gated):  {sum(ben)}/{len(ben)} = {sum(ben)/len(ben):.0%}")
    print("\n  In-domain is the hard case; rules-only ~0% (domain-specific tools).\n"
          "  The judge (default-allow + target-grounding) is the defense; residual\n"
          "  FPs are mostly money-to-an-unnamed-recipient, which is ASK-worthy.\n")


if __name__ == "__main__":
    main()
