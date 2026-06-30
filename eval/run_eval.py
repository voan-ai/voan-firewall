"""Eval harness — the moat number.

Runs a labeled set of agent actions (eval/traces.jsonl) through two pipelines and
reports how well each catches attacks WITHOUT blocking legitimate work:

  rules-only   : the regex policy engine alone (the cheap baseline)
  rules+judge  : same, but the LLM judge may escalate a non-block verdict to BLOCK
                 (exactly how the live Firewall behaves — judge runs only when the
                 rules did not already block)

Metrics: attack recall (caught = BLOCK) and benign false-positive rate (wrongly
BLOCKED). The gap between the two pipelines is the value the judge layer adds.

    python eval/run_eval.py            # OpenAI judge (.env key) or local Ollama
    python eval/run_eval.py ollama     # force local phi4-mini
"""
import json
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from voanfw import LLMJudge, PolicyEngine, ollama_llm, openai_llm  # noqa: E402
from voanfw.schema import Action, Decision  # noqa: E402

DATA = pathlib.Path(__file__).parent / "traces.jsonl"


def pick_llm():
    if len(sys.argv) > 1 and sys.argv[1] == "ollama":
        return ollama_llm("phi4-mini"), "Ollama phi4-mini (local)"
    if openai_llm() is not None:
        return openai_llm(), "OpenAI (.env key)"
    return ollama_llm("phi4-mini"), "Ollama phi4-mini (no OpenAI key)"


def run():
    cases = [json.loads(l) for l in DATA.read_text("utf-8").splitlines() if l.strip()]
    llm, label = pick_llm()
    rules = PolicyEngine()
    judge = LLMJudge(llm=llm)
    print(f"\n  Voan Firewall eval — {len(cases)} cases — judge backend: {label}\n")
    print(f"  {'id':<16} {'expect':<6} {'rules':<6} {'+judge':<7} result")
    print("  " + "-" * 52)

    rows = []
    for c in cases:
        a = Action(tool=c["action"]["tool"], args=c["action"]["args"], agent="eval")
        rv = rules.evaluate(a)
        rules_block = rv.decision == Decision.BLOCK
        if rules_block:
            combined_block, used = True, False
        else:
            jv = judge.evaluate(c["goal"], a, c.get("trace", []))
            combined_block = bool(jv and jv.decision == Decision.BLOCK)
            used = True
        attack = c["expect"] == "block"
        ok = combined_block == attack
        rows.append((c, attack, rules_block, combined_block, used))
        print(f"  {c['id']:<16} {c['expect']:<6} "
              f"{'BLOCK' if rules_block else '-':<6} "
              f"{'BLOCK' if combined_block else '-':<7} {'✅' if ok else '❌ MISS'}")

    _report(rows)


def _rate(n, d):
    return f"{(100*n/d if d else 0):5.1f}%  ({n}/{d})"


def _report(rows):
    atk = [r for r in rows if r[1]]
    ben = [r for r in rows if not r[1]]
    r_recall = sum(1 for r in atk if r[2])
    c_recall = sum(1 for r in atk if r[3])
    r_fp = sum(1 for r in ben if r[2])
    c_fp = sum(1 for r in ben if r[3])
    lift = [r[0]["id"] for r in atk if not r[2] and r[3]]
    judge_calls = sum(1 for r in rows if r[4])

    print("\n  ── results " + "─" * 42)
    print(f"  attack recall (caught=BLOCK)   rules-only: {_rate(r_recall, len(atk))}"
          f"   →  +judge: {_rate(c_recall, len(atk))}")
    print(f"  benign false-positive (blocked) rules-only: {_rate(r_fp, len(ben))}"
          f"   →  +judge: {_rate(c_fp, len(ben))}")
    print(f"\n  judge LIFT — attacks regex missed but judge caught: "
          f"{len(lift)}  {lift}")
    print(f"  judge calls made: {judge_calls}  (rest were blocked by cheap rules)")
    misses = [r[0]["id"] for r in rows if r[3] != r[1]]
    print(f"  remaining errors: {misses or 'none ✅'}\n")


if __name__ == "__main__":
    run()
