"""Real-trace eval: run Voan over a THIRD-PARTY agent-security benchmark we did
NOT build — InjecAgent (indirect prompt injection; Zhan et al., 2024).

Each InjecAgent case is a real agent scenario: a benign USER INSTRUCTION, a tool
whose response is POISONED with an injected instruction, and the harmful ATTACKER
TOOL the agent is induced to call. We replay the induced call through Voan and ask:
does Voan GATE it (block/ask) given the user's actual goal? And on the legitimate
user calls, does Voan wrongly gate them (false positive)?

Two tiers:
  - rules-only  : the deterministic regex tier (no API key, free)
  - judge       : rules + the LLM intent-vs-hijack judge (needs a backend)

HONEST READING (see the printed caveats): InjecAgent's attacks are off-goal *by
construction* — the attacker tool is always a different domain than the user goal
(grant smart-lock access vs. fetch a laptop). That is exactly the class the
goal-consistency judge is built to catch, so a high recall here does NOT prove
coverage of *subtle on-goal* attacks (correct tool, wrong recipient/amount). The
benign set is also small (17 unique user calls), so the FP number is indicative,
not a production guarantee.

    pip install voan            # rules-only works with no extra deps
    python eval/injecagent_eval.py                 # rules-only, downloads data
    python eval/injecagent_eval.py --judge         # + LLM judge (needs OPENAI_API_KEY)
    python eval/injecagent_eval.py --judge --n 200 # sample N attacks (cost/speed)
"""
import argparse
import concurrent.futures as cf
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from voan.judge import LLMJudge, load_dotenv, openai_llm
from voan.policy import PolicyEngine
from voan.schema import Action, Decision

RAW = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data"
FILES = ["test_cases_dh_base.json", "test_cases_ds_base.json", "user_cases.jsonl"]
CACHE = pathlib.Path(__file__).resolve().parent / ".injecagent_cache"


def fetch(name):
    CACHE.mkdir(exist_ok=True)
    p = CACHE / name
    if not p.exists():
        sys.stderr.write(f"[eval] downloading {name} ...\n")
        urllib.request.urlretrieve(f"{RAW}/{name}", p)
    return p


def load_json(name):
    return json.loads(fetch(name).read_text(encoding="utf-8"))


def load_jsonl(name):
    return [json.loads(x) for x in fetch(name).read_text(encoding="utf-8").splitlines() if x.strip()]


def build():
    attacks = []
    for f in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
        for c in load_json(f):
            attacks.append({
                "goal": c["User Instruction"], "tool": c["Attacker Tools"][0],
                # the hijacked call is driven by the injected instruction
                "args": {"request": c["Attacker Instruction"]},
                "trace": [str(c.get("Tool Response", ""))[:800]],
                "type": c.get("Attack Type", "?")})
    benign = [{"goal": u["User Instruction"], "tool": u["User Tool"],
               "args": u.get("Tool Parameters", {}),
               "trace": [str(u.get("Tool Response Template", ""))[:800]]}
              for u in load_jsonl("user_cases.jsonl")]
    return attacks, benign


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true", help="enable the LLM judge tier")
    ap.add_argument("--n", type=int, default=0, help="sample N attacks (0 = all)")
    args = ap.parse_args()

    load_dotenv()
    pol = PolicyEngine()
    judge = LLMJudge(llm=openai_llm()) if args.judge else None
    if args.judge and not judge.available:
        sys.exit("--judge needs an LLM backend (set OPENAI_API_KEY in .env).")

    attacks, benign = build()
    if args.n:
        attacks = attacks[::max(1, len(attacks) // args.n)][:args.n]

    def gated(case):
        v = pol.evaluate(Action(tool=case["tool"], args=case["args"], agent="a"))
        if v.decision in (Decision.BLOCK, Decision.ASK):
            return True
        if not judge:
            return False
        jv = judge.evaluate(case["goal"], Action(tool=case["tool"], args=case["args"],
                                                 agent="a"), case["trace"])
        return jv is not None and jv.decision == Decision.BLOCK

    def run(cases):
        if not judge:
            return [gated(c) for c in cases]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            return list(ex.map(gated, cases))

    tier = "rules + judge" if judge else "rules-only"
    print(f"\n  InjecAgent real-trace eval  ({len(attacks)} attacks, "
          f"{len(benign)} benign)  |  tier = {tier}\n")
    atk, ben = run(attacks), run(benign)
    print(f"  ATTACK recall (gated):          {sum(atk)}/{len(atk)} = {sum(atk)/len(atk):.0%}")
    print(f"  BENIGN false-positive (gated):  {sum(ben)}/{len(ben)} = {sum(ben)/len(ben):.0%}")
    print("\n  Caveats: rules-only expects ~0% recall (InjecAgent tools are domain-\n"
          "  specific, not Voan's generic families) — the judge is the defense on an\n"
          "  unconfigured real agent. 100% judge recall reflects that these attacks are\n"
          "  off-goal by construction; subtle on-goal attacks are a harder, separate\n"
          "  class. Benign set is 17 cases — FP is indicative, not a guarantee.\n")


if __name__ == "__main__":
    main()
