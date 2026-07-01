"""Auto-derive a plan-then-execute plan from the user goal.

Plan mode is strong but needs a plan; writing one by hand is friction. This asks
an LLM to produce the intended tool-call sequence from the USER GOAL and the tool
list — BEFORE any untrusted data is read, so an injection can't influence it. Feed
the result to `Firewall.set_plan(...)`. The plan is deliberately allowed to include
the reads the task needs (reads are safe); its job is to bound the SIDE EFFECTS, so
an injection that adds an extra send/pay/post finds no step and is blocked.

    from voan import Firewall, LLMJudge, derive_plan, openai_llm
    plan = derive_plan(goal, ["read_file", "send_money", ...], openai_llm())
    fw = Firewall(judge=LLMJudge()).set_goal(goal).set_plan(plan)  # plan + judge backstop
"""
import json

_PLAN_SYS = (
    "You are a security planner for an AI agent. You are given the USER GOAL and "
    "the list of available TOOLS. Output the MINIMAL sequence of tool calls needed "
    "to accomplish the goal — and nothing the goal does not require. This plan is "
    "committed BEFORE the agent reads any external data, so it fixes what the agent "
    "is allowed to do; an instruction injected into a tool result later cannot add "
    "to it. Include the reads the task needs, but include a SIDE EFFECT (send, pay, "
    "transfer, post, delete, share) ONLY if the goal explicitly asks for it, and if "
    "the goal names the target (a recipient, account, channel) put it in the step. "
    'Output ONLY a JSON list; each item is {"tool": "<name>"} with optional fixed '
    'argument values you can already tell from the goal, e.g. '
    '{"tool": "send_money", "recipient": "<iban the user gave>"}.'
)


def _parse_list(raw):
    raw = (raw or "").strip()
    a, b = raw.find("["), raw.rfind("]")
    if a >= 0 and b > a:
        try:
            data = json.loads(raw[a:b + 1])
            return data if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []
    return []


_PROG_SYS = (
    "You are the PRIVILEGED planner of a capability-secured agent (CaMeL-style). "
    "You see ONLY the trusted user goal and the tool list — never any external data. "
    "Emit the program the agent will run, as a JSON list of steps. Each step is "
    '{"tool": "<name>", "args": {...}, "var": "<name, optional>"}. An arg value of '
    '"$x" references the output stored by an earlier step\'s var (that is how data '
    "read from a tool flows on). Use a step's var to name outputs you will reuse. "
    "Do NOT invent recipients/accounts from nowhere; if the goal names one, use it "
    "as a literal. Output ONLY the JSON list.")


def derive_capability_program(goal, tools, llm, max_steps=12):
    """Ask the (privileged) LLM to emit a capability-interpreter PROGRAM from the
    trusted goal — the planning half of CaMeL. Feed the result to
    `CapabilityEngine.run(program, tools, ...)`, which threads capabilities and
    enforces the invariants, so even a mis-planned or injection-shaped program can
    never pay an untrusted recipient. Returns [] if unparseable."""
    names = [t if isinstance(t, str) else t.get("name", "") for t in tools]
    user = f"USER GOAL:\n{goal}\n\nTOOLS:\n{', '.join(names)}\n\nProgram (JSON list):"
    steps = _parse_list(llm(_PROG_SYS, user))[:max_steps]
    return [s for s in steps if isinstance(s, dict) and s.get("tool") in names]


def derive_plan(goal, tools, llm, max_steps=12):
    """Return a list of plan steps (for Firewall.set_plan) derived from `goal`.
    `tools` is a list of tool names (or {"name","description"} dicts). `llm` is the
    same callable(system, user) -> str the judge uses. Returns [] if it can't parse
    (set_plan([]) then blocks everything, so callers should check / fall back)."""
    names = [t if isinstance(t, str) else t.get("name", "") for t in tools]
    desc = "\n".join(
        f"- {n}" + (f": {t.get('description','')[:80]}" if isinstance(t, dict) else "")
        for n, t in zip(names, tools))
    user = f"USER GOAL:\n{goal}\n\nAVAILABLE TOOLS:\n{desc}\n\nPlan (JSON list):"
    steps = _parse_list(llm(_PLAN_SYS, user))[:max_steps]
    out = []
    for s in steps:
        if isinstance(s, str) and s in names:
            out.append(s)
        elif isinstance(s, dict) and s.get("tool") in names:
            out.append(s)
    return out
