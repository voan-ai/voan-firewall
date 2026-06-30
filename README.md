<h1 align="center">Voan Firewall</h1>
<p align="center"><b>The firewall for AI agents.</b><br>
Catches known-bad <i>and</i> goal-inconsistent agent actions — RCE, data exfiltration, fraud — <i>before</i> they execute.</p>

<p align="center">
  <a href="https://github.com/voan-ai/voan-firewall/actions/workflows/ci.yml"><img src="https://github.com/voan-ai/voan-firewall/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/core%20deps-zero-brightgreen" alt="Zero core deps">
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-informational" alt="Security policy"></a>
</p>

---

AI agents now take real actions: they run shell commands, move money, touch your
database, call your APIs. One prompt injection or one poisoned tool result and an
agent does something it was never asked to. **Voan Firewall sits inline on every
tool call, in the agent's own process, and decides `allow / ask / block` before
any side effect happens.** Think of it as the antivirus/EDR layer for agents: a
fast signature tier plus an optional LLM judge for the gray zone.

```
Voan Firewall  → runtime:    block the exploit as it happens   (this repo)
Voan Scanner   → pre-deploy: find the agent's holes            (companion, private beta)
```

## Why not just regex rules?

Pattern rules catch the loud stuff (`rm -rf`, known-bad domains). They **cannot**
tell whether a *benign-looking* action — an email to a normal address, a data
export — is what the user asked for, or was hijacked by poisoned tool output. So
Voan adds a second tier: an **LLM judge** that compares each action against the
user's actual goal. The judge only ever *escalates* a verdict to BLOCK; it never
loosens one.

On a 36-case eval ([`eval/`](eval/), grounded in an agentic-attack taxonomy —
OWASP Agentic Top 10; see the `klass` field in [`eval/traces.jsonl`](eval/traces.jsonl);
gpt-4o-mini judge):

| 36-case eval | regex rules only | **+ Voan judge** |
|---|:--:|:--:|
| Attacks **silently allowed** (no gate at all) | 30% (6/20) | **0% (0/20)** |
| Attacks auto-blocked | 35% (7/20) | **100% (20/20)** |
| Benign **hard-blocked** (false positive) | 6% (1/16) | 6% (1/16) |

Read it honestly: rules alone auto-block 35% of attacks and **hold another 35%
for a human** (`ASK` on money/external sends), but **silently allow the remaining
30%** — that 30% is the real blind spot. The judge closes it to **zero**, turning
the silently-allowed attacks into blocks and the held ones into auto-blocks. The
one false positive is a *legitimate* `DROP TABLE`: destructive DB ops are
hard-blocked by design (allowlist them explicitly), and the judge can't loosen a
hard block. A further 5/16 benign actions are *held for approval*, not blocked —
intended behaviour for money and outbound sends.

> Honest caveat: 36 hand-curated cases is an optimistic ceiling, not a production
> guarantee, and the judge score is one run of an LLM grader. The defensible
> number comes from feeding real traces through the same harness — that loop is on
> the roadmap.

## Install

Not yet on PyPI/npm — install from source (it's a single editable install):

```bash
git clone https://github.com/voan-ai/voan-firewall && cd voan-firewall
pip install -e .                 # core SDK — zero runtime dependencies
pip install -e ".[dashboard]"    # + live dashboard (fastapi, uvicorn)
pip install -e ".[langchain]"    # + the LangChain adapter demo (langchain-core)
```

A TypeScript/JS **port** lives in [`sdk-js/`](sdk-js/) (Node 22.6+, native TS).
It currently implements the **regex policy tier only** — the LLM judge is
Python-only for now (JS judge is on the roadmap). Consumed locally from the repo;
not yet published to npm.

## One line to protect an agent

```python
import voan

tools = voan.guard(tools)      # wrap your dict/list of tool functions
```

That one line gives you the **regex tier** (the "silently-allow 30%" column above).
To get the full intent-vs-hijack coverage, add the judge and tell it the user's
goal:

```python
import voan
from voan import LLMJudge, ollama_llm

fw = voan.Firewall(judge=LLMJudge())     # needs a backend (see note)
fw.set_goal("Check the delivery status of order ORD-1001.")
tools = fw.guard_tools(tools)
# An agent hijacked into emailing customer data now raises BlockedAction.
```

> The judge needs an LLM backend: `OPENAI_API_KEY` in `.env`, **or** a local one
> via `LLMJudge(llm=ollama_llm())`. With no backend it is a **no-op (fails open)**
> and emits a warning. The judge sends the action + recent (untrusted) tool
> context to that backend — secrets and card numbers are auto-redacted first, but
> for privacy-sensitive/regulated agents use a **local** backend. See
> [Data handling](#data-handling--threat-model).

Works on real frameworks too — genuine LangChain tools (with `langchain-core`
installed) via [`voan/adapters.py`](voan/adapters.py):

```python
from voan.adapters import guard_langchain
guard_langchain(my_langchain_tools)
```

## See it work

```bash
uvicorn server.app:app --port 8088     # live dashboard at http://127.0.0.1:8088
python demo/demo_agent.py              # naive agent: 1 allow, 1 held, 3 blocked
python demo/judge_demo.py              # intent-vs-hijack tier (needs a judge backend)
python demo/langchain_demo.py          # real LangChain tools (needs .[langchain])
python eval/run_eval.py                # reproduce the eval numbers above
```

## How it works

- **Sensor** ([`hook.py`](voan/hook.py)) — in-process wrapper on every tool call.
  In-process means it covers Python (and, via the port, JS) agent tools you can
  wrap; protocol-level/MCP coverage is on the roadmap.
- **Brain** ([`policy.py`](voan/policy.py) + [`rules.py`](voan/rules.py)) — fast
  regex tier; first matching rule wins. It is a **signature blocklist that is
  default-allow** out of the box (flip to deny-by-default, or rely on the judge,
  for unrecognized actions). Local and sub-millisecond.
- **Judge** ([`judge.py`](voan/judge.py)) — LLM "intent vs hijack" tier, **opt-in**,
  that only ever *escalates* to BLOCK. Adds an LLM round-trip (latency + cost) per
  gray-zone action, so it runs off the regex hot path. Pluggable backend
  (OpenAI / local Ollama / any callable).
- **Audit + dashboard** — JSONL trail + live WebSocket feed.

## Data handling & threat model

When the judge is enabled, each evaluated action's arguments plus up to the last 5
(untrusted) tool outputs are sent to your chosen LLM backend. **With the default
OpenAI backend, that context leaves your environment.** Two mitigations ship in the
box: (1) a redactor masks obvious secrets and card-like numbers before anything is
sent (the regex tier still sees the raw values, so blocking is unaffected); (2) the
prompt instructs the model to treat untrusted tool output as data only — a
best-effort, not a guarantee, against injection of the judge itself. For sensitive
or regulated deployments, run the judge on a **local** model
(`LLMJudge(llm=ollama_llm())`) so nothing leaves your network. To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Roadmap

- Real-trace eval harness (the production FP/FN number)
- LLM judge parity in the JS port
- MCP proxy sensor (protocol-level, framework-agnostic)
- Deny-by-default presets for sensitive tool families
- Hosted policy management + team audit (the commercial open-core layer)

Apache-2.0 · [github.com/voan-ai/voan-firewall](https://github.com/voan-ai/voan-firewall)
