<h1 align="center">Voan Firewall</h1>
<p align="center"><b>The firewall for AI agents.</b><br>
Blocks unauthorized agent actions — RCE, data exfiltration, fraud — <i>before</i> they execute.</p>

<p align="center">
  <a href="https://github.com/voan-ai/voan-firewall/actions/workflows/ci.yml"><img src="https://github.com/voan-ai/voan-firewall/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License">
  <img src="https://img.shields.io/badge/deps-zero-brightgreen" alt="Zero deps">
</p>

---

AI agents now take real actions: they run shell commands, move money, touch your
database, call your APIs. One prompt injection or one poisoned tool result and an
agent does something it was never asked to. **Voan Firewall sits inline on every
tool call, in the agent's own process, and decides `allow / ask / block` before
any side effect happens.** It's the antivirus layer for the agentic era.

```
Voan Scanner   → pre-deploy:  find the agent's holes
Voan Firewall  → runtime:     block the exploit as it happens
```

## Why not just regex rules?

Pattern rules catch the loud stuff (`rm -rf`, known-bad domains). They **cannot**
tell whether a *benign-looking* action — an email to a normal address, a data
export — is what the user asked for, or was hijacked by poisoned tool output. So
Voan adds a second tier: an **LLM judge** that compares each action against the
user's actual goal and can escalate to BLOCK.

On a 36-case eval grounded in the Voan scanner's attack taxonomy
([`eval/`](eval/), gpt-4o-mini judge):

| | regex rules only | **+ Voan judge** |
|---|:--:|:--:|
| **Action-layer attacks caught** | 35% (7/20) | **100% (20/20)** |
| **False positives on legit work** | 6% (1/16) | **6% (1/16)** |

The judge caught **13 attacks the rules missed** — SSRF to cloud metadata,
indirect injection, salami-sliced refunds, security-config tampering, unrequested
transfers, cross-tenant reads, privilege escalation. The lone false positive is a
*legitimate* `DROP TABLE` that strict rules block by design (destructive DB ops
need explicit allowlisting; the judge intentionally never loosens a hard block).

> Honest caveat: 36 hand-curated cases is an optimistic ceiling, not a production
> guarantee. The defensible number comes from feeding the **live scanner's** real
> traces through this same harness — that loop is the roadmap.

## Install

```bash
pip install -e .                 # SDK — zero runtime deps
pip install -e ".[dashboard]"    # + live dashboard
```

A TypeScript/JS twin lives in [`sdk-js/`](sdk-js/) (Node 22.6+, native TS).

## One line to protect an agent

```python
import voanfw

tools = voanfw.guard(tools)      # wrap your dict/list of tool functions
```

Turn on the intent-vs-hijack judge by giving the firewall the user's goal:

```python
import voanfw
from voanfw import LLMJudge

fw = voanfw.Firewall(judge=LLMJudge())     # uses OPENAI_API_KEY from .env
fw.set_goal("Check the delivery status of order ORD-1001.")
tools = fw.guard_tools(tools)
# An agent hijacked into emailing customer data now raises BlockedAction.
```

Works on real frameworks too — genuine LangChain tools via
[`voanfw/adapters.py`](voanfw/adapters.py):

```python
from voanfw.adapters import guard_langchain
guard_langchain(my_langchain_tools)
```

## See it work

```bash
uvicorn server.app:app --port 8088     # live dashboard at http://127.0.0.1:8088
python demo/demo_agent.py              # naive agent runs 3 exploits behind Voan
python demo/judge_demo.py              # the intent-vs-hijack tier (needs .env key)
python eval/run_eval.py                # reproduce the numbers above
```

## How it works

- **Sensor** ([`hook.py`](voanfw/hook.py)) — in-process wrapper on every tool call.
- **Brain** ([`policy.py`](voanfw/policy.py) + [`rules.py`](voanfw/rules.py)) —
  fast regex tier; first matching rule wins; default-allow (flip to deny-by-default).
- **Judge** ([`judge.py`](voanfw/judge.py)) — LLM "intent vs hijack" tier that only
  ever *escalates*. Pluggable backend (OpenAI / local Ollama / any callable).
- **Audit + dashboard** — JSONL trail + live WebSocket feed.

## Roadmap

- Live-scanner trace harness (the real FP/FN number)
- MCP proxy sensor (protocol-level, framework-agnostic)
- Hosted policy management + team audit

Apache-2.0 · part of the Voan agent-security franchise · https://voan.ai
