"""Voan Firewall — the runtime guard for AI agents.

The pre-deploy Voan scanner finds the holes; this firewall blocks the exploit
live. It sits inline on every tool call, in the agent's own process, and decides
allow / ask / block before any side effect happens.

Quick start:
    import voan

    tools = voan.guard(tools)          # wrap a dict/list of tool fns
    # ...or a single function / decorator:
    @voan.Firewall().guard
    def run_command(command): ...

See README.md for the dashboard and demo.
"""
from .audit import AuditLog
from .backends import anthropic_llm, openai_compatible_llm
from .hook import Firewall, guard
from .judge import LLMJudge, ollama_llm, openai_llm
from .policy import PolicyEngine
from .rules import DEFAULT_RULES, Rule
from .schema import Action, BlockedAction, Decision, Session, Verdict

__version__ = "0.1.7"
__all__ = [
    "guard", "Firewall", "PolicyEngine", "AuditLog",
    "LLMJudge", "openai_llm", "ollama_llm", "anthropic_llm",
    "openai_compatible_llm",
    "Rule", "DEFAULT_RULES",
    "Action", "Verdict", "Decision", "Session", "BlockedAction",
]
