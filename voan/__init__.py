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
from .authorize import goal_authorized
from .auto import AutoGuard, capability_agent, guard_langchain_auto
from .backends import anthropic_llm, openai_compatible_llm
from .capability import CapabilityEngine, Capsule, Denied
from .flow import FlowMonitor
from .hook import Firewall, guard
from .judge import LLMJudge, ollama_llm, openai_llm
from .plan import Plan, PlanStep
from .planner import derive_capability_program, derive_plan
from .policy import PolicyEngine
from .presets import FAMILIES, deny_by_default, deny_by_default_rules
from .quarantine import quarantined_llm
from .rule_of_two import RuleOfTwo
from .rules import DEFAULT_RULES, Rule
from .schema import Action, BlockedAction, Decision, Session, Verdict
from .taint import TaintTracker

__version__ = "0.1.11"
__all__ = [
    "guard", "Firewall", "PolicyEngine", "AuditLog",
    "LLMJudge", "openai_llm", "ollama_llm", "anthropic_llm",
    "openai_compatible_llm",
    "deny_by_default", "deny_by_default_rules", "FAMILIES",
    "Plan", "PlanStep", "derive_plan", "TaintTracker", "RuleOfTwo", "FlowMonitor",
    "CapabilityEngine", "Capsule", "Denied", "quarantined_llm",
    "derive_capability_program", "AutoGuard", "guard_langchain_auto", "goal_authorized",
    "capability_agent",
    "Rule", "DEFAULT_RULES",
    "Action", "Verdict", "Decision", "Session", "BlockedAction",
]
