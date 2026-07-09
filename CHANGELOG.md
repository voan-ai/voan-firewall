# Changelog

All notable changes to Voan Firewall. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `voan` PyPI package.

## [Unreleased]

## [0.1.11] - 2026-07-10

### Added — the 2026 deterministic + provable spectrum
- **Mechanical auto-instrumentation** (`guard_langchain_auto`, `AutoGuard`): zero-config
  guard that classifies tools itself and holds a side effect whose recipient the user
  didn't name — deterministic, no model in the gate. Optional `verify=llm` only ever
  *downgrades* a hold to allow (reduces human asks), never gates by itself.
- **Capability engine** (`CapabilityEngine`, `Capsule`) + interpreter (`.run`) and
  one-call loop (`capability_agent`): the CaMeL/FIDES provable core — per-value
  integrity + confidentiality invariants, enforced by construction.
- **Quarantined extractor** (`quarantined_llm`) and **privileged planner**
  (`derive_capability_program`) — the two halves of the CaMeL dual-LLM model.
- **Rule of Two** (`RuleOfTwo`), **taint** (`TaintTracker`), **information flow**
  (`FlowMonitor`), **plan-then-execute** (`Plan`, `set_plan`), **deny-by-default
  presets** (`deny_by_default`), and **goal-authorized verification**
  (`goal_authorized`).
- **MCP**: `guard_mcp` (client session) and `voan-mcp-proxy` (transparent proxy, stdio
  and HTTP upstream, plus `--serve-http`).
- **Full TypeScript/JS parity** in `sdk-js/` for the whole spectrum, incl. the
  capability engine and interpreter. Strict `tsc` type-check in CI.
- Real-trace evals (`eval/injecagent_eval.py`, `eval/agentdojo_eval.py`), an
  adaptive-attack harness (`benchmark/adaptive_attack.py`), and a performance
  benchmark (`benchmark/perf.py`).

### Hardened (production-readiness)
- `voan.guard()` now forwards **every** `Firewall(...)` option (`egress_allowlist`,
  `taint`, `flow`, `rule_of_two`, `judge_fail_closed`, `plan_judge_fallback`); an
  unknown option raises `TypeError` instead of being silently dropped and protecting
  nothing.
- Audit write is fail-safe: a read-only / full-disk filesystem no longer turns a
  guarded call into an `OSError` (warn-once, keep enforcing); the JSONL trail rotates
  past 50 MB; dashboard streaming (`emit`) now defaults **off** (no per-call thread)
  and is opt-in.
- Plan-then-execute keeps its hard off-plan **BLOCK** even when a judge is configured
  — the judge backstop for an incomplete plan is now opt-in via `plan_judge_fallback=True`.
- Provenance classifier (`taint` / `flow`) now fails **closed**: a sink verb in a tool
  name (`list_payout`, `budget_transfer`) is treated as a side effect, not a read.

### Quality
- Ruff lint (library + tests strictly clean), 75% test coverage gate, CI matrix
  Python 3.9–3.13, strict TypeScript type-check.

## [0.1.10] and earlier
- Initial firewall: rules/egress/judge tiers, LangChain/OpenAI adapters, dashboard,
  36-case eval. See git history.
