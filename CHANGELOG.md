# Changelog

All notable changes to Voan Firewall. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions are the `voan` PyPI package.

## [0.1.13] - 2026-07-12

### Changed — safe-by-default posture
- **`Firewall()` / `voan.guard()` now HOLD (ASK) unrecognized shell/db actions by
  default** (money / mail / http already ASK), so the out-of-box posture is a sound
  floor — no dangerous side effect runs unapproved. Provide an `on_ask` callback to
  auto-approve known-safe calls for autonomous runs, add front allow-rules, or pass
  `policy=PolicyEngine()` for the previous default-allow signature tier.

### Security — adversarial hardening
- Fixed **47+ bypasses / fail-opens** found by a multi-round adversarial review plus a
  hands-on re-attack across every tier (regex signatures, taint/provenance, judge
  grounding, information-flow, async guarding, adapters, MCP proxy). Each is pinned by a
  regression test ([`tests/test_review_fixes.py`](tests/test_review_fixes.py)).
- The **capability engine** now holds its integrity + confidentiality invariants **by
  construction** under a determined laundering attack — a Capsule can no longer be
  hidden in a nested container, a custom object (`__dict__` / `__slots__`), a lazy
  iterator, or another Capsule's value; an unresolved `$ref` fails closed.

### Fixed
- **`voan-mcp-proxy` now fails closed on ASK.** The transparent MCP proxy previously
  enforced only `BLOCK` verdicts and forwarded `ASK`-classified calls — payments
  (`PAYMENT_HUMAN`) and outbound sends (`EXTERNAL_SEND`) — upstream **unblocked**. A
  transparent proxy has no human to prompt, so an ASK is now held as a block: those
  side effects no longer pass through silently. Use the in-process `guard_mcp` sensor
  if you need the human-in-the-loop ASK path.

### Docs
- Positioning: README/BENCHMARK reframed as a **layered** firewall (like Meta
  LlamaFirewall / Lakera) whose differentiators are (1) a **provenance/capability**
  deterministic tier (vs. their regex/static-analysis) and (2) an **optional,
  off-by-default** model judge (vs. their primary model detectors). The judge is the
  same category as Meta's AlignmentCheck — one opt-in layer, not the foundation.
- Honesty pass on module docstrings: dropped "unevadable" on the string-level
  provenance gate (`auto.py`) and "tamper-evident" on the plain append-only audit log
  (`audit.py`); bounded "adaptive-attack-proof" to the committed tool multiset + pinned
  args (`hook.py`, `rule_of_two.py`); corrected `deny_by_default` default families
  (`presets.py`: `shell, db` — not `payment`).

## [0.1.12] - 2026-07-10

### Changed — auto-instrumentation precision + safety (`guard_langchain_auto`)
- **Fail loud, never silent.** A tool that can't be instrumented now raises `TypeError`
  instead of being passed through unprotected (the worst failure for a firewall — you
  think you're protected and you're not). Plain function tools are now supported (wrapped
  directly), not silently skipped. Always use the returned tool list.
- **Provenance-gated by default.** A recipient is now held only if it is un-named by the
  user **and** actually arrived via untrusted tool output (the real injection vector) —
  so hardcoded / user-context recipients are no longer falsely held. This is the
  evidence-based default (the "lethal trifecta" taint-then-gate posture; CaMeL/FIDES).
  Set `strict=True` to restore holding **every** un-named recipient regardless of
  provenance (for unattended / high-security deployments).
- **`trusted=[...]`**: declare data sources whose output is safe (e.g. your own trusted
  DB). A recipient pulled from a trusted source is not held — the sound way to authorize
  data-derived destinations is *declared* trust, not inference (an untrusted source can
  hide the attacker's address in the exact field a legitimate one uses).
- **Idempotent re-guarding.** Calling `guard_langchain_auto` again on the same tools
  (e.g. per request with a new `goal`) now replaces the guard instead of stacking
  wrappers that would enforce a stale goal.

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
