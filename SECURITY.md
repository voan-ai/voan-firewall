# Security Policy

Voan Firewall is a security tool, so we take reports seriously and want them to
reach a monitored channel.

## Reporting a vulnerability

Please report privately — do not open a public issue for an exploitable bug.

- Preferred: open a [GitHub private security advisory](https://github.com/voan-ai/voan-firewall/security/advisories/new).
- Alternatively, open a regular [GitHub issue](https://github.com/voan-ai/voan-firewall/issues)
  describing the impact at a high level and asking for a private channel.

We aim to acknowledge within a few days. This is an early-stage, open-source
project maintained by a small team — please set expectations accordingly.

## Scope & known limitations (by design)

Voan is defense-in-depth, not a guarantee. A few properties are intentional and
are **not** vulnerabilities:

- **Default-allow.** The regex policy engine is a signature blocklist that
  defaults to ALLOW for unrecognized actions. Flip to deny-by-default, or rely on
  the LLM judge, for stronger posture.
- **Judge fails open.** With no LLM backend configured, the judge is a no-op and
  the rule verdict stands (it emits a warning). It only ever *escalates* to BLOCK.
- **Judge data egress.** When the LLM judge runs with an external backend (e.g.
  OpenAI), the action arguments and recent untrusted tool context are sent to that
  backend. Secrets and card-like numbers are redacted first, but for sensitive
  deployments use a local backend (`LLMJudge(llm=ollama_llm())`).
- **Prompt-injection of the judge.** Untrusted tool output is shown to the judge
  as data with instructions to ignore it; this is best-effort, not a guarantee.

Reports that improve any of the above — especially redaction bypasses or judge
injection — are very welcome.
