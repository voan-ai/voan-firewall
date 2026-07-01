# Contributing to Voan

Thanks for looking at Voan. It's a small, dependency-light codebase and easy to run.

## Principles (please keep these)

1. **Enforcement is mechanical.** A block must be a deterministic, auditable rule —
   never an LLM's probabilistic decision. An LLM may *reduce how often a human is
   asked* (downgrade a hold to allow), but it must not be the thing that gates.
2. **Be honest in the docs.** State what a tier does *not* catch and its false-positive
   behaviour. See `BENCHMARK.md` for the tone — we report where it over-holds and why.
3. **Small files.** Library modules stay well under 200 lines, zero required runtime deps.

## Dev setup

```bash
pip install -e ".[dev,mcp]"     # Python: tests, coverage, ruff, mcp
pytest --cov=voan               # run tests + coverage (gate: 75%)
ruff check .                    # lint (library + tests must be clean)

cd sdk-js && npm install -D typescript @types/node
npx tsc --noEmit                # strict type-check of the JS library
node auto_verify.ts             # run any *_verify.ts parity suite
```

## Pull requests

- Add or update tests for any behaviour change (Python `tests/`, JS `*_verify.ts`).
- Keep Python ↔ TypeScript at parity when you touch a shared tier.
- Run `ruff check .`, `pytest`, and `npx tsc --noEmit` before opening the PR.
- CI runs the lint/type gates, the full Python matrix (3.9–3.13), the mcp leg, and the
  JS suites.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please don't open a public issue for a vulnerability.
