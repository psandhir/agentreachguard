# Contributing to HorusTrace

HorusTrace is security tooling, so correctness and explainability matter more than rule count.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check src tests
```

## Rule contribution criteria

A rule should include:

1. A clearly described security condition.
2. Evidence HorusTrace can deterministically observe.
3. A practical remediation.
4. At least one positive test fixture and, where applicable, a secure counterexample.
5. Conservative severity. Avoid making a finding critical unless the capability path justifies it.

## Adapter contribution criteria

Framework adapters should parse source/configuration without importing or executing the target application.

Open an issue before large architectural changes so the graph model can remain framework-neutral.

## Pull requests

Keep pull requests focused. Explain which analysis layer changes, what evidence is observed, and how false positives are constrained. New security rules should document both the vulnerable condition and a secure counterexample.

By contributing, you agree that your contribution is provided under the repository's Apache-2.0 license.
