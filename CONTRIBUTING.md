# Contributing to OEPT

No corporate CLA is required for v0.1 contributions. By submitting a pull
request you agree your contribution is provided under the Apache-2.0
license of this project.

## Development setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Python 3.10+ is required. The test suite, linters, and type checker run
under `pytest`, `ruff`, and `mypy` (strict mode).

## Tests

```bash
pytest
pytest conformance  # via: oept conformance
ruff check src tests conformance/make_fixtures.py
ruff format --check src tests conformance/make_fixtures.py
mypy src/oept
```

All four must pass. New bundle/verifier behavior requires new
conformance fixtures with expected results.

## Code style

- `ruff` defaults in `pyproject.toml` (line length 100).
- `mypy --strict` for `src/oept`. No new `type: ignore` without a comment
  explaining why the checker cannot see the invariant.
- Public API lives in `oept/__init__.py` and stays tiny; do not export
  internals without discussion.

## Schema changes

Schemas are versioned (`schemas/*.schema.json` with `$id` per version).
Changing a published schema requires a new schema version and a migration
note in `CHANGELOG.md`. The `$id` namespace is provisional
(`example.invalid`) until a project domain is selected.

## Bundle-spec change process

1. Propose the change with rationale and affected statuses.
2. Bump the spec version per `spec/bundle-spec.md` §11 (minor for
   optional additions only; major otherwise).
3. Add conformance fixtures covering the change.
4. Update `spec/bundle-spec.md`, schemas, and the verifier together.

## Security-sensitive changes

Canonicalization, digest model, signature coverage, path validation, and
resource limits are security-sensitive: they additionally require threat
model review (`spec/threat-model.md`) and hostile-input tests. When in
doubt, fail closed and ask for review.
