"""Conformance corpus runner.

Each fixture directory under the corpus root contains a ``bundle.zip``
(or ``bundle/`` directory) plus ``expected-result.json`` with at least a
``status`` field. The runner verifies every fixture and compares the
terminal status. Trust keys for signed fixtures live in the fixture
directory (``trust-keys.json``) and are TEST ONLY material.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .errors import OeptError
from .signing import TrustedKey, load_trust_keys
from .verify import verify_bundle, verify_bundle_dir


def default_corpus_dir() -> Path:
    """Packaged conformance corpus (repo layout)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent.parent / "conformance" / "fixtures",
        Path(__file__).resolve().parents[2] / "conformance" / "fixtures",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise OeptError("OEPT conformance corpus not found")


def run_conformance(corpus_dir: Optional[Path] = None) -> dict[str, Any]:
    """Run every fixture. Returns {total, passed, failed, cases}."""
    root = Path(corpus_dir) if corpus_dir else default_corpus_dir()
    if not root.is_dir():
        raise OeptError(f"conformance corpus is not a directory: {root}")
    cases: list[tuple[str, str, str, bool]] = []
    passed = 0
    for fixture in sorted(p for p in root.iterdir() if p.is_dir()):
        expected_path = fixture / "expected-result.json"
        if not expected_path.exists():
            raise OeptError(f"fixture {fixture.name} lacks expected-result.json")
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        want = expected.get("status")
        trust_file = fixture / "trust-keys.json"
        keys: list[TrustedKey] = []
        if trust_file.exists():
            keys = load_trust_keys(trust_file)
        bundle_zip = fixture / "bundle.zip"
        bundle_dir = fixture / "bundle"
        if bundle_zip.exists():
            got = verify_bundle(bundle_zip, keys).status
        elif bundle_dir.is_dir():
            got = verify_bundle_dir(bundle_dir, keys).status
        else:
            raise OeptError(f"fixture {fixture.name} has no bundle.zip/bundle/")
        ok = got == want
        passed += 1 if ok else 0
        cases.append((fixture.name, got, str(want), ok))
    total = len(cases)
    return {"total": total, "passed": passed, "failed": total - passed,
            "cases": cases}
