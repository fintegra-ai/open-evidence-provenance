"""CLI, conformance corpus, schemas, and independence tests."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "oept"


def _run_cli(*argv: str, cwd: Path | None = None):
    return subprocess.run(
        [sys.executable, "-m", "oept.cli", *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd or ROOT),
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )


def test_cli_verify_human(tmp_path):
    bundle = ROOT / "examples" / "valid-unsigned.zip"
    proc = _run_cli("verify", str(bundle))
    assert proc.returncode == 0, proc.stderr
    assert "Result: VALID_UNSIGNED" in proc.stdout
    assert "Technical verification only" in proc.stdout


def test_cli_verify_json(tmp_path):
    bundle = ROOT / "examples" / "valid-unsigned.zip"
    proc = _run_cli("verify", str(bundle), "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "VALID_UNSIGNED"


def test_cli_verify_failure_exit_code_1(tmp_path):
    bundle = ROOT / "conformance" / "fixtures" / "03-tampered-artifact" / "bundle.zip"
    proc = _run_cli("verify", str(bundle))
    assert proc.returncode == 1
    assert "Result: HASH_MISMATCH" in proc.stdout
    assert "Technical verification only" in proc.stdout


def test_cli_verify_json_failure(tmp_path):
    bundle = ROOT / "conformance" / "fixtures" / "04-missing-member" / "bundle.zip"
    proc = _run_cli("verify", str(bundle), "--json")
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["status"] == "MISSING_FILE"


def test_cli_usage_error_exit_code_2():
    proc = _run_cli("verify", "/nonexistent/bundle.zip")
    assert proc.returncode == 2


def test_cli_bundle_roundtrip(tmp_path):
    source = ROOT / "examples" / "evidence-project"
    output = tmp_path / "roundtrip.zip"
    proc = _run_cli("bundle", str(source), "--output", str(output))
    assert proc.returncode == 0, proc.stderr
    check = _run_cli("verify", str(output))
    assert check.returncode == 0
    assert "Result: VALID_UNSIGNED" in check.stdout


def test_cli_conformance(tmp_path):
    proc = _run_cli("conformance")
    assert proc.returncode == 0, proc.stderr
    assert "10/10 conformance cases pass" in proc.stdout


def test_cli_schema_list():
    proc = _run_cli("schema", "list")
    assert proc.returncode == 0
    for name in ("bundle-manifest", "fact", "verification-result"):
        assert name in proc.stdout


def test_conformance_runner_api():
    from oept.conformance import run_conformance

    report = run_conformance()
    assert report["total"] == 10
    assert report["failed"] == 0
    assert report["passed"] == 10


def test_schemas_validate_and_reject():
    from oept.schemas import list_schemas, validate_against_schema

    assert len(list_schemas()) == 7
    good = {
        "bundle_spec_version": "oept-bundle/0.1",
        "bundle_id": "b",
        "created_at": "2026-01-01T00:00:00Z",
        "files": [],
    }
    assert validate_against_schema("bundle-manifest", good) == []
    bad = {"bundle_spec_version": "oept-bundle/0.1"}
    assert validate_against_schema("bundle-manifest", bad) != []
    fact_good = {
        "id": "f",
        "fact_type": "t",
        "subject": "s",
        "revisions": [
            {
                "id": "r",
                "fact_id": "f",
                "value": "1.5",
                "value_type": "decimal",
                "observed_at": "2026-01-01T00:00:00Z",
            }
        ],
    }
    assert validate_against_schema("fact", fact_good) == []
    fact_bad = dict(fact_good, revisions=[])
    assert validate_against_schema("fact", fact_bad) != []


def test_public_api_surface():
    import oept

    assert set(oept.__all__) == {
        "BundleBuilder",
        "ConfigurationError",
        "IntegrityError",
        "OeptError",
        "UnsupportedSpecError",
        "ValidationError",
        "VerificationResult",
        "build_bundle",
        "verify_bundle",
        "verify_bundle_bytes",
    }


# --- independence guard: no finance runtime, no heavy deps ---

FORBIDDEN_IMPORTS = {
    "evidenceos_core",
    "services.evidenceos_core",
    "services.evidenceos",
    "fastapi",
    "pydantic",
    "psycopg",
    "psycopg_pool",
    "sqlalchemy",
    "redis",
    "boto3",
    "lxml",
    "openai",
}

FORBIDDEN_VOCABULARY = {
    "receivable",
    "debtor",
    "factoring",
    "underwriting",
}


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(part.name.split(".")[0] for part in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if (node.level or 0) > 0:
                continue  # relative: intra-package import
            found.add(node.module.split(".")[0])
    return found


def test_runtime_has_no_forbidden_imports():
    offenders: list[str] = []
    for path in sorted(SRC.glob("*.py")):
        if path.name == "__init__.py":
            continue
        imports = _module_imports(path)
        bad = sorted(imports & FORBIDDEN_IMPORTS)
        if bad:
            offenders.append(f"{path.name}: {bad}")
    assert not offenders, f"forbidden runtime imports: {offenders}"


def test_runtime_has_no_finance_vocabulary():
    offenders: list[str] = []
    for path in sorted(SRC.glob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        hits = sorted(w for w in FORBIDDEN_VOCABULARY if w in text)
        if hits:
            offenders.append(f"{path.name}: {hits}")
    assert not offenders, f"finance vocabulary in runtime: {offenders}"


def test_only_minimal_third_party_imports():
    allowed = {"cryptography", "jcs", "jsonschema"}
    found: set[str] = set()
    stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
    for path in sorted(SRC.glob("*.py")):
        for module in _module_imports(path):
            if module in ("oept",) or module.startswith("_"):
                continue
            if module in stdlib:
                continue
            found.add(module)
    assert found <= allowed, f"unexpected third-party imports: {found - allowed}"
