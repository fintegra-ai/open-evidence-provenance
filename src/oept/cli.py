"""OEPT command line interface.

Commands:
  oept bundle DIRECTORY --output BUNDLE   build a bundle from a directory
  oept verify BUNDLE [--json] [--trust-keys FILE]
  oept conformance [--dir DIR] [--json]   run the conformance corpus
  oept schema (list | show NAME)          print JSON Schemas

Exit codes: 0 verified/valid, 1 integrity failure, 2 usage/config error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .bundle import BundleBuilder
from .errors import ConfigurationError, OeptError, ValidationError
from .models import VerificationResult
from .signing import load_trust_keys, sign_manifest
from .verify import verify_bundle

FOOTER = "Technical verification only — not a legal, compliance, or factual conclusion."


def _render_human(bundle_label: str, result: VerificationResult) -> str:
    if result.status == "VALID_SIGNED":
        signature = (
            f"SIGNED (trusted key: {result.trusted_key_id})" if result.trusted_key_id else "SIGNED"
        )
    elif result.status == "VALID_UNSIGNED":
        signature = "NOT PRESENT"
    elif result.status == "SIGNATURE_KEY_UNKNOWN":
        signature = "PRESENT (no trusted key supplied or matched)"
    elif result.status in ("SIGNATURE_INVALID",):
        signature = "INVALID"
    else:
        signature = "NOT EVALUATED"
    lines = [
        f"Bundle: {bundle_label}",
        f"Specification: {result.bundle_spec_version or '-'}",
        f"Structure: {'VALID' if result.status not in ('MALFORMED_BUNDLE', 'UNSAFE_ARCHIVE', 'UNSUPPORTED_SPEC_VERSION') else 'INVALID'}",
        f"Member digests: {'VALID' if not result.mismatches and not result.missing else 'INVALID'}",
        f"Signature: {signature}",
        f"Result: {result.status}",
    ]
    for note in result.notes:
        lines.append(f"Note: {note}")
    if result.missing:
        lines.append(f"Missing files: {len(result.missing)}")
    if result.unexpected:
        lines.append(f"Unexpected files: {len(result.unexpected)}")
    if result.mismatches:
        lines.append(f"Hash mismatches: {len(result.mismatches)}")
    lines.append("")
    lines.append(FOOTER)
    return "\n".join(lines)


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        trusted = load_trust_keys(args.trust_keys) if args.trust_keys else []
    except ConfigurationError as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2
    target = Path(args.bundle)
    if not target.exists():
        print(f"oept: error: bundle not found: {target}", file=sys.stderr)
        return 2
    try:
        result = verify_bundle(target, trusted)
    except OeptError as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(_render_human(str(target), result))
    return 0 if result.ok else 1


def _iter_input_files(root: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink():
            raise ValidationError(f"input contains symlink (refusing to bundle): {path}")
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValidationError(f"unresolvable input path: {path}") from exc
        if name == "manifest.json" or name.startswith("signatures/"):
            raise ValidationError(f"reserved bundle member in input directory: {name!r}")
        members[name] = path.read_bytes()
    if "facts.json" not in members or "provenance.json" not in members:
        raise ValidationError("input directory must contain facts.json and provenance.json")
    return members


def cmd_bundle(args: argparse.Namespace) -> int:
    if args.sign and not args.key_id:
        print("oept: error: --sign requires --key-id", file=sys.stderr)
        return 2
    source = Path(args.directory)
    if not source.is_dir():
        print(f"oept: error: not a directory: {source}", file=sys.stderr)
        return 2
    try:
        members = _iter_input_files(source)
        builder = BundleBuilder(
            bundle_id=args.bundle_id or source.name,
            created_at=args.created_at or "",
            key_id=args.key_id,
        )
        for path in sorted(members):
            builder.add_file(path, members[path])
        signature = None
        if args.sign:
            try:
                private_key = Path(args.sign).read_bytes()
            except OSError as exc:
                print(f"oept: error: cannot read signing key: {exc}", file=sys.stderr)
                return 2
            try:
                signature = sign_manifest(builder.manifest_bytes(), private_key)
            except ConfigurationError as exc:
                print(f"oept: error: {exc}", file=sys.stderr)
                return 2
        output = builder.write_zip(args.output, signature)
    except (ValidationError, OeptError) as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {output} ({len(builder.manifest_dict()['files'])} members)")
    return 0


def cmd_conformance(args: argparse.Namespace) -> int:
    from .conformance import run_conformance

    root = Path(args.dir) if args.dir else None
    try:
        report = run_conformance(root)
    except OeptError as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for name, status, expected, ok in report["cases"]:
            mark = "ok" if ok else "MISMATCH"
            print(f"{mark:8} {name:28} got={status} want={expected}")
        print(f"{report['passed']}/{report['total']} conformance cases pass")
    return 0 if report["failed"] == 0 else 1


def cmd_schema(args: argparse.Namespace) -> int:
    from .schemas import list_schemas, load_schema

    if args.action == "list":
        for name in list_schemas():
            print(name)
        return 0
    try:
        schema = load_schema(args.action)
    except OeptError as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(schema, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oept", description="Open Evidence Provenance Toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify a bundle offline")
    p_verify.add_argument("bundle", help="bundle .zip file")
    p_verify.add_argument("--json", action="store_true", help="machine-readable output")
    p_verify.add_argument("--trust-keys", help="JSON trust-keys file for signatures")
    p_verify.set_defaults(func=cmd_verify)

    p_bundle = sub.add_parser("bundle", help="build a bundle from a directory")
    p_bundle.add_argument("directory", help="evidence directory to package")
    p_bundle.add_argument("--output", required=True, help="output .zip path")
    p_bundle.add_argument(
        "--bundle-id", default="", help="bundle identifier (default: directory name)"
    )
    p_bundle.add_argument("--created-at", default="", help="ISO-8601 timestamp (default: now, UTC)")
    p_bundle.add_argument("--sign", default="", help="Ed25519 private key PEM file for signing")
    p_bundle.add_argument(
        "--key-id", default="", help="key identifier label (required with --sign)"
    )
    p_bundle.set_defaults(func=cmd_bundle)

    p_conf = sub.add_parser("conformance", help="run the conformance corpus")
    p_conf.add_argument(
        "--dir", default="", help="conformance corpus directory (default: packaged corpus)"
    )
    p_conf.add_argument("--json", action="store_true", help="machine-readable output")
    p_conf.set_defaults(func=cmd_conformance)

    p_schema = sub.add_parser("schema", help="inspect JSON Schemas")
    p_schema.add_argument("action", help="'list' or a schema name")
    p_schema.set_defaults(func=cmd_schema)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 1
    except OeptError as exc:
        print(f"oept: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
