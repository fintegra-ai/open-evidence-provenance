"""OEPT data model: small, typed, finance-free containers.

Every model is a frozen dataclass with to_dict/from_dict round-tripping over
plain JSON-compatible values. Datetimes are UTC ISO-8601 strings with a
trailing ``Z`` (seconds precision). Decimal quantities are strings.
Digests are lowercase hex SHA-256.

Nothing here is domain-specific: the vocabulary stays at the level of
sources, observations, claims, and traces, and works for arbitrary data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    """Current UTC instant as ISO-8601 ``YYYY-MM-DDTHH:MM:SSZ``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str, digest: str, length: int = 16) -> str:
    """Deterministic readable id: ``<prefix>_<hex[:length]>``."""
    return f"{prefix}_{digest[:length]}"


@dataclass(frozen=True)
class EvidenceObject:
    """Logical identity of one source object (the thing, not its bytes)."""

    id: str
    logical_reference: str
    media_type: str = "application/octet-stream"
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "logical_reference": self.logical_reference,
            "media_type": self.media_type,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceObject:
        return cls(
            id=str(data["id"]),
            logical_reference=str(data["logical_reference"]),
            media_type=str(data.get("media_type", "application/octet-stream")),
            created_at=str(data.get("created_at", "")),
        )


@dataclass(frozen=True)
class EvidenceVersion:
    """One immutable observation of an EvidenceObject's bytes."""

    id: str
    object_id: str
    version_number: int
    sha256: str
    size_bytes: int
    observed_at: str
    effective_at: str | None = None
    transform: dict[str, Any] | None = None
    predecessor_version_id: str | None = None
    filename: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "object_id": self.object_id,
            "version_number": self.version_number,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "observed_at": self.observed_at,
            "effective_at": self.effective_at,
            "transform": self.transform,
            "predecessor_version_id": self.predecessor_version_id,
            "filename": self.filename,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceVersion:
        return cls(
            id=str(data["id"]),
            object_id=str(data["object_id"]),
            version_number=int(data["version_number"]),
            sha256=str(data["sha256"]),
            size_bytes=int(data["size_bytes"]),
            observed_at=str(data["observed_at"]),
            effective_at=data.get("effective_at"),
            transform=data.get("transform"),
            predecessor_version_id=data.get("predecessor_version_id"),
            filename=str(data.get("filename", "")),
        )


@dataclass(frozen=True)
class ProvenancePointer:
    """Exact locator binding one fact revision to one evidence version."""

    id: str
    fact_revision_id: str
    evidence_version_id: str
    locator_type: str
    locator: str
    method: str
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fact_revision_id": self.fact_revision_id,
            "evidence_version_id": self.evidence_version_id,
            "locator_type": self.locator_type,
            "locator": self.locator,
            "method": self.method,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenancePointer:
        return cls(
            id=str(data["id"]),
            fact_revision_id=str(data["fact_revision_id"]),
            evidence_version_id=str(data["evidence_version_id"]),
            locator_type=str(data["locator_type"]),
            locator=str(data["locator"]),
            method=str(data["method"]),
            note=data.get("note"),
        )


@dataclass(frozen=True)
class Fact:
    """A named, subject-scoped claim slot. Values live in revisions."""

    id: str
    fact_type: str
    subject: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "fact_type": self.fact_type, "subject": self.subject}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Fact:
        return cls(
            id=str(data["id"]), fact_type=str(data["fact_type"]), subject=str(data["subject"])
        )


@dataclass(frozen=True)
class FactRevision:
    """One append-only value observation for a Fact."""

    id: str
    fact_id: str
    value: Any
    value_type: str
    observed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fact_id": self.fact_id,
            "value": self.value,
            "value_type": self.value_type,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FactRevision:
        return cls(
            id=str(data["id"]),
            fact_id=str(data["fact_id"]),
            value=data["value"],
            value_type=str(data["value_type"]),
            observed_at=str(data["observed_at"]),
        )


@dataclass(frozen=True)
class RuleTrace:
    """The RECORD of one deterministic evaluation (format only).

    OEPT standardizes how a decision is recorded so third parties can
    re-check the referenced inputs. It ships no business rule logic.
    """

    id: str
    rule_id: str
    rule_version: str
    engine: str
    input_revision_ids: list[str] = field(default_factory=list)
    result: str = "UNVERIFIABLE"
    trace: dict[str, Any] = field(default_factory=dict)
    missing_inputs: list[str] = field(default_factory=list)
    executed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "engine": self.engine,
            "input_revision_ids": list(self.input_revision_ids),
            "result": self.result,
            "trace": dict(self.trace),
            "missing_inputs": list(self.missing_inputs),
            "executed_at": self.executed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleTrace:
        return cls(
            id=str(data["id"]),
            rule_id=str(data["rule_id"]),
            rule_version=str(data["rule_version"]),
            engine=str(data["engine"]),
            input_revision_ids=[str(v) for v in data.get("input_revision_ids", [])],
            result=str(data.get("result", "UNVERIFIABLE")),
            trace=dict(data.get("trace", {})),
            missing_inputs=[str(v) for v in data.get("missing_inputs", [])],
            executed_at=str(data.get("executed_at", "")),
        )


@dataclass(frozen=True)
class VerificationResult:
    """Terminal technical verdict for one bundle verification."""

    status: str
    bundle_spec_version: str | None = None
    bundle_id: str | None = None
    signing_state: str | None = None
    mismatches: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    signature_checked: bool = False
    trusted_key_id: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True for VALID_SIGNED and VALID_UNSIGNED only."""
        return self.status in ("VALID_SIGNED", "VALID_UNSIGNED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verifier": "oept-verify/0.1.0",
            "status": self.status,
            "bundle_spec_version": self.bundle_spec_version,
            "bundle_id": self.bundle_id,
            "signing_state": self.signing_state,
            "mismatches": [dict(m) for m in self.mismatches],
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "signature_checked": self.signature_checked,
            "trusted_key_id": self.trusted_key_id,
            "notes": list(self.notes),
            "scope_note": (
                "Technical byte-and-reference integrity only; not a legal, "
                "compliance, factual, or fraud conclusion."
            ),
        }
