"""Ed25519 application signatures for bundle manifests.

Trust rule (non-negotiable): a public key embedded inside a bundle is NEVER
automatically trusted. Embedded key metadata may carry a ``key_id`` label,
but verification trust comes exclusively from caller-supplied trusted keys
(``--trust-keys``). Embedded keys are identifiers, never trust roots.

These signatures are application-level authenticity marks. They are NOT
qualified electronic signatures, NOT eIDAS instruments, NOT timestamps,
and NOT certificate chains.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TrustedKey:
    """One caller-supplied trust root."""

    key_id: str
    public_key_pem: bytes


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair. Returns (private_pem, public_pem).

    Test and development use only. Production keys must come from the
    operator's own key management.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_manifest(canonical_manifest: bytes, private_key_pem: bytes) -> bytes:
    """Sign canonical manifest bytes with an Ed25519 private key (PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        from .errors import ConfigurationError

        raise ConfigurationError(
            f"cannot load Ed25519 private key: {exc}"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        from .errors import ConfigurationError

        raise ConfigurationError("signing key must be an Ed25519 private key")
    return key.sign(canonical_manifest)


def verify_manifest_signature(
    canonical_manifest: bytes,
    signature: bytes,
    trusted_keys: list[TrustedKey],
) -> Optional[str]:
    """Return the matching trusted key_id, or None when no key matches.

    Every supplied key is tried; invalid signatures are skipped, never
    raised. An empty trust list never verifies.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature

    for trusted in trusted_keys:
        try:
            public = serialization.load_pem_public_key(trusted.public_key_pem)
        except Exception:
            continue
        if not isinstance(public, Ed25519PublicKey):
            continue
        try:
            public.verify(signature, canonical_manifest)
        except InvalidSignature:
            continue
        return trusted.key_id
    return None


def load_trust_keys(path: object) -> list[TrustedKey]:
    """Load a trust-keys file: JSON list of {key_id, public_key_pem}."""
    import json
    from pathlib import Path

    from .errors import ConfigurationError

    try:
        raw = json.loads(Path(str(path)).read_bytes().decode("utf-8"))
    except Exception as exc:
        raise ConfigurationError(
            f"cannot read trust-keys file: {exc}"
        ) from exc
    if not isinstance(raw, list) or not raw:
        raise ConfigurationError(
            "trust-keys file must be a non-empty JSON list"
        )
    keys: list[TrustedKey] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigurationError(
                "trust-keys entries must be objects")
        key_id = entry.get("key_id")
        pem = entry.get("public_key_pem")
        if not isinstance(key_id, str) or not key_id:
            raise ConfigurationError(
                "trust-keys entry needs a non-empty key_id")
        if not isinstance(pem, str) or "PUBLIC KEY" not in pem:
            raise ConfigurationError(
                f"trust-keys entry {key_id!r} needs a PEM public key")
        keys.append(TrustedKey(key_id=key_id,
                               public_key_pem=pem.encode("utf-8")))
    if len(keys) > 64:
        raise ConfigurationError("trust-keys file holds at most 64 keys")
    return keys
