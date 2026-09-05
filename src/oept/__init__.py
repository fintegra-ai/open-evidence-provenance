"""OEPT public API.

Intentionally tiny. Everything else is internal and may change.
"""
from __future__ import annotations

from .bundle import BundleBuilder, build_bundle
from .errors import (
    ConfigurationError,
    IntegrityError,
    OeptError,
    UnsupportedSpecError,
    ValidationError,
)
from .models import VerificationResult
from .verify import verify_bundle, verify_bundle_bytes

__all__ = [
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
]

__version__ = "0.1.0"
