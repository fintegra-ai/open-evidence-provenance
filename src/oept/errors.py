"""OEPT error model.

All public errors derive from OeptError. Verification outcomes are NOT
errors: a tampered bundle yields a result object with a failure status,
never an exception. Exceptions signal caller misuse, unreadable input, or
unsupported configuration.
"""

from __future__ import annotations


class OeptError(Exception):
    """Base class for all OEPT errors."""


class ValidationError(OeptError):
    """Caller-supplied data violates a schema or structural contract."""


class IntegrityError(OeptError):
    """A digest or structural integrity check failed during construction."""


class UnsupportedSpecError(OeptError):
    """A bundle or key declares a spec version this toolkit cannot process."""


class ConfigurationError(OeptError):
    """CLI usage error or invalid caller-supplied configuration."""
