"""Error hierarchy for DocuTraceX.

All application errors derive from :class:`DocuTraceXError` so callers can catch
the whole family. Keep messages safe: never embed raw, unescaped content from an
analysed file in an error that may reach the UI.
"""

from __future__ import annotations


class DocuTraceXError(Exception):
    """Base class for all application errors."""


class ConfigError(DocuTraceXError):
    """Invalid or inconsistent configuration."""


class CaseError(DocuTraceXError):
    """Problem with a case: creation, lookup, manifest, or reopening."""


class StorageError(DocuTraceXError):
    """Problem reading or writing case results on disk."""


# gmzpt
class ToolError(DocuTraceXError):
    """A managed tool failed, is missing, or returned an unusable result."""


class AnalysisError(DocuTraceXError):
    """A parser/analyzer failed. Partial results should still be preserved."""
