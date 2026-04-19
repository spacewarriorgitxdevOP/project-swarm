"""
src/core/exceptions.py

Domain-specific exception hierarchy for Project Swarm.
All exceptions carry a human-readable message and an optional
context dict for structured logging / telemetry.
"""

from __future__ import annotations

from typing import Any


class SwarmBaseException(Exception):
    """Root exception for every Project Swarm error."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.context: dict[str, Any] = context or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, context={self.context!r})"


class MapperException(SwarmBaseException):
    """Raised by the Mapper agent when repository ingestion or AST parsing fails."""


class HunterException(SwarmBaseException):
    """Raised by the Hunter agent when vulnerability hypothesis generation fails."""


class SandboxerException(SwarmBaseException):
    """Raised by the Sandboxer agent when exploit execution encounters an error."""


class PatcherException(SwarmBaseException):
    """Raised by the Patcher agent when diff generation or application fails."""


class AuditorException(SwarmBaseException):
    """Raised by the Auditor agent when patch verification fails unexpectedly."""


class BuildFailedException(SwarmBaseException):
    """Raised when a patched project fails to compile or pass its test suite."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message, context)
        self.exit_code: int | None = exit_code


class ExploitExecutionException(SwarmBaseException):
    """Raised when a sandboxed exploit crashes in an unexpected way."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(message, context)
        self.stderr: str | None = stderr


class HallucinationException(SwarmBaseException):
    """Raised when an LLM response is detected as factually invalid for this codebase."""


class GraphWriteException(SwarmBaseException):
    """Raised when a Neo4j write transaction fails."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        query: str | None = None,
    ) -> None:
        super().__init__(message, context)
        self.query: str | None = query


class PatchConfidenceException(SwarmBaseException):
    """Raised when a generated patch confidence score falls below the required threshold."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        confidence_score: float | None = None,
        threshold: float | None = None,
    ) -> None:
        super().__init__(message, context)
        self.confidence_score: float | None = confidence_score
        self.threshold: float | None = threshold
