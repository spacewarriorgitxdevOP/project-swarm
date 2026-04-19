"""
src/core/config.py

Centralised, validated configuration for Project Swarm.
All values are sourced from environment variables via a .env file.
Raises EnvironmentError at import time if required vars are missing.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=False)


def _require(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise EnvironmentError(
            f"[Project Swarm] Required environment variable '{key}' is missing or empty. "
            f"Check your .env file at {_ENV_PATH}."
        )
    return value


def _optional(key: str, default: str) -> str:
    value = os.environ.get(key, "").strip()
    return value if value else default


def _parse_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise EnvironmentError(
            f"[Project Swarm] Environment variable '{key}' must be an integer — got {raw!r}."
        ) from exc


def _parse_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise EnvironmentError(
            f"[Project Swarm] Environment variable '{key}' must be a float — got {raw!r}."
        ) from exc


def _parse_log_level(raw: str) -> int:
    level = getattr(logging, raw.upper(), None)
    if not isinstance(level, int):
        raise EnvironmentError(
            f"[Project Swarm] LOG_LEVEL '{raw}' is not valid. "
            "Expected one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        )
    return level


class _SwarmConfig:
    """Immutable configuration object populated from environment variables."""

    __slots__ = (
        "ANTHROPIC_API_KEY",
        "NEO4J_URI",
        "NEO4J_USERNAME",
        "NEO4J_PASSWORD",
        "GITHUB_TOKEN",
        "SANDBOX_TIMEOUT_SECONDS",
        "MAX_HYPOTHESES_PER_SCAN",
        "LOG_LEVEL",
        "LOG_LEVEL_NAME",
        "CVSS_MINIMUM_SCORE",
    )

    def __init__(self) -> None:
        self.ANTHROPIC_API_KEY: str = _require("ANTHROPIC_API_KEY")
        self.NEO4J_URI: str = _require("NEO4J_URI")
        self.NEO4J_USERNAME: str = _require("NEO4J_USERNAME")
        self.NEO4J_PASSWORD: str = _require("NEO4J_PASSWORD")
        self.GITHUB_TOKEN: str = _require("GITHUB_TOKEN")
        self.SANDBOX_TIMEOUT_SECONDS: int = _parse_int("SANDBOX_TIMEOUT_SECONDS", default=60)
        self.MAX_HYPOTHESES_PER_SCAN: int = _parse_int("MAX_HYPOTHESES_PER_SCAN", default=10)
        self.CVSS_MINIMUM_SCORE: float = _parse_float("CVSS_MINIMUM_SCORE", default=7.0)
        _log_level_name: str = _optional("LOG_LEVEL", "INFO")
        self.LOG_LEVEL: int = _parse_log_level(_log_level_name)
        self.LOG_LEVEL_NAME: str = _log_level_name.upper()

    def __repr__(self) -> str:
        return (
            f"_SwarmConfig("
            f"NEO4J_URI={self.NEO4J_URI!r}, "
            f"LOG_LEVEL={self.LOG_LEVEL_NAME!r}, "
            f"SANDBOX_TIMEOUT_SECONDS={self.SANDBOX_TIMEOUT_SECONDS}, "
            f"MAX_HYPOTHESES_PER_SCAN={self.MAX_HYPOTHESES_PER_SCAN}, "
            f"CVSS_MINIMUM_SCORE={self.CVSS_MINIMUM_SCORE}"
            f")"
        )


config: _SwarmConfig = _SwarmConfig()
