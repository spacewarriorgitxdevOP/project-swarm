"""
src/core/models.py

Pydantic v2 domain models for Project Swarm.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class SandboxStatus(str, Enum):
    PROVEN = "PROVEN"
    HALLUCINATION = "HALLUCINATION"


class AuditVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class RepoTarget(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    url: str = Field(...)
    branch: str = Field(default="main")
    scan_config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class CodeGraph(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    sink_locations: list[dict[str, Any]] = Field(default_factory=list)
    repo_target: RepoTarget = Field(...)
    created_at: datetime = Field(default_factory=_utcnow)


class VulnHypothesis(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    vuln_class: str = Field(...)
    file_path: str = Field(...)
    line_number: int = Field(..., ge=1)
    severity_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: str = Field(...)
    exploit_plan: str = Field(...)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate_cvss_prefix(self) -> "VulnHypothesis":
        if not self.cvss_vector.startswith("CVSS:"):
            raise ValueError(f"cvss_vector must begin with 'CVSS:' — got {self.cvss_vector!r}")
        return self


class SandboxResult(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    hypothesis_id: str = Field(...)
    status: SandboxStatus = Field(...)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    execution_time_ms: int = Field(..., ge=0)
    created_at: datetime = Field(default_factory=_utcnow)


class PatchDiff(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    hypothesis_id: str = Field(...)
    diff_content: str = Field(...)
    affected_files: list[str] = Field(..., min_length=1)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)


class AuditReport(BaseModel):
    model_config = {"frozen": True}
    id: str = Field(default_factory=_new_uuid)
    patch_diff_id: str = Field(...)
    verdict: AuditVerdict = Field(...)
    risk_notes: list[str] = Field(default_factory=list)
    regression_status: bool = Field(...)
    created_at: datetime = Field(default_factory=_utcnow)
