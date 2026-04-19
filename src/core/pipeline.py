"""
src/core/pipeline.py

Master state machine for Project Swarm.
Orchestrates five agents: Mapper → Hunter → Sandboxer → Patcher → Auditor.
"""

from __future__ import annotations

import time
from typing import Final

from src.auditor.agent import AuditorAgent
from src.hunter.agent import HunterAgent
from src.mapper.parser import MapperAgent
from src.patcher.agent import PatcherAgent
from src.sandboxer.agent import SandboxerAgent
from src.core.config import config
from src.core.exceptions import (
    AuditorException,
    HallucinationException,
    HunterException,
    MapperException,
    PatcherException,
    SandboxerException,
)
from src.core.logger import logger
from src.core.models import (
    AuditReport,
    AuditVerdict,
    CodeGraph,
    PatchDiff,
    RepoTarget,
    SandboxResult,
    SandboxStatus,
    VulnHypothesis,
)

_STAGE_MAPPER: Final[str] = "MAPPER"
_STAGE_HUNTER: Final[str] = "HUNTER"
_STAGE_SANDBOXER: Final[str] = "SANDBOXER"
_STAGE_PATCHER: Final[str] = "PATCHER"
_STAGE_AUDITOR: Final[str] = "AUDITOR"


class Pipeline:
    """Master state machine that wires all five Project Swarm agents together."""

    def __init__(self) -> None:
        """Instantiate all five agents."""
        self._mapper = MapperAgent()
        self._hunter = HunterAgent()
        self._sandboxer = SandboxerAgent()
        self._patcher = PatcherAgent()
        self._auditor = AuditorAgent()
        logger.info("Pipeline initialised.", extra={
            "cvss_minimum_score": config.CVSS_MINIMUM_SCORE,
            "max_hypotheses_per_scan": config.MAX_HYPOTHESES_PER_SCAN,
            "sandbox_timeout_seconds": config.SANDBOX_TIMEOUT_SECONDS,
        })

    def run(self, target: RepoTarget) -> AuditReport:
        """Execute the full Swarm pipeline and return an AuditReport."""
        pipeline_start = time.monotonic()
        logger.info("Pipeline run started.", extra={
            "repo_url": target.url, "branch": target.branch, "target_id": target.id
        })

        graph: CodeGraph = self._run_mapper(target)
        hypotheses: list[VulnHypothesis] = self._run_hunter(graph)
        proven_results: list[SandboxResult] = self._run_sandboxer(hypotheses)
        diff: PatchDiff = self._run_patcher(proven_results[0])
        report: AuditReport = self._run_auditor(diff)

        elapsed_ms = int((time.monotonic() - pipeline_start) * 1_000)
        logger.info("Pipeline run completed.", extra={
            "target_id": target.id,
            "audit_verdict": report.verdict,
            "report_id": report.id,
            "elapsed_ms": elapsed_ms,
        })
        return report

    def _run_mapper(self, target: RepoTarget) -> CodeGraph:
        """Run the Mapper agent and return a CodeGraph."""
        logger.info("Stage started.", extra={"stage": _STAGE_MAPPER, "target_id": target.id})
        start = time.monotonic()
        try:
            graph: CodeGraph = self._mapper.run(target)
        except MapperException:
            logger.exception("Stage failed.", extra={"stage": _STAGE_MAPPER, "target_id": target.id})
            raise
        except Exception as exc:
            raise MapperException(
                f"Unexpected error in Mapper stage: {exc}",
                context={"target_id": target.id, "original_error": str(exc)},
            ) from exc
        logger.info("Stage completed.", extra={
            "stage": _STAGE_MAPPER, "target_id": target.id,
            "node_count": len(graph.nodes), "edge_count": len(graph.edges),
            "sink_count": len(graph.sink_locations),
            "elapsed_ms": int((time.monotonic() - start) * 1_000),
        })
        return graph

    def _run_hunter(self, graph: CodeGraph) -> list[VulnHypothesis]:
        """Run the Hunter agent, filter by CVSS, cap at max hypotheses."""
        logger.info("Stage started.", extra={"stage": _STAGE_HUNTER, "graph_id": graph.id})
        start = time.monotonic()
        try:
            raw_hypotheses: list[VulnHypothesis] = self._hunter.run(graph)
        except HunterException:
            logger.exception("Stage failed.", extra={"stage": _STAGE_HUNTER, "graph_id": graph.id})
            raise
        except Exception as exc:
            raise HunterException(
                f"Unexpected error in Hunter stage: {exc}",
                context={"graph_id": graph.id, "original_error": str(exc)},
            ) from exc

        filtered = [h for h in raw_hypotheses if h.severity_score >= config.CVSS_MINIMUM_SCORE]
        if not filtered:
            raise HunterException(
                f"No hypotheses met CVSS minimum {config.CVSS_MINIMUM_SCORE}.",
                context={"graph_id": graph.id, "raw_count": len(raw_hypotheses)},
            )
        filtered.sort(key=lambda h: h.severity_score, reverse=True)
        capped = filtered[: config.MAX_HYPOTHESES_PER_SCAN]
        logger.info("Stage completed.", extra={
            "stage": _STAGE_HUNTER, "graph_id": graph.id,
            "raw_count": len(raw_hypotheses), "capped_count": len(capped),
            "top_cvss": capped[0].severity_score,
            "elapsed_ms": int((time.monotonic() - start) * 1_000),
        })
        return capped

    def _run_sandboxer(self, hypotheses: list[VulnHypothesis]) -> list[SandboxResult]:
        """Run Sandboxer on each hypothesis, return only PROVEN results."""
        logger.info("Stage started.", extra={"stage": _STAGE_SANDBOXER, "hypothesis_count": len(hypotheses)})
        start = time.monotonic()
        all_results: list[SandboxResult] = []
        proven: list[SandboxResult] = []

        for hypothesis in hypotheses:
            try:
                result: SandboxResult = self._sandboxer.run(hypothesis)
            except (SandboxerException, Exception) as exc:
                logger.warning("Sandboxer skipping hypothesis.", extra={
                    "stage": _STAGE_SANDBOXER, "hypothesis_id": hypothesis.id, "error": str(exc)
                })
                continue
            all_results.append(result)
            if result.status == SandboxStatus.PROVEN:
                proven.append(result)
                logger.info("Hypothesis PROVEN.", extra={
                    "stage": _STAGE_SANDBOXER, "hypothesis_id": hypothesis.id
                })

        if not proven:
            raise HallucinationException(
                "All hypotheses were unproven. No exploitable vulnerabilities reproduced.",
                context={"hypothesis_count": len(hypotheses), "sandbox_run_count": len(all_results)},
            )
        logger.info("Stage completed.", extra={
            "stage": _STAGE_SANDBOXER, "proven_count": len(proven),
            "elapsed_ms": int((time.monotonic() - start) * 1_000),
        })
        return proven

    def _run_patcher(self, result: SandboxResult) -> PatchDiff:
        """Run the Patcher agent on the first PROVEN sandbox result."""
        logger.info("Stage started.", extra={"stage": _STAGE_PATCHER, "hypothesis_id": result.hypothesis_id})
        start = time.monotonic()
        try:
            diff: PatchDiff = self._patcher.run(result)
        except PatcherException:
            logger.exception("Stage failed.", extra={"stage": _STAGE_PATCHER})
            raise
        except Exception as exc:
            raise PatcherException(
                f"Unexpected error in Patcher stage: {exc}",
                context={"hypothesis_id": result.hypothesis_id, "original_error": str(exc)},
            ) from exc
        logger.info("Stage completed.", extra={
            "stage": _STAGE_PATCHER, "patch_diff_id": diff.id,
            "confidence_score": diff.confidence_score,
            "elapsed_ms": int((time.monotonic() - start) * 1_000),
        })
        return diff

    def _run_auditor(self, diff: PatchDiff) -> AuditReport:
        """Run the Auditor agent and raise if verdict is FAIL."""
        logger.info("Stage started.", extra={"stage": _STAGE_AUDITOR, "patch_diff_id": diff.id})
        start = time.monotonic()
        try:
            report: AuditReport = self._auditor.run(diff)
        except AuditorException:
            logger.exception("Stage failed.", extra={"stage": _STAGE_AUDITOR})
            raise
        except Exception as exc:
            raise AuditorException(
                f"Unexpected error in Auditor stage: {exc}",
                context={"patch_diff_id": diff.id, "original_error": str(exc)},
            ) from exc
        logger.info("Stage completed.", extra={
            "stage": _STAGE_AUDITOR, "verdict": report.verdict,
            "elapsed_ms": int((time.monotonic() - start) * 1_000),
        })
        if report.verdict == AuditVerdict.FAIL:
            raise AuditorException(
                "Auditor returned FAIL verdict — patch must not be merged.",
                context={"report_id": report.id, "risk_notes": report.risk_notes},
            )
        return report
