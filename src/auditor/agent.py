import json
import re
from typing import Any

import anthropic

from src.core.config import config
from src.core.exceptions import AuditorException
from src.core.logger import logger
from src.core.models import AuditReport, AuditVerdict, PatchDiff

_MODEL: str = "claude-sonnet-4-20250514"
_MAX_TOKENS: int = 2048

_SYSTEM_PROMPT: str = """
You are a senior application-security engineer performing a final safety audit
on a candidate security patch before it is applied to a production codebase.

You will receive:
- Metadata about the original vulnerability (class, file, line, severity, CVSS).
- The unified diff of the proposed patch.
- The list of affected files.
- The patch confidence score assigned by the patch generator.

Your job is to audit the diff for:
1. New vulnerabilities introduced by the patch itself.
2. Logic regressions (behaviour changes that could break functionality).
3. Unsafe patterns (hard-coded secrets, debug code, overly broad permissions, etc.).

Respond ONLY with a JSON object. No markdown fences, no prose, no preamble.

Schema:
{
  "verdict": "<PASS | FAIL>",
  "risk_notes": ["<string: concise risk observation>", ...],
  "regression_risk": <true | false>
}

Rules:
- verdict is "PASS" only if the diff introduces no new vulnerabilities, no logic
  regressions, and no unsafe patterns. Any concern, however minor, must yield "FAIL".
- risk_notes must be a list of strings (may be empty if verdict is "PASS").
- regression_risk is true if you believe the patch may alter observable behaviour
  beyond the security fix, false otherwise.
- Be conservative: when in doubt, FAIL.
""".strip()


class AuditorAgent:
    """Performs an independent LLM-driven security audit on a :class:`PatchDiff`."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        logger.debug("AuditorAgent: Anthropic client initialised (model=%s)", _MODEL)

    def run(self, diff: PatchDiff) -> AuditReport:
        logger.info(
            "AuditorAgent: auditing patch for vuln_class=%r file=%r confidence=%.2f",
            diff.hypothesis.vuln_class,
            diff.hypothesis.file_path,
            diff.confidence,
        )

        prompt = self._build_prompt(diff)
        raw = self._call_llm(prompt)
        verdict, risk_notes, regression_risk = self._parse_verdict(raw)

        report = AuditReport(
            diff=diff,
            verdict=verdict,
            risk_notes=risk_notes,
            regression_risk=regression_risk,
        )

        logger.info(
            "AuditorAgent: verdict=%s regression_risk=%s notes=%d for vuln_class=%r",
            verdict,
            regression_risk,
            len(risk_notes),
            diff.hypothesis.vuln_class,
        )
        return report

    def _build_prompt(self, diff: PatchDiff) -> str:
        h = diff.hypothesis
        prompt = (
            "## Original Vulnerability\n"
            f"- Class:      {h.vuln_class}\n"
            f"- File:       {h.file_path}\n"
            f"- Line:       {h.line_number}\n"
            f"- Severity:   {h.severity_score:.1f} / 10\n"
            f"- CVSS:       {h.cvss_vector}\n\n"
            "## Affected Files\n"
            + "\n".join(f"- {f}" for f in diff.affected_files)
            + f"\n\n## Patch Confidence\n{diff.confidence:.2f} / 1.00\n\n"
            "## Unified Diff\n"
            "```diff\n"
            f"{diff.diff}\n"
            "```\n\n"
            "Audit the patch above and return your JSON verdict."
        )

        logger.debug(
            "AuditorAgent: prompt built — %d char(s) for vuln_class=%r",
            len(prompt),
            h.vuln_class,
        )
        return prompt

    def _call_llm(self, prompt: str) -> str:
        logger.debug("AuditorAgent: calling %s (max_tokens=%d)", _MODEL, _MAX_TOKENS)
        try:
            message = self._client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            raise AuditorException(
                f"AuditorAgent: Anthropic API error: {exc}"
            ) from exc
        except Exception as exc:
            raise AuditorException(
                f"AuditorAgent: unexpected error calling LLM: {exc}"
            ) from exc

        text_blocks = [b.text for b in message.content if hasattr(b, "text")]
        if not text_blocks:
            raise AuditorException("AuditorAgent: LLM returned no text content blocks")

        raw = "\n".join(text_blocks).strip()

        if message.stop_reason == "max_tokens":
            logger.warning(
                "AuditorAgent: response truncated (stop_reason=max_tokens); "
                "JSON parse may fail"
            )

        logger.debug(
            "AuditorAgent: received %d char(s) stop_reason=%s",
            len(raw),
            message.stop_reason,
        )
        return raw

    def _parse_verdict(self, response: str) -> tuple[AuditVerdict, list[str], bool]:
        cleaned = re.sub(
            r"^```[a-z]*\n?|```$", "", response.strip(), flags=re.MULTILINE
        ).strip()

        try:
            payload: Any = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise AuditorException(
                f"AuditorAgent: failed to decode LLM JSON: {exc}\n"
                f"Raw response (first 500 chars): {response[:500]!r}"
            ) from exc

        if not isinstance(payload, dict):
            raise AuditorException(
                f"AuditorAgent: expected a JSON object, got {type(payload).__name__}"
            )

        raw_verdict = payload.get("verdict")
        if raw_verdict not in {"PASS", "FAIL"}:
            raise AuditorException(
                f"AuditorAgent: 'verdict' must be 'PASS' or 'FAIL', "
                f"got {raw_verdict!r}"
            )
        verdict = AuditVerdict.PASS if raw_verdict == "PASS" else AuditVerdict.FAIL

        risk_notes = payload.get("risk_notes")
        if not isinstance(risk_notes, list):
            raise AuditorException(
                f"AuditorAgent: 'risk_notes' must be a list, "
                f"got {type(risk_notes).__name__}"
            )
        non_strings = [n for n in risk_notes if not isinstance(n, str)]
        if non_strings:
            raise AuditorException(
                f"AuditorAgent: 'risk_notes' contains non-string entries: {non_strings}"
            )

        regression_risk = payload.get("regression_risk")
        if not isinstance(regression_risk, bool):
            raise AuditorException(
                f"AuditorAgent: 'regression_risk' must be a boolean, "
                f"got {type(regression_risk).__name__}"
            )

        if verdict is AuditVerdict.PASS and risk_notes:
            logger.warning(
                "AuditorAgent: model returned PASS with %d risk note(s) — "
                "overriding to FAIL",
                len(risk_notes),
            )
            verdict = AuditVerdict.FAIL

        logger.debug(
            "AuditorAgent: parsed verdict=%s regression_risk=%s notes=%d",
            verdict,
            regression_risk,
            len(risk_notes),
        )
        return verdict, risk_notes, regression_risk
