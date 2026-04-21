import json
import re
from typing import Any

import anthropic

from src.core.config import config
from src.core.exceptions import PatchConfidenceException, PatcherException
from src.core.logger import logger
from src.core.models import PatchDiff, SandboxResult

_MODEL: str = "claude-sonnet-4-20250514"
_MAX_TOKENS: int = 4096
_MIN_CONFIDENCE: float = 0.7

_UNIFIED_DIFF_RE = re.compile(r"^---\s+\S+.*\n\+\+\+\s+\S+.*\n.*@@", re.MULTILINE)

_SYSTEM_PROMPT: str = """
You are an expert security engineer. You will be given a proven vulnerability finding —
including the vulnerable code location, the exploit plan that was confirmed, and
execution output — and you must produce a minimal, correct security patch.

Respond ONLY with a JSON object. No markdown fences, no prose, no preamble.

Schema:
{
  "diff": "<string: complete unified diff patch (--- / +++ / @@ headers required)>",
  "affected_files": ["<relative file path>", ...],
  "confidence": <float between 0.0 and 1.0>
}

Rules:
- diff must be valid unified diff format: start with '--- a/<file>', then '+++ b/<file>',
  then one or more hunks beginning with '@@ ... @@'.
- affected_files must list every file touched by the diff.
- confidence reflects your certainty that the patch fully remediates the vulnerability
  without breaking functionality. Be honest; never inflate this score.
- A confidence below 0.7 means the patch should not be applied automatically.
""".strip()


class PatcherAgent:
    """Generates a security patch for a proven vulnerability using an LLM."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        logger.debug("PatcherAgent: Anthropic client initialised (model=%s)", _MODEL)

    def run(self, result: SandboxResult) -> PatchDiff:
        logger.info(
            "PatcherAgent: generating patch for vuln_class=%r file=%r line=%d",
            result.hypothesis.vuln_class,
            result.hypothesis.file_path,
            result.hypothesis.line_number,
        )

        prompt = self._build_prompt(result)
        raw = self._call_llm(prompt)
        diff, affected_files, confidence = self._parse_diff(raw)
        self._validate_confidence(confidence)

        patch = PatchDiff(
            hypothesis=result.hypothesis,
            diff=diff,
            affected_files=affected_files,
            confidence=confidence,
        )

        logger.info(
            "PatcherAgent: patch accepted confidence=%.2f files=%s",
            confidence,
            affected_files,
        )
        return patch

    def _build_prompt(self, result: SandboxResult) -> str:
        h = result.hypothesis
        prompt = (
            "## Vulnerability Finding\n"
            f"- Class:    {h.vuln_class}\n"
            f"- File:     {h.file_path}\n"
            f"- Line:     {h.line_number}\n"
            f"- Severity: {h.severity_score:.1f} / 10\n"
            f"- CVSS:     {h.cvss_vector}\n\n"
            "## Exploit Plan (confirmed by sandbox)\n"
            f"{h.exploit_plan}\n\n"
            "## Sandbox Execution Output\n"
            f"exit_code : {result.exit_code}\n"
            "stdout:\n"
            f"{result.stdout or '(empty)'}\n"
            "stderr:\n"
            f"{result.stderr or '(empty)'}\n\n"
            "Produce a minimal security patch that remediates this vulnerability. "
            "Return the JSON object as specified."
        )

        logger.debug(
            "PatcherAgent: prompt built — %d char(s) for vuln_class=%r",
            len(prompt),
            h.vuln_class,
        )
        return prompt

    def _call_llm(self, prompt: str) -> str:
        logger.debug("PatcherAgent: calling %s (max_tokens=%d)", _MODEL, _MAX_TOKENS)
        try:
            message = self._client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            raise PatcherException(
                f"PatcherAgent: Anthropic API error: {exc}"
            ) from exc
        except Exception as exc:
            raise PatcherException(
                f"PatcherAgent: unexpected error calling LLM: {exc}"
            ) from exc

        text_blocks = [b.text for b in message.content if hasattr(b, "text")]
        if not text_blocks:
            raise PatcherException(
                "PatcherAgent: LLM returned no text content blocks"
            )

        raw = "\n".join(text_blocks).strip()

        if message.stop_reason == "max_tokens":
            logger.warning(
                "PatcherAgent: response truncated (stop_reason=max_tokens); "
                "JSON parse may fail"
            )

        logger.debug(
            "PatcherAgent: received %d char(s) stop_reason=%s",
            len(raw),
            message.stop_reason,
        )
        return raw

    def _parse_diff(self, response: str) -> tuple[str, list[str], float]:
        cleaned = re.sub(r"^```[a-z]*\n?|```$", "", response.strip(), flags=re.MULTILINE).strip()

        try:
            payload: Any = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise PatcherException(
                f"PatcherAgent: failed to decode LLM JSON: {exc}\n"
                f"Raw response (first 500 chars): {response[:500]!r}"
            ) from exc

        if not isinstance(payload, dict):
            raise PatcherException(
                f"PatcherAgent: expected a JSON object, got {type(payload).__name__}"
            )

        diff = payload.get("diff")
        if not isinstance(diff, str) or not diff.strip():
            raise PatcherException(
                "PatcherAgent: 'diff' field is missing or not a non-empty string"
            )

        affected_files = payload.get("affected_files")
        if not isinstance(affected_files, list) or not affected_files:
            raise PatcherException(
                "PatcherAgent: 'affected_files' must be a non-empty list of strings"
            )
        non_strings = [f for f in affected_files if not isinstance(f, str)]
        if non_strings:
            raise PatcherException(
                f"PatcherAgent: 'affected_files' contains non-string entries: {non_strings}"
            )

        confidence_raw = payload.get("confidence")
        if not isinstance(confidence_raw, (int, float)):
            raise PatcherException(
                f"PatcherAgent: 'confidence' must be a number, "
                f"got {type(confidence_raw).__name__}"
            )
        confidence = float(confidence_raw)
        if not (0.0 <= confidence <= 1.0):
            raise PatcherException(
                f"PatcherAgent: 'confidence' must be in [0.0, 1.0], got {confidence}"
            )

        if not _UNIFIED_DIFF_RE.search(diff):
            raise PatcherException(
                "PatcherAgent: 'diff' does not appear to be valid unified diff format "
                "(expected '--- ...', '+++ ...', '@@ ... @@' headers)"
            )

        logger.debug(
            "PatcherAgent: parsed diff — %d char(s), %d file(s), confidence=%.2f",
            len(diff),
            len(affected_files),
            confidence,
        )
        return diff, affected_files, confidence

    def _validate_confidence(self, score: float) -> None:
        if score < _MIN_CONFIDENCE:
            raise PatchConfidenceException(
                f"PatcherAgent: patch confidence {score:.2f} is below minimum "
                f"threshold {_MIN_CONFIDENCE:.2f} — manual review required"
            )
        logger.debug(
            "PatcherAgent: confidence %.2f >= threshold %.2f — accepted",
            score,
            _MIN_CONFIDENCE,
        )
