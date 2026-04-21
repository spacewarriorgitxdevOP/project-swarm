import json
from typing import Any

import anthropic

from src.core.config import config
from src.core.exceptions import HunterException
from src.core.logger import logger
from src.core.models import CodeGraph, VulnHypothesis

_MODEL: str = "claude-sonnet-4-20250514"
_MAX_TOKENS: int = 4096
_TOP_N: int = 20

_SYSTEM_PROMPT: str = """
You are an expert application-security researcher performing automated vulnerability hunting
on a parsed code graph from a Python repository.

You will receive:
- sink_locations: dangerous function call sites detected in the codebase
- nodes: the top code graph nodes (functions, classes, modules) by relevance
- edges: the top call-graph edges by relevance

Your task is to reason about potential vulnerability chains and return a JSON array of
hypotheses. Each element must conform to this exact schema — no additional keys, no missing keys:

[
  {
    "vuln_class":    "<string: e.g. SQL Injection, Command Injection, RCE …>",
    "file_path":     "<string: relative file path>",
    "line_number":   <integer>,
    "severity_score": <float 0.0–10.0>,
    "cvss_vector":   "<string: CVSS v3.1 vector, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H>",
    "exploit_plan":  "<string: step-by-step attacker narrative>"
  }
]

Rules:
- Return ONLY the raw JSON array. No markdown fences, no prose, no preamble.
- If no plausible vulnerability exists, return an empty array: []
- severity_score must be a number, not a string.
- line_number must be an integer, not a string.
""".strip()


class HunterAgent:
    """Drives an LLM-powered vulnerability hypothesis pass over a :class:`CodeGraph`."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        logger.debug("HunterAgent: Anthropic client initialised (model=%s)", _MODEL)

    def run(self, graph: CodeGraph) -> list[VulnHypothesis]:
        logger.info(
            "HunterAgent: starting analysis — %d node(s), %d edge(s), %d sink(s)",
            len(graph.nodes),
            len(graph.edges),
            len(graph.sinks),
        )

        prompt = self._build_prompt(graph)
        raw_response = self._call_llm(prompt)
        hypotheses = self._parse_response(raw_response)

        logger.info(
            "HunterAgent: analysis complete — %d hypothesis(es) generated",
            len(hypotheses),
        )
        return hypotheses

    def _build_prompt(self, graph: CodeGraph) -> str:
        sink_block = json.dumps(graph.sinks, indent=2)
        node_block = json.dumps(graph.nodes[:_TOP_N], indent=2)
        edge_block = json.dumps(graph.edges[:_TOP_N], indent=2)

        prompt = (
            "## Sink Locations\n"
            f"{sink_block}\n\n"
            f"## Top {_TOP_N} Nodes\n"
            f"{node_block}\n\n"
            f"## Top {_TOP_N} Edges\n"
            f"{edge_block}\n\n"
            "Analyse the above data and return your vulnerability hypotheses as a JSON array."
        )

        logger.debug(
            "HunterAgent: prompt built — %d char(s), %d sink(s), %d node(s), %d edge(s)",
            len(prompt),
            len(graph.sinks),
            min(len(graph.nodes), _TOP_N),
            min(len(graph.edges), _TOP_N),
        )
        return prompt

    def _call_llm(self, prompt: str) -> str:
        logger.debug("HunterAgent: calling %s (max_tokens=%d)", _MODEL, _MAX_TOKENS)
        try:
            message = self._client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:
            raise HunterException(
                f"HunterAgent: Anthropic API error: {exc}"
            ) from exc
        except Exception as exc:
            raise HunterException(
                f"HunterAgent: unexpected error calling LLM: {exc}"
            ) from exc

        text_blocks = [b.text for b in message.content if hasattr(b, "text")]
        if not text_blocks:
            raise HunterException(
                "HunterAgent: LLM returned no text content blocks"
            )

        raw = "\n".join(text_blocks).strip()
        logger.debug(
            "HunterAgent: received response — %d char(s), stop_reason=%s",
            len(raw),
            message.stop_reason,
        )

        if message.stop_reason == "max_tokens":
            logger.warning(
                "HunterAgent: response was truncated (stop_reason=max_tokens); "
                "JSON parse may fail"
            )

        return raw

    def _parse_response(self, response: str) -> list[VulnHypothesis]:
        try:
            parsed: Any = json.loads(response)
        except json.JSONDecodeError as exc:
            raise HunterException(
                f"HunterAgent: failed to decode LLM JSON response: {exc}\n"
                f"Raw response (first 500 chars): {response[:500]!r}"
            ) from exc

        if not isinstance(parsed, list):
            raise HunterException(
                f"HunterAgent: expected a JSON array, got {type(parsed).__name__}"
            )

        hypotheses: list[VulnHypothesis] = []
        errors: list[str] = []

        for index, item in enumerate(parsed):
            if not isinstance(item, dict):
                errors.append(f"  [{index}] not a dict — got {type(item).__name__}")
                continue
            try:
                hypotheses.append(VulnHypothesis(**item))
            except (TypeError, ValueError) as exc:
                errors.append(f"  [{index}] schema error: {exc}")

        if errors:
            error_summary = "\n".join(errors)
            raise HunterException(
                f"HunterAgent: {len(errors)} hypothesis(es) failed validation:\n"
                f"{error_summary}"
            )

        logger.debug(
            "HunterAgent: parsed %d valid hypothesis(es) from LLM response",
            len(hypotheses),
        )
        return hypotheses
