from __future__ import annotations

from src.core.exceptions import MapperException
from src.core.logger import logger

_SINK_CATEGORIES: dict[str, list[str]] = {
    "command_injection": [
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen",
    ],
    "code_execution": ["exec", "eval"],
    "sql_injection": ["cursor.execute", "cursor.executemany"],
    "file_access": ["open"],
    "deserialization": ["pickle.loads", "yaml.load"],
}

_SINK_LOOKUP: dict[str, str] = {
    sink: category
    for category, sinks in _SINK_CATEGORIES.items()
    for sink in sinks
}


class SinkDetector:
    """Identifies dangerous sink calls in a parsed edge graph."""

    def run(self, edges: list[dict]) -> list[dict]:
        """Scan edges and return one result dict per sink-bound edge."""
        if not isinstance(edges, list):
            raise MapperException(
                f"SinkDetector.run expects a list, got {type(edges).__name__}"
            )
        logger.debug("SinkDetector: scanning %d edges for sinks", len(edges))
        findings: list[dict] = []
        try:
            for edge in edges:
                dst: str = edge.get("dst", "")
                if not self._is_sink(dst):
                    continue
                finding = {
                    "file": edge.get("file"),
                    "line": edge.get("line"),
                    "sink_type": dst,
                    "category": self._categorize(dst),
                    "edge_id": edge.get("id"),
                }
                logger.info(
                    "Sink detected: %s (%s) at %s:%s",
                    dst, finding["category"], finding["file"], finding["line"],
                )
                findings.append(finding)
        except MapperException:
            raise
        except Exception as exc:
            raise MapperException(f"SinkDetector failed during edge scan: {exc}") from exc
        logger.debug("SinkDetector: found %d sink(s)", len(findings))
        return findings

    def _is_sink(self, dst: str) -> bool:
        """Return True if dst matches any known sink."""
        return dst in _SINK_LOOKUP

    def _categorize(self, dst: str) -> str:
        """Return the category for dst."""
        try:
            return _SINK_LOOKUP[dst]
        except KeyError:
            raise MapperException(
                f"_categorize called with unrecognised sink: {dst!r}"
            ) from None
