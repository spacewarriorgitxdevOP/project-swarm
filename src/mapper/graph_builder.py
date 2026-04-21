from src.core.exceptions import MapperException
from src.core.logger import logger
from src.core.models import CodeGraph, RepoTarget

_REQUIRED_NODE_FIELDS: frozenset[str] = frozenset(
    {"id", "type", "name", "file", "start_line", "end_line"}
)
_REQUIRED_EDGE_FIELDS: frozenset[str] = frozenset(
    {"id", "src", "dst", "relationship", "file", "line"}
)


class GraphBuilder:
    """Assembles a validated, deduplicated :class:`CodeGraph` from raw mapper data."""

    def run(
        self,
        nodes: list[dict],
        edges: list[dict],
        sinks: list[dict],
        target: RepoTarget,
    ) -> CodeGraph:
        for label, value in (("nodes", nodes), ("edges", edges), ("sinks", sinks)):
            if not isinstance(value, list):
                raise MapperException(
                    f"GraphBuilder.run: '{label}' must be a list, got {type(value).__name__}"
                )

        logger.debug(
            "GraphBuilder: received %d node(s), %d edge(s), %d sink(s) for target '%s'",
            len(nodes),
            len(edges),
            len(sinks),
            target,
        )

        try:
            self._validate_nodes(nodes)
            self._validate_edges(edges)

            clean_nodes = self._deduplicate(nodes)
            clean_edges = self._deduplicate(edges)
            clean_sinks = self._deduplicate(sinks)

            dropped_nodes = len(nodes) - len(clean_nodes)
            dropped_edges = len(edges) - len(clean_edges)
            dropped_sinks = len(sinks) - len(clean_sinks)

            if dropped_nodes or dropped_edges or dropped_sinks:
                logger.warning(
                    "GraphBuilder: deduplication removed %d node(s), %d edge(s), %d sink(s)",
                    dropped_nodes,
                    dropped_edges,
                    dropped_sinks,
                )

            graph = CodeGraph(
                target=target,
                nodes=clean_nodes,
                edges=clean_edges,
                sinks=clean_sinks,
            )

        except MapperException:
            raise
        except Exception as exc:
            raise MapperException(
                f"GraphBuilder failed while building CodeGraph: {exc}"
            ) from exc

        logger.info(
            "GraphBuilder: graph built — %d node(s), %d edge(s), %d sink(s)",
            len(clean_nodes),
            len(clean_edges),
            len(clean_sinks),
        )
        return graph

    def _validate_nodes(self, nodes: list[dict]) -> None:
        self._validate_items(nodes, _REQUIRED_NODE_FIELDS, "node")

    def _validate_edges(self, edges: list[dict]) -> None:
        self._validate_items(edges, _REQUIRED_EDGE_FIELDS, "edge")

    @staticmethod
    def _validate_items(
        items: list[dict],
        required: frozenset[str],
        label: str,
    ) -> None:
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise MapperException(
                    f"GraphBuilder: {label}[{index}] is not a dict — got {type(item).__name__}"
                )
            missing = required - item.keys()
            if missing:
                raise MapperException(
                    f"GraphBuilder: {label}[{index}] (id={item.get('id')!r}) "
                    f"is missing required field(s): {sorted(missing)}"
                )

    def _deduplicate(self, items: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique: list[dict] = []

        for item in items:
            item_id: str | None = item.get("id")

            if item_id is None:
                unique.append(item)
                continue

            if item_id in seen:
                logger.debug("GraphBuilder: dropping duplicate id=%r", item_id)
                continue

            seen.add(item_id)
            unique.append(item)

        return unique
