from neo4j import GraphDatabase, Driver, Session
from neo4j.exceptions import Neo4jError

from src.core.config import config
from src.core.exceptions import GraphWriteException
from src.core.logger import logger
from src.core.models import CodeGraph

_BATCH_SIZE: int = 100

_CYPHER_NODES = """
UNWIND $batch AS n
MERGE (node:CodeNode {id: n.id})
SET node.type       = n.type,
    node.name       = n.name,
    node.file       = n.file,
    node.start_line = n.start_line,
    node.end_line   = n.end_line
"""

_CYPHER_EDGES = """
UNWIND $batch AS e
MERGE (src:CodeNode {id: e.src})
MERGE (dst:CodeNode {id: e.dst})
MERGE (src)-[r:CALLS {id: e.id}]->(dst)
SET r.relationship = e.relationship,
    r.file         = e.file,
    r.line         = e.line
"""

_CYPHER_SINKS = """
UNWIND $batch AS s
MERGE (sink:Sink {edge_id: s.edge_id})
SET sink.sink_type = s.sink_type,
    sink.category  = s.category,
    sink.file      = s.file,
    sink.line      = s.line
WITH sink, s
MATCH (dst:CodeNode {id: s.edge_id})
MERGE (dst)-[:HAS_SINK]->(sink)
"""


class Neo4jWriter:
    """Persists a :class:`CodeGraph` to Neo4j using batched MERGE operations."""

    def __init__(self) -> None:
        logger.debug(
            "Neo4jWriter: connecting to %s as '%s'",
            config.NEO4J_URI,
            config.NEO4J_USERNAME,
        )
        try:
            self._driver: Driver = GraphDatabase.driver(
                config.NEO4J_URI,
                auth=(config.NEO4J_USERNAME, config.NEO4J_PASSWORD),
            )
            self._driver.verify_connectivity()
        except Neo4jError as exc:
            raise GraphWriteException(
                f"Neo4jWriter: failed to connect to {config.NEO4J_URI}: {exc}"
            ) from exc

        logger.info("Neo4jWriter: connected to %s", config.NEO4J_URI)

    def run(self, graph: CodeGraph) -> None:
        logger.info(
            "Neo4jWriter: writing graph — %d node(s), %d edge(s), %d sink(s)",
            len(graph.nodes),
            len(graph.edges),
            len(graph.sinks),
        )
        try:
            with self._driver.session() as session:
                self._write_nodes(session, graph.nodes)
                self._write_edges(session, graph.edges)
                self._write_sinks(session, graph.sinks)
        except GraphWriteException:
            raise
        except Exception as exc:
            raise GraphWriteException(
                f"Neo4jWriter.run: unexpected failure: {exc}"
            ) from exc

        logger.info("Neo4jWriter: graph write complete")

    def close(self) -> None:
        try:
            self._driver.close()
            logger.info("Neo4jWriter: driver closed")
        except Exception as exc:
            logger.warning("Neo4jWriter: error while closing driver: %s", exc)

    def _write_nodes(self, session: Session, nodes: list[dict]) -> None:
        self._execute_batches(session, nodes, _CYPHER_NODES, label="nodes")

    def _write_edges(self, session: Session, edges: list[dict]) -> None:
        self._execute_batches(session, edges, _CYPHER_EDGES, label="edges")

    def _write_sinks(self, session: Session, sinks: list[dict]) -> None:
        self._execute_batches(session, sinks, _CYPHER_SINKS, label="sinks")

    @staticmethod
    def _execute_batches(
        session: Session,
        items: list[dict],
        cypher: str,
        *,
        label: str,
    ) -> None:
        if not items:
            logger.debug("Neo4jWriter: no %s to write — skipping", label)
            return

        total = len(items)
        batches = range(0, total, _BATCH_SIZE)

        logger.debug(
            "Neo4jWriter: writing %d %s in %d batch(es)",
            total,
            label,
            len(batches),
        )

        for batch_start in batches:
            batch = items[batch_start : batch_start + _BATCH_SIZE]
            try:
                session.execute_write(
                    lambda tx, b=batch: tx.run(cypher, batch=b)
                )
            except Neo4jError as exc:
                raise GraphWriteException(
                    f"Neo4jWriter: failed writing {label} "
                    f"(batch starting at index {batch_start}): {exc}"
                ) from exc

            logger.debug(
                "Neo4jWriter: wrote %s batch %d–%d",
                label,
                batch_start,
                batch_start + len(batch) - 1,
            )

    def __enter__(self) -> "Neo4jWriter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
