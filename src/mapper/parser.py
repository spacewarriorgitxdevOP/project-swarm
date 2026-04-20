from __future__ import annotations

import subprocess
import tempfile
import shutil
from pathlib import Path
from uuid import uuid4

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from src.core.models import RepoTarget, CodeGraph
from src.core.exceptions import MapperException
from src.core.logger import logger
from src.core.config import config

PY_LANGUAGE = Language(tspython.language())

_DANGEROUS_SINKS: frozenset[str] = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "os.system", "os.popen", "exec", "eval",
    "cursor.execute", "cursor.executemany",
    "open", "pickle.loads", "yaml.load",
})


class MapperAgent:
    """Clones a repository, parses Python source into a CodeGraph, detects dangerous sinks."""

    def __init__(self) -> None:
        self._parser = Parser(PY_LANGUAGE)

    def run(self, target: RepoTarget) -> CodeGraph:
        """Clone → parse → detect sinks → return CodeGraph."""
        logger.info("MapperAgent starting run", extra={"url": target.url, "branch": target.branch})
        try:
            repo_path = self._clone_repo(target.url, target.branch)
        except MapperException:
            raise
        except Exception as exc:
            raise MapperException(f"Unexpected error during clone: {exc}") from exc

        try:
            nodes, edges = self._parse_files(repo_path)
            sinks = self._detect_sinks(nodes, edges)
            graph = CodeGraph(
                nodes=nodes,
                edges=edges,
                sink_locations=sinks,
                repo_target=target,
            )
            logger.info("MapperAgent finished", extra={
                "nodes": len(nodes), "edges": len(edges), "sinks": len(sinks)
            })
            return graph
        except MapperException:
            raise
        except Exception as exc:
            raise MapperException(f"Unexpected error during parse/analysis: {exc}") from exc
        finally:
            self._cleanup(repo_path)

    def _clone_repo(self, url: str, branch: str) -> Path:
        """Clone url@branch into a temp directory, return its path."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="swarm_clone_"))
        logger.debug("Cloning repo", extra={"url": url, "branch": branch, "dest": str(tmp_dir)})
        try:
            self._run_subprocess(
                ["git", "clone", "--depth", "1", "--branch", branch, url, str(tmp_dir)],
                error_context=f"git clone of {url}@{branch}",
            )
        except MapperException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        logger.info("Repo cloned successfully", extra={"path": str(tmp_dir)})
        return tmp_dir

    def _parse_files(self, repo_path: Path) -> tuple[list[dict], list[dict]]:
        """Walk repo_path for .py files, return aggregated (nodes, edges)."""
        all_nodes: list[dict] = []
        all_edges: list[dict] = []
        py_files = sorted(repo_path.rglob("*.py"))
        logger.debug("Discovered Python files", extra={"count": len(py_files)})
        for file_path in py_files:
            try:
                file_nodes, file_edges = self._parse_file(file_path, repo_path)
            except MapperException:
                raise
            except Exception as exc:
                raise MapperException(f"Unhandled error parsing {file_path}: {exc}") from exc
            all_nodes.extend(file_nodes)
            all_edges.extend(file_edges)
        logger.debug("Parsed all files", extra={"nodes": len(all_nodes), "edges": len(all_edges)})
        return all_nodes, all_edges

    def _parse_file(self, file_path: Path, repo_root: Path) -> tuple[list[dict], list[dict]]:
        """Parse a single .py file with Tree-sitter, return (nodes, edges)."""
        try:
            source_bytes = file_path.read_bytes()
        except OSError as exc:
            raise MapperException(f"Cannot read {file_path}: {exc}") from exc
        try:
            tree = self._parser.parse(source_bytes)
        except Exception as exc:
            raise MapperException(f"Tree-sitter failed on {file_path}: {exc}") from exc

        rel_path = str(file_path.relative_to(repo_root))
        nodes: list[dict] = []
        edges: list[dict] = []
        func_ranges: list[tuple[int, int, str]] = []

        for fn_node in self._iter_nodes(tree.root_node, "function_definition"):
            name = self._child_text(fn_node, "identifier", source_bytes)
            node_id = str(uuid4())
            nodes.append({
                "id": node_id, "type": "function", "name": name,
                "file": rel_path,
                "start_line": fn_node.start_point[0] + 1,
                "end_line": fn_node.end_point[0] + 1,
            })
            func_ranges.append((fn_node.start_byte, fn_node.end_byte, node_id))

        for call_node in self._iter_nodes(tree.root_node, "call"):
            callee = self._call_name(call_node, source_bytes)
            if not callee:
                continue
            line = call_node.start_point[0] + 1
            src_id = self._enclosing_function_id(call_node.start_byte, func_ranges)
            edges.append({
                "id": str(uuid4()), "src": src_id, "dst": callee,
                "relationship": "calls", "file": rel_path, "line": line,
            })
        return nodes, edges

    def _detect_sinks(self, nodes: list[dict], edges: list[dict]) -> list[dict]:
        """Return sink_location dicts for edges matching dangerous sinks."""
        sinks: list[dict] = []
        for edge in edges:
            dst: str | None = edge.get("dst")
            if dst and dst in _DANGEROUS_SINKS:
                sinks.append({
                    "file": edge["file"], "line": edge["line"],
                    "sink_type": dst, "edge_id": edge["id"],
                })
        logger.debug("Sink detection complete", extra={"total_sinks": len(sinks)})
        return sinks

    @staticmethod
    def _iter_nodes(root: Node, node_type: str):
        """Yield all descendant nodes with the given type."""
        visited: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            if node.type == node_type:
                yield node
            stack.extend(reversed(node.children))

    @staticmethod
    def _child_text(node: Node, child_type: str, source: bytes) -> str:
        """Return UTF-8 text of the first direct child with child_type."""
        for child in node.children:
            if child.type == child_type:
                return source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        return "<unknown>"

    @staticmethod
    def _call_name(call_node: Node, source: bytes) -> str | None:
        """Resolve callee name from a call node."""
        if not call_node.children:
            return None
        func_node = call_node.children[0]
        if func_node.type in ("identifier", "attribute"):
            return source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
        return None

    @staticmethod
    def _enclosing_function_id(byte_offset: int, func_ranges: list[tuple[int, int, str]]) -> str | None:
        """Return id of the innermost function containing byte_offset."""
        best: tuple[int, str] | None = None
        for start, end, node_id in func_ranges:
            if start <= byte_offset < end:
                span = end - start
                if best is None or span < best[0]:
                    best = (span, node_id)
        return best[1] if best else None

    @staticmethod
    def _run_subprocess(cmd: list[str], error_context: str) -> None:
        """Run cmd, raise MapperException on failure."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            raise MapperException(f"Timeout during {error_context}") from exc
        except OSError as exc:
            raise MapperException(f"OS error during {error_context}: {exc}") from exc
        if result.returncode != 0:
            raise MapperException(
                f"{error_context} exited with code {result.returncode}. "
                f"stderr={result.stderr.strip()!r}"
            )

    @staticmethod
    def _cleanup(path: Path) -> None:
        """Remove temp clone directory."""
        try:
            shutil.rmtree(path, ignore_errors=False)
            logger.debug("Cleaned up temp directory", extra={"path": str(path)})
        except Exception as exc:
            logger.warning("Failed to clean up temp directory", extra={
                "path": str(path), "error": str(exc)
            })
