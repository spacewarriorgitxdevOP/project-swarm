"""tests/unit/test_mapper.py

Unit tests for :class:`src.mapper.parser.MapperAgent`.

All external I/O (subprocess, filesystem, network) is mocked so these tests
run fully offline and deterministically.
"""

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.exceptions import MapperException
from src.core.models import CodeGraph, RepoTarget
from src.mapper.parser import MapperAgent


@pytest.fixture()
def repo_target() -> RepoTarget:
    return RepoTarget(
        url="https://github.com/example/repo",
        branch="main",
        scan_config={},
    )


@pytest.fixture()
def agent() -> MapperAgent:
    return MapperAgent()


def _make_edge(dst: str, idx: int = 0) -> dict:
    return {
        "id": f"edge-{idx}",
        "src": "module.caller",
        "dst": dst,
        "relationship": "calls",
        "file": "src/example.py",
        "line": 10 + idx,
    }


class TestRunReturnsCodeGraph:
    def test_run_returns_code_graph(
        self,
        agent: MapperAgent,
        repo_target: RepoTarget,
    ) -> None:
        fake_nodes = [
            {
                "id": "n1",
                "type": "function",
                "name": "foo",
                "file": "src/a.py",
                "start_line": 1,
                "end_line": 5,
            }
        ]
        fake_edges = [_make_edge("os.path.join")]

        with (
            patch.object(agent, "_clone_repo", return_value=Path("/tmp/fake-repo")),
            patch.object(
                agent,
                "_parse_files",
                return_value=(fake_nodes, fake_edges),
            ),
            patch.object(agent, "_cleanup", return_value=None),
        ):
            result = agent.run(repo_target)

        assert isinstance(result, CodeGraph), "run() must return a CodeGraph"
        assert result.repo_target == repo_target
        assert result.nodes == fake_nodes
        assert result.edges == fake_edges


class TestCloneFailureRaisesMapperException:
    def test_clone_failure_raises_mapper_exception(
        self,
        agent: MapperAgent,
        repo_target: RepoTarget,
    ) -> None:
        import subprocess

        failed_proc = MagicMock()
        failed_proc.returncode = 128
        failed_proc.stderr = "fatal: repository not found"

        with (
            patch(
                "subprocess.run",
                return_value=failed_proc,
            ) as mock_sub,
            patch.object(agent, "_cleanup", return_value=None),
        ):
            mock_sub.side_effect = subprocess.CalledProcessError(
                returncode=128,
                cmd=["git", "clone"],
                stderr="fatal: repository not found",
            )

            with pytest.raises(MapperException):
                agent.run(repo_target)


class TestDetectSinksFinds:
    def test_detect_sinks_finds_dangerous_calls(
        self,
        agent: MapperAgent,
    ) -> None:
        dangerous_edges = [_make_edge("subprocess.run")]

        from src.mapper.sink_detector import SinkDetector

        detector = SinkDetector()
        sinks = detector.run(dangerous_edges)

        assert len(sinks) == 1, "Exactly one sink should be detected"
        assert sinks[0]["sink_type"] == "subprocess.run"
        assert sinks[0]["category"] == "command_injection"
        assert sinks[0]["edge_id"] == dangerous_edges[0]["id"]


class TestDetectSinksIgnoresSafe:
    def test_detect_sinks_ignores_safe_calls(
        self,
        agent: MapperAgent,
    ) -> None:
        safe_edges = [
            _make_edge("print", 0),
            _make_edge("str.format", 1),
            _make_edge("os.path.join", 2),
            _make_edge("logging.info", 3),
        ]

        from src.mapper.sink_detector import SinkDetector

        detector = SinkDetector()
        sinks = detector.run(safe_edges)

        assert sinks == [], (
            f"Expected no sinks for safe calls, got: {sinks}"
        )


class TestParseFileExtractsFunctions:
    def test_parse_file_extracts_functions(
        self,
        agent: MapperAgent,
        tmp_path: Path,
    ) -> None:
        snippet = textwrap.dedent("""\
            import subprocess

            def vulnerable_function(cmd: str) -> None:
                subprocess.run(cmd, shell=True)

            def safe_function(x: int) -> int:
                return x + 1
        """)

        source_file = tmp_path / "sample.py"
        source_file.write_text(snippet, encoding="utf-8")

        nodes, edges = agent._parse_file(source_file, source_file.parent)

        required_fields = {"id", "type", "name", "file", "start_line", "end_line"}
        assert nodes, "Expected at least one node from the parsed snippet"

        for node in nodes:
            missing = required_fields - set(node.keys())
            assert not missing, f"Node missing fields: {missing} — node: {node}"

        names = {n["name"] for n in nodes}
        assert "vulnerable_function" in names, (
            f"'vulnerable_function' not found in extracted nodes: {names}"
        )


class TestCleanupCalledOnFailure:
    def test_cleanup_called_on_failure(
        self,
        agent: MapperAgent,
        repo_target: RepoTarget,
    ) -> None:
        fake_clone_path = Path("/tmp/swarm-clone-abc123")

        with (
            patch.object(agent, "_clone_repo", return_value=fake_clone_path),
            patch.object(
                agent,
                "_parse_files",
                side_effect=MapperException("parse exploded"),
            ),
            patch.object(agent, "_cleanup") as mock_cleanup,
        ):
            with pytest.raises(MapperException, match="parse exploded"):
                agent.run(repo_target)

        mock_cleanup.assert_called_once_with(fake_clone_path)
