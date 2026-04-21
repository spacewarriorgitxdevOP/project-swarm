import io
import tarfile

import docker
import docker.errors
from docker import DockerClient
from docker.models.containers import Container

from src.core.config import config
from src.core.exceptions import SandboxerException
from src.core.logger import logger
from src.core.models import SandboxResult, SandboxStatus, VulnHypothesis

_EXPLOIT_MARKER: str = "EXPLOITED"
_MEM_LIMIT: str = "512m"
_NETWORK_MODE: str = "none"
_CONTAINER_IMAGE: str = "python:3.11-slim"


class SandboxerAgent:
    """
    Validates a :class:`VulnHypothesis` by executing its exploit plan inside an
    isolated Docker container and interpreting the outcome.
    """

    def __init__(self) -> None:
        try:
            self._client: DockerClient = docker.from_env()
            self._client.ping()
        except docker.errors.DockerException as exc:
            raise SandboxerException(
                f"SandboxerAgent: cannot connect to Docker daemon: {exc}"
            ) from exc

        logger.debug(
            "SandboxerAgent: Docker client ready "
            "(image=%s, mem_limit=%s, timeout=%ds)",
            _CONTAINER_IMAGE,
            _MEM_LIMIT,
            config.SANDBOX_TIMEOUT_SECONDS,
        )

    def run(self, hypothesis: VulnHypothesis) -> SandboxResult:
        logger.info(
            "SandboxerAgent: running sandbox for hypothesis "
            "vuln_class=%r file=%r line=%d",
            hypothesis.vuln_class,
            hypothesis.file_path,
            hypothesis.line_number,
        )

        container_id: str = self._spin_container(hypothesis)
        try:
            stdout, stderr, exit_code = self._execute_exploit(container_id, hypothesis)
        finally:
            self._teardown_container(container_id)

        status: SandboxStatus = self._parse_result(stdout, stderr, exit_code)

        logger.info(
            "SandboxerAgent: result status=%s exit_code=%d for vuln_class=%r",
            status,
            exit_code,
            hypothesis.vuln_class,
        )

        return SandboxResult(
            hypothesis=hypothesis,
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        )

    def _spin_container(self, hypothesis: VulnHypothesis) -> str:
        label = (
            f"swarm-sandbox-{hypothesis.vuln_class.lower().replace(' ', '_')}"
            f"-{hypothesis.line_number}"
        )

        logger.debug("SandboxerAgent: spinning container label=%r", label)

        try:
            container: Container = self._client.containers.run(
                image=_CONTAINER_IMAGE,
                name=label,
                command="sleep infinity",
                detach=True,
                network_mode=_NETWORK_MODE,
                mem_limit=_MEM_LIMIT,
                auto_remove=False,
                labels={
                    "project": "swarm",
                    "vuln_class": hypothesis.vuln_class,
                },
            )
        except docker.errors.ImageNotFound as exc:
            raise SandboxerException(
                f"SandboxerAgent: Docker image '{_CONTAINER_IMAGE}' not found: {exc}"
            ) from exc
        except docker.errors.APIError as exc:
            raise SandboxerException(
                f"SandboxerAgent: Docker API error while creating container: {exc}"
            ) from exc

        container_id: str = container.id
        logger.debug("SandboxerAgent: container started id=%s", container_id[:12])
        return container_id

    def _execute_exploit(
        self,
        container_id: str,
        hypothesis: VulnHypothesis,
    ) -> tuple[str, str, int]:
        logger.debug(
            "SandboxerAgent: executing exploit in container %s (timeout=%ds)",
            container_id[:12],
            config.SANDBOX_TIMEOUT_SECONDS,
        )

        script: str = _build_exploit_script(hypothesis.exploit_plan)
        script_bytes: bytes = script.encode()

        try:
            container: Container = self._client.containers.get(container_id)

            tarstream = io.BytesIO()
            with tarfile.open(fileobj=tarstream, mode="w") as tar:
                info = tarfile.TarInfo(name="exploit.py")
                info.size = len(script_bytes)
                tar.addfile(info, io.BytesIO(script_bytes))
            tarstream.seek(0)
            container.put_archive("/tmp", tarstream)

            result = container.exec_run(
                cmd=["python", "/tmp/exploit.py"],
                demux=True,
                tty=False,
            )
        except docker.errors.NotFound as exc:
            raise SandboxerException(
                f"SandboxerAgent: container {container_id[:12]} not found "
                f"during exec: {exc}"
            ) from exc
        except docker.errors.APIError as exc:
            raise SandboxerException(
                f"SandboxerAgent: Docker API error during exec "
                f"in container {container_id[:12]}: {exc}"
            ) from exc

        exit_code: int = result.exit_code if result.exit_code is not None else -1

        raw_stdout, raw_stderr = result.output
        stdout: str = (raw_stdout or b"").decode(errors="replace").strip()
        stderr: str = (raw_stderr or b"").decode(errors="replace").strip()

        logger.debug(
            "SandboxerAgent: exec finished exit_code=%d "
            "stdout_len=%d stderr_len=%d",
            exit_code,
            len(stdout),
            len(stderr),
        )
        return stdout, stderr, exit_code

    def _teardown_container(self, container_id: str) -> None:
        logger.debug("SandboxerAgent: tearing down container %s", container_id[:12])
        try:
            container: Container = self._client.containers.get(container_id)
            container.stop(timeout=5)
            container.remove(force=True)
            logger.debug("SandboxerAgent: container %s removed", container_id[:12])
        except docker.errors.NotFound:
            logger.debug(
                "SandboxerAgent: container %s already removed", container_id[:12]
            )
        except docker.errors.APIError as exc:
            logger.warning(
                "SandboxerAgent: failed to remove container %s: %s",
                container_id[:12],
                exc,
            )

    def _parse_result(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
    ) -> SandboxStatus:
        marker_found: bool = _EXPLOIT_MARKER in stdout
        proven: bool = exit_code == 0 and marker_found

        logger.debug(
            "SandboxerAgent: parse_result exit_code=%d marker_found=%s → %s",
            exit_code,
            marker_found,
            "PROVEN" if proven else "HALLUCINATION",
        )

        if stderr:
            logger.debug("SandboxerAgent: stderr: %s", stderr[:500])

        return SandboxStatus.PROVEN if proven else SandboxStatus.HALLUCINATION


def _build_exploit_script(exploit_plan: str) -> str:
    indented = "\n".join(f"    {line}" for line in exploit_plan.splitlines())
    return (
        "import sys\n"
        "\n"
        "\n"
        "def main() -> None:\n"
        f"{indented}\n"
        "\n"
        "\n"
        "main()\n"
        f'print("{_EXPLOIT_MARKER}")\n'
        "sys.exit(0)\n"
    )
