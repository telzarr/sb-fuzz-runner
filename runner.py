"""Container control via docker-py.

We intentionally never shell out to `docker run`; all lifecycle
operations go through the docker SDK so behavior is testable via
mocking the `docker.DockerClient` object.
"""
from __future__ import annotations

from typing import Optional

from sbf.config import settings
from sbf.models import FuzzerKind, JobConfig
from sbf.security import container_security_opts, resolve_network_policy
from sbf.utils import audit_log, get_logger

logger = get_logger(__name__)

# Maps fuzzer kind -> docker image tag built by scripts/build_images.sh
IMAGE_FOR_FUZZER = {
    FuzzerKind.afl: "sbf-afl:latest",
    FuzzerKind.honggfuzz: "sbf-honggfuzz:latest",
    FuzzerKind.libfuzzer: "sbf-libfuzzer:latest",
}

# Canonical in-container invocation per fuzzer. `{target}` and `{args}`
# are substituted; seeds/output are always mounted at /in and /out.
COMMAND_TEMPLATE = {
    FuzzerKind.afl: "afl-fuzz -i /in -o /out -m none -- {target} {args}",
    FuzzerKind.honggfuzz: "honggfuzz -f /in -o /out -- {target} {args}",
    FuzzerKind.libfuzzer: "{target} -artifact_prefix=/out/ /in",
}


def _get_docker_client():
    import docker  # imported lazily so unit tests can run without docker installed

    return docker.from_env()


def build_container_kwargs(job: JobConfig) -> dict:
    """Pure function: given a JobConfig, compute the docker-py `run()` kwargs.

    Kept separate from the actual `.run()` call so it's trivially unit
    testable without touching a real or mocked docker client.
    """
    image = IMAGE_FOR_FUZZER[job.fuzzer]
    target_args = " ".join(job.target.args)
    command = "/bin/bash -lc \"" + COMMAND_TEMPLATE[job.fuzzer].format(
        target=job.target.path, args=target_args
    ) + "\""

    network_enabled = resolve_network_policy(job)
    sec_opts = container_security_opts(settings.default_non_root_uid)

    volumes = {
        job.seeds_dir: {"bind": "/in", "mode": "ro"},
        job.output_dir: {"bind": "/out", "mode": "rw"},
    }

    kwargs = {
        "image": image,
        "command": command,
        "detach": True,
        "network_mode": "bridge" if network_enabled else "none",
        "user": sec_opts["user"],
        "security_opt": sec_opts["security_opt"],
        "volumes": volumes,
        "mem_limit": f"{job.memory_limit_mb}m",
        "cpu_quota": int(job.cpu_limit * 100000),
        "cpu_period": 100000,
        "environment": job.env,
        "labels": {"sbf.job_id": job.job_id},
        "name": f"sbf-{job.job_id}",
    }
    return kwargs


def launch_fuzz_container(job: JobConfig, docker_client: Optional[object] = None) -> str:
    """Start the runner container for a job. Returns the container id.

    `docker_client` can be injected (used by unit tests to pass a mock).
    """
    client = docker_client or _get_docker_client()
    kwargs = build_container_kwargs(job)

    audit_log(
        "container_launch",
        job_id=job.job_id,
        fuzzer=job.fuzzer.value,
        network_mode=kwargs["network_mode"],
        mem_limit=kwargs["mem_limit"],
        cpu_quota=kwargs["cpu_quota"],
    )
    container = client.containers.run(**kwargs)
    return container.id


def stop_container(container_id: str, docker_client: Optional[object] = None, timeout: int = 10) -> None:
    """Stop and remove a runner container cleanly."""
    client = docker_client or _get_docker_client()
    container = client.containers.get(container_id)
    audit_log("container_stop", container_id=container_id)
    container.stop(timeout=timeout)
    try:
        container.remove(force=True)
    except Exception:  # noqa: BLE001 - best effort cleanup
        logger.warning("Failed to remove container %s after stop", container_id)


def container_status(container_id: str, docker_client: Optional[object] = None) -> str:
    client = docker_client or _get_docker_client()
    container = client.containers.get(container_id)
    container.reload()
    return container.status
