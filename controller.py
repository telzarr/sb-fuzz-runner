"""Job lifecycle orchestration: create, start, stop, list, show.

The Controller is the only component that should be driven directly by
the CLI or REST API. It composes db.JobStore, security enforcement, and
runner container control, and is responsible for keeping job state
consistent across all of those.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Optional

from sbf.db import JobStore
from sbf.models import JobConfig, JobRecord, JobStatus
from sbf.security import SecurityPolicyError, enforce_legal_acknowledgement
from sbf import runner as runner_mod
from sbf.utils import audit_log, ensure_dir, get_logger

logger = get_logger(__name__)


class ControllerError(Exception):
    pass


class Controller:
    def __init__(self, store: Optional[JobStore] = None, docker_client: Optional[object] = None):
        self.store = store or JobStore()
        self.docker_client = docker_client  # injectable for tests
        self._timeout_threads: dict[str, threading.Timer] = {}

    # ---- creation -----------------------------------------------------

    def create_job_from_file(self, config_path: str) -> str:
        with open(config_path, "r") as fh:
            raw = json.load(fh)
        return self.create_job(raw)

    def create_job(self, raw_config: dict) -> str:
        """Validate and persist a new job. Raises SecurityPolicyError /
        pydantic ValidationError if the config is invalid or missing
        the legal acknowledgement.
        """
        job = JobConfig.model_validate(raw_config)

        try:
            enforce_legal_acknowledgement(job)
        except SecurityPolicyError:
            audit_log("job_rejected", job_id=job.job_id, reason="missing_legal_acknowledgement")
            raise

        ensure_dir(job.seeds_dir) if False else None  # seeds must already exist; do not silently create
        ensure_dir(job.output_dir)

        record = JobRecord(config=job, status=JobStatus.created)
        self.store.save(record)
        audit_log("job_created", job_id=job.job_id, fuzzer=job.fuzzer.value)
        return job.job_id

    # ---- lifecycle ------------------------------------------------------

    def start_job(self, job_id: str) -> None:
        record = self._get_or_raise(job_id)

        # Defensive re-check: never start a job whose acknowledgement is invalid,
        # even if it somehow got persisted (e.g. record loaded from an old DB).
        enforce_legal_acknowledgement(record.config)

        record.status = JobStatus.starting
        self.store.save(record)

        try:
            container_id = runner_mod.launch_fuzz_container(record.config, docker_client=self.docker_client)
        except Exception as exc:  # noqa: BLE001
            record.status = JobStatus.failed
            record.error = str(exc)
            self.store.save(record)
            audit_log("job_start_failed", job_id=job_id, error=str(exc))
            raise ControllerError(f"Failed to start job {job_id}: {exc}") from exc

        record.container_id = container_id
        record.status = JobStatus.running
        from datetime import datetime, timezone

        record.started_at = datetime.now(timezone.utc)
        self.store.save(record)
        audit_log("job_started", job_id=job_id, container_id=container_id)

        self._schedule_timeout(record)

    def stop_job(self, job_id: str) -> None:
        record = self._get_or_raise(job_id)
        self._cancel_timeout(job_id)

        if record.container_id:
            record.status = JobStatus.stopping
            self.store.save(record)
            try:
                runner_mod.stop_container(record.container_id, docker_client=self.docker_client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error stopping container for job %s: %s", job_id, exc)

        from datetime import datetime, timezone

        record.status = JobStatus.stopped
        record.stopped_at = datetime.now(timezone.utc)
        self.store.save(record)
        audit_log("job_stopped", job_id=job_id)

    def list_jobs(self) -> list[JobRecord]:
        return self.store.list()

    def show_job(self, job_id: str) -> JobRecord:
        return self._get_or_raise(job_id)

    # ---- internals ------------------------------------------------------

    def _get_or_raise(self, job_id: str) -> JobRecord:
        record = self.store.get(job_id)
        if record is None:
            raise ControllerError(f"No such job: {job_id}")
        return record

    def _schedule_timeout(self, record: JobRecord) -> None:
        """Stop the job automatically once timeout_seconds elapses."""
        job_id = record.config.job_id
        timeout = record.config.timeout_seconds

        def _on_timeout():
            audit_log("job_timeout_reached", job_id=job_id, timeout_seconds=timeout)
            try:
                self.stop_job(job_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Timeout stop failed for job %s: %s", job_id, exc)

        timer = threading.Timer(timeout, _on_timeout)
        timer.daemon = True
        timer.start()
        self._timeout_threads[job_id] = timer

    def _cancel_timeout(self, job_id: str) -> None:
        timer = self._timeout_threads.pop(job_id, None)
        if timer:
            timer.cancel()
