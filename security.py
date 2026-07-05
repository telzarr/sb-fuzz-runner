"""Security & legal enforcement.

This module is intentionally the single choke point for the two
non-negotiable policies:

1. No job may be created or started without an affirmative legal
   acknowledgement (consent == true).
2. No runner container gets network access unless a job explicitly
   opts in via `allow_network: true`, and that decision is audited.

Callers (controller.py, runner.py) must go through these functions
rather than re-implementing the checks, so the policy lives in one place.
"""
from __future__ import annotations

from sbf.models import JobConfig
from sbf.utils import audit_log


class SecurityPolicyError(Exception):
    """Raised when a job or run configuration violates a required policy."""


def enforce_legal_acknowledgement(job: JobConfig) -> None:
    """Raise if the job's legal acknowledgement is missing or not affirmative.

    Pydantic validation on LegalAcknowledgement already rejects
    consent != true at parse time, but we re-check here defensively in
    case a JobConfig is ever constructed by means other than normal
    validation (e.g. deserialized from an older/partial record).
    """
    ack = job.legal_acknowledgement
    if ack is None or ack.consent is not True:
        raise SecurityPolicyError(
            "Job rejected: legal_acknowledgement.consent must be true before "
            "a fuzz job can be created or started."
        )


def resolve_network_policy(job: JobConfig) -> bool:
    """Return whether the container should have network enabled.

    Defaults to disabled. Only returns True if the job explicitly set
    allow_network=true; that decision is always logged to the audit trail.
    """
    if job.allow_network:
        audit_log(
            "network_override_enabled",
            job_id=job.job_id,
            created_by=job.created_by,
            reason="job.allow_network=true",
        )
        return True
    return False


def container_security_opts(non_root_uid: str) -> dict:
    """Canonical hardening options applied to every runner container."""
    return {
        "user": non_root_uid,
        "security_opt": ["no-new-privileges"],
    }


def startup_secret_scan(repo_root: str) -> list[str]:
    """Best-effort scan for obvious hardcoded credentials in source.

    Not a substitute for a real secret scanner (e.g. gitleaks/trufflehog)
    but catches egregious cases and refuses to run if found.
    Returns a list of suspicious file paths (empty if none found).
    """
    import os
    import re

    suspicious_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
        re.compile(r"ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    ]
    hits: list[str] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not fname.endswith((".py", ".env", ".yml", ".yaml", ".json", ".sh")):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            for pattern in suspicious_patterns:
                if pattern.search(content):
                    hits.append(fpath)
                    break
    return hits
