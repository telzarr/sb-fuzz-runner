"""Default configuration and environment-driven settings for sb-fuzz-runner.

All values here are safe-by-default. Anything that loosens isolation
(e.g. allowing network access) must be explicit in a job config, never
in a global default.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _default_data_dir() -> str:
    return os.environ.get("SBF_DATA_DIR", os.path.join(os.getcwd(), ".sbf_data"))


@dataclass(frozen=True)
class Settings:
    # Storage
    data_dir: str = field(default_factory=_default_data_dir)
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", f"sqlite:///{_default_data_dir()}/sbf.db"
        )
    )

    # Retention
    artifact_retention_days: int = int(os.environ.get("SBF_RETENTION_DAYS", "90"))

    # Security defaults (never loosen these without an explicit job field)
    default_network_disabled: bool = True
    default_non_root_uid: str = os.environ.get("SBF_NONROOT_UID", "1000:1000")
    default_no_new_privileges: bool = True

    # Resource defaults, used only if a job omits them
    default_memory_limit_mb: int = int(os.environ.get("SBF_DEFAULT_MEM_MB", "2048"))
    default_cpu_limit: float = float(os.environ.get("SBF_DEFAULT_CPU_LIMIT", "1.0"))
    default_timeout_seconds: int = int(os.environ.get("SBF_DEFAULT_TIMEOUT_S", "3600"))

    # Feature flags
    allow_network_override: bool = os.environ.get("SBF_ALLOW_NETWORK_OVERRIDE", "0") == "1"


settings = Settings()
