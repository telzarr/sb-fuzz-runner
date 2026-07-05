"""Pydantic schema for fuzz job configuration and status."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class FuzzerKind(str, enum.Enum):
    afl = "afl"
    honggfuzz = "honggfuzz"
    libfuzzer = "libfuzzer"


class TargetKind(str, enum.Enum):
    binary = "binary"
    docker_image = "docker-image"


class JobStatus(str, enum.Enum):
    created = "created"
    starting = "starting"
    running = "running"
    stopping = "stopping"
    stopped = "stopped"
    completed = "completed"
    failed = "failed"
    rejected = "rejected"


class LegalAcknowledgement(BaseModel):
    """Explicit consent record. A job cannot be created without this."""

    consent: bool = Field(
        ..., description="Must be true: confirms the submitter owns or has permission to fuzz the target."
    )
    consent_text: str = Field(
        default="I confirm I own the target or have written permission to fuzz it."
    )
    owner_contact: Optional[str] = None

    @field_validator("consent")
    @classmethod
    def consent_must_be_true(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("legal_acknowledgement.consent must be true")
        return v


class Target(BaseModel):
    type: TargetKind
    path: str
    args: list[str] = Field(default_factory=lambda: ["@@"])
    symbols_present: bool = True


class NotifyConfig(BaseModel):
    on_crash: list[str] = Field(default_factory=list)


class JobConfig(BaseModel):
    """Canonical job submission schema (matches docs/design job JSON)."""

    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None

    legal_acknowledgement: LegalAcknowledgement

    fuzzer: FuzzerKind
    target: Target

    seeds_dir: str
    output_dir: str

    timeout_seconds: int = Field(default=3600, gt=0, le=24 * 3600)
    memory_limit_mb: int = Field(default=2048, gt=0)
    cpu_limit: float = Field(default=1.0, gt=0)
    qemu_mode: bool = False
    sanitizers: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)

    # Security override — must be explicit and is logged & audited when true.
    allow_network: bool = False

    @model_validator(mode="after")
    def set_created_at(self) -> "JobConfig":
        if self.created_at is None:
            object.__setattr__(self, "created_at", datetime.now(timezone.utc))
        return self


class JobRecord(BaseModel):
    """Persisted job state, wraps a JobConfig with runtime status."""

    config: JobConfig
    status: JobStatus = JobStatus.created
    container_id: Optional[str] = None
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    error: Optional[str] = None
    report_path: Optional[str] = None
