"""Minimal persistence layer for job records.

MVP uses SQLite (single table, JSON payload column) accessed via
sqlalchemy core. Swapping to Postgres only requires setting
DATABASE_URL, e.g. postgresql+psycopg2://user:pass@host/db
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Column, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.engine import Engine

from sbf.config import settings
from sbf.models import JobRecord
from sbf.utils import ensure_dir

metadata = MetaData()

jobs_table = Table(
    "jobs",
    metadata,
    Column("job_id", String(64), primary_key=True),
    Column("status", String(32), nullable=False),
    Column("payload", Text, nullable=False),  # full JobRecord as JSON
)


class JobStore:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or settings.database_url
        if self.database_url.startswith("sqlite"):
            ensure_dir(settings.data_dir)
        self.engine: Engine = create_engine(self.database_url, future=True)
        metadata.create_all(self.engine)

    def save(self, record: JobRecord) -> None:
        payload = record.model_dump_json()
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(jobs_table.c.job_id).where(jobs_table.c.job_id == record.config.job_id)
            ).first()
            if existing:
                conn.execute(
                    jobs_table.update()
                    .where(jobs_table.c.job_id == record.config.job_id)
                    .values(status=record.status.value, payload=payload)
                )
            else:
                conn.execute(
                    jobs_table.insert().values(
                        job_id=record.config.job_id,
                        status=record.status.value,
                        payload=payload,
                    )
                )

    def get(self, job_id: str) -> Optional[JobRecord]:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(jobs_table.c.payload).where(jobs_table.c.job_id == job_id)
            ).first()
        if row is None:
            return None
        return JobRecord.model_validate_json(row[0])

    def list(self) -> list[JobRecord]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(jobs_table.c.payload)).fetchall()
        return [JobRecord.model_validate_json(r[0]) for r in rows]

    def delete(self, job_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(jobs_table.delete().where(jobs_table.c.job_id == job_id))
