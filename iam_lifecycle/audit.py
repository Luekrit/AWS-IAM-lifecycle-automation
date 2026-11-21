"""Structured audit trail: one JSON line per action, written locally and to stdout.

CloudTrail already records the API calls; this log adds the business context
(who ran it, which ticket, dry-run or not, and the outcome). In production you
would ship this file to a SIEM or CloudWatch Logs.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .config import REPO_ROOT

log = logging.getLogger("iamlab")


class AuditLog:
    def __init__(self, actor: str, dry_run: bool, directory: Path | None = None):
        self.actor = actor
        self.dry_run = dry_run
        self.run_id = str(uuid.uuid4())
        self.directory = directory or REPO_ROOT / "audit-logs"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / f"{datetime.now(UTC):%Y-%m-%d}.jsonl"
        self.events: list[dict] = []

    def record(self, action: str, target: str, result: str, ticket: str = "", **details) -> dict:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "actor": self.actor,
            "action": action,
            "target": target,
            "ticket": ticket,
            "dry_run": self.dry_run,
            "result": result,
            **details,
        }
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        level = logging.ERROR if result == "failed" else logging.INFO
        prefix = "[DRY-RUN] " if self.dry_run else ""
        log.log(level, "%s%s %s -> %s %s", prefix, action, target, result, details or "")
        return event

    @property
    def failures(self) -> int:
        return sum(1 for e in self.events if e["result"] == "failed")
