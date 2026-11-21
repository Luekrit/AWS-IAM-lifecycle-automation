"""Load and validate lifecycle CSV files before anything touches AWS."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from .config import ROLES

USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{1,62}$")
TICKET_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{1,8}$")  # e.g. HR-1042, CHG-2207
ACTIONS = {"join", "move", "leave"}

SCHEMAS: dict[str, tuple[str, ...]] = {
    "joiner": ("username", "role", "ticket"),
    "lifecycle": ("username", "action", "role", "ticket"),
}


class CsvValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Request:
    line: int
    username: str
    action: str
    role: str
    ticket: str


def _clean(value: str | None) -> str:
    return (value or "").strip()


def load_requests(path: str | Path, schema: str) -> list[Request]:
    """Parse ``path`` and return validated requests, or raise CsvValidationError listing every problem."""
    required = SCHEMAS[schema]
    errors: list[str] = []
    requests: list[Request] = []
    seen: set[str] = set()

    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        headers = [_clean(h).lower() for h in (reader.fieldnames or [])]
        missing = [h for h in required if h not in headers]
        if missing:
            raise CsvValidationError([f"{path}: missing column(s): {', '.join(missing)} (found: {', '.join(headers)})"])
        reader.fieldnames = headers

        for line, raw in enumerate(reader, start=2):
            row = {k: _clean(v) for k, v in raw.items() if k}
            if not any(row.values()):
                continue
            username = row.get("username", "").lower()
            action = row.get("action", "join").lower() or "join"
            role = row.get("role", "").lower()
            ticket = row.get("ticket", "").upper()
            where = f"line {line}"

            for name, value in row.items():
                if value[:1] in ("=", "+", "@") or value.startswith("-="):
                    errors.append(f"{where}: column '{name}' looks like a spreadsheet formula: {value!r}")
            if not USERNAME_RE.match(username):
                errors.append(f"{where}: invalid username {username!r} (lowercase letters, digits, . _ -)")
            if action not in ACTIONS:
                errors.append(f"{where}: unknown action {action!r} (expected one of {sorted(ACTIONS)})")
            if action in ("join", "move") and role not in ROLES:
                errors.append(f"{where}: unknown role {role!r} (allowed: {', '.join(sorted(ROLES))})")
            if action == "leave" and role not in ("", "n/a"):
                errors.append(f"{where}: leavers must not have a role (got {role!r})")
            if not TICKET_RE.match(ticket):
                errors.append(f"{where}: missing or invalid ticket reference {ticket!r} (e.g. HR-1042)")
            if username in seen:
                errors.append(f"{where}: duplicate username {username!r} in the same file")
            seen.add(username)

            requests.append(Request(line, username, action, "" if action == "leave" else role, ticket))

    if errors:
        raise CsvValidationError(errors)
    return requests
