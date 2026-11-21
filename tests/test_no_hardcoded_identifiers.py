"""Guardrail: fail the build if an AWS account ID or access key ID is committed in text files."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "_original_screenshots_DO_NOT_COMMIT",
             "audit-logs", "reports", ".pytest_cache", ".ruff_cache"}
TEXT_SUFFIXES = {".py", ".json", ".md", ".csv", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".sh", ".ps1"}

ACCOUNT_IN_ARN = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):")
ACCESS_KEY_ID = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
BARE_ACCOUNT = re.compile(r"(?i)account[_ -]?id\W{0,5}[\"']?(\d{12})\b")
ALLOWED_ACCOUNTS = {"123456789012", "111122223333"}  # AWS documentation placeholders


def _files():
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and not SKIP_DIRS & set(path.parts):
            yield path


def test_no_account_ids_or_access_keys_in_repo():
    problems = []
    for path in _files():
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for rx in (ACCOUNT_IN_ARN, BARE_ACCOUNT):
            problems += [f"{path.relative_to(ROOT)}: account id {m.group(1)}" for m in rx.finditer(text)
                         if m.group(1) not in ALLOWED_ACCOUNTS]
        problems += [f"{path.relative_to(ROOT)}: access key id {m.group(0)[:8]}..." for m in ACCESS_KEY_ID.finditer(text)]
    assert not problems, "Hardcoded identifiers found:\n" + "\n".join(problems)
