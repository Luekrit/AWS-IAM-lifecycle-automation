"""Rule-based access review over the IAM credential report and group memberships.

This is the deterministic baseline for Phase 4: every finding is explainable and
maps to a governance control. ML-based anomaly detection can be layered on top
later, using these findings as labelled examples.
"""

from __future__ import annotations

import csv
import io
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from . import config
from .aws import paginate

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    severity: str
    rule: str
    user: str
    detail: str
    recommendation: str

    def as_dict(self) -> dict:
        return asdict(self)


def _parse_time(value: str) -> datetime | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _days(since: datetime | None, now: datetime) -> int | None:
    return None if since is None else (now - since).days


def fetch_credential_report(iam, timeout_s: int = 60) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    while iam.generate_credential_report()["State"] != "COMPLETE":
        if time.monotonic() > deadline:
            raise TimeoutError("credential report generation timed out")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def review(iam, now: datetime | None = None, report: list[dict] | None = None) -> list[Finding]:
    now = now or datetime.now(UTC)
    report = report if report is not None else fetch_credential_report(iam)
    findings: list[Finding] = []
    add = findings.append

    for row in report:
        user = row["user"]

        if user == "<root_account>":
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                add(Finding("critical", "root-access-key", user, "Root user has an active access key",
                            "Delete root access keys; use roles for automation."))
            if row.get("mfa_active") != "true":
                add(Finding("critical", "root-no-mfa", user, "Root user has no MFA",
                            "Enable a phishing-resistant MFA device (passkey/FIDO2) on root."))
            last = _days(_parse_time(row.get("password_last_used", "")), now)
            if last is not None and last < 30:
                add(Finding("medium", "root-recent-use", user, f"Root signed in {last} day(s) ago",
                            "Confirm the root sign-in was a documented break-glass event."))
            continue

        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            add(Finding("high", "console-without-mfa", user, "Console access is enabled without MFA",
                        "Enforce MFA (iamlab-enforce-mfa) or move the user to IAM Identity Center."))

        pw_unused = _days(_parse_time(row.get("password_last_used", "")) or _parse_time(row.get("password_last_changed", "")), now)
        if row.get("password_enabled") == "true" and pw_unused is not None and pw_unused > config.CREDENTIAL_UNUSED_DAYS:
            add(Finding("medium", "unused-password", user, f"Console password not used for {pw_unused} days",
                        "Remove the login profile if the user no longer needs console access."))

        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            age = _days(_parse_time(row.get(f"access_key_{n}_last_rotated", "")), now)
            used = _days(_parse_time(row.get(f"access_key_{n}_last_used_date", "")), now)
            add(Finding("medium", "long-term-access-key", user, f"Access key {n} is active",
                        "Prefer temporary credentials (Identity Center / roles) over IAM user keys."))
            if age is not None and age > config.KEY_MAX_AGE_DAYS:
                add(Finding("high", "stale-access-key", user, f"Access key {n} is {age} days old",
                            f"Rotate or delete keys older than {config.KEY_MAX_AGE_DAYS} days."))
            if (used is None and age is not None and age > config.CREDENTIAL_UNUSED_DAYS) or \
                    (used is not None and used > config.CREDENTIAL_UNUSED_DAYS):
                add(Finding("medium", "unused-access-key", user,
                            f"Access key {n} unused for {used if used is not None else str(age) + '+'} days",
                            "Deactivate and delete unused access keys."))

    findings.extend(_review_entitlements(iam))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.user, f.rule))
    return findings


def _review_entitlements(iam) -> list[Finding]:
    out: list[Finding] = []
    for listed in paginate(iam, "list_users", "Users"):
        u = listed["UserName"]
        user = iam.get_user(UserName=u)["User"]  # ListUsers omits PermissionsBoundary
        tags = {t["Key"]: t["Value"] for t in paginate(iam, "list_user_tags", "Tags", UserName=u)}
        groups = [g["GroupName"] for g in paginate(iam, "list_groups_for_user", "Groups", UserName=u)]
        direct = [p["PolicyName"] for p in paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=u)]
        inline = [p for p in paginate(iam, "list_user_policies", "PolicyNames", UserName=u)
                  if p != config.QUARANTINE_INLINE_POLICY]
        managed = user.get("Path") == config.IAM_PATH

        if tags.get(config.TAG_STATUS) == config.STATUS_TERMINATED:
            active_keys = [k for k in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=u)
                           if k["Status"] == "Active"]
            try:
                iam.get_login_profile(UserName=u)
                has_password = True
            except iam.exceptions.NoSuchEntityException:
                has_password = False
            leftovers = []
            if active_keys:
                leftovers.append("active access keys")
            if has_password:
                leftovers.append("console password")
            if groups:
                leftovers.append(f"groups {groups}")
            if leftovers:
                out.append(Finding("critical", "leaver-still-has-access", u,
                                   f"Terminated user still has: {', '.join(leftovers)}",
                                   "Re-run leaver.py --apply and investigate why revocation was incomplete."))
            continue

        if direct or inline:
            out.append(Finding("medium", "direct-user-policy", u,
                               f"Permissions attached to the user instead of a group: {direct + inline}",
                               "Move permissions to the role group (RBAC) and detach from the user."))
        if managed and "PermissionsBoundary" not in user:
            out.append(Finding("high", "missing-permissions-boundary", u, "Managed lab user has no permissions boundary",
                               "Re-create through joiner.py or attach iamlab-user-boundary."))
        if not managed:
            out.append(Finding("low", "unmanaged-identity", u, f"User is outside {config.IAM_PATH} (not governed by JML)",
                               "Confirm an owner exists, or migrate the user into the governed path."))

        roles = [r for r in (config.role_for_group(g) for g in groups) if r]
        for r in roles:
            conflicts = [o.name for o in roles if o.name in r.incompatible_with]
            if conflicts:
                out.append(Finding("high", "segregation-of-duties", u,
                                   f"Holds {r.name} together with incompatible role(s) {conflicts}",
                                   "Remove one of the conflicting group memberships."))
                break
        expected_dept = roles[0].department if len(roles) == 1 else None
        if expected_dept and tags.get(config.TAG_DEPARTMENT) != expected_dept:
            out.append(Finding("medium", "department-tag-mismatch", u,
                               f"department tag {tags.get(config.TAG_DEPARTMENT)!r} does not match role group ({expected_dept})",
                               "Fix the tag: ABAC policies scope data access by it."))
    return out


def to_markdown(findings: list[Finding], generated: datetime) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    lines = [
        "# IAM Access Review",
        "",
        f"Generated {generated:%Y-%m-%d %H:%M} UTC. " + ", ".join(f"{k}: {v}" for k, v in counts.items()),
        "",
        "| Severity | Rule | User | Detail | Recommendation |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.severity} | {f.rule} | `{f.user}` | {f.detail} | {f.recommendation} |")
    if not findings:
        lines.append("| - | - | - | No findings | - |")
    return "\n".join(lines) + "\n"
