from datetime import UTC, datetime, timedelta

import pytest
from conftest import req

from iam_lifecycle import config
from iam_lifecycle.csvio import CsvValidationError, load_requests
from iam_lifecycle.review import review

REPO = config.REPO_ROOT


# ------------------------------------------------------------------------ CSV
def test_shipped_csv_files_are_valid():
    assert len(load_requests(REPO / "Phase2_Joiner_automation" / "Joiner.csv", "joiner")) == 3
    rows = load_requests(REPO / "Phase3_mover_leaver_automation" / "mover_leaver.csv", "lifecycle")
    assert [(r.username, r.action) for r in rows] == [("bob.dev", "move"), ("carol.sec", "leave")]


@pytest.mark.parametrize("body, expected", [
    ("username,role,ticket\nalice,admin,HR-1\n", "unknown role"),
    ("username,role,ticket\nAlice!,developer,HR-1\n", "invalid username"),
    ("username,role,ticket\nalice,developer,\n", "ticket"),
    ("username,role,ticket\nalice,developer,HR-1\nalice,developer,HR-2\n", "duplicate"),
    ("username,role,ticket\n=cmd|' /C calc'!A0,developer,HR-1\n", "formula"),
    ("username,group,policy\nalice,x,y\n", "missing column"),
])
def test_invalid_csv_is_rejected(tmp_path, body, expected):
    f = tmp_path / "in.csv"
    f.write_text(body)
    with pytest.raises(CsvValidationError) as exc:
        load_requests(f, "joiner")
    assert expected in str(exc.value)


def test_header_whitespace_and_bom_tolerated(tmp_path):
    f = tmp_path / "in.csv"
    f.write_bytes("﻿username , role ,ticket\nalice.hr,hr-analyst,hr-7\n".encode())
    assert load_requests(f, "joiner")[0].ticket == "HR-7"


# --------------------------------------------------------------------- review
def _report_row(user, **kw):
    base = {"user": user, "password_enabled": "false", "mfa_active": "false", "password_last_used": "N/A",
            "password_last_changed": "N/A", "access_key_1_active": "false", "access_key_2_active": "false",
            "access_key_1_last_rotated": "N/A", "access_key_2_last_rotated": "N/A",
            "access_key_1_last_used_date": "N/A", "access_key_2_last_used_date": "N/A"}
    base.update(kw)
    return base


def test_review_flags_credential_risks(aws):
    now = datetime(2026, 11, 21, tzinfo=UTC)
    old = (now - timedelta(days=200)).isoformat()
    report = [
        _report_row("<root_account>", access_key_1_active="true"),
        _report_row("nomfa", password_enabled="true", password_last_used=now.isoformat()),
        _report_row("stale", access_key_1_active="true", access_key_1_last_rotated=old),
    ]
    rules = {(f.rule, f.user) for f in review(aws.iam, now=now, report=report)}
    assert ("root-access-key", "<root_account>") in rules
    assert ("root-no-mfa", "<root_account>") in rules
    assert ("console-without-mfa", "nomfa") in rules
    assert ("stale-access-key", "stale") in rules
    assert ("unused-access-key", "stale") in rules


def test_review_flags_governance_drift(lc, aws):
    lc.joiner(req("bob.dev", "developer"))
    aws.iam.add_user_to_group(UserName="bob.dev", GroupName="Security-AWS")          # SoD conflict
    lc.joiner(req("alice.hr", "hr-analyst"))
    aws.iam.attach_user_policy(UserName="alice.hr", PolicyArn=aws.policy_arn("iamlab-security-audit"))  # RBAC bypass
    lc.joiner(req("carol.sec", "security-analyst"))
    lc.leaver(req("carol.sec", action="leave"))
    aws.iam.add_user_to_group(UserName="carol.sec", GroupName="Security-AWS")        # leaver regained access

    rules = {(f.rule, f.user) for f in review(aws.iam, report=[])}
    assert ("segregation-of-duties", "bob.dev") in rules
    assert ("direct-user-policy", "alice.hr") in rules
    assert ("leaver-still-has-access", "carol.sec") in rules


def test_clean_lab_has_no_governance_findings(lc, aws):
    lc.joiner(req("alice.hr", "hr-analyst"))
    assert review(aws.iam, report=[]) == []
