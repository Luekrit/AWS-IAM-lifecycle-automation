import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.audit import AuditLog  # noqa: E402
from iam_lifecycle.aws import AwsContext  # noqa: E402
from iam_lifecycle.csvio import Request  # noqa: E402
from iam_lifecycle.lifecycle import Lifecycle  # noqa: E402


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    # Never let tests reach a real account.
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "ap-southeast-2"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture(autouse=True)
def no_service_specific_creds(monkeypatch):
    # moto does not implement ListServiceSpecificCredentials; real AWS does.
    monkeypatch.setattr(Lifecycle, "_service_credentials", lambda self, username: [])


def _emulate_real_iam(iam):
    """Patch gaps in moto's IAM emulation so tests reflect real AWS behaviour.

    * moto ignores PermissionsBoundary on users; real GetUser returns it.
    * moto's UpdateLoginProfile without a Password deletes the profile; real AWS keeps it.
    Every call made through these methods is recorded in ``iam.calls`` for assertions.
    """
    boundaries: dict[str, str] = {}
    iam.calls = []
    create_user, get_user = iam.create_user, iam.get_user
    create_lp, update_lp = iam.create_login_profile, iam.update_login_profile

    def _create_user(**kw):
        iam.calls.append(("create_user", kw))
        if "PermissionsBoundary" in kw:
            boundaries[kw["UserName"]] = kw["PermissionsBoundary"]
        return create_user(**kw)

    def _get_user(**kw):
        resp = get_user(**kw)
        name = resp["User"]["UserName"]
        if name in boundaries:
            resp["User"]["PermissionsBoundary"] = {"PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                                                   "PermissionsBoundaryArn": boundaries[name]}
        return resp

    def _create_lp(**kw):
        iam.calls.append(("create_login_profile", {k: v for k, v in kw.items() if k != "Password"}))
        return create_lp(**kw)

    def _update_lp(**kw):
        iam.calls.append(("update_login_profile", kw))
        if "Password" not in kw:
            return {}
        return update_lp(**kw)

    iam.create_user, iam.get_user = _create_user, _get_user
    iam.create_login_profile, iam.update_login_profile = _create_lp, _update_lp
    return iam


@pytest.fixture
def aws():
    with mock_aws():
        ctx = AwsContext(session=boto3.session.Session(region_name=os.environ["AWS_DEFAULT_REGION"]))
        _emulate_real_iam(ctx.iam)
        yield ctx


@pytest.fixture
def make_lc(aws, tmp_path):
    def _make(apply=True):
        return Lifecycle(aws, AuditLog(actor=aws.actor, dry_run=not apply, directory=tmp_path), apply=apply)
    return _make


@pytest.fixture
def lc(make_lc):
    lifecycle = make_lc(apply=True)
    assert lifecycle.bootstrap()
    return lifecycle


def req(username, role="", action="join", ticket="HR-1"):
    return Request(line=2, username=username, action=action, role=role, ticket=ticket)
