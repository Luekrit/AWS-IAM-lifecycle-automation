"""AWS session handling. No credentials or account IDs are stored in code.

Credentials come from the standard boto3 chain (an SSO profile via
``aws sso login`` is recommended). Pass ``--role-arn`` to assume the scoped
``iamlab-jml-operator`` role instead of running with your own admin rights.
"""

from __future__ import annotations

import getpass
import re
from dataclasses import dataclass
from functools import cached_property

import boto3
from botocore.config import Config

from . import config

BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"}, user_agent_extra="iamlab-jml/2")


@dataclass
class AwsContext:
    session: boto3.session.Session

    @cached_property
    def iam(self):
        return self.session.client("iam", config=BOTO_CONFIG)

    @cached_property
    def sts(self):
        return self.session.client("sts", config=BOTO_CONFIG)

    @cached_property
    def secretsmanager(self):
        return self.session.client("secretsmanager", config=BOTO_CONFIG)

    @cached_property
    def identity(self) -> dict:
        return self.sts.get_caller_identity()

    @property
    def account_id(self) -> str:
        return self.identity["Account"]

    @property
    def partition(self) -> str:
        return self.identity["Arn"].split(":")[1]

    @property
    def actor(self) -> str:
        return self.identity["Arn"]

    def policy_arn(self, name: str) -> str:
        return f"arn:{self.partition}:iam::{self.account_id}:policy{config.IAM_PATH}{name}"


def build_context(profile: str | None = None, role_arn: str | None = None, region: str | None = None) -> AwsContext:
    session = boto3.session.Session(profile_name=profile, region_name=region)
    if role_arn:
        sts = session.client("sts", config=BOTO_CONFIG)
        operator = re.sub(r"[^\w+=,.@-]", "-", getpass.getuser())[:40]
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"iamlab-jml-{operator}",
            DurationSeconds=3600,
        )["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=session.region_name,
        )
    return AwsContext(session=session)


def paginate(client, operation: str, key: str, **kwargs):
    """Yield every item across all pages of a list_* call."""
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(key, [])
