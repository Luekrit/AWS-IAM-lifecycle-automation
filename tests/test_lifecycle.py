from datetime import date, timedelta

from conftest import req

from iam_lifecycle import config
from iam_lifecycle.lifecycle import DONE, FAILED, PLANNED, SKIPPED


def groups_of(iam, user):
    return [g["GroupName"] for g in iam.list_groups_for_user(UserName=user)["Groups"]]


def tags_of(iam, user):
    return {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=user)["Tags"]}


# ------------------------------------------------------------------ bootstrap
def test_bootstrap_creates_groups_with_policies_and_is_idempotent(lc, aws):
    iam = aws.iam
    for role in config.ROLES.values():
        attached = {p["PolicyName"] for p in iam.list_attached_group_policies(GroupName=role.group)["AttachedPolicies"]}
        assert attached == {*role.policies, config.MFA_POLICY}
        assert iam.get_group(GroupName=role.group)["Group"]["Path"] == config.IAM_PATH
    assert iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"] == 14
    assert lc.bootstrap()  # second run: no errors, nothing duplicated


def test_no_account_id_is_hardcoded(aws):
    arn = aws.policy_arn("x")
    assert aws.account_id in arn  # comes from STS at runtime


# --------------------------------------------------------------------- joiner
def test_joiner_creates_governed_user_without_keys(lc, aws):
    assert lc.joiner(req("alice.hr", "hr-analyst")) == DONE
    user = aws.iam.get_user(UserName="alice.hr")["User"]
    assert user["Path"] == config.IAM_PATH
    assert user["PermissionsBoundary"]["PermissionsBoundaryArn"].endswith(config.BOUNDARY_POLICY)
    assert groups_of(aws.iam, "alice.hr") == ["HR-ReadOnly"]
    assert aws.iam.list_attached_user_policies(UserName="alice.hr")["AttachedPolicies"] == []
    assert aws.iam.list_access_keys(UserName="alice.hr")["AccessKeyMetadata"] == []
    tags = tags_of(aws.iam, "alice.hr")
    assert tags[config.TAG_DEPARTMENT] == "hr" and tags[config.TAG_TICKET] == "HR-1"


def test_joiner_is_idempotent(lc):
    assert lc.joiner(req("alice.hr", "hr-analyst")) == DONE
    assert lc.joiner(req("alice.hr", "hr-analyst")) == SKIPPED


def test_joiner_dry_run_changes_nothing(lc, make_lc, aws):
    dry = make_lc(apply=False)
    assert dry.joiner(req("dave.dev", "developer")) == PLANNED
    assert "dave.dev" not in [u["UserName"] for u in aws.iam.list_users()["Users"]]


def test_joiner_fails_cleanly_without_bootstrap(make_lc, aws):
    lc = make_lc(apply=True)
    assert lc.joiner(req("eve", "developer")) == FAILED
    assert aws.iam.list_users()["Users"] == []


def test_joiner_console_password_goes_to_secrets_manager_only(lc, aws, capsys):
    assert lc.joiner(req("alice.hr", "hr-analyst"), console_access=True) == DONE
    assert ("create_login_profile", {"UserName": "alice.hr", "PasswordResetRequired": True}) in aws.iam.calls
    secret = aws.secretsmanager.get_secret_value(SecretId="iamlab/onboarding/alice.hr")["SecretString"]
    password = __import__("json").loads(secret)["password"]
    out = capsys.readouterr()
    assert password not in out.out + out.err
    assert all(password not in str(e) for e in lc.audit.events)


# ---------------------------------------------------------------------- mover
def test_mover_swaps_group_and_revokes_old_credentials(lc, aws):
    lc.joiner(req("bob.dev", "developer"))
    key = aws.iam.create_access_key(UserName="bob.dev")["AccessKey"]["AccessKeyId"]
    aws.iam.create_login_profile(UserName="bob.dev", Password="Old-Passw0rd!xyz", PasswordResetRequired=False)

    assert lc.mover(req("bob.dev", "security-analyst", action="move")) == DONE
    assert groups_of(aws.iam, "bob.dev") == ["Security-AWS"]
    keys = aws.iam.list_access_keys(UserName="bob.dev")["AccessKeyMetadata"]
    assert [(k["AccessKeyId"], k["Status"]) for k in keys] == [(key, "Inactive")]
    assert ("update_login_profile", {"UserName": "bob.dev", "PasswordResetRequired": True}) in aws.iam.calls
    assert tags_of(aws.iam, "bob.dev")[config.TAG_DEPARTMENT] == "security"


def test_mover_removes_legacy_direct_policies(lc, aws):
    lc.joiner(req("bob.dev", "developer"))
    arn = aws.policy_arn("iamlab-ec2-developer")
    aws.iam.attach_user_policy(UserName="bob.dev", PolicyArn=arn)
    lc.mover(req("bob.dev", "security-analyst", action="move"))
    assert aws.iam.list_attached_user_policies(UserName="bob.dev")["AttachedPolicies"] == []


def test_mover_does_not_create_missing_users(lc, aws):
    assert lc.mover(req("ghost", "developer", action="move")) == FAILED
    assert aws.iam.list_users()["Users"] == []


def test_mover_refuses_users_outside_managed_path(lc, aws):
    aws.iam.create_user(UserName="admin")
    assert lc.mover(req("admin", "developer", action="move")) == FAILED
    assert groups_of(aws.iam, "admin") == []


# --------------------------------------------------------------------- leaver
def _leaver_with_everything(lc, aws):
    lc.joiner(req("carol.sec", "security-analyst"))
    iam = aws.iam
    iam.create_access_key(UserName="carol.sec")
    iam.create_login_profile(UserName="carol.sec", Password="Some-Passw0rd!xyz")
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="carol.sec")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="carol.sec", SerialNumber=mfa, AuthenticationCode1="123456",
                          AuthenticationCode2="654321")
    iam.put_user_policy(UserName="carol.sec", PolicyName="sneaky",
                        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')
    return mfa


def test_leaver_revokes_everything_but_keeps_identity(lc, aws):
    _leaver_with_everything(lc, aws)
    assert lc.leaver(req("carol.sec", action="leave")) == DONE
    iam = aws.iam
    assert iam.list_user_policies(UserName="carol.sec")["PolicyNames"] == [config.QUARANTINE_INLINE_POLICY]
    assert all(k["Status"] == "Inactive" for k in iam.list_access_keys(UserName="carol.sec")["AccessKeyMetadata"])
    assert groups_of(iam, "carol.sec") == []
    assert tags_of(iam, "carol.sec")[config.TAG_STATUS] == config.STATUS_TERMINATED
    try:
        iam.get_login_profile(UserName="carol.sec")
        raise AssertionError("login profile should be gone")
    except iam.exceptions.NoSuchEntityException:
        pass
    assert iam.get_user(UserName="carol.sec")  # retained for audit


def test_leaver_quarantine_is_the_first_action(lc, aws):
    _leaver_with_everything(lc, aws)
    lc.leaver(req("carol.sec", action="leave"))
    actions = [e["action"] for e in lc.audit.events if e["target"] == "carol.sec" and e["ticket"] == "HR-1"
               and e["action"] not in ("create_user", "add_to_group")]
    assert actions[0] == "attach_quarantine_deny_all"


def test_purge_respects_retention_then_deletes_completely(lc, aws):
    _leaver_with_everything(lc, aws)
    lc.leaver(req("carol.sec", action="leave"))
    assert lc.purge(today=date.today() + timedelta(days=5)) == []
    assert lc.purge(today=date.today() + timedelta(days=config.LEAVER_RETENTION_DAYS + 1)) == ["carol.sec"]
    assert "carol.sec" not in [u["UserName"] for u in aws.iam.list_users()["Users"]]
    assert aws.iam.list_virtual_mfa_devices()["VirtualMFADevices"] == []


def test_purge_ignores_active_users_and_unmanaged_path(lc, aws):
    lc.joiner(req("alice.hr", "hr-analyst"))
    aws.iam.create_user(UserName="breakglass", Tags=[{"Key": config.TAG_STATUS, "Value": "terminated"},
                                                     {"Key": config.TAG_STATUS_DATE, "Value": "2000-01-01"}])
    assert lc.purge(today=date.today() + timedelta(days=365)) == []
    names = {u["UserName"] for u in aws.iam.list_users()["Users"]}
    assert {"alice.hr", "breakglass"} <= names


def test_leaver_refuses_unmanaged_users(lc, aws):
    aws.iam.create_user(UserName="admin")
    assert lc.leaver(req("admin", action="leave")) == FAILED
    assert aws.iam.list_user_policies(UserName="admin")["PolicyNames"] == []


def test_audit_log_is_jsonl_with_actor(lc, aws):
    lc.joiner(req("alice.hr", "hr-analyst"))
    import json
    lines = [json.loads(line) for line in lc.audit.path.read_text().splitlines()]
    assert lines and all(e["actor"] == aws.actor and "run_id" in e for e in lines)
