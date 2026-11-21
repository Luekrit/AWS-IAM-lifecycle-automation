"""Joiner / Mover / Leaver operations.

Design rules:
* Dry-run by default: every function records what it *would* do unless ``apply=True``.
* Permissions live on groups only. Users are never given directly attached policies.
* Every user gets the lab permissions boundary and lives under ``config.IAM_PATH``.
  Anything outside that path is refused, so a typo cannot touch an admin account.
* Automation never creates access keys. Console passwords (optional) are written
  straight to Secrets Manager and never printed.
* Leavers are revoked immediately (deny-all first) and purged after a retention period.
"""

from __future__ import annotations

import json
import secrets
import string
from datetime import UTC, date, datetime

from botocore.exceptions import ClientError

from . import config
from .audit import AuditLog
from .aws import AwsContext, paginate
from .csvio import Request

PLANNED, DONE, SKIPPED, FAILED = "planned", "success", "skipped", "failed"


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def _err_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


class Lifecycle:
    def __init__(self, ctx: AwsContext, audit: AuditLog, apply: bool = False):
        self.ctx = ctx
        self.iam = ctx.iam
        self.audit = audit
        self.apply = apply

    # ------------------------------------------------------------------ helpers
    def _get_user(self, username: str) -> dict | None:
        try:
            return self.iam.get_user(UserName=username)["User"]
        except self.iam.exceptions.NoSuchEntityException:
            return None

    def _tags(self, username: str) -> dict[str, str]:
        return {t["Key"]: t["Value"] for t in paginate(self.iam, "list_user_tags", "Tags", UserName=username)}

    def _group_exists(self, group: str) -> bool:
        try:
            self.iam.get_group(GroupName=group, MaxItems=1)
            return True
        except self.iam.exceptions.NoSuchEntityException:
            return False

    def _guard_managed(self, user: dict, action: str, ticket: str) -> bool:
        if user.get("Path") != config.IAM_PATH:
            self.audit.record(action, user["UserName"], FAILED, ticket,
                              reason=f"user is outside managed path {config.IAM_PATH}; refusing to modify")
            return False
        return True

    def _step(self, action: str, target: str, ticket: str, fn, **details) -> bool:
        """Run one AWS mutation (or just record it in dry-run)."""
        if not self.apply:
            self.audit.record(action, target, PLANNED, ticket, **details)
            return True
        try:
            fn()
        except ClientError as exc:
            self.audit.record(action, target, FAILED, ticket, error=_err_code(exc), message=str(exc), **details)
            return False
        self.audit.record(action, target, DONE, ticket, **details)
        return True

    def _status_tags(self, status: str, ticket: str, role: config.Role | None = None) -> list[dict]:
        tags = {
            config.TAG_STATUS: status,
            config.TAG_STATUS_DATE: _today(),
            config.TAG_TICKET: ticket,
            config.TAG_MANAGED_BY: "iamlab-jml",
        }
        if role:
            tags[config.TAG_ROLE] = role.name
            tags[config.TAG_DEPARTMENT] = role.department
        return [{"Key": k, "Value": v} for k, v in tags.items()]

    def _strip_access(self, username: str, ticket: str, keep_inline: tuple[str, ...] = ()) -> bool:
        ok = True
        for g in list(paginate(self.iam, "list_groups_for_user", "Groups", UserName=username)):
            ok &= self._step("remove_from_group", username, ticket,
                             lambda g=g: self.iam.remove_user_from_group(UserName=username, GroupName=g["GroupName"]),
                             group=g["GroupName"])
        for p in list(paginate(self.iam, "list_attached_user_policies", "AttachedPolicies", UserName=username)):
            ok &= self._step("detach_user_policy", username, ticket,
                             lambda p=p: self.iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"]),
                             policy=p["PolicyName"])
        for name in list(paginate(self.iam, "list_user_policies", "PolicyNames", UserName=username)):
            if name in keep_inline:
                continue
            ok &= self._step("delete_inline_policy", username, ticket,
                             lambda n=name: self.iam.delete_user_policy(UserName=username, PolicyName=n), policy=name)
        return ok

    def _set_access_keys(self, username: str, ticket: str, status: str = "Inactive") -> bool:
        ok = True
        for key in list(paginate(self.iam, "list_access_keys", "AccessKeyMetadata", UserName=username)):
            if key["Status"] == status:
                continue
            ok &= self._step("deactivate_access_key", username, ticket,
                             lambda k=key: self.iam.update_access_key(UserName=username, AccessKeyId=k["AccessKeyId"],
                                                                      Status=status),
                             key_suffix=key["AccessKeyId"][-4:])
        return ok

    def _service_credentials(self, username: str) -> list[dict]:
        """CodeCommit/Keyspaces/Bedrock service-specific credentials (not paginated by AWS)."""
        return self.iam.list_service_specific_credentials(UserName=username).get("ServiceSpecificCredentials", [])

    def _has_login_profile(self, username: str) -> bool:
        try:
            self.iam.get_login_profile(UserName=username)
            return True
        except self.iam.exceptions.NoSuchEntityException:
            return False

    # ---------------------------------------------------------------- bootstrap
    def bootstrap(self) -> bool:
        """Create/refresh the lab's managed policies and RBAC groups (idempotent)."""
        ok = True
        for name, filename in config.MANAGED_POLICIES.items():
            document = json.loads((config.POLICY_DIR / filename).read_text(encoding="utf-8"))
            ok &= self._ensure_policy(name, document)

        for role in config.ROLES.values():
            if not self._group_exists(role.group):
                ok &= self._step("create_group", role.group, "", lambda r=role: self.iam.create_group(
                    GroupName=r.group, Path=config.IAM_PATH))
            wanted = {self.ctx.policy_arn(p) for p in (*role.policies, *config.BASELINE_GROUP_POLICIES)}
            attached = set()
            if self._group_exists(role.group):
                attached = {p["PolicyArn"] for p in paginate(self.iam, "list_attached_group_policies",
                                                              "AttachedPolicies", GroupName=role.group)}
            for arn in sorted(wanted - attached):
                ok &= self._step("attach_group_policy", role.group, "",
                                 lambda a=arn, r=role: self.iam.attach_group_policy(GroupName=r.group, PolicyArn=a),
                                 policy=arn.rsplit("/", 1)[-1])
            for arn in sorted(attached - wanted):
                ok &= self._step("detach_unexpected_group_policy", role.group, "",
                                 lambda a=arn, r=role: self.iam.detach_group_policy(GroupName=r.group, PolicyArn=a),
                                 policy=arn.rsplit("/", 1)[-1])

        ok &= self._step("set_account_password_policy", "account", "", lambda: self.iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            PasswordReusePrevention=24,
        ))
        return ok

    def _ensure_policy(self, name: str, document: dict) -> bool:
        arn = self.ctx.policy_arn(name)
        body = json.dumps(document)
        try:
            policy = self.iam.get_policy(PolicyArn=arn)["Policy"]
        except self.iam.exceptions.NoSuchEntityException:
            return self._step("create_policy", name, "", lambda: self.iam.create_policy(
                PolicyName=name, Path=config.IAM_PATH, PolicyDocument=body,
                Description="Managed by iamlab-jml bootstrap",
                Tags=[{"Key": config.TAG_MANAGED_BY, "Value": "iamlab-jml"}]))

        current = self.iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]
        current_doc = current["Document"]
        if isinstance(current_doc, str):
            from urllib.parse import unquote
            current_doc = json.loads(unquote(current_doc))
        if current_doc == document:
            self.audit.record("ensure_policy", name, SKIPPED, reason="already up to date")
            return True

        def update():
            versions = self.iam.list_policy_versions(PolicyArn=arn)["Versions"]
            if len(versions) >= 5:  # IAM keeps at most 5 versions
                oldest = min((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])
                self.iam.delete_policy_version(PolicyArn=arn, VersionId=oldest["VersionId"])
            self.iam.create_policy_version(PolicyArn=arn, PolicyDocument=body, SetAsDefault=True)

        return self._step("update_policy", name, "", update)

    # ------------------------------------------------------------------- joiner
    def joiner(self, req: Request, console_access: bool = False) -> str:
        role = config.ROLES[req.role]
        if self._get_user(req.username):
            self.audit.record("joiner", req.username, SKIPPED, req.ticket, reason="user already exists")
            return SKIPPED
        if not self._group_exists(role.group):
            self.audit.record("joiner", req.username, FAILED, req.ticket,
                              reason=f"group {role.group} not found - run bootstrap.py first")
            return FAILED

        boundary = self.ctx.policy_arn(config.BOUNDARY_POLICY)
        created = self._step("create_user", req.username, req.ticket, lambda: self.iam.create_user(
            UserName=req.username,
            Path=config.IAM_PATH,
            PermissionsBoundary=boundary,
            Tags=self._status_tags(config.STATUS_ACTIVE, req.ticket, role),
        ), role=role.name, boundary=config.BOUNDARY_POLICY)
        if not created:
            return FAILED

        if not self._step("add_to_group", req.username, req.ticket,
                          lambda: self.iam.add_user_to_group(UserName=req.username, GroupName=role.group),
                          group=role.group):
            self._rollback_user(req)
            return FAILED

        if console_access and not self._issue_console_password(req):
            self._rollback_user(req)
            return FAILED

        return DONE if self.apply else PLANNED

    def _rollback_user(self, req: Request) -> None:
        if not self.apply:
            return
        try:
            self._strip_access(req.username, req.ticket)
            if self._has_login_profile(req.username):
                self.iam.delete_login_profile(UserName=req.username)
            self.iam.delete_user(UserName=req.username)
            self.audit.record("rollback_user", req.username, DONE, req.ticket)
        except ClientError as exc:
            self.audit.record("rollback_user", req.username, FAILED, req.ticket, error=_err_code(exc))

    @staticmethod
    def _random_password(length: int = 24) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        while True:
            pw = "".join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                    and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
                return pw

    def _issue_console_password(self, req: Request) -> bool:
        password = self._random_password()
        secret_name = f"{config.ONBOARDING_SECRET_PREFIX}{req.username}"
        if not self._step("create_login_profile", req.username, req.ticket, lambda: self.iam.create_login_profile(
                UserName=req.username, Password=password, PasswordResetRequired=True)):
            return False
        return self._step("store_onboarding_secret", req.username, req.ticket,
                          lambda: self.ctx.secretsmanager.create_secret(
                              Name=secret_name,
                              Description="One-time console password; user must reset at first sign-in",
                              SecretString=json.dumps({"username": req.username, "password": password}),
                              Tags=[{"Key": config.TAG_TICKET, "Value": req.ticket},
                                    {"Key": config.TAG_MANAGED_BY, "Value": "iamlab-jml"}]),
                          secret=secret_name)

    # -------------------------------------------------------------------- mover
    def mover(self, req: Request) -> str:
        role = config.ROLES[req.role]
        user = self._get_user(req.username)
        if not user:
            self.audit.record("mover", req.username, FAILED, req.ticket,
                              reason="user does not exist - onboard through the joiner process")
            return FAILED
        if not self._guard_managed(user, "mover", req.ticket):
            return FAILED
        if self._tags(req.username).get(config.TAG_STATUS) == config.STATUS_TERMINATED:
            self.audit.record("mover", req.username, FAILED, req.ticket, reason="user is a terminated leaver")
            return FAILED
        if not self._group_exists(role.group):
            self.audit.record("mover", req.username, FAILED, req.ticket,
                              reason=f"group {role.group} not found - run bootstrap.py first")
            return FAILED

        groups = [g["GroupName"] for g in paginate(self.iam, "list_groups_for_user", "Groups", UserName=req.username)]
        if groups == [role.group]:
            self.audit.record("mover", req.username, SKIPPED, req.ticket, reason=f"already in {role.group}")
            return SKIPPED

        # 1. Remove old access first (least privilege: never hold old + new at once)
        ok = self._strip_access(req.username, req.ticket)
        # 2. Grant the new role through its group
        ok &= self._step("add_to_group", req.username, req.ticket,
                         lambda: self.iam.add_user_to_group(UserName=req.username, GroupName=role.group),
                         group=role.group, previous_groups=groups)
        # 3. Credentials issued under the old role are not trusted for the new one
        ok &= self._set_access_keys(req.username, req.ticket)
        if self._has_login_profile(req.username):
            ok &= self._step("force_password_reset", req.username, req.ticket,
                             lambda: self.iam.update_login_profile(UserName=req.username, PasswordResetRequired=True))
        # 4. Update governance metadata (drives ABAC department scoping)
        ok &= self._step("tag_user", req.username, req.ticket, lambda: self.iam.tag_user(
            UserName=req.username, Tags=self._status_tags(config.STATUS_ACTIVE, req.ticket, role)))

        if not ok:
            return FAILED
        return DONE if self.apply else PLANNED

    # ------------------------------------------------------------------- leaver
    def leaver(self, req: Request) -> str:
        """Immediately revoke all access. The identity is kept (disabled) for the retention period."""
        user = self._get_user(req.username)
        if not user:
            self.audit.record("leaver", req.username, SKIPPED, req.ticket, reason="user does not exist")
            return SKIPPED
        if not self._guard_managed(user, "leaver", req.ticket):
            return FAILED

        u = req.username
        # 1. Deny-all FIRST: also neutralises any session or key we have not reached yet
        quarantine = (config.POLICY_DIR / "leaver-quarantine-deny-all.json").read_text(encoding="utf-8")
        ok = self._step("attach_quarantine_deny_all", u, req.ticket, lambda: self.iam.put_user_policy(
            UserName=u, PolicyName=config.QUARANTINE_INLINE_POLICY, PolicyDocument=quarantine))
        # 2. Kill every credential type
        if self._has_login_profile(u):
            ok &= self._step("delete_login_profile", u, req.ticket, lambda: self.iam.delete_login_profile(UserName=u))
        ok &= self._set_access_keys(u, req.ticket)
        for key in list(paginate(self.iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=u)):
            if key["Status"] != "Inactive":
                ok &= self._step("deactivate_ssh_key", u, req.ticket, lambda k=key: self.iam.update_ssh_public_key(
                    UserName=u, SSHPublicKeyId=k["SSHPublicKeyId"], Status="Inactive"))
        for cert in list(paginate(self.iam, "list_signing_certificates", "Certificates", UserName=u)):
            if cert["Status"] != "Inactive":
                ok &= self._step("deactivate_signing_cert", u, req.ticket, lambda c=cert: self.iam.update_signing_certificate(
                    UserName=u, CertificateId=c["CertificateId"], Status="Inactive"))
        for cred in self._service_credentials(u):
            if cred["Status"] != "Inactive":
                ok &= self._step("deactivate_service_credential", u, req.ticket,
                                 lambda c=cred: self.iam.update_service_specific_credential(
                                     UserName=u, ServiceSpecificCredentialId=c["ServiceSpecificCredentialId"],
                                     Status="Inactive"))
        # 3. Remove entitlements
        ok &= self._strip_access(u, req.ticket, keep_inline=(config.QUARANTINE_INLINE_POLICY,))
        # 4. Mark for retention-based purge
        ok &= self._step("tag_user", u, req.ticket, lambda: self.iam.tag_user(
            UserName=u, Tags=self._status_tags(config.STATUS_TERMINATED, req.ticket)))

        if not ok:
            return FAILED
        return DONE if self.apply else PLANNED

    # -------------------------------------------------------------------- purge
    def purge(self, today: date | None = None, retention_days: int = config.LEAVER_RETENTION_DAYS) -> list[str]:
        """Delete leavers whose retention period has expired. Returns the usernames handled."""
        today = today or datetime.now(UTC).date()
        handled = []
        for user in list(paginate(self.iam, "list_users", "Users", PathPrefix=config.IAM_PATH)):
            u = user["UserName"]
            tags = self._tags(u)
            if tags.get(config.TAG_STATUS) != config.STATUS_TERMINATED:
                continue
            try:
                terminated_on = date.fromisoformat(tags.get(config.TAG_STATUS_DATE, ""))
            except ValueError:
                self.audit.record("purge", u, FAILED, tags.get(config.TAG_TICKET, ""), reason="missing/invalid status date")
                continue
            age = (today - terminated_on).days
            if age < retention_days:
                self.audit.record("purge", u, SKIPPED, tags.get(config.TAG_TICKET, ""),
                                  reason=f"in retention ({age}/{retention_days} days)")
                continue
            handled.append(u)
            self._delete_user_completely(u, tags.get(config.TAG_TICKET, ""))
        return handled

    def _delete_user_completely(self, u: str, ticket: str) -> bool:
        iam = self.iam
        ok = True
        if self._has_login_profile(u):
            ok &= self._step("delete_login_profile", u, ticket, lambda: iam.delete_login_profile(UserName=u))
        for k in list(paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=u)):
            ok &= self._step("delete_access_key", u, ticket,
                             lambda k=k: iam.delete_access_key(UserName=u, AccessKeyId=k["AccessKeyId"]),
                             key_suffix=k["AccessKeyId"][-4:])
        for k in list(paginate(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=u)):
            ok &= self._step("delete_ssh_key", u, ticket,
                             lambda k=k: iam.delete_ssh_public_key(UserName=u, SSHPublicKeyId=k["SSHPublicKeyId"]))
        for c in list(paginate(iam, "list_signing_certificates", "Certificates", UserName=u)):
            ok &= self._step("delete_signing_cert", u, ticket,
                             lambda c=c: iam.delete_signing_certificate(UserName=u, CertificateId=c["CertificateId"]))
        for c in self._service_credentials(u):
            ok &= self._step("delete_service_credential", u, ticket,
                             lambda c=c: iam.delete_service_specific_credential(
                                 UserName=u, ServiceSpecificCredentialId=c["ServiceSpecificCredentialId"]))
        for d in list(paginate(iam, "list_mfa_devices", "MFADevices", UserName=u)):
            serial = d["SerialNumber"]

            def remove_mfa(serial=serial):
                iam.deactivate_mfa_device(UserName=u, SerialNumber=serial)
                if ":mfa/" in serial:  # virtual device
                    iam.delete_virtual_mfa_device(SerialNumber=serial)

            ok &= self._step("remove_mfa_device", u, ticket, remove_mfa)
        ok &= self._strip_access(u, ticket)  # also deletes the quarantine policy last
        if ok:
            ok &= self._step("delete_user", u, ticket, lambda: iam.delete_user(UserName=u))
        else:
            self.audit.record("delete_user", u, FAILED, ticket, reason="earlier cleanup step failed; user kept")
        return ok
