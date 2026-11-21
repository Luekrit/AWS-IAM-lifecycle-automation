"""Role catalog and governance constants.

The CSV files only say *who* and *which role*. What a role is allowed to do is
decided here, in reviewed code, so editing a CSV can never grant an arbitrary
policy. Nothing in this module (or anywhere in the repo) contains an account
ID: ARNs are built at runtime from the caller's STS identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "Phase1_Manual_Identity_Lifecycle_Simulation_Setup"

# Every identity, group and policy this lab manages lives under this IAM path.
# The automation operator policy is scoped to it, so the scripts cannot touch
# break-glass admins or anything else in the account.
IAM_PATH = "/iamlab/"
PREFIX = "iamlab-"

BOUNDARY_POLICY = f"{PREFIX}user-boundary"
MFA_POLICY = f"{PREFIX}enforce-mfa"
QUARANTINE_INLINE_POLICY = "LeaverQuarantineDenyAll"
ONBOARDING_SECRET_PREFIX = "iamlab/onboarding/"

# Leavers are disabled immediately and only purged after this many days, so the
# identity record stays available for investigations and audit.
LEAVER_RETENTION_DAYS = 30

# Access-review thresholds (aligned with the CIS AWS Foundations Benchmark
# recommendations on MFA, credential rotation and unused credentials).
KEY_MAX_AGE_DAYS = 90
CREDENTIAL_UNUSED_DAYS = 45
USER_INACTIVE_DAYS = 90

# Tag keys
TAG_DEPARTMENT = "department"  # lowercase: used for ABAC in s3/ec2/lambda policies
TAG_ROLE = "role"
TAG_STATUS = "lifecycle-status"
TAG_TICKET = "ticket"
TAG_STATUS_DATE = "lifecycle-status-date"
TAG_MANAGED_BY = "managed-by"

STATUS_ACTIVE = "active"
STATUS_TERMINATED = "terminated"


@dataclass(frozen=True)
class Role:
    name: str
    group: str
    department: str
    policies: tuple[str, ...]
    # Roles that must never be held together (segregation of duties).
    incompatible_with: tuple[str, ...] = field(default_factory=tuple)


# managed-policy name -> JSON file in POLICY_DIR
MANAGED_POLICIES: dict[str, str] = {
    BOUNDARY_POLICY: "user-permissions-boundary.json",
    MFA_POLICY: "enforce-mfa.json",
    f"{PREFIX}s3-department-readonly": "s3-readonly.json",
    f"{PREFIX}ec2-developer": "ec2-developer.json",
    f"{PREFIX}lambda-developer": "lambda-developer.json",
    f"{PREFIX}security-audit": "security-audit.json",
}

ROLES: dict[str, Role] = {
    "hr-analyst": Role(
        name="hr-analyst",
        group="HR-ReadOnly",
        department="hr",
        policies=(f"{PREFIX}s3-department-readonly",),
    ),
    "developer": Role(
        name="developer",
        group="Developers-AWS",
        department="development",
        policies=(f"{PREFIX}ec2-developer", f"{PREFIX}lambda-developer"),
        incompatible_with=("security-analyst",),
    ),
    "security-analyst": Role(
        name="security-analyst",
        group="Security-AWS",
        department="security",
        policies=(f"{PREFIX}security-audit",),
        incompatible_with=("developer",),
    ),
}

# Attached to every workforce group on top of the role's own policies.
BASELINE_GROUP_POLICIES: tuple[str, ...] = (MFA_POLICY,)


def role_for_group(group_name: str) -> Role | None:
    return next((r for r in ROLES.values() if r.group == group_name), None)
