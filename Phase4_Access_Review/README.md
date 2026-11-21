## Phase 4: Identity Analytics, step 1: Rule-Based Access Review

### Objective

Continuously answer "who has access they should not have?" Phase 4 starts with a **deterministic, explainable** review. Every finding maps to a governance control. ML-based anomaly detection on CloudTrail is the planned next step and is **not implemented yet**.

---

### What `access_review.py` checks

| Severity | Rule | What it means |
|---|---|---|
| critical | `root-access-key` | The root user has an active access key |
| critical | `root-no-mfa` | The root user has no MFA |
| critical | `leaver-still-has-access` | A user tagged `terminated` still has an active key, a console password or a group |
| high | `console-without-mfa` | Console access without MFA |
| high | `stale-access-key` | Active access key older than 90 days |
| high | `missing-permissions-boundary` | A governed (`/iamlab/`) user has no permissions boundary |
| high | `segregation-of-duties` | User holds incompatible roles (e.g. developer + security analyst) |
| medium | `long-term-access-key` | Any active IAM user key (temporary credentials are preferred) |
| medium | `unused-access-key` / `unused-password` | Credential unused for 45+ days |
| medium | `direct-user-policy` | Permissions attached to the user instead of a group (RBAC bypass) |
| medium | `department-tag-mismatch` | `department` tag does not match the role group, which would break ABAC scoping |
| medium | `root-recent-use` | Root signed in during the last 30 days |
| low | `unmanaged-identity` | User outside `/iamlab/`, not governed by the JML process |

Thresholds are in `iam_lifecycle/config.py` and follow the CIS AWS Foundations Benchmark recommendations on MFA, key rotation and unused credentials.

---

### How to run

```bash
python access_review.py --profile iamlab                 # any role with security-audit.json is enough
python access_review.py --profile iamlab --fail-on high  # exit 1 if high/critical findings (for scheduled runs)
```

Outputs `reports/access-review-<timestamp>.json` and `.md` (git-ignored, because they contain identities).

---

### Roadmap

1. **Now:** rule-based review of the credential report and entitlements (this script).
2. **Next:** CloudTrail analysis: after-hours activity, new source IPs/regions, privilege-escalation API sequences (`AttachUserPolicy`, `CreateAccessKey`, `PassRole`), using rule thresholds first.
3. **Then:** unsupervised anomaly detection (e.g. Isolation Forest) on per-identity activity features, using the rule findings to evaluate it.
