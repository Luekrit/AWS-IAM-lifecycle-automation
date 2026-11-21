"""Phase 4, step 1: rule-based access review (read-only).

Pulls the IAM credential report plus group/tag/policy data and flags:
root key/MFA issues, console users without MFA, stale or unused access keys,
leavers who still have access, permissions attached directly to users,
missing permissions boundaries, segregation-of-duties conflicts and
department-tag drift (which would break ABAC scoping).

    python access_review.py --profile iamlab
    python access_review.py --fail-on high        # non-zero exit for CI / scheduled runs

Writes reports/access-review-<timestamp>.json and .md (git-ignored).
"""

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.aws import build_context  # noqa: E402
from iam_lifecycle.config import REPO_ROOT  # noqa: E402
from iam_lifecycle.review import SEVERITY_ORDER, review, to_markdown  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile")
    p.add_argument("--role-arn")
    p.add_argument("--out-dir", type=Path, default=REPO_ROOT / "reports")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                   help="Exit 1 if any finding is at or above this severity.")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    ctx = build_context(profile=args.profile, role_arn=args.role_arn)
    now = datetime.now(UTC)
    findings = review(ctx.iam, now=now)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.out_dir / f"access-review-{now:%Y%m%dT%H%M%SZ}"
    stem.with_suffix(".json").write_text(json.dumps({
        "generated": now.isoformat(), "account": ctx.account_id, "reviewer": ctx.actor,
        "findings": [f.as_dict() for f in findings]}, indent=2), encoding="utf-8")
    stem.with_suffix(".md").write_text(to_markdown(findings, now), encoding="utf-8")

    for f in findings:
        print(f"[{f.severity.upper():8}] {f.rule:<30} {f.user:<20} {f.detail}")
    print(f"\n{len(findings)} finding(s). Reports: {stem}.json / .md")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
