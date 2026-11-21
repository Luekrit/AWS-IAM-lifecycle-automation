"""Shared command-line plumbing for the phase scripts."""

from __future__ import annotations

import argparse
import logging
import sys

from .audit import AuditLog
from .aws import AwsContext, build_context
from .lifecycle import FAILED, Lifecycle


def base_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--apply", action="store_true",
                   help="Make the changes. Without this flag the script only shows what it would do (dry run).")
    p.add_argument("--yes", action="store_true", help="Skip the interactive confirmation (for CI pipelines).")
    p.add_argument("--profile", help="AWS CLI profile (e.g. an IAM Identity Center profile from `aws configure sso`).")
    p.add_argument("--role-arn", help="Assume this operator role (least privilege) before running.")
    p.add_argument("--region", default=None, help="AWS region for regional services such as Secrets Manager.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def setup(args) -> tuple[AwsContext, AuditLog, Lifecycle]:
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("botocore").setLevel(logging.WARNING)
    ctx = build_context(profile=args.profile, role_arn=args.role_arn, region=args.region)
    audit = AuditLog(actor=ctx.actor, dry_run=not args.apply)
    logging.getLogger("iamlab").info("Account %s | actor %s | mode %s",
                                     ctx.account_id, ctx.actor, "APPLY" if args.apply else "DRY-RUN")
    return ctx, audit, Lifecycle(ctx, audit, apply=args.apply)


def confirm(args, summary: str) -> bool:
    if not args.apply or args.yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to apply changes non-interactively without --yes.", file=sys.stderr)
        return False
    answer = input(f"{summary}\nType 'apply' to continue: ").strip().lower()
    return answer == "apply"


def finish(audit: AuditLog, results: list[str]) -> int:
    print(f"\nDone. {len(results)} request(s): " +
          ", ".join(f"{r}={results.count(r)}" for r in sorted(set(results))) +
          f". Audit log: {audit.path}")
    if audit.dry_run:
        print("This was a DRY RUN. Re-run with --apply to make the changes.")
    return 1 if FAILED in results or audit.failures else 0
