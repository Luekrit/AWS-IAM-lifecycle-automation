"""Joiner: provision new workforce identities from a validated CSV.

Each user is created under the /iamlab/ path with the lab permissions boundary,
tagged with role/department/ticket, and added to the role's group. No access
keys are ever created. Use --console-access to issue a one-time console password
that is stored in Secrets Manager (never printed) and must be reset at first sign-in.

    python Joiner.py                       # dry run using Joiner.csv
    python Joiner.py --apply               # provision
    python Joiner.py --csv other.csv --apply --console-access --region ap-southeast-2
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.cli import base_parser, confirm, finish, setup  # noqa: E402
from iam_lifecycle.csvio import CsvValidationError, load_requests  # noqa: E402

DEFAULT_CSV = Path(__file__).with_name("Joiner.csv")


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--console-access", action="store_true",
                        help="Create a console password (stored in Secrets Manager, reset required at first sign-in).")
    args = parser.parse_args()

    try:
        requests = load_requests(args.csv, "joiner")
    except CsvValidationError as exc:
        print(f"CSV validation failed - nothing was changed:\n{exc}", file=sys.stderr)
        return 2

    _, audit, lc = setup(args)
    if not confirm(args, f"About to onboard {len(requests)} user(s) from {args.csv.name}."):
        return 1
    results = [lc.joiner(r, console_access=args.console_access) for r in requests]
    return finish(audit, results)


if __name__ == "__main__":
    sys.exit(main())
