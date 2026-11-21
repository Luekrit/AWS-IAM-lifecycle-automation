"""Process Mover and Leaver requests from one lifecycle CSV.

    python mover_leaver.py              # dry run using mover_leaver.csv
    python mover_leaver.py --apply      # make the changes (asks for confirmation)

Movers: old groups removed first, new role group added, access keys deactivated,
password reset forced, tags updated. Leavers: deny-all quarantine first, every
credential disabled, entitlements removed, user tagged terminated and kept for
the retention period (purge with: python leaver.py --purge --apply).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.cli import base_parser, confirm, finish, setup  # noqa: E402
from iam_lifecycle.csvio import CsvValidationError, load_requests  # noqa: E402

DEFAULT_CSV = Path(__file__).with_name("mover_leaver.csv")


def run(actions: set[str], description: str) -> int:
    parser = base_parser(description)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    args = parser.parse_args()

    try:
        requests = [r for r in load_requests(args.csv, "lifecycle") if r.action in actions]
    except CsvValidationError as exc:
        print(f"CSV validation failed - nothing was changed:\n{exc}", file=sys.stderr)
        return 2
    if not requests:
        print(f"No {'/'.join(sorted(actions))} rows in {args.csv.name}.")
        return 0

    _, audit, lc = setup(args)
    summary = ", ".join(f"{r.action} {r.username}" for r in requests)
    if not confirm(args, f"About to process: {summary}"):
        return 1

    results = []
    for r in requests:
        if r.action == "move":
            results.append(lc.mover(r))
        elif r.action == "leave":
            results.append(lc.leaver(r))
    return finish(audit, results)


if __name__ == "__main__":
    sys.exit(run({"move", "leave"}, __doc__))
