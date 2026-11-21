"""Validate a lifecycle CSV without calling AWS.

    python validate_csv.py                                  # checks Joiner.csv
    python validate_csv.py ../Phase3_mover_leaver_automation/mover_leaver.csv --schema lifecycle

Checks: required columns, username format, role exists in the role catalog,
ticket reference present, valid action, no duplicates, no spreadsheet formulas.
Exit code 0 = valid, 2 = invalid.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.csvio import CsvValidationError, load_requests  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv", nargs="?", type=Path, default=Path(__file__).with_name("Joiner.csv"))
    p.add_argument("--schema", choices=["joiner", "lifecycle"], default="joiner")
    args = p.parse_args()
    try:
        requests = load_requests(args.csv, args.schema)
    except CsvValidationError as exc:
        print(f"INVALID: {args.csv}")
        for e in exc.errors:
            print(f"  - {e}")
        return 2
    print(f"VALID: {args.csv} ({len(requests)} request(s))")
    for r in requests:
        print(f"  line {r.line}: {r.action:<5} {r.username:<15} role={r.role or '-':<17} ticket={r.ticket}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
