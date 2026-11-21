"""Leaver offboarding.

Stage 1 - disable (immediately, from the 'leave' rows of mover_leaver.csv):
    python leaver.py                 # dry run
    python leaver.py --apply

Stage 2 - purge (after the retention period, default 30 days):
    python leaver.py --purge                 # dry run: lists who would be deleted
    python leaver.py --purge --apply
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mover_leaver import run  # noqa: E402

from iam_lifecycle import config  # noqa: E402
from iam_lifecycle.cli import base_parser, confirm, finish, setup  # noqa: E402
from iam_lifecycle.lifecycle import DONE, PLANNED  # noqa: E402


def purge() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--purge", action="store_true")
    parser.add_argument("--retention-days", type=int, default=config.LEAVER_RETENTION_DAYS)
    args = parser.parse_args()
    _, audit, lc = setup(args)
    if not confirm(args, f"Permanently delete leavers terminated more than {args.retention_days} days ago. "
                         "This cannot be undone."):
        return 1
    handled = lc.purge(retention_days=args.retention_days)
    return finish(audit, [DONE if args.apply else PLANNED] * len(handled))


if __name__ == "__main__":
    if "--purge" in sys.argv:
        sys.exit(purge())
    sys.exit(run({"leave"}, __doc__))
