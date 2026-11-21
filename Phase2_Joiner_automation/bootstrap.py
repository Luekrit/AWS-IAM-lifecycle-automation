"""Create or refresh the lab's managed policies, RBAC groups and password policy.

Run once before the Joiner, and again whenever a policy JSON changes:
    python bootstrap.py            # dry run
    python bootstrap.py --apply    # make the changes
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iam_lifecycle.cli import base_parser, confirm, finish, setup  # noqa: E402
from iam_lifecycle.lifecycle import DONE, FAILED, PLANNED  # noqa: E402


def main() -> int:
    args = base_parser(__doc__).parse_args()
    _, audit, lc = setup(args)
    if not confirm(args, "Bootstrap will create/update iamlab policies, groups and the account password policy."):
        return 1
    ok = lc.bootstrap()
    return finish(audit, [(DONE if args.apply else PLANNED) if ok else FAILED])


if __name__ == "__main__":
    sys.exit(main())
