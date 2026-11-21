"""Process only the Mover ('move') rows of mover_leaver.csv.

    python mover.py            # dry run
    python mover.py --apply
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mover_leaver import run  # noqa: E402

if __name__ == "__main__":
    sys.exit(run({"move"}, __doc__))
