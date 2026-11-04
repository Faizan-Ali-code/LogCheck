"""python -m autologger [--cli] [-Dname=value ...]"""

import sys

from autologger.cli import main

if __name__ == "__main__":
    sys.exit(main())
