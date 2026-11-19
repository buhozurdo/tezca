"""
Module execution entrypoint for python -m tezca.
"""

import sys

from tezca.cli import main

if __name__ == "__main__":
    sys.exit(main())
