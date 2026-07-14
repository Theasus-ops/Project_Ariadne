import sys

from .cli import main

if __name__ == "__main__":
    # Propagate the CLI exit code so `python -m ariadne` behaves like the console
    # script (0 ok, 2 bad input, 1 unexpected, 130 on Ctrl-C).
    sys.exit(main())
