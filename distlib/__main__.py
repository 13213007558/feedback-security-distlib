# -*- coding: utf-8 -*-
"""Allow ``python -m distlib.impact ...`` invocation of the impact CLI."""
import sys

from .impact import main

if __name__ == '__main__':
    sys.exit(main())
