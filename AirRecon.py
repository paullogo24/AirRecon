#!/usr/bin/env python3
"""Launch AirRecon. The code lives in the airrecon/ package next to this file."""
import sys

from airrecon.cli import main

if __name__ == '__main__':
    sys.exit(main())
