"""`python -m interlockd` runs the CLI (the background service uses this form)."""

import sys

from .cli import main

sys.exit(main())
