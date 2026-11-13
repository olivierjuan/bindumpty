"""pytest configuration: make the project root importable.

Tests import `humpty.*` from the repo root; this guarantees sys.path is
correct regardless of the working directory pytest is launched from.
Alembic tests also rely on the repo root (alembic.ini lives there).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
