#!/usr/bin/env python3
"""
Smoke tests for self-contained Python examples.

These examples are meant to be runnable references for the Python bindings, so
CI should exercise their main paths and catch broken constants or API drift.
"""

from pathlib import Path
import sys
import traceback

# Match the CI invocation (`python tests/test_all.py` from the `python/` dir),
# where `tests/` is on `sys.path` but the package root is not.
PYTHON_ROOT = Path(__file__).resolve().parents[1]
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def test_examples():
    """Run self-contained example entrypoints and ensure they complete."""
    try:
        from examples.bootstrap_extended_channel_server_example import (
            main as bootstrap_extended_main,
        )
        from examples.bootstrap_standard_group_channel_server_example import (
            main as bootstrap_standard_group_main,
        )
        from examples.extranonce_allocator_example import main as extranonce_allocator_main

        extranonce_allocator_main()
        bootstrap_extended_main()
        bootstrap_standard_group_main()

        print("✓ Example smoke tests passed")
        return True

    except Exception as e:
        print(f"✗ Example smoke tests failed: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_examples()
    exit(0 if success else 1)
