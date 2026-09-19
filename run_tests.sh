#!/usr/bin/env bash
#
# Run the full test suite.
#
#   ./run_tests.sh                # quiet
#   ./run_tests.sh -v             # per-test output
#   ./run_tests.sh -k test_top    # only test methods whose name contains this
#   ./run_tests.sh -k '*Crack*'   # glob form, matched against the full test id
#
# Note: -k is case-sensitive. A bare word is matched against the test method
# name, so use the glob form to match a class name such as TestCrackCommand.
#
# Exits non-zero if anything fails, so it works as a CI or pre-commit gate.

set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found. Set PYTHON=/path/to/python3 and retry." >&2
  exit 1
fi

echo "Running tests with $("$PYTHON" --version)"
echo

# -t . sets the top-level directory so `import main` and `import caesar` both
# resolve from the project root regardless of where this script was called.
exec "$PYTHON" -m unittest discover -s tests -t . "$@"
