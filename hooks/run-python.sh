#!/usr/bin/env bash
# Run the guard with the first Python 3.8+ found. Skips stubs that exist but don't run
# (for example the Windows Store "python3" alias).
for p in python3 python py; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
    exec "$p" "$@"
  fi
done
echo "secret-guard: no Python 3.8+ found, so the hook did not run" >&2
exit 0
