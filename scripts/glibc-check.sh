#!/usr/bin/env bash
# glibc-check.sh verifies a built u1s1.so does not require glibc symbols newer
# than the target CPA container provides (Debian 12 / glibc 2.36).
#
# The comparison is version-ordered (sort -V): a build that needs only
# GLIBC_2.33 or older is strictly more compatible and must pass. An equality
# whitelist (case 2.34|2.35|2.36) would reject such a build outright — the
# release pipeline is a gate, not a straitjacket.
#
# Usage: GLIBC_SO=<path> scripts/glibc-check.sh   (default: dist/u1s1.so)
set -euo pipefail

# Single source of truth for the maximum glibc the CPA container can load.
# Keep in sync with the "container:" image in .github/workflows/release.yml
# (debian:12 ships glibc 2.36).
TARGET_GLIBC="2.36"

SO="${GLIBC_SO:-dist/u1s1.so}"
if [ ! -f "$SO" ]; then
  echo "error: $SO not found (run make build first, or set GLIBC_SO)" >&2
  exit 1
fi

max=$(objdump -T "$SO" | grep 'GLIBC_' | sed -E 's/.*GLIBC_([0-9.]+).*/\1/' | sort -Vu | tail -1 || true)
if [ -z "$max" ]; then
  echo "error: no GLIBC_ symbol references found in $SO" >&2
  exit 1
fi

echo "max glibc symbol: GLIBC_$max (target container: glibc $TARGET_GLIBC)"

# sort -V understands dotted numeric versions, so "2.3" < "2.36" and
# "2.36" <= "2.36" both hold; anything greater fails.
if [ "$(printf '%s\n%s\n' "$TARGET_GLIBC" "$max" | sort -V | tail -1)" = "$TARGET_GLIBC" ]; then
  echo "OK: requires glibc <= $TARGET_GLIBC"
else
  echo "error: plugin requires GLIBC_$max, container provides $TARGET_GLIBC" >&2
  exit 1
fi
