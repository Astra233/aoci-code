#!/usr/bin/env bash
# Per-package statement-coverage floors for the safety core.
#
# scripts/coverage-floors.txt maps an import path to the minimum statement
# coverage the package's own tests must reach under `go test -short`. The
# coverage snapshot in full-confidence is visibility only; this is the gate.
# A change that removes or weakens tests in a safety-core package fails here
# instead of showing up as a smaller number in a build summary nobody reads.
#
# Usage:
#   scripts/check-coverage-floors.sh                  run go test -short -count=1 -cover over the listed packages
#   scripts/check-coverage-floors.sh --profile FILE   read an existing coverprofile (go test -coverprofile) instead
#
# Both modes print every listed package with its current coverage and floor.
# Exit status: 0 when every package is at or above its floor; 1 when any is
# below, when a listed package does not exist, or when the floors file is
# missing (a missing gate is a broken gate, never a skipped one).
#
# Raising a floor is a deliberate edit of the floors file. Lowering one must
# say why in the commit message, because it means a guarded path lost its test.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
GO_BIN="${GO_BIN:-go}"
FLOORS="scripts/coverage-floors.txt"
PROFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) [ $# -ge 2 ] || { echo "check-coverage-floors: --profile needs a file" >&2; exit 2; }; PROFILE="$2"; shift 2 ;;
    --profile=*) PROFILE="${1#--profile=}"; shift ;;
    *) echo "check-coverage-floors: unknown argument $1" >&2; exit 2 ;;
  esac
done

if [ ! -f "$FLOORS" ]; then
  echo "check-coverage-floors: $FLOORS is missing; the gate is broken, not skipped" >&2
  exit 1
fi

PACKAGES=()
MINIMUMS=()
while read -r package minimum _; do
  case "$package" in ''|'#'*) continue ;; esac
  case "$minimum" in
    ''|*[!0-9.]*) echo "check-coverage-floors: $FLOORS: floor for $package is not a number: '$minimum'" >&2; exit 1 ;;
  esac
  PACKAGES+=("$package")
  MINIMUMS+=("$minimum")
done < "$FLOORS"
if [ "${#PACKAGES[@]}" -eq 0 ]; then
  echo "check-coverage-floors: $FLOORS lists no packages" >&2
  exit 1
fi

MEASURED="$(mktemp)"
trap 'rm -f "$MEASURED"' EXIT

if [ -n "$PROFILE" ]; then
  if [ ! -f "$PROFILE" ]; then
    echo "check-coverage-floors: profile $PROFILE does not exist" >&2
    exit 1
  fi
  # Every listed package must resolve; a typo must not pass as "0.0 >= 0.0".
  if ! "$GO_BIN" list "${PACKAGES[@]}" >/dev/null; then
    echo "check-coverage-floors: $FLOORS names a package that does not exist" >&2
    exit 1
  fi
  # A profile line is "<file>:<range> <statements> <count>". The same block can
  # appear more than once when several test binaries instrumented one package
  # (-coverpkg), so a block counts as covered when any copy saw it. The package
  # is the directory of the file, which the profile spells as the import path.
  awk '
    NR == 1 && /^mode:/ { next }
    {
      key = $1; statements = $2 + 0; count = $3 + 0
      package = key
      sub(/:[^:]*$/, "", package)
      sub(/\/[^\/]*$/, "", package)
      if (!(key in statementsOf)) {
        statementsOf[key] = statements
        packageOf[key] = package
        total[package] += statements
        covered[key] = 0
      }
      if (count > 0) { covered[key] = 1 }
    }
    END {
      for (key in statementsOf) {
        if (covered[key]) { hit[packageOf[key]] += statementsOf[key] }
      }
      for (package in total) {
        printf "%s %.1f\n", package, (total[package] > 0 ? 100 * hit[package] / total[package] : 0)
      }
    }
  ' "$PROFILE" > "$MEASURED"
else
  OUTPUT="$(mktemp)"
  trap 'rm -f "$MEASURED" "$OUTPUT"' EXIT
  status=0
  "$GO_BIN" test -short -count=1 -cover "${PACKAGES[@]}" > "$OUTPUT" 2>&1 || status=$?
  cat "$OUTPUT"
  if [ "$status" -ne 0 ]; then
    echo "check-coverage-floors: go test failed (exit $status); coverage is not measured on a failing suite" >&2
    exit 1
  fi
  # "ok  <pkg> <time> coverage: N% of statements", "<pkg> coverage: N% of
  # statements" (no test files, newer Go), or "? <pkg> [no test files]".
  awk '
    /coverage: [0-9.]+% of statements/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[a-zA-Z0-9_.\/~-]+\/[a-zA-Z0-9_.-]+$/ && $i !~ /^[0-9.]+s$/) { package = $i; break }
      }
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9.]+%$/) { percent = $i; sub(/%$/, "", percent); printf "%s %s\n", package, percent; break }
      }
      next
    }
    /\[no test files\]/ { printf "%s 0.0\n", $2 }
  ' "$OUTPUT" > "$MEASURED"
fi

failed=0
printf '%-60s %8s %8s  %s\n' "package" "current" "floor" "status"
for index in "${!PACKAGES[@]}"; do
  package="${PACKAGES[$index]}"
  minimum="${MINIMUMS[$index]}"
  current="$(awk -v package="$package" '$1 == package { print $2; exit }' "$MEASURED")"
  if [ -z "$current" ]; then
    if [ -n "$PROFILE" ]; then
      # The package exists (go list passed) but instrumented nothing: no test
      # files. That is 0.0, the same answer go test -cover prints for it.
      current="0.0"
    else
      printf '%-60s %8s %8s  %s\n' "$package" "missing" "$minimum" "FAIL (not measured)"
      failed=1
      continue
    fi
  fi
  if awk -v current="$current" -v minimum="$minimum" 'BEGIN { exit !(current + 0 >= minimum + 0) }'; then
    printf '%-60s %7s%% %7s%%  %s\n' "$package" "$current" "$minimum" "ok"
  else
    printf '%-60s %7s%% %7s%%  %s\n' "$package" "$current" "$minimum" "FAIL (below floor)"
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "check-coverage-floors: FAIL — a safety-core package is below its statement-coverage floor ($FLOORS)" >&2
  exit 1
fi
echo "check-coverage-floors: ${#PACKAGES[@]} packages at or above their floors"
