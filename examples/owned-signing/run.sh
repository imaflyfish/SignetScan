#!/bin/bash
# Build only owned fixtures; retain reports and remove temporary binaries.
set -euo pipefail

if [[ $# != 2 || $(uname -s) != Darwin ]]; then
  echo "Usage on macOS: $0 BUILD_DIRECTORY NEW_REPORT_DIRECTORY" >&2
  exit 2
fi
example_directory=$(cd "$(dirname "$0")" && pwd)
build_directory=$(cd "$1" && pwd)
inspector="$build_directory/signet-scan"
verifier="$build_directory/scan-verify-system"
if [[ ! -x "$inspector" || ! -x "$verifier" ]]; then
  echo "Build signet-scan and scan-verify-system first." >&2
  exit 2
fi
if [[ -e "$2" || -L "$2" ]]; then
  echo "Choose a new report directory; existing output is never overwritten." >&2
  exit 2
fi
mkdir -p "$2"
reports=$(cd "$2" && pwd)
workspace=$(mktemp -d "${TMPDIR:-/tmp}/signet-scan-owned-example.XXXXXX")
trap 'rm -rf "$workspace"' EXIT

{
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  sw_vers
  uname -m
  /usr/bin/clang --version
} > "$reports/environment.txt"
printf 'case\texpected_exit\tactual_exit\n' > "$reports/exits.tsv"

check_exit() {
  local expected=$1 label=$2 actual
  shift 2
  if "$@" > "$reports/$label.stdout" 2> "$reports/$label.stderr"; then
    actual=0
  else
    actual=$?
  fi
  printf '%s\t%s\t%s\n' "$label" "$expected" "$actual" >> "$reports/exits.tsv"
  if [[ $actual != "$expected" ]]; then
    echo "$label: expected exit $expected, observed $actual; see $reports" >&2
    exit 1
  fi
}

cd "$workspace"
check_exit 0 compile /usr/bin/clang "$example_directory/fixture.c" -o fixture
for variant in control review; do
  cp fixture "$variant"
  check_exit 0 "$variant-sign" /usr/bin/codesign --force --sign - \
    --identifier "org.signetscan.example.$variant" --options runtime \
    --entitlements "$example_directory/$variant.plist" "$variant"
  check_exit 0 "$variant-verify" /usr/bin/codesign --verify --strict --verbose=2 "$variant"
  check_exit 0 "$variant-metadata" /usr/bin/codesign --display --verbose=4 "$variant"
  check_exit 0 "$variant-entitlements" /usr/bin/codesign --display --entitlements :- --xml "$variant"
  expected=0
  if [[ $variant == review ]]; then expected=1; fi
  check_exit "$expected" "$variant-inspection-text" "$inspector" --verbose --fail-on high "$variant"
  check_exit "$expected" "$variant-inspection-json" "$inspector" --json --fail-on high "$variant"
done
check_exit 0 comparison "$verifier" control review
shasum -a 256 control review > "$reports/fixture-sha256.txt"
cat "$reports/exits.tsv"
echo "Reports: $reports"
echo "Both fixtures were inspected without being executed; temporary binaries will be removed."
