# Verification and current limits

This page states what the test suites check, how to run them, and what the
product deliberately does not establish. It records no run of its own; see
[`validation/README.md`](../validation/README.md) for the suites and their scope.

## Reproduce

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --verbose
cmake --preset release
cmake --build --preset release
ctest --preset release --verbose
build/release/scan-verify-system
```

For a clang installation containing libFuzzer, choose its compiler explicitly:

```sh
cmake --fresh --preset sanitize \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build --preset sanitize
ctest --preset sanitize --verbose
build/sanitize/scan-boundary-tests build/fuzz-corpus
build/sanitize/scan-fuzz build/fuzz-corpus \
  -max_total_time=30 -max_len=65536 -timeout=5 -rss_limit_mb=1024 -seed=9802
```

The fuzz driver targets the inspection entry point, signature containers, plist
and DER. System-installed third-party dependencies are not rebuilt with
instrumentation, so coverage and sanitizer visibility are strongest in this
project's own code. A short fuzz run is regression evidence, not an exhaustive
proof of parser safety.

## What the suites cover

Five native test programs cover parser contracts, resource rules, inspection
rules, malformed-input boundaries and real compiler/`codesign`/CLI integration.
The inventory in [`COVERAGE.md`](COVERAGE.md) maps each covered behavior to the
program responsible for it.

Integration fixtures are compiled and signed during the tests. Clean, modified,
added and removed resources are checked against both the inspector and codesign.
Separate resource fixtures cover omission/weight/tie rules, nested code, unknown
digests, parent/leaf symlinks, out-of-bundle paths and capped findings. No test
requires reading a private file.

Structural refusals have their own boundary cases: a fat slice exceeding its
file, a header exceeding its declared slice, a SuperBlob exceeding its command
and a child exceeding its SuperBlob are each rejected with status 2 rather than
accepted by borrowing bytes outside a declared structure.

Resource handling has two behaviors worth stating explicitly, because both are
easy to get wrong:

- A resource that codesign explicitly marks optional may be absent without
  becoming a missing-resource finding. Optional resources that do exist are still
  checked, and changed contents or missing **required** files are still reported.
- An unreadable regular file during a recursive scan is a persistent read error,
  not a silent skip: it appears beside the successful results in JSON and the run
  returns exit 2. Readable short files remain skipped.

The optional merge policy is conservative when legacy and modern records differ;
[the report format](FORMAT.md) documents it without claiming complete Apple
resource-sealer equivalence.

## Comparison with the system tools

The system verifier asks codesign for identifier, team, CodeDirectory size/version,
flags, slot counts, algorithm, every full candidate digest and declared
entitlements. Failed queries or missing comparison fields produce issues, and
zero compared slices does not count as a successful run.

The native default corpus uses `/usr/bin/*`, `/usr/lib/*.dylib`, `/usr/libexec/*`,
`/sbin/*` and `/bin/*`. Corpus size depends on the host installation and is not a
fixed test target.

## What this does not establish

These checks do not authenticate CMS signatures, verify code pages, evaluate
requirements, determine OS grants, prove hostile filesystem-race resistance, cover
every resource-sealer corner case, establish Linux support or guarantee acceptance
for uses outside these tested contracts. Product boundaries are listed in the README and format
documentation.
