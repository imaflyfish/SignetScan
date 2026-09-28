# Validation scope

This directory describes how to verify a checkout of SignetScan. It publishes no
recorded run: counts and transcripts belong to the machine that ran them, so run
the suites yourself and read your own output.

## Suites

```sh
cmake --preset debug   && cmake --build --preset debug   && ctest --preset debug --verbose
cmake --preset release && cmake --build --preset release && ctest --preset release --verbose
```

Five native test programs cover parser contracts, resource rules, inspection
rules, malformed-input boundaries and real compiler/`codesign`/CLI integration.
The macOS integration test reports a skip (exit 77) on other platforms.

For the sanitizer and fuzz build, select a clang installation that ships a
libFuzzer runtime:

```sh
cmake --fresh --preset sanitize -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build --preset sanitize
ctest --preset sanitize --verbose
build/sanitize/scan-fuzz build/fuzz-corpus -max_total_time=30 -max_len=65536 -timeout=5
```

Third-party dependencies are used as installed and are not rebuilt with
instrumentation, so sanitizer visibility is strongest in this project's own code.
A short fuzz run is regression evidence, not a proof of parser safety.

## Comparison against the system tools

```sh
build/release/scan-verify-system
```

This asks `codesign` for identifier, team, CodeDirectory size/version, flags,
slot counts, algorithm, candidate digests and declared entitlements, then compares
them with the inspector's own reading of the same files. Failed queries and
missing comparison fields are reported as issues, and a run that compared zero
slices does not count as a success. The corpus is one macOS installation's
`/usr/bin`, `/usr/lib`, `/usr/libexec`, `/sbin` and `/bin`; its size depends on
the host and is not a fixed target.

The owned-binary walkthrough in [`docs/OWNED_BINARY_EXAMPLE.md`](../docs/OWNED_BINARY_EXAMPLE.md)
builds and signs its own fixtures, so it needs no external input.

## Limits

Linux and Windows execution are unverified; the CMake files alone do not
establish a portable build. Finite tests are not an equivalence proof for
arbitrary input. What the product deliberately does not verify — CMS
authentication, code pages, requirements and OS grants — is listed in
[`docs/VERIFICATION.md`](../docs/VERIFICATION.md).
