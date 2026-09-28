# SignetScan

A C++20 library and command-line tool for inspecting Mach-O signing metadata,
declared entitlements, hardening settings and application resource seals.

The inspector explains what a file declares and compares sealed resources with
their recorded digests. It does not authenticate CMS signatures, validate a
certificate chain, recompute executable code pages or determine OS-granted
permissions. Use Apple's `codesign -v` for the system's signature verdict.

## Build

On macOS with the Xcode command-line tools and Homebrew:

```sh
brew install cmake ninja pkgconf nlohmann-json libplist openssl@3 pcre2
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The executable is `build/release/signet-scan`. Dependencies and the exact versions
used for local verification are recorded in `dependencies.lock.json`. That file is
a validation manifest; CMake accepts the documented compatible versions rather
than silently downloading dependencies. The product has no Python runtime.

## Inspect

For a complete example, [build two owned fixtures and compare their declarations
with codesign](docs/OWNED_BINARY_EXAMPLE.md). The three selected entitlements are
false in the control and true in the review fixture. The recorded run reports
zero versus three high-severity entitlement observations while both ad-hoc
signatures pass `codesign --verify --strict`.

```sh
build/release/signet-scan /usr/bin/otool
build/release/signet-scan Example.app
build/release/signet-scan --json Example.app
build/release/signet-scan -r --summary build/
build/release/signet-scan --fail-on high --verbose Example.app
```

Every report distinguishes structural parsing from verification. JSON retains all
architecture slices, CodeDirectories, both entitlement declarations, observations
and errors. Resource inspection detects changed, missing required and newly unlisted files,
changed links, and disagreement between the resource manifest and the digest
recorded by a CodeDirectory. Missing explicitly optional resources remain visible
in JSON without a discrepancy; optional resources that exist are still checked.
Nested-code identity remains unevaluated.

Exit codes are `0` for a completed inspection below the configured threshold,
`1` for a completed inspection reaching `--fail-on`, and `2` for usage, input or
parsing failures, including partial failures. JSON is still emitted when an input
fails. Findings alone do not fail a run unless a threshold is requested.

## Use the library

```cpp
#include <signet_scan/audit.hpp>

auto report = signet_scan::AuditSession().inspect_path("Example.app");
auto json = signet_scan::JsonWriter::render({report});
```

Install to a chosen prefix, then use `find_package(SignetScan 1 CONFIG REQUIRED)`
and link `SignetScan::signet_scan`. An independent consumer is provided in
`examples/library-consumer/`; it configures and links against the installed library.

## Verification

Five native C++ test executables cover parser contracts, resource rules,
inspection rules, malformed-input boundaries and real compiler/codesign/CLI
integration. Run them in Debug, Release and ASan/UBSan; what each suite checks
and what it does not establish is described in [Verification](docs/VERIFICATION.md).

The C++ verification tool performs a fresh comparison with Apple's tools:

```sh
build/release/scan-verify-system
```

It reads one macOS installation's system binaries and compares the inspector's
reading of each slice with `codesign`. Corpus size depends on the host and is not
a fixed test target; a run that compared zero slices is not a success.

Linux parsing and inspection paths are designed to build with the same C++
dependencies, but **Linux execution is not validated in this delivery**. The macOS
integration test explicitly skips there. A portable build is not established by
the existence of CMake files.

## Scope

Dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The scope includes thin/fat Mach-O, XML/binary plist and Apple entitlement DER,
code-signing metadata, declared hardening and macOS/iOS-style app resource seals.
Framework `Versions` layouts, code-page authentication, certificate trust and
requirements evaluation are outside this version. Resource-rule matching is a
documented approximation, not Apple's complete sealing implementation. Inspect a
stable copy: path containment and change checks are not a transactional snapshot.

- [Architecture](docs/ARCHITECTURE.md)
- [Command line](docs/CLI.md)
- [Report format](docs/FORMAT.md)
- [Deliberate behavior decisions](docs/BEHAVIOR.md)
- [Verification and current limits](docs/VERIFICATION.md)
- [Test coverage inventory](docs/COVERAGE.md)

How to run the suites and what they cover: [validation/README.md](validation/README.md).
