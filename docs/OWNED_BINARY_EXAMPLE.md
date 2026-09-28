# Inspect a binary you build

This example compiles the small [owned fixture](../examples/owned-signing/fixture.c),
copies it into `control` and `review`, and signs each copy with an ad-hoc signature
and hardened-runtime metadata. The three declared entitlements are `false` in the
[control plist](../examples/owned-signing/control.plist) and `true` in the
[review plist](../examples/owned-signing/review.plist). Neither binary is executed.

## Reproduce on macOS

Build the project as described in the [README](../README.md), then run:

```sh
bash examples/owned-signing/run.sh build/release build/owned-signing-example
```

Choose a new output directory for each run. The script requires Apple's `clang`,
`codesign` and the two built C++ executables; it uses no signing identity, Python
package or third-party input binary. It removes the temporary binaries when it
exits and retains the reports in the chosen directory. An unexpected command
status makes the script fail; the review fixture's expected inspector status is
`1` because `--fail-on high` is intentional.

The same steps can be read directly in [run.sh](../examples/owned-signing/run.sh):

1. Compile `fixture.c` and sign the two copies with their respective plists.
2. Run `codesign --verify --strict` on each copy.
3. Save `codesign` metadata and entitlement XML alongside verbose inspector text
   and JSON reports.
4. Run `scan-verify-system control review`. It compares identifiers, directory
   metadata, digests and typed entitlement values with `codesign`; mismatches or
   zero compared slices return failure.

## Read the results

The recorded local run on 2026-09-25 produced:

| Check | Control fixture | Review fixture |
|---|---|---|
| Three selected entitlement declarations | All `false` | All `true` |
| Signing flags | `CS_ADHOC`, `CS_RUNTIME` | `CS_ADHOC`, `CS_RUNTIME` |
| High-severity entitlement observations | 0 | 3 |
| Inspector with `--fail-on high` | Exit 0 | Exit 1 |
| `codesign --verify --strict` | Exit 0 | Exit 0 |
| XML/DER declarations | Agree | Agree |

The review report includes these actual lines:

```text
  high [entitlement:com.apple.security.cs.allow-unsigned-executable-memory] Declared entitlement: com.apple.security.cs.allow-unsigned-executable-memory
  high [entitlement:com.apple.security.cs.disable-library-validation] Declared entitlement: com.apple.security.cs.disable-library-validation
  high [entitlement:com.apple.security.get-task-allow] Declared entitlement: com.apple.security.get-task-allow
```

Both signatures passed the system check while the inspector reported different
declarations. A valid ad-hoc signature does not establish a certificate-backed
identity, suitability of the entitlements or permissions granted by the OS. The
inspector therefore retains its ad-hoc-signature observation and explicit
`cryptographic_verification=not_performed` / `os_grants=not_inspected` fields.

The comparison report contains two signed slices, two metadata comparisons, two
XML/DER pairs and two entitlement comparisons with `codesign`, with zero issues.
Counts and hashes may change with the compiler or OS; agreement and expected
exit statuses are the contract.

## Scope of this example

`run.sh` writes every report, `codesign` transcript and exit status into its own
temporary fixture directory, so the comparison above is reproduced from your run
rather than read from a stored copy.

No existing application, private repository source or third-party binary is
involved: the example compiles and ad-hoc signs its own fixtures from the source
and plists in this directory.

The macOS integration test in `tests/integration/macos_live.cpp` also builds an app bundle, changes its resources, and checks both the inspector
findings and `codesign` rejection. This walkthrough focuses on signing metadata
and declared entitlements; it does not authenticate code pages itself.
