# Test coverage inventory

What each test program is responsible for. Run them as described in
[`validation/README.md`](../validation/README.md); this page is a map, not a
record of results.

| Program | Responsible for |
|---|---|
| `tests/unit/core_contract.cpp` | Thin and fat header parsing, image widths, byte order, architecture naming, header and segment flags, load commands, dependency and search-path lists, signature range discovery |
| `tests/unit/boundary_contract.cpp` | Refusal of malformed input: empty and tiny files, slices exceeding their file, headers exceeding their slice, SuperBlobs exceeding their command, children exceeding their SuperBlob, duplicate slots, overlapping children, DER minimality and depth, invalid UTF-8, trailing values, size and count limits |
| `tests/unit/rule_contract.cpp` | Observation rules and their severities: ad-hoc signatures, hardened-runtime and library-validation flags, debugger and JIT entitlements, unverified-by-design fields, threshold behavior |
| `tests/unit/seal_contract.cpp` | Resource manifests against synthetic bundles: clean, modified, added, removed and newly unlisted files, required versus optional resources, changed links, omission/weight/tie rules, nested code, unknown digests, parent and leaf symlinks, out-of-bundle paths, capped findings, and manifest/CodeDirectory disagreement |
| `tests/integration/macos_live.cpp` | Real compiler and `codesign` integration: builds and signs an app bundle, changes its resources, and checks both the inspector's findings and codesign's rejection. Reports a skip (exit 77) off macOS |
| `tools/system_probe.cpp` | Whole-installation comparison with `codesign` over the system binary corpus |
| `tests/fuzz/decoder_driver.cpp` | Bounded coverage-guided fuzzing of the inspection entry point, signature containers, plist and DER |

Deliberate strictness decisions, and the reasoning behind them, are in
[BEHAVIOR.md](BEHAVIOR.md). Each one has a regression check in the program listed
above for its area.

Structural refusals are worth calling out separately: they are checked as
positive requirements, not as incidental parse failures. An input that is only
readable by borrowing bytes outside a declared structure must be rejected with
status 2, and `boundary_contract.cpp` asserts exactly that for each declared
container in turn.
