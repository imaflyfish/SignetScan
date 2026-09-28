# Sources and dependencies

SignetScan is MIT licensed; see `LICENSE`. The dependency versions below are the
ones used for local verification.

| Dependency | Validated version | License | Local license copy |
|---|---|---|---|
| nlohmann/json | 3.12.0 | MIT | `licenses/nlohmann-json-MIT.txt` |
| libplist | 2.7.0 | LGPL-2.1-or-later | `licenses/libplist-LGPL-2.1.txt`, `licenses/libplist-GPL-2.txt` |
| OpenSSL | 3.6.2 | Apache-2.0 | `licenses/OpenSSL-Apache-2.0.txt` |
| PCRE2 | 10.47 | BSD-3-Clause WITH PCRE2-exception | `licenses/PCRE2-LICENCE.md` |

Upstream source locations are recorded in `dependencies.lock.json`. Dependency
source is not vendored. The normal macOS build dynamically links libplist,
OpenSSL and PCRE2 from the installed package-manager locations. nlohmann/json is
used as a header-only dependency. Rebuilding allows use of compatible replacement
libraries; the included CMake consumer demonstrates linking the installed library.

LLVM/libFuzzer and sanitizers are development tools, not product runtime
dependencies. Apple's compiler and codesign are used to create and verify local
test fixtures. No Apple system binary is included in the source distribution.
