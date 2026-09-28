# Architecture

`AuditSession` coordinates an input without mixing parsing, policy and
presentation. The public header is `include/signet_scan/audit.hpp`.

1. `InputSource` operations read regular files through a descriptor and check for
   observable size/timestamp changes. Resource digests use streamed reads.
2. `ByteWindow` creates checked views. A child structure can only read its enclosing
   view; addition and multiplication are checked through bounded widths and
   subtraction-based range checks.
3. `MachImageSet` decodes architecture slices and load commands. `SignatureBlob`
   decodes independent signing records. No parser invokes `codesign`.
4. `GrantDocument` retains plist and DER values and the source selected for
   reporting. `ClaimNode` uses a typed ordered JSON value, including binary data.
   Dictionary order is retained for resource-rule tie handling.
5. `AuditRuleSet` evaluates the decoded facts without opening files. Stable
   observation codes retain correspondence with baseline checks.
6. `BundleLayout`, `BundlePath` and `SealManifest` handle bundle layout,
   controlled path resolution, recorded resources and signature-manifest linkage.
7. `JsonWriter` and `TextWriter` render one result model. The CLI handles option
   parsing, traversal and the final failure-threshold contract.

Internal parsers throw `ParseFault` carrying a stage, offset and message.
Session entry points convert failures to report diagnostics, including partial
results. Memory allocation and filesystem failures become inspection errors.

## Bounds

- File inspection: 512 MiB per input, 64 fat slices, 10,000 load commands per slice.
- Signature container: 64 entries, 64 special hash slots, 4,194,304 code slots.
- Entitlement or resource plist: 16 MiB, 200,000 converted nodes, depth at most 32.
- DER: 16 MiB, 200,000 nodes, depth at most 32, signed integers of at most 8 bytes.
- Directory traversal: 250,000 visited entries.
- Resource regular expression: 16,384 pattern bytes, 100,000 PCRE2 match steps,
  match depth 256. Unsupported or exhausted rules produce an error.

The third-party plist parser operates before the converted-node limits; its own
parser defenses and the input-byte cap also matter. These bounds are not a
guarantee of constant execution time for hostile files.

## Dependencies

nlohmann/json implements serialization; libplist decodes XML and binary property
lists; OpenSSL EVP computes digests; PCRE2 matches resource rules. The Mach-O,
CodeDirectory and entitlement-DER logic lives in this project's C++ sources.

The normal binaries link to installed dependency libraries. The local macOS
package is not a fully self-contained universal executable. Dependencies can be
replaced by rebuilding against compatible installed versions.
