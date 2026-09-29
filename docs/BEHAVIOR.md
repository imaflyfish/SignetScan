# Deliberate behavior decisions

These are the places where SignetScan is deliberately stricter, or reports
differently, than a permissive reader of the same structures would be. Each one
has a regression check in the suites.

## Exit status and output

Any partial input or parsing failure returns 2. A run that inspected several
inputs and failed on one does not return 0. JSON is still emitted when every
inspected input fails, so a caller parsing the report does not also have to parse
an error stream.

Findings alone do not fail a run. Status 1 is returned only when a threshold is
requested with `--fail-on` and reached.

## Structural refusals

Declared fat-slice, command, signature-container and child-blob boundaries are
enforced independently of each other. An input that is only acceptable because it
borrows bytes outside a declared structure is rejected rather than read.
Version-gated fields must be present when their version says so.

Rejected outright: duplicate signing slots, overlapping structural children,
mismatched digest widths, nonminimal DER lengths and integers, duplicate DER keys,
invalid UTF-8, and trailing DER values. An empty encoded entitlement slot is
invalid; an encoded empty dictionary is valid.

A slice carries at most one signature, encryption and build load command. A
second one is rejected rather than allowed to replace the first, because the
report would otherwise describe one of two contradictory declarations without
saying that the other existed.

DER integer size and resource counts have explicit limits. These bound input
processing, and they will reject constructs that an arbitrary-precision reader
would accept.

Code-slot shortfalls are detected even when the declared slot count is zero.

## Resources

Every understood ResourceDir digest across slices is compared. Accepting one
matching algorithm and collapsing conflicting records would hide a real
disagreement, so conflicting records are reported instead.

Resource-rule compilation and matching errors are reported rather than silently
dropping the unsupported expression. PCRE2 is not claimed to implement every
extension of every other regular-expression dialect. Highest weight wins, input
order is retained for ties, and v1 omissions remain relevant when both rule
tables exist.

A resource explicitly marked optional may be absent without becoming a finding;
one that exists is still checked. An unreadable regular file during a recursive
scan is a persistent read error, not a skip.

## Report shape

Text output is plain. Observation wording describes what a file *declares*, and
duplicate input paths are normalized. Terminal styling and exact sentences are
not part of the API; the `code` on each observation is.

XML and binary plist dates and UID values have tagged JSON representations. This
is a deliberate, documented non-lossless edge of the report API rather than an
attempt to model every source type exactly.

## What comparison with the system tools does and does not mean

`scan-verify-system` compares architectures, selected signing identity and CDHash,
typed entitlement values, and finding code/severity pairs against `codesign` over
a stated corpus. Agreement there is a functional comparison on that corpus. It is
not a claim that every malformed input or every possible app behaves identically,
and it is not a signature verdict — see [VERIFICATION.md](VERIFICATION.md) for
what is explicitly not verified.
