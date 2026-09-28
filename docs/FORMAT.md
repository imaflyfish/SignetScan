# JSON schema version 1

The root has `schema_version`, `tool`, `summary` and `inputs`. Inputs retain caller
paths and contain `status`, `errors`, `images`, and optional `resources`.
`status=inspected` means the requested structural checks completed; it does not
mean the binary is secure or its signature is authentic.

Each image records architecture, image kind, header flags, ranges, commands,
Both numeric flag values and recognized symbolic names are retained.

Images also contain segments, library dependencies, search paths, encryption and build declarations.

The `signing` object contains:

- `state`: `absent`, `parsed` or `malformed`.
- `cryptographic_verification` and `code_page_verification`: `not_performed`.
- Every decoded `directories` record and container `entries` descriptor.
- `cms_bytes`: observed wrapper payload size, without CMS authentication.
- `selected_directory_slot`: the record used for the summary and policy rules.
  The selection orders supported SHA-1, truncated SHA-256, full SHA-256, SHA-384
  and SHA-512 from lower to higher preference. This is the inspector's policy,
  not proof of what an OS version selects or trusts.

Directory records include both the full `digest` and the 20-byte `cdhash`, flags,
identifier, team, platform, hash-slot counts, special-slot digests, code coverage,
page size and executable-segment fields. Type 3's digest is truncated SHA-256.

The `entitlements` object retains `plist`, `der`, `declared`, `source`, `disagree`,
`differences`, `errors` and `os_grants=not_inspected`. Difference entries identify
the key, kind (`value`, `plist_only`, `der_only`) and available values. A successfully decoded DER declaration is
preferred for display; otherwise the plist declaration is used. An empty decoded
dictionary differs from an absent or malformed slot. Binary plist values use
JSON's binary representation (`bytes` plus `subtype`); plist date and UID values
use `$date_unix` / `$uid` marker objects. Those two marker encodings can resemble
ordinary user dictionaries and are not a lossless general-purpose plist API.

Observations have `code`, `severity`, `message`, `explanation` and `evidence`.
Observations are ordered by descending severity and then code.
Diagnostics have `stage`, `message` and `offset`. Offsets refer to the relevant
parser's enclosing view unless the stage reports a file-relative position; they
are not suitable for blindly patching a binary.

Resources include the bundle path and the executable path relative to that bundle.
Resource `linkage` is `match`, `mismatch`, `absent`, `unrecorded` or `unreadable`.
Each entry records its path, kind and comparison status. All understood recorded
manifest digests must agree. `nested` entries only check existence and explicitly
report `identity_verification=not_performed`. All per-entry statuses remain in
JSON; individual discrepancy observations are capped at 40 plus a remainder count.

An absent resource explicitly marked `optional=true` is recorded with status
`optional-missing` and produces no discrepancy observation. If it exists, its
recorded digest, type and path-containment checks still apply. The optional flag
must be a plist boolean. When the same path appears in both `files` and `files2`,
this inspector conservatively permits absence only if both records mark it
optional; that merge policy does not claim to reproduce every Apple sealing rule.

Conflicting recorded digests for the same path and algorithm, non-data digest
values, and non-dictionary rule tables make resource inspection incomplete.
A supported digest cannot hide an additional unsupported digest: a matching known
digest still leaves that entry `unsupported`. When a manifest supplies only
legacy `rules`, those rules determine which additional files should be sealed.
The existing documented approximation for combined legacy and modern rules is
unchanged.
