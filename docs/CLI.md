# Command line

`signet-scan [options] PATH...`

| Option | Meaning |
|---|---|
| `-r`, `--recursive` | Enumerate regular Mach-O files in ordinary directories; do not follow directory or leaf symlinks during that enumeration |
| `-j`, `--json` | Emit the complete schema-versioned report, including failed inputs |
| `-v`, `--verbose` | Add signing declarations and reasons to text output |
| `--min-severity info\|low\|medium\|high` | Filter text observations; JSON retains all observations |
| `--fail-on never\|info\|low\|medium\|high` | Choose the findings threshold for exit 1; default `never` |
| `--summary` | Show aggregate text counts; JSON remains complete |
| `--no-resources` | Inspect the bundle executable without checking its resource manifest |
| `--no-colour`, `--no-color` | Accepted; current text output is plain |
| `--version`, `--help` | Print product version or help |
| `--` | Treat remaining arguments as paths |

A recognized app bundle is inspected as one input even with `-r`. Other
directories require `-r`. Files explicitly supplied as inputs are inspected even
if they are not Mach-O; their failures are reported. Duplicate normalized absolute
input paths are inspected once. Filesystem aliases are not globally deduplicated.
If a regular file's prefix cannot be read during enumeration, it is passed to the
input reader so a persistent read failure appears in the report and returns exit
2 alongside any successfully inspected files. Readable empty or short non-Mach-O
files are still skipped.

When `Info.plist` declares `CFBundleExecutable`, that exact filename must name a
regular file in the bundle's executable directory. A missing file, a directory
or a non-string declaration is an inspection error; another Mach-O is never
substituted. Deterministic Mach-O discovery is used only when the declaration is
absent.

Exit status priority is:

1. `2`: bad arguments, no applicable inputs, or any input/parse/inspection error.
2. `1`: otherwise, at least one observation meets `--fail-on`.
3. `0`: otherwise, inspection completed under the selected threshold.

A resource digest mismatch is a completed check producing an observation, not a
parsing error. An unreadable or malformed manifest is an incomplete inspection.
The text and JSON output preserve the difference.
