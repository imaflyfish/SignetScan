# Security reporting

For a sensitive report, use GitHub's [private vulnerability reporting](https://github.com/imaflyfish/SignetScan/security/advisories/new).
The private reporting channel is enabled for this repository. Ordinary correctness
bugs can be filed as public issues with private information removed. If the private
form is unavailable, open a minimal issue asking for a reporting channel without
including sensitive details.

Reports are handled on a best-effort basis; no response deadline or maintained
binary-release support window is promised. Identify the exact commit and compare
with the current default branch where practical.

SignetScan parses potentially malformed Mach-O files, signing containers and
resource manifests. Reports about memory errors, unbounded processing, unintended
file access or an incorrect resource-integrity result are welcome.

Include the exact commit, OS/compiler versions, command and a minimal input you
can share. A compiler-built fixture or input generator is preferable to a private
application binary. Note whether the failure is in parsing, resource checking or
reporting.

The tool does not authenticate CMS, verify executable code pages, establish
certificate trust or determine runtime OS permissions. Resource-rule handling is
an approximation, and inspection requires a stable input copy. These documented
limits do not exclude reports that the implementation violates its stated contract.
See [verification scope](../docs/VERIFICATION.md).
