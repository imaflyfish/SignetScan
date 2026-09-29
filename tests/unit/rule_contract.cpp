#include <iostream>
#include <signet_scan/audit.hpp>
using namespace signet_scan;
namespace {
unsigned passed = 0, failed = 0;
void check(bool condition, const std::string &name) {
  if (condition)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
SliceOutcome fixture() {
  SliceOutcome result;
  result.image.image_kind = 2;
  result.image.header_flags = 0x200000;
  result.image.architecture = "arm64";
  result.image.signature_range = {{4096, 100}};
  result.signing = SignatureBlob{};
  CodeDirectoryEntry record;
  record.attributes = 0x10000;
  record.algorithm_code = 2;
  record.algorithm = "sha256";
  record.covered_bytes = 4096;
  record.page_bytes = 4096;
  record.code_slots = 1;
  record.identifier = "test";
  record.team_identifier = "TEAM";
  result.signing->cms_bytes = 10;
  result.signing->directories.push_back(record);
  return result;
}
std::optional<Severity> finding(const SliceOutcome &fixture,
                                const std::string &code) {
  for (const auto &result : AuditRuleSet::evaluate(fixture))
    if (result.code == code)
      return result.impact;
  return std::nullopt;
}
} // namespace
int main() {
  auto clean = fixture();
  check(AuditRuleSet::evaluate(clean).empty(), "clean constructed facts");
  auto unsigned_exe = clean;
  unsigned_exe.image.signature_range.reset();
  unsigned_exe.signing.reset();
  check(finding(unsigned_exe, "unsigned") == Severity::high,
        "unsigned executable severity");
  unsigned_exe.image.image_kind = 6;
  check(finding(unsigned_exe, "unsigned") == Severity::medium,
        "unsigned library severity");
  auto broken = clean;
  broken.signing.reset();
  check(finding(broken, "signature-unparsable") == Severity::high,
        "malformed embedded signature");
  for (auto [bit, code, level] :
       std::vector<std::tuple<unsigned, std::string, Severity>>{
           {2, "adhoc-signature", Severity::medium},
           {4, "cs-get-task-allow", Severity::high},
           {8, "cs-installer", Severity::low},
           {0x20, "cs-invalid-allowed", Severity::high},
           {0x20000, "linker-signed", Severity::info}}) {
    auto changed = clean;
    changed.signing->directories[0].attributes |= bit;
    check(!finding(clean, code) && finding(changed, code) == level,
          "signature flag " + code);
  }
  auto missing_cms = clean;
  missing_cms.signing->cms_bytes = 0;
  check(finding(missing_cms, "no-cms-signature") == Severity::medium,
        "missing CMS");
  missing_cms.signing->directories[0].attributes |= 2;
  check(!finding(missing_cms, "no-cms-signature"), "ad-hoc CMS exemption");
  auto no_team = clean;
  no_team.signing->directories[0].team_identifier.clear();
  check(finding(no_team, "no-team-identifier") == Severity::low, "team absent");
  no_team.signing->directories[0].platform = 26;
  check(!finding(no_team, "no-team-identifier"), "platform team exemption");
  auto runtime = clean;
  runtime.signing->directories[0].attributes = 0;
  check(finding(runtime, "no-hardened-runtime") == Severity::medium,
        "runtime absent");
  runtime.signing->directories[0].attributes = 2;
  check(finding(runtime, "no-hardened-runtime") == Severity::medium,
        "ad-hoc does not imply runtime");
  runtime.signing->directories[0].platform = 26;
  check(!finding(runtime, "no-hardened-runtime") &&
            finding(runtime, "platform-binary") == Severity::info,
        "declared platform runtime exemption");
  auto hashes = clean;
  hashes.signing->directories[0].algorithm_code = 1;
  check(finding(hashes, "sha1-only") == Severity::high, "SHA1-only");
  auto alternate = clean.signing->directories[0];
  alternate.slot = 0x1000;
  hashes.signing->directories.push_back(alternate);
  check(!finding(hashes, "sha1-only") &&
            finding(hashes, "sha1-legacy-directory") == Severity::info,
        "legacy SHA1 with alternate");
  check(hashes.signing->preferred().slot == 0x1000,
        "preferred SHA256 alternate");
  hashes.signing->directories[0].algorithm_code = 3;
  check(hashes.signing->preferred().algorithm_code == 2,
        "full SHA256 preferred over truncated SHA256");
  for (auto [bit, code] : std::vector<std::pair<unsigned, std::string>>{
           {0x10, "allow-unsigned"},
           {0x20, "debugger"},
           {0x40, "jit"},
           {0x80, "skip-lv"},
           {0x100, "can-load-cdhash"},
           {0x200, "can-exec-cdhash"}}) {
    auto changed = clean;
    changed.signing->directories[0].executable_flags = bit;
    auto expected = bit == 0x40 ? Severity::medium : Severity::high;
    check(!finding(clean, "execseg-" + code) &&
              finding(changed, "execseg-" + code) == expected,
          "execution permission " + code);
  }
  const std::vector<std::pair<std::string, Severity>> claims = {
      {"com.apple.security.get-task-allow", Severity::high},
      {"com.apple.security.cs.debugger", Severity::high},
      {"com.apple.security.cs.disable-library-validation", Severity::high},
      {"com.apple.security.cs.allow-unsigned-executable-memory",
       Severity::high},
      {"com.apple.security.cs.disable-executable-page-protection",
       Severity::high},
      {"com.apple.security.cs.allow-dyld-environment-variables",
       Severity::high},
      {"com.apple.private.security.no-sandbox", Severity::high},
      {"task_for_pid-allow", Severity::high},
      {"platform-application", Severity::high},
      {"com.apple.security.cs.allow-jit", Severity::medium},
      {"com.apple.system-task-ports", Severity::medium},
      {"com.apple.security.cs.allow-relative-library-loads", Severity::medium},
      {"com.apple.private.tcc.allow", Severity::medium},
      {"com.apple.rootless.install", Severity::medium},
      {"com.apple.rootless.install.heritable", Severity::medium},
      {"keychain-access-groups", Severity::low},
      {"com.apple.security.app-sandbox", Severity::info},
      {"com.apple.security.temporary-exception.test", Severity::medium},
      {"com.apple.security.cs.new-option", Severity::medium},
      {"com.apple.private.test", Severity::low},
      {"com.apple.security.device.test", Severity::info},
      {"com.apple.security.files.test", Severity::info},
      {"com.apple.security.network.test", Severity::info}};
  for (const auto &[key, level] : claims) {
    auto declared = clean;
    declared.claims.selected[key] = true;
    check(finding(declared, "entitlement:" + key) == level,
          "entitlement classification " + key);
    declared.claims.selected[key] = false;
    check(!finding(declared, "entitlement:" + key), "false entitlement " + key);
  }
  auto unknown = clean;
  unknown.claims.selected["test.unclassified"] = true;
  check(!finding(unknown, "entitlement:test.unclassified"),
        "unknown claim inventory only");
  auto zero = clean;
  zero.claims.selected["task_for_pid-allow"] = 0;
  check(finding(zero, "entitlement:task_for_pid-allow").has_value(),
        "integer zero is not boolean false");
  auto slot = clean;
  slot.claims.disagree = true;
  check(finding(slot, "entitlements-slot-mismatch") == Severity::high,
        "entitlement slot disagreement");
  slot.claims.plist = ClaimNode::object();
  check(finding(slot, "entitlements-no-der") == Severity::low,
        "plist without DER");
  slot.claims.der = ClaimNode::object();
  check(!finding(slot, "entitlements-no-der"), "DER companion present");
  slot.claims.errors = {{"plist", "invalid plist", 0},
                        {"der", "invalid DER", 0}};
  check(finding(slot, "entitlements-plist-unparsable").has_value() &&
            finding(slot, "entitlements-der-unparsable").has_value(),
        "both claim decode errors");
  auto flags = clean;
  flags.image.header_flags = 0;
  check(finding(flags, "no-pie") == Severity::high, "PIE absent executable");
  flags.image.image_kind = 6;
  check(!finding(flags, "no-pie"), "PIE not required for dylib");
  flags.image.header_flags = 0x20000;
  check(finding(flags, "executable-stack") == Severity::high,
        "executable stack");
  auto segment = clean;
  SegmentEntry mapping;
  mapping.label = "__TEST";
  mapping.initial_protection = 7;
  segment.image.segments.push_back(mapping);
  check(finding(segment, "wx-segment") == Severity::high, "W+X mapping");
  segment.image.segments[0].initial_protection = 5;
  check(!finding(segment, "wx-segment"), "RX mapping");
  auto dependency = clean;
  dependency.image.dependencies = {{0x80000018, "@rpath/test.dylib"}};
  check(finding(dependency, "weak-dylibs") == Severity::low, "weak library");
  check(!finding(dependency, "rpath-resolution"),
        "rpath finding needs search paths");
  dependency.image.search_paths = {"@executable_path/lib"};
  check(finding(dependency, "rpath-resolution") == Severity::info,
        "rpath resolution");
  auto encrypted = clean;
  encrypted.image.encryption = {{"identifier", 1}};
  check(finding(encrypted, "encrypted") == Severity::info, "encrypted range");
  encrypted.image.encryption["identifier"] = 0;
  check(!finding(encrypted, "encrypted"), "unencrypted range");
  auto gap = clean;
  gap.signing->directories[0].covered_bytes = 2048;
  check(finding(gap, "signature-gap") == Severity::high,
        "declared coverage gap");
  gap.signing->directories[0].covered_bytes = 8192;
  check(finding(gap, "code-slot-shortfall") == Severity::high,
        "insufficient page slots");
  gap.signing->directories[0].code_slots = 0;
  check(finding(gap, "code-slot-shortfall") == Severity::high,
        "zero page slots still insufficient");
  gap.signing->directories[0].page_bytes = 0;
  check(!finding(gap, "code-slot-shortfall"),
        "unpaged metadata has no page-size claim");
  std::cout << passed << " rule checks passed; " << failed << " failed\n";
  return failed ? 1 : 0;
}
