#include <algorithm>
#include <set>
#include <signet_scan/audit.hpp>
#include <tuple>

namespace signet_scan {
void sort_remarks(std::vector<Remark> &findings) {
  std::stable_sort(findings.begin(), findings.end(),
                   [](const Remark &first, const Remark &second) {
                     return first.severity != second.severity
                                ? first.severity > second.severity
                                : first.code < second.code;
                   });
}
std::string severity_label(Severity severity) {
  switch (severity) {
  case Severity::high:
    return "high";
  case Severity::medium:
    return "medium";
  case Severity::low:
    return "low";
  case Severity::info:
    return "info";
  }
  return "info";
}
Severity parse_severity(const std::string &name) {
  if (name == "high")
    return Severity::high;
  if (name == "medium")
    return Severity::medium;
  if (name == "low")
    return Severity::low;
  if (name == "info")
    return Severity::info;
  throw ParseFault("options", "unknown severity: " + name);
}
namespace {
// A flag bit, the code it reports, its severity and its message. These tables
// are policy, not state: build them once rather than per inspected slice.
using FlagRule = std::tuple<unsigned, std::string, Severity, std::string>;
} // namespace
std::vector<Remark> AuditRuleSet::evaluate(const SliceOutcome &facts) {
  const auto &image = facts.image;
  std::vector<Remark> result;
  auto add = [&](std::string code, Severity level, std::string message,
                 std::string explanation,
                 ClaimNode evidence = ClaimNode::object()) {
    result.push_back({std::move(code), level, std::move(message),
                      std::move(explanation), std::move(evidence)});
  };
  if (image.image_kind == 2 && !(image.header_flags & 0x200000))
    add("no-pie", Severity::high, "Position independence is not declared",
        "MH_PIE is clear in this executable's header.");
  if (image.header_flags & 0x20000)
    add("executable-stack", Severity::high, "Executable stack requested",
        "MH_ALLOW_STACK_EXECUTION is set.");
  for (const auto &segment : image.segments)
    if ((segment.initial_protection & 6) == 6)
      add("wx-segment", Severity::high,
          "Writable and executable segment: " + segment.label,
          "The initial mapping protection includes both write and execute.",
          {{"segment", segment.label},
           {"initial_protection", segment.initial_protection}});
  ClaimNode weak = ClaimNode::array(), relative = ClaimNode::array();
  for (const auto &[kind, path] : image.dependencies) {
    if (kind == 0x80000018)
      weak.push_back(path);
    if (path.starts_with("@rpath/"))
      relative.push_back(path);
  }
  if (!weak.empty())
    add("weak-dylibs", Severity::low, "Optional library dependencies",
        "Review whether missing dependencies can be supplied from writable "
        "locations.",
        {{"libraries", weak}});
  if (!relative.empty() && !image.search_paths.empty())
    add("rpath-resolution", Severity::info, "Libraries use run-path search",
        "The declared search order affects which dependency is selected.",
        {{"search_paths", image.search_paths}, {"libraries", relative}});
  // evaluate() reads a slice a caller may have built, not only one this parser
  // produced, so the lookup must survive a record that omits the field.
  if (image.encryption.is_object() &&
      image.encryption.value("identifier", ClaimNode(0)) != 0)
    add("encrypted", Severity::info, "Encrypted range declared",
        "Static bytes in the declared encrypted range do not represent decoded "
        "instructions.",
        image.encryption);
  if (!image.signature_range) {
    add("unsigned", image.image_kind == 2 ? Severity::high : Severity::medium,
        "No embedded signature declared",
        "No LC_CODE_SIGNATURE is present in this slice.");
    return result;
  }
  if (!facts.signing) {
    add("signature-unparsable", Severity::high,
        "Signature structure could not be decoded",
        "See the structured parsing error. No signature validity conclusion is "
        "available.");
    return result;
  }
  const auto &signature = *facts.signing;
  // preferred() is the directory the report names in selected_directory_slot,
  // not primary(), which is the slot-zero directory.
  const auto &selected_directory = signature.preferred();
  bool adhoc = selected_directory.attributes & 2;
  if (adhoc)
    add("adhoc-signature", Severity::medium, "Ad-hoc signing metadata",
        "The ad-hoc flag declares no certificate-backed identity. This "
        "inspection does not recompute code pages.",
        {{"identifier", selected_directory.identifier}});
  else if (!signature.cms_bytes)
    add("no-cms-signature", Severity::medium, "CMS payload is absent",
        "The signature is not marked ad-hoc but has no nonempty CMS wrapper.");
  if (selected_directory.attributes & 0x20000)
    add("linker-signed", Severity::info, "Linker signing flag declared",
        "This flag commonly appears on linker output before a separate signing "
        "step.");
  if (!adhoc && signature.cms_bytes &&
      selected_directory.team_identifier.empty() &&
      !selected_directory.platform)
    add("no-team-identifier", Severity::low, "Team identifier is absent",
        "The inspected CodeDirectory does not declare a development team.");
  std::set<unsigned> kinds;
  for (const auto &record : signature.directories)
    kinds.insert(record.algorithm_code);
  if (kinds == std::set<unsigned>{1})
    add("sha1-only", Severity::high, "Only SHA-1 directories declared",
        "No stronger alternative CodeDirectory is present.");
  else if (kinds.contains(1))
    add("sha1-legacy-directory", Severity::info,
        "SHA-1 directory accompanies another algorithm",
        "Legacy compatibility metadata remains present; inspect the alternate "
        "algorithms.");
  static const std::vector<FlagRule> attributes = {
      {4, "cs-get-task-allow", Severity::high, "Task-access flag declared"},
      {0x20, "cs-invalid-allowed", Severity::high,
       "Invalid-signature execution flag declared"},
      {8, "cs-installer", Severity::low, "Installer flag declared"}};
  for (const auto &[flag, code, level, description] : attributes)
    if (selected_directory.attributes & flag)
      add(code, level, description,
          "This is a recorded CodeDirectory flag, not a measurement of "
          "permissions granted by the operating system.");
  if (image.image_kind == 2 && !(selected_directory.attributes & 0x10000)) {
    if (selected_directory.platform)
      add("platform-binary", Severity::info, "Platform identifier declared",
          "The hardened-runtime rule exempts slices that declare a platform "
          "identifier; the identifier is not authenticated here.",
          {{"platform", selected_directory.platform}});
    else
      add("no-hardened-runtime", Severity::medium,
          "Hardened runtime is not declared",
          "CS_RUNTIME is clear in the inspected CodeDirectory.");
  }
  static const std::vector<FlagRule> execution = {
      {0x10, "allow-unsigned", Severity::high,
       "Unsigned execution permission requested"},
      {0x20, "debugger", Severity::high, "Debugger permission requested"},
      {0x40, "jit", Severity::medium, "JIT execution permission requested"},
      {0x80, "skip-lv", Severity::high,
       "Library-validation exception requested"},
      {0x100, "can-load-cdhash", Severity::high,
       "Code-hash loading permission requested"},
      {0x200, "can-exec-cdhash", Severity::high,
       "Code-hash execution permission requested"}};
  for (const auto &[flag, code, level, message] : execution)
    if (selected_directory.executable_flags & flag)
      add("execseg-" + code, level, message,
          "The executable-segment flags declare this capability; actual "
          "authorization is not inspected.");
  for (const auto &error : facts.claims.errors)
    add(error.stage == "der" ? "entitlements-der-unparsable"
                             : "entitlements-plist-unparsable",
        Severity::medium, "Entitlement document could not be decoded",
        error.message);
  if (facts.claims.disagree)
    add("entitlements-slot-mismatch", Severity::high,
        "Entitlement declarations disagree",
        "The plist and DER slots decode to different typed values. Both "
        "declarations are retained in the report.",
        {{"differences", facts.claims.differences}});
  if (facts.claims.plist && !facts.claims.der)
    add("entitlements-no-der", Severity::low,
        "Only the plist declaration was decoded",
        "No usable DER entitlement declaration was found.");
  static const std::map<std::string, std::pair<Severity, std::string>>
      named_claims = {
          {"com.apple.security.get-task-allow",
           {Severity::high, "Requests debugger attachment to this process"}},
          {"com.apple.security.cs.debugger",
           {Severity::high, "Requests debugger capabilities"}},
          {"com.apple.security.cs.disable-library-validation",
           {Severity::high, "Requests loading libraries without the normal "
                            "signing-team restriction"}},
          {"com.apple.security.cs.allow-unsigned-executable-memory",
           {Severity::high, "Requests unsigned executable memory"}},
          {"com.apple.security.cs.disable-executable-page-protection",
           {Severity::high, "Requests relaxed protection of executable pages"}},
          {"com.apple.security.cs.allow-dyld-environment-variables",
           {Severity::high, "Requests loader environment overrides"}},
          {"com.apple.private.security.no-sandbox",
           {Severity::high, "Requests a sandbox exemption"}},
          {"task_for_pid-allow", {Severity::high, "Requests task-port access"}},
          {"platform-application",
           {Severity::high, "Declares platform-application status"}},
          {"com.apple.security.cs.allow-jit",
           {Severity::medium, "Requests JIT memory"}},
          {"com.apple.system-task-ports",
           {Severity::medium, "Requests system task-port access"}},
          {"com.apple.security.cs.allow-relative-library-loads",
           {Severity::medium, "Requests relative library loading"}},
          {"com.apple.private.tcc.allow",
           {Severity::medium, "Requests TCC exceptions"}},
          {"com.apple.rootless.install",
           {Severity::medium, "Requests protected-path installation access"}},
          {"com.apple.rootless.install.heritable",
           {Severity::medium,
            "Requests inheritable protected-path installation access"}},
          {"keychain-access-groups",
           {Severity::low, "Declares shared keychain groups"}},
          {"com.apple.security.app-sandbox",
           {Severity::info, "Requests App Sandbox confinement"}}};
  static const std::vector<std::tuple<std::string, Severity, std::string>>
      prefixes = {
          {"com.apple.security.temporary-exception.", Severity::medium,
           "Requests a sandbox exception"},
          {"com.apple.security.cs.", Severity::medium,
           "Declares a code-signing capability"},
          {"com.apple.private.", Severity::low,
           "Declares an Apple-private entitlement"},
          {"com.apple.security.device.", Severity::info,
           "Requests device access"},
          {"com.apple.security.files.", Severity::info, "Requests file access"},
          {"com.apple.security.network.", Severity::info,
           "Requests network access"}};
  for (auto entry = facts.claims.selected.begin();
       entry != facts.claims.selected.end(); ++entry) {
    if (entry.value().is_boolean() && !entry.value().get<bool>())
      continue;
    auto known = named_claims.find(entry.key());
    std::optional<std::pair<Severity, std::string>> classification;
    if (known != named_claims.end())
      classification = known->second;
    else
      for (const auto &[prefix, level, message] : prefixes)
        if (entry.key().starts_with(prefix)) {
          classification = {{level, message}};
          break;
        }
    if (classification)
      add("entitlement:" + entry.key(), classification->first,
          "Declared entitlement: " + entry.key(),
          classification->second +
              ". The operating system's actual grant is not established.",
          {{"value", entry.value()}, {"source", facts.claims.source}});
  }
  auto signature_offset = image.signature_range->first;
  if (selected_directory.covered_bytes &&
      selected_directory.covered_bytes < signature_offset)
    add("signature-gap", Severity::high,
        "Signature coverage metadata ends early",
        "The declared code limit precedes the signature region.",
        {{"covered_bytes", selected_directory.covered_bytes},
         {"signature_offset", signature_offset},
         {"uncovered_bytes",
          signature_offset - selected_directory.covered_bytes}});
  if (selected_directory.page_bytes && selected_directory.covered_bytes) {
    auto needed =
        selected_directory.covered_bytes / selected_directory.page_bytes +
        (selected_directory.covered_bytes % selected_directory.page_bytes != 0);
    if (selected_directory.code_slots < needed)
      add("code-slot-shortfall", Severity::high, "Too few code-hash slots",
          "The declared slot count is insufficient for the declared coverage "
          "and page size.");
  }
  return result;
}
} // namespace signet_scan
