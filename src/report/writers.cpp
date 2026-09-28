#include <signet_scan/audit.hpp>
#include <sstream>

namespace signet_scan {
namespace {
ClaimNode flag_names(std::uint64_t bits,
                      const std::map<std::uint64_t, std::string> &labels) {
  ClaimNode names = ClaimNode::array();
  for (const auto &[mask, label] : labels)
    if (bits & mask)
      names.push_back(label);
  return names;
}
const std::map<std::uint64_t, std::string> signing_labels = {
    {1, "CS_VALID"},
    {2, "CS_ADHOC"},
    {4, "CS_GET_TASK_ALLOW"},
    {8, "CS_INSTALLER"},
    {0x10, "CS_FORCED_LV"},
    {0x20, "CS_INVALID_ALLOWED"},
    {0x100, "CS_HARD"},
    {0x200, "CS_KILL"},
    {0x400, "CS_CHECK_EXPIRATION"},
    {0x800, "CS_RESTRICT"},
    {0x1000, "CS_ENFORCEMENT"},
    {0x2000, "CS_REQUIRE_LV"},
    {0x4000, "CS_ENTITLEMENTS_VALIDATED"},
    {0x8000, "CS_NVRAM_UNRESTRICTED"},
    {0x10000, "CS_RUNTIME"},
    {0x20000, "CS_LINKER_SIGNED"}};
const std::map<std::uint64_t, std::string> execution_labels = {
    {1, "CS_EXECSEG_MAIN_BINARY"},        {0x10, "CS_EXECSEG_ALLOW_UNSIGNED"},
    {0x20, "CS_EXECSEG_DEBUGGER"},        {0x40, "CS_EXECSEG_JIT"},
    {0x80, "CS_EXECSEG_SKIP_LV"},         {0x100, "CS_EXECSEG_CAN_LOAD_CDHASH"},
    {0x200, "CS_EXECSEG_CAN_EXEC_CDHASH"}};
const std::map<std::uint64_t, std::string> header_labels = {
    {1, "MH_NOUNDEFS"},
    {4, "MH_DYLDLINK"},
    {8, "MH_BINDATLOAD"},
    {0x80, "MH_TWOLEVEL"},
    {0x20000, "MH_ALLOW_STACK_EXECUTION"},
    {0x40000, "MH_ROOT_SAFE"},
    {0x80000, "MH_SETUID_SAFE"},
    {0x100000, "MH_WEAK_DEFINES"},
    {0x200000, "MH_PIE"},
    {0x800000, "MH_HAS_TLV_DESCRIPTORS"},
    {0x1000000, "MH_NO_HEAP_EXECUTION"},
    {0x2000000, "MH_APP_EXTENSION_SAFE"}};
ClaimNode diagnostics(const std::vector<FaultNote> &errors) {
  ClaimNode rows = ClaimNode::array();
  for (const auto &error : errors)
    rows.push_back({{"stage", error.stage},
                    {"message", error.message},
                    {"offset", error.offset}});
  return rows;
}
ClaimNode observations(const std::vector<Remark> &findings) {
  ClaimNode rows = ClaimNode::array();
  auto ordered = findings;
  std::stable_sort(ordered.begin(), ordered.end(),
                   [](const auto &first, const auto &second) {
                     return first.impact != second.impact
                                ? first.impact > second.impact
                                : first.code < second.code;
                   });
  for (const auto &finding : ordered)
    rows.push_back({{"code", finding.code},
                    {"severity", severity_label(finding.impact)},
                    {"message", finding.message},
                    {"explanation", finding.explanation},
                    {"evidence", finding.evidence}});
  return rows;
}
ClaimNode directory_json(const CodeDirectoryEntry &record) {
  ClaimNode special = ClaimNode::object();
  for (const auto &[slot, digest] : record.special_digests)
    special[std::to_string(slot)] = digest;
  return {{"slot", record.slot},
          {"version", record.version},
          {"flags", record.attributes},
          {"flag_names", flag_names(record.attributes, signing_labels)},
          {"identifier", record.identifier},
          {"team_identifier", record.team_identifier.empty()
                                  ? ClaimNode(nullptr)
                                  : ClaimNode(record.team_identifier)},
          {"hash_type", record.algorithm_code},
          {"algorithm", record.algorithm},
          {"digest_width", record.digest_width},
          {"digest", record.digest},
          {"cdhash", record.digest.substr(0, 40)},
          {"page_bytes", record.page_bytes},
          {"covered_bytes", record.covered_bytes},
          {"code_slots", record.code_slots},
          {"special_slots", record.special_slots},
          {"special_digests", special},
          {"platform", record.platform},
          {"encoded_bytes", record.encoded_bytes},
          {"executable_base", record.executable_base},
          {"executable_limit", record.executable_limit},
          {"executable_flags", record.executable_flags},
          {"executable_flag_names",
           flag_names(record.executable_flags, execution_labels)}};
}
ClaimNode image_json(const SliceOutcome &report) {
  const auto &image = report.image;
  ClaimNode output = {
      {"architecture", image.architecture},
      {"header_flag_names", flag_names(image.header_flags, header_labels)},
      {"cpu_kind", image.cpu_kind},
      {"cpu_variant", image.cpu_variant},
      {"image_kind", image.image_kind},
      {"header_flags", image.header_flags},
      {"file_offset", image.file_offset},
      {"byte_length", image.byte_length},
      {"width", image.wide ? 64 : 32},
      {"endianness", image.big_endian ? "big" : "little"},
      {"commands", image.commands},
      {"segments", ClaimNode::array()},
      {"dependencies", ClaimNode::array()},
      {"search_paths", image.search_paths},
      {"encryption", image.encryption},
      {"build", image.build}};
  for (const auto &segment : image.segments)
    output["segments"].push_back(
        {{"name", segment.label},
         {"virtual_address", segment.virtual_address},
         {"virtual_size", segment.virtual_size},
         {"file_offset", segment.file_offset},
         {"file_length", segment.file_length},
         {"initial_protection", segment.initial_protection},
         {"maximum_protection", segment.maximum_protection},
         {"section_count", segment.section_count}});
  for (const auto &[kind, path] : image.dependencies)
    output["dependencies"].push_back({{"command", kind}, {"path", path}});
  ClaimNode signing = {{"state", !image.signature_range ? "absent"
                                  : report.signing       ? "parsed"
                                                         : "malformed"},
                        {"cryptographic_verification", "not_performed"},
                        {"code_page_verification", "not_performed"},
                        {"directories", ClaimNode::array()},
                        {"entries", ClaimNode::array()},
                        {"cms_bytes", 0}};
  if (image.signature_range) {
    signing["slice_offset"] = image.signature_range->first;
    signing["byte_length"] = image.signature_range->second;
  }
  if (report.signing) {
    signing["selected_directory_slot"] = report.signing->preferred().slot;
    signing["selection_policy"] = "strongest_supported_declared_hash";
    for (const auto &record : report.signing->directories)
      signing["directories"].push_back(directory_json(record));
    signing["entries"] = report.signing->entries;
    signing["cms_bytes"] = report.signing->cms_bytes;
  }
  output["signing"] = std::move(signing);
  output["entitlements"] = {
      {"source", report.claims.source},
      {"declared", report.claims.selected},
      {"plist", report.claims.plist.value_or(ClaimNode(nullptr))},
      {"der", report.claims.der.value_or(ClaimNode(nullptr))},
      {"disagree", report.claims.disagree},
      {"differences", report.claims.differences},
      {"os_grants", "not_inspected"},
      {"errors", diagnostics(report.claims.errors)}};
  output["observations"] = observations(report.observations);
  output["errors"] = diagnostics(report.errors);
  return output;
}
} // namespace
ClaimNode JsonWriter::render(const std::vector<AuditReport> &results) {
  ClaimNode output = {
      {"schema_version", 1},
      {"tool", {{"name", "SignetScan"}, {"version", "1.0.0"}}},
      {"summary",
       {{"inputs", results.size()},
        {"failed_inputs", 0},
        {"slices", 0},
        {"by_severity", {{"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}}},
        {"by_code", ClaimNode::object()}}},
      {"inputs", ClaimNode::array()}};
  for (const auto &result : results) {
    auto &summary = output["summary"];
    summary["failed_inputs"] =
        summary["failed_inputs"].get<std::size_t>() + result.failed();
    summary["slices"] =
        summary["slices"].get<std::size_t>() + result.images.size();
    for (const auto &finding : result.observations()) {
      auto level = severity_label(finding.impact);
      summary["by_severity"][level] =
          summary["by_severity"][level].get<std::size_t>() + 1;
      summary["by_code"][finding.code] =
          summary["by_code"].value(finding.code, std::size_t(0)) + 1;
    }
    ClaimNode input = {
        {"path", result.path},
        {"byte_length", result.byte_length},
        {"status", result.failed() ? "incomplete" : "inspected"},
        {"errors", diagnostics(result.errors)},
        {"images", ClaimNode::array()}};
    for (const auto &image : result.images)
      input["images"].push_back(image_json(image));
    if (result.resources)
      input["resources"] = {
          {"linkage", result.resources->linkage},
          {"executable", result.resources->executable},
          {"checks", result.resources->checks},
          {"unlisted", result.resources->unlisted},
          {"observations", observations(result.resources->observations)},
          {"errors", diagnostics(result.resources->errors)}};
    output["inputs"].push_back(std::move(input));
  }
  return output;
}
std::string TextWriter::render(const std::vector<AuditReport> &results,
                                Severity minimum, bool verbose, bool summary) {
  std::ostringstream output;
  if (summary) {
    auto counts = JsonWriter::render(results)["summary"];
    output << "Inputs inspected: " << counts["inputs"]
           << "\nIncomplete inputs: " << counts["failed_inputs"]
           << "\nArchitecture slices: " << counts["slices"] << '\n';
    for (auto item = counts["by_severity"].begin();
         item != counts["by_severity"].end(); ++item)
      output << item.key() << ": " << item.value() << '\n';
    return output.str();
  }
  auto errors = [&](const auto &collection) {
    for (const auto &error : collection)
      output << "  ERROR [" << error.stage << "] " << error.message
             << " (offset " << error.offset << ")\n";
  };
  for (const auto &result : results) {
    output << result.path << '\n';
    errors(result.errors);
    for (const auto &image : result.images) {
      output << "  [" << image.image.architecture << "] signature metadata: "
             << (image.signing                 ? "parsed"
                 : image.image.signature_range ? "malformed"
                                               : "absent")
             << '\n';
      errors(image.errors);
      errors(image.claims.errors);
      if (verbose && image.signing) {
        const auto &record = image.signing->preferred();
        output << "    header flags: "
               << flag_names(image.image.header_flags, header_labels).dump()
               << "\n    signing flags: "
               << flag_names(record.attributes, signing_labels).dump()
               << "\n    execution flags: "
               << flag_names(record.executable_flags, execution_labels).dump()
               << '\n';
        output << "    identifier: " << record.identifier
               << "\n    declared team: " << record.team_identifier
               << "\n    CDHash: " << record.digest.substr(0, 40)
               << "\n    declared entitlements (" << image.claims.source
               << "): " << image.claims.selected.dump() << '\n';
      }
    }
    for (const auto &finding : result.observations())
      if (finding.impact >= minimum) {
        output << "  " << severity_label(finding.impact) << " [" << finding.code
               << "] " << finding.message << '\n';
        if (verbose)
          output << "    " << finding.explanation << '\n';
      }
    if (result.resources) {
      output << "  Resource seal linkage: " << result.resources->linkage
             << '\n';
      errors(result.resources->errors);
    }
  }
  output << "Structural inspection only. Cryptographic signatures and "
            "OS-granted permissions were not verified.\n";
  return output.str();
}
} // namespace signet_scan
