#include <signet_scan/audit.hpp>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <fstream>
#include <memory>
#include <pcre2.h>
#include <set>

namespace signet_scan {
namespace fs = std::filesystem;
namespace {
bool beneath(const fs::path &root, const fs::path &candidate) {
  auto ancestor = root.begin(), descendant = candidate.begin();
  for (; ancestor != root.end(); ++ancestor, ++descendant)
    if (descendant == candidate.end() || *ancestor != *descendant)
      return false;
  return true;
}
bool seems_image(const fs::path &path) {
  std::ifstream stream(path, std::ios::binary);
  std::array<std::uint8_t, 4> prefix{};
  stream.read(reinterpret_cast<char *>(prefix.data()), 4);
  return stream.gcount() == 4 && MachImageSet::recognises(prefix);
}
std::string digest_algorithm(std::size_t bytes) {
  switch (bytes) {
  case 20:
    return "sha1";
  case 32:
    return "sha256";
  case 48:
    return "sha384";
  case 64:
    return "sha512";
  default:
    return "";
  }
}
bool truth(const ClaimNode &value) {
  if (value.is_null())
    return false;
  if (value.is_boolean())
    return value.get<bool>();
  if (value.is_number())
    return value.get<double>() != 0;
  if (value.is_string())
    return !value.get_ref<const std::string &>().empty();
  return !value.empty();
}
struct SealEntry {
  std::map<std::string, std::string> digests;
  std::optional<std::string> link;
  bool nested = false, unknown = false;
  bool optional = true;
  std::string category() const {
    return link                          ? "symlink"
           : nested                      ? "nested"
           : !digests.empty() || unknown ? "hash"
                                         : "unknown";
  }
};
void merge_entry(SealEntry &target, const ClaimNode &value) {
  if (value.is_object() && value.contains("optional") &&
      !value["optional"].is_boolean())
    throw ParseFault("resources", "resource optional flag is not a boolean");
  // Conservatively retain a requirement from either manifest table. The usual
  // codesign localization records mark the resource optional in both tables.
  target.optional = target.optional && value.is_object() &&
                    value.value("optional", false);
  auto digest = [&](const ClaimNode &candidate) {
    if (!candidate.is_binary())
      throw ParseFault("resources", "resource digest is not binary data");
    const auto &bytes = candidate.get_binary();
    auto algorithm = digest_algorithm(bytes.size());
    if (algorithm.empty())
      target.unknown = true;
    else {
      auto encoded = hex_encode(bytes);
      const auto [entry, inserted] = target.digests.try_emplace(algorithm, encoded);
      if (!inserted && entry->second != encoded)
        throw ParseFault("resources", "conflicting " + algorithm +
                                             " digests for one resource");
    }
  };
  if (value.is_binary()) {
    digest(value);
    return;
  }
  if (!value.is_object()) {
    target.unknown = true;
    return;
  }
  for (const auto *key : {"hash", "hash2", "hash3"})
    if (value.contains(key))
      digest(value[key]);
  if (value.contains("symlink") && value["symlink"].is_string() && !target.link)
    target.link = value["symlink"].get<std::string>();
  if ((value.contains("requirement") && !value["requirement"].is_null()) ||
      (value.contains("cdhash") && value["cdhash"].is_binary() &&
       !value["cdhash"].get_binary().empty()))
    target.nested = true;
}
struct SealPattern {
  std::shared_ptr<pcre2_code> expression;
  std::string treatment;
  double weight;
};
std::vector<SealPattern> compile_rules(const ClaimNode &table) {
  std::vector<SealPattern> result;
  if (!table.is_object())
    throw ParseFault("resources", "resource rule table is not a dictionary");
  for (auto item = table.begin(); item != table.end(); ++item) {
    auto body = item.value();
    if (body.is_boolean())
      body = ClaimNode{{"omit", !body.get<bool>()}};
    if (!body.is_object())
      throw ParseFault("resources", "invalid rule body");
    auto pattern = item.key();
    if (pattern.size() > 16384)
      throw ParseFault("resources", "resource rule exceeds length limit");
    int error = 0;
    PCRE2_SIZE offset = 0;
    auto *expression =
        pcre2_compile(reinterpret_cast<PCRE2_SPTR>(pattern.data()),
                      pattern.size(), PCRE2_UTF, &error, &offset, nullptr);
    if (!expression)
      throw ParseFault(
          "resources", "resource rule could not compile: " + pattern, offset);
    std::shared_ptr<pcre2_code> owner(expression, pcre2_code_free);
    double weight = 0;
    if (body.contains("weight")) {
      if (body["weight"].is_number())
        weight = body["weight"].get<double>();
      else if (body["weight"].is_string()) {
        try {
          weight = std::stod(body["weight"].get<std::string>());
        } catch (const std::exception &) {
          weight = 0;
        }
      }
    }
    if (!std::isfinite(weight))
      throw ParseFault("resources", "non-finite rule weight");
    result.push_back({std::move(owner),
                      truth(body.value("omit", ClaimNode(false))) ? "omit"
                      : truth(body.value("nested", ClaimNode(false)))
                          ? "nested"
                          : "hash",
                      weight});
  }
  std::stable_sort(result.begin(), result.end(),
                   [](const auto &left, const auto &right) {
                     return left.weight > right.weight;
                   });
  return result;
}
std::string treatment(const std::string &path,
                      const std::vector<SealPattern> &rules) {
  std::unique_ptr<pcre2_match_context, decltype(&pcre2_match_context_free)>
      context(pcre2_match_context_create(nullptr), pcre2_match_context_free);
  if (!context)
    throw ParseFault("resources", "match context allocation failed");
  pcre2_set_match_limit(context.get(), 100000);
  pcre2_set_depth_limit(context.get(), 256);
  for (const auto &rule : rules) {
    std::unique_ptr<pcre2_match_data, decltype(&pcre2_match_data_free)> match(
        pcre2_match_data_create_from_pattern(rule.expression.get(), nullptr),
        pcre2_match_data_free);
    if (!match)
      throw ParseFault("resources", "match allocation failed");
    int status = pcre2_match(rule.expression.get(),
                             reinterpret_cast<PCRE2_SPTR>(path.data()),
                             path.size(), 0, 0, match.get(), context.get());
    if (status >= 0)
      return rule.treatment;
    if (status != PCRE2_ERROR_NOMATCH)
      throw ParseFault("resources",
                          "resource rule matching failed or reached its limit");
  }
  return "none";
}
ClaimNode inspect_entry(const fs::path &base, const std::string &relative,
                         const SealEntry &entry) {
  ClaimNode result = {
      {"path", relative}, {"kind", entry.category()}, {"status", "ok"}};
  fs::path path;
  try {
    path = BundlePath::resolve(base, relative, false);
  } catch (const ParseFault &error) {
    result["status"] = "escape";
    result["detail"] = error.what();
    return result;
  }
  auto state = fs::symlink_status(path);
  if (!fs::exists(state)) {
    result["status"] = entry.optional ? "optional-missing" : "missing";
    return result;
  }
  if (entry.link) {
    result["expected"] = *entry.link;
    if (!fs::is_symlink(state))
      result["status"] = "type";
    else {
      result["actual"] = fs::read_symlink(path).string();
      if (result["actual"] != result["expected"])
        result["status"] = "mismatch";
    }
    return result;
  }
  if (entry.nested) {
    try {
      path = BundlePath::resolve(base, relative, true);
      if (!fs::exists(path))
        result["status"] = "missing";
    } catch (const ParseFault &error) {
      result["status"] = "escape";
      result["detail"] = error.what();
    }
    result["identity_verification"] = "not_performed";
    return result;
  }
  if (entry.digests.empty()) {
    result["status"] = "unsupported";
    return result;
  }
  if (!fs::is_regular_file(state)) {
    result["status"] = "type";
    return result;
  }
  for (const auto &[algorithm, expected] : entry.digests) {
    auto actual = digest_of_file(path, algorithm);
    if (actual != expected) {
      result["status"] = "mismatch";
      result["algorithm"] = algorithm;
      result["expected"] = expected;
      result["actual"] = actual;
      break;
    }
  }
  if (result["status"] == "ok" && entry.unknown)
    result["status"] = "unsupported";
  return result;
}
void add_observations(SealVerdict &report) {
  auto add = [&](std::string code, Severity level, std::string message,
                 ClaimNode evidence = ClaimNode::object()) {
    report.observations.push_back(
        {std::move(code), level, std::move(message),
         "This compares recorded bundle metadata with the inspected files; it "
         "does not authenticate the signature.",
         std::move(evidence)});
  };
  if (!report.errors.empty())
    add("resource-seal-unreadable", Severity::medium,
        "Resource inspection could not complete");
  if (report.linkage == "mismatch")
    add("resource-seal-mismatch", Severity::high,
        "Resource manifest differs from a recorded signature digest");
  if (report.linkage == "absent")
    add("resource-seal-absent", Severity::high,
        "Recorded resource manifest is missing");
  std::size_t problems = 0;
  for (const auto &check : report.checks) {
    auto status = check["status"].get<std::string>();
    if (status == "ok" || status == "optional-missing")
      continue;
    ++problems;
    if (problems > 40)
      continue;
    auto path = check["path"].get<std::string>();
    if (status == "mismatch")
      add(check["kind"] == "symlink" ? "resource-symlink-changed"
                                     : "resource-hash-mismatch",
          check["kind"] == "symlink" ? Severity::medium : Severity::high,
          "Resource differs: " + path, check);
    else if (status == "missing")
      add("resource-missing", Severity::high, "Resource is missing: " + path,
          check);
    else if (status == "type")
      add("resource-type-changed", Severity::medium,
          "Resource kind changed: " + path, check);
    else if (status == "escape")
      add("resource-path-escape", Severity::high,
          "Resource path escapes the bundle: " + path, check);
    else
      add("resource-hash-unsupported", Severity::medium,
          "Resource cannot be evaluated: " + path, check);
  }
  if (problems > 40)
    add("resource-problems-remain", Severity::high,
        "Additional resource discrepancies", {{"count", problems - 40}});
  if (!report.unlisted.empty())
    add("resource-unsealed", Severity::medium,
        "Files required by seal rules are unlisted",
        {{"count", report.unlisted.size()},
         {"examples",
          ClaimNode(report.unlisted.begin(),
                     report.unlisted.begin() +
                         static_cast<std::ptrdiff_t>(std::min<std::size_t>(
                             20, report.unlisted.size())))}});
}
} // namespace
fs::path BundlePath::resolve(const fs::path &root, const fs::path &relative,
                               bool follow_leaf) {
  auto name = relative.string();
  if (relative.is_absolute() || name.find('\0') != std::string::npos ||
      name.starts_with('~'))
    throw ParseFault("resources", "invalid bundle-relative path");
  auto canonical_root = fs::canonical(root);
  auto candidate = (canonical_root / relative).lexically_normal();
  if (!beneath(canonical_root, candidate))
    throw ParseFault("resources", "path escapes the bundle");
  auto resolved = follow_leaf ? fs::weakly_canonical(candidate)
                              : fs::weakly_canonical(candidate.parent_path()) /
                                    candidate.filename();
  if (!beneath(canonical_root, resolved))
    throw ParseFault("resources", "symlink resolves outside the bundle");
  return resolved;
}
std::optional<BundleLayout>
BundleLayout::discover(const fs::path &root) {
  if (!fs::is_directory(root))
    return std::nullopt;
  for (bool flat : {false, true}) {
    auto base = flat ? fs::path(".") : fs::path("Contents");
    auto info = BundlePath::resolve(root, base / "Info.plist");
    if (!fs::is_regular_file(info))
      continue;
    auto bytes = load_input(info, max_document_bytes);
    auto metadata = parse_plist(bytes);
    BundleLayout bundle;
    bundle.root = fs::canonical(root);
    bundle.content = BundlePath::resolve(root, base);
    bundle.flat = flat;
    bundle.manifest = bundle.content / "_CodeSignature/CodeResources";
    auto folder = flat ? fs::path(".") : fs::path("MacOS");
    if (metadata.contains("CFBundleExecutable")) {
      if (!metadata["CFBundleExecutable"].is_string())
        throw ParseFault("bundle", "CFBundleExecutable is not a string");
      auto name = metadata["CFBundleExecutable"].get<std::string>();
      if (name.empty() || name == "." || name == ".." ||
          name.find_first_of("/\\") != std::string::npos ||
          name.find('\0') != std::string::npos)
        throw ParseFault("bundle", "invalid CFBundleExecutable filename");
      auto candidate = BundlePath::resolve(bundle.content, folder / name);
      if (!fs::is_regular_file(candidate))
        throw ParseFault("bundle",
                            "declared bundle executable is missing or is not a regular file: " +
                                name);
      bundle.executable = candidate;
    }
    if (bundle.executable.empty()) {
      auto directory = BundlePath::resolve(bundle.content, folder);
      if (fs::is_directory(directory)) {
        std::vector<fs::path> choices;
        for (const auto &entry : fs::directory_iterator(directory)) {
          if (choices.size() > 250000)
            throw ParseFault("bundle", "directory entry limit exceeded");
          choices.push_back(entry.path());
        }
        std::sort(choices.begin(), choices.end());
        for (const auto &choice : choices) {
          auto candidate = BundlePath::resolve(
              bundle.content, choice.lexically_relative(bundle.content));
          if (fs::is_regular_file(candidate) && seems_image(candidate)) {
            bundle.executable = candidate;
            break;
          }
        }
      }
    }
    return bundle;
  }
  return std::nullopt;
}
SealVerdict
SealManifest::inspect(const BundleLayout &bundle,
                          const std::vector<SliceOutcome> &images) {
  SealVerdict report;
  if (!bundle.executable.empty())
    report.executable =
        bundle.executable.lexically_relative(bundle.root).generic_string();
  try {
    auto manifest_path =
        BundlePath::resolve(bundle.content, "_CodeSignature/CodeResources");
    std::vector<std::pair<std::string, std::string>> recorded;
    for (const auto &image : images)
      if (image.signing)
        for (const auto &directory : image.signing->directories) {
          auto slot = directory.special_digests.find(3);
          if (slot != directory.special_digests.end() &&
              !directory.algorithm.starts_with("unknown-"))
            recorded.emplace_back(directory.algorithm, slot->second);
        }
    if (!fs::is_regular_file(manifest_path)) {
      report.linkage = recorded.empty() ? "unrecorded" : "absent";
      add_observations(report);
      return report;
    }
    auto bytes = load_input(manifest_path, max_document_bytes);
    auto document = parse_plist(bytes);
    if (!recorded.empty()) {
      report.linkage = "match";
      std::map<std::string, std::string> computed;
      for (const auto &[algorithm, expected] : recorded) {
        if (!computed.contains(algorithm))
          computed[algorithm] = compute_digest(bytes, algorithm);
        if (computed[algorithm].substr(0, expected.size()) != expected)
          report.linkage = "mismatch";
      }
    }
    std::map<std::string, SealEntry> entries;
    for (const auto *name : {"files", "files2"})
      if (document.contains(name)) {
        if (!document[name].is_object())
          throw ParseFault("resources",
                              "resource file table is not a dictionary");
        for (auto entry = document[name].begin(); entry != document[name].end();
             ++entry)
          merge_entry(entries[entry.key()], entry.value());
      }
    for (const auto &[relative, entry] : entries)
      report.checks.push_back(inspect_entry(bundle.content, relative, entry));
    auto old_rules =
        compile_rules(document.value("rules", ClaimNode::object()));
    auto new_rules =
        compile_rules(document.value("rules2", ClaimNode::object()));
    std::vector<std::string> unlisted;
    std::size_t visited = 0;
    for (auto iterator = fs::recursive_directory_iterator(bundle.content);
         iterator != fs::recursive_directory_iterator(); ++iterator) {
      if (++visited > 250000)
        throw ParseFault("resources", "resource traversal limit exceeded");
      const auto &path = iterator->path();
      auto relative = path.lexically_relative(bundle.content);
      if (relative == "_CodeSignature") {
        iterator.disable_recursion_pending();
        continue;
      }
      auto state = iterator->symlink_status();
      if (fs::is_directory(state))
        continue;
      auto name = relative.generic_string();
      if (entries.contains(name))
        continue;
      const bool sealed = document.contains("rules2")
                              ? treatment(name, new_rules) == "hash" &&
                                    (old_rules.empty() ||
                                     treatment(name, old_rules) == "hash")
                              : treatment(name, old_rules) == "hash";
      if (sealed)
        unlisted.push_back(name);
    }
    std::sort(unlisted.begin(), unlisted.end());
    report.unlisted = unlisted;
  } catch (const ParseFault &error) {
    report.errors.push_back(error.diagnostic);
    if (report.linkage == "unrecorded")
      report.linkage = "unreadable";
  } catch (const std::exception &error) {
    report.errors.push_back({"resources", error.what(), 0});
    if (report.linkage == "unrecorded")
      report.linkage = "unreadable";
  }
  add_observations(report);
  return report;
}
} // namespace signet_scan
