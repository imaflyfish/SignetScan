#include <fstream>
#include <iostream>
#include <plist/plist.h>
#include <signet_scan/audit.hpp>
#include <unistd.h>
using namespace signet_scan;
namespace fs = std::filesystem;
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
void write(const fs::path &path, const std::string &value) {
  fs::create_directories(path.parent_path());
  std::ofstream stream(path, std::ios::binary);
  stream << value;
}
plist_t native(const ClaimNode &value) {
  if (value.is_object()) {
    auto node = plist_new_dict();
    for (auto item = value.begin(); item != value.end(); ++item)
      plist_dict_set_item(node, item.key().c_str(), native(item.value()));
    return node;
  }
  if (value.is_array()) {
    auto node = plist_new_array();
    for (const auto &item : value)
      plist_array_append_item(node, native(item));
    return node;
  }
  if (value.is_binary()) {
    const auto &bytes = value.get_binary();
    return plist_new_data(reinterpret_cast<const char *>(bytes.data()),
                          bytes.size());
  }
  if (value.is_string())
    return plist_new_string(value.get_ref<const std::string &>().c_str());
  if (value.is_boolean())
    return plist_new_bool(value.get<bool>());
  if (value.is_number())
    return plist_new_real(value.get<double>());
  return plist_new_null();
}
void save(const fs::path &path, const ClaimNode &value) {
  auto node = native(value);
  char *xml = nullptr;
  std::uint32_t length = 0;
  if (plist_to_xml(node, &xml, &length) != PLIST_ERR_SUCCESS)
    throw std::runtime_error("fixture plist encoding failed");
  write(path, std::string(xml, length));
  plist_mem_free(xml);
  plist_free(node);
}
bool has(const SealVerdict &report, const std::string &code) {
  return std::any_of(report.observations.begin(), report.observations.end(),
                     [&](const auto &item) { return item.code == code; });
}
ClaimNode hash_value(const std::string &value) {
  auto hex = compute_digest(
      ByteView(reinterpret_cast<const std::uint8_t *>(value.data()),
               value.size()),
      "sha256");
  std::vector<std::uint8_t> bytes;
  for (std::size_t index = 0; index < hex.size(); index += 2)
    bytes.push_back(static_cast<std::uint8_t>(
        std::stoul(hex.substr(index, 2), nullptr, 16)));
  return ClaimNode::binary(bytes);
}
} // namespace
int main() {
  try {
    std::string pattern =
        (fs::temp_directory_path() / "signet-scan-seal-tests-XXXXXX").string();
    if (!mkdtemp(pattern.data()))
      throw std::runtime_error("mkdtemp failed");
    fs::path workspace = pattern;
    struct Cleanup {
      fs::path path;
      ~Cleanup() {
        std::error_code error;
        fs::remove_all(path, error);
      }
    } cleanup{workspace};
    auto base = workspace / "App/Contents";
    fs::create_directories(base);
    BundleLayout bundle{workspace / "App",
                        base,
                        base / "_CodeSignature/CodeResources",
                        {},
                        false};
    auto assess = [&](ClaimNode document) {
      save(bundle.manifest, document);
      return SealManifest::inspect(bundle, {});
    };
    ClaimNode document = {
        {"files2", {{"Resources/item", {{"hash2", hash_value("original")}}}}},
        {"rules2",
         {{"^Resources/", {{"weight", 20}}}, {"^.*", {{"omit", true}}}}}};
    write(base / "Resources/item", "original");
    auto report = assess(document);
    check(report.errors.empty() && report.observations.empty(),
          "synthetic clean seal");
    write(base / "Resources/item", "changed");
    check(has(assess(document), "resource-hash-mismatch"), "hash mismatch");
    write(base / "Resources/item", "original");
    write(base / "Resources/unlisted", "later");
    check(has(assess(document), "resource-unsealed"), "unlisted file");
    auto exempt = document;
    exempt["rules2"]["^Resources/unlisted$"] = {{"omit", true}, {"weight", 30}};
    check(!has(assess(exempt), "resource-unsealed"),
          "higher-weight omission wins");
    auto order = document;
    order["rules2"] = ClaimNode::object();
    order["rules2"]["^Resources/"] = {{"omit", true}, {"weight", 1}};
    order["rules2"]["^Resources/.*"] = {{"weight", 1}};
    check(!has(assess(order), "resource-unsealed"),
          "equal-weight original insertion order");
    order["rules2"] = ClaimNode::object();
    order["rules2"]["^Resources/.*"] = {{"weight", 1}};
    order["rules2"]["^Resources/"] = {{"omit", true}, {"weight", 1}};
    check(has(assess(order), "resource-unsealed"),
          "equal-weight reverse insertion order");
    auto v1 = document;
    v1["rules"] = {{"^Resources/", {{"omit", true}}}};
    check(!has(assess(v1), "resource-unsealed"),
          "v1 omission remains effective");
    fs::remove(base / "Resources/unlisted");
    auto bad_regex = document;
    bad_regex["rules2"] = {{"[", true}};
    check(!assess(bad_regex).errors.empty(),
          "invalid regular expression is incomplete");
    fs::remove(base / "Resources/item");
    check(has(assess(document), "resource-missing"), "missing sealed file");
    auto optional = document;
    optional["files2"]["Resources/item"]["optional"] = true;
    report = assess(optional);
    check(report.errors.empty() && report.observations.empty() &&
              report.checks[0]["status"] == "optional-missing",
          "explicitly optional missing resource is recorded without a finding");
    auto required = optional;
    required["files2"]["Resources/item"]["optional"] = false;
    check(has(assess(required), "resource-missing"),
          "explicitly required missing resource is a finding");
    auto invalid_optional = optional;
    invalid_optional["files2"]["Resources/item"]["optional"] = "true";
    check(!assess(invalid_optional).errors.empty(),
          "optional must be a boolean, not a truthy string");
    auto combined = optional;
    combined["files"] = combined["files2"];
    check(assess(combined).observations.empty(),
          "both manifest records permit optional absence");
    combined["files"]["Resources/item"] = hash_value("original");
    check(has(assess(combined), "resource-missing"),
          "modern optional record cannot weaken legacy required record");
    combined = optional;
    combined["files"] = combined["files2"];
    combined["files2"]["Resources/item"].erase("optional");
    check(has(assess(combined), "resource-missing"),
          "legacy optional record cannot weaken modern required record");
    auto optional_legacy = optional;
    optional_legacy["files"] = optional_legacy["files2"];
    optional_legacy.erase("files2");
    check(assess(optional_legacy).observations.empty(),
          "legacy optional record permits absence");
    fs::create_directory(base / "Resources/item");
    check(has(assess(document), "resource-type-changed"),
          "file changed into directory");
    check(has(assess(optional), "resource-type-changed"),
          "present optional resource still requires the sealed file type");
    fs::remove(base / "Resources/item");
    write(base / "Resources/item", "changed");
    check(has(assess(optional), "resource-hash-mismatch"),
          "present optional resource still requires the sealed hash");
    write(base / "Resources/item", "original");
    check(assess(optional).observations.empty(),
          "present unchanged optional resource passes");
    auto unknown = document;
    unknown["files2"]["Resources/item"]["hash2"] =
        ClaimNode::binary(std::vector<std::uint8_t>(17, 1));
    check(has(assess(unknown), "resource-hash-unsupported"),
          "unsupported digest size");
    unknown["files2"]["Resources/item"]["hash"] = hash_value("original");
    check(has(assess(unknown), "resource-hash-unsupported"),
          "known digest does not hide unsupported additional digest");
    auto conflicting = document;
    conflicting["files"]["Resources/item"] = hash_value("different");
    check(!assess(conflicting).errors.empty(),
          "conflicting digests across resource tables rejected");
    conflicting["files"]["Resources/item"] = hash_value("original");
    check(assess(conflicting).observations.empty(),
          "identical digests across resource tables accepted");
    conflicting = document;
    conflicting["files2"]["Resources/item"]["hash"] = hash_value("different");
    check(!assess(conflicting).errors.empty(),
          "conflicting same-algorithm hashes in one record rejected");
    auto wrong_type = document;
    wrong_type["files2"]["Resources/item"]["hash"] = "not binary data";
    check(!assess(wrong_type).errors.empty(),
          "valid hash does not hide malformed additional hash");
    for (const auto *name : {"rules", "rules2"}) {
      auto wrong_rules = document;
      wrong_rules[name] = ClaimNode::array({true});
      check(!assess(wrong_rules).errors.empty(),
            std::string(name) + " must be a dictionary");
    }
    auto legacy = document;
    legacy["rules"] = legacy["rules2"];
    legacy.erase("rules2");
    legacy["files"] = legacy["files2"];
    legacy.erase("files2");
    write(base / "Resources/legacy-unlisted", "later");
    check(has(assess(legacy), "resource-unsealed"),
          "legacy-only seal rules detect unlisted files");
    legacy["rules"]["^Resources/legacy-unlisted$"] = {{"omit", true},
                                                      {"weight", 30}};
    check(!has(assess(legacy), "resource-unsealed"),
          "legacy-only seal rules honor omission weights");
    fs::remove(base / "Resources/legacy-unlisted");
    auto symbolic = document;
    symbolic["files2"]["Resources/link"] = {{"symlink", "item"}};
    fs::create_symlink("item", base / "Resources/link");
    check(assess(symbolic).observations.empty(),
          "sealed symlink compares target text");
    fs::remove(base / "Resources/link");
    fs::create_symlink("other", base / "Resources/link");
    check(has(assess(symbolic), "resource-symlink-changed"),
          "changed dangling symlink");
    fs::remove(base / "Resources/link");
    write(base / "Resources/link", "file");
    check(has(assess(symbolic), "resource-type-changed"),
          "symlink changed into file");
    fs::remove(base / "Resources/link");
    auto nested = document;
    nested["files2"]["Nested"] = {{"requirement", "identifier test.nested"}};
    check(has(assess(nested), "resource-missing"), "missing nested code");
    fs::create_directory(base / "Nested");
    report = assess(nested);
    check(report.observations.empty() &&
              report.checks[0]["identity_verification"] == "not_performed",
          "nested code identity explicitly unevaluated");
    fs::remove(base / "Nested");
    fs::create_directory(workspace / "outside-nested");
    fs::create_directory_symlink(workspace / "outside-nested", base / "Nested");
    check(has(assess(nested), "resource-path-escape"), "nested code escape");
    fs::remove(base / "Nested");
    auto traversal = document;
    traversal["files2"]["../../outside"] = {{"hash2", hash_value("x")}};
    check(has(assess(traversal), "resource-path-escape"),
          "relative path escape");
    traversal = document;
    traversal["files2"]["/tmp/not-read"] = {{"hash2", hash_value("x")}};
    check(has(assess(traversal), "resource-path-escape"),
          "absolute path escape");
    write(base / "real/item", "original");
    fs::remove_all(base / "Resources");
    fs::create_directory_symlink(base / "real", base / "Resources");
    check(assess(document).observations.empty(),
          "parent symlink within bundle hashes correctly");
    fs::remove(base / "Resources");
    fs::create_directories(base / "Resources");
    write(base / "Resources/item", "original");
    fs::remove_all(base / "real");
    auto many = document;
    for (unsigned index = 0; index < 55; ++index)
      many["files2"]["Resources/missing-" + std::to_string(index)] = {
          {"hash2", hash_value("missing")}};
    report = assess(many);
    check(report.observations.size() == 41 &&
              has(report, "resource-problems-remain"),
          "resource findings capped with remaining count");
    save(bundle.manifest, document);
    auto encoded = load_input(bundle.manifest);
    SliceOutcome image;
    image.signing = SignatureBlob{};
    CodeDirectoryEntry record;
    record.algorithm = "sha256";
    record.special_digests[3] = compute_digest(encoded, "sha256");
    image.signing->directories.push_back(record);
    check(SealManifest::inspect(bundle, {image}).linkage == "match",
          "manifest matches CodeDirectory special slot");
    auto other = image;
    other.signing->directories[0].special_digests[3] = std::string(64, '0');
    check(SealManifest::inspect(bundle, {image, other}).linkage == "mismatch",
          "all recorded architecture seals must agree");
    fs::remove(bundle.manifest);
    check(SealManifest::inspect(bundle, {image}).linkage == "absent",
          "recorded absent seal");
    check(SealManifest::inspect(bundle, {}).linkage == "unrecorded",
          "unrecorded absent seal");
    write(bundle.manifest, "broken plist");
    check(!SealManifest::inspect(bundle, {}).errors.empty(),
          "malformed resource manifest is an error");
    // A distinct synthetic Mach-O must not substitute for a missing declared
    // bundle executable. No host executable or private input is needed.
    std::string thin(32, '\0');
    thin[0] = char(0xcf);
    thin[1] = char(0xfa);
    thin[2] = char(0xed);
    thin[3] = char(0xfe);
    thin[4] = 12;
    thin[7] = 1;
    thin[12] = 2;
    write(base / "MacOS/helper", thin);
    auto inspect_bundle = [&](const ClaimNode &info) {
      save(base / "Info.plist", info);
      return AuditSession().inspect_path(bundle.root, {false});
    };
    check(inspect_bundle({{"CFBundleExecutable", "missing"}}).failed(),
          "declared missing executable cannot fall back to another image");
    fs::create_directory(base / "MacOS/folder");
    check(inspect_bundle({{"CFBundleExecutable", "folder"}}).failed(),
          "declared directory executable cannot fall back to another image");
    check(inspect_bundle({{"CFBundleExecutable", true}}).failed(),
          "non-string executable declaration cannot fall back");
    check(!inspect_bundle({{"CFBundleExecutable", "helper"}}).failed(),
          "declared synthetic executable inspected");
    check(!inspect_bundle(ClaimNode::object()).failed(),
          "missing executable declaration retains documented discovery");
    std::cout << passed << " resource checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
