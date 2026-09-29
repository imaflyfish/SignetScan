#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace signet_scan {
using ClaimNode = nlohmann::ordered_json;
using ByteView = std::span<const std::uint8_t>;
inline constexpr std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
inline constexpr std::size_t max_document_bytes = 16 * 1024 * 1024;
// The other limits bound a structure the input declares. This one bounds an
// open-ended walk of the filesystem, so every traversal shares it: a bundle's
// resources, a bundle's executable folder and a recursive command-line scan.
inline constexpr std::size_t max_traversed_entries = 250000;

struct FaultNote {
  std::string stage;
  std::string message;
  std::uint64_t offset = 0;
};
class ParseFault final : public std::runtime_error {
public:
  FaultNote diagnostic;
  ParseFault(std::string stage, std::string message, std::uint64_t offset = 0)
      : std::runtime_error(message),
        diagnostic{std::move(stage), std::move(message), offset} {}
};

class ByteWindow {
  ByteView bytes_;
  std::string stage_;
  std::uint64_t origin_;

public:
  explicit ByteWindow(ByteView bytes, std::string stage = "binary",
                      std::uint64_t origin = 0)
      : bytes_(bytes), stage_(std::move(stage)), origin_(origin) {}
  std::size_t size() const { return bytes_.size(); }
  ByteView bytes() const { return bytes_; }
  // Where this window starts in the original input, so a caller rejecting the
  // bytes it holds can report the same location the reader itself would.
  std::uint64_t origin() const { return origin_; }
  void require(std::uint64_t offset, std::uint64_t length) const;
  ByteWindow region(std::uint64_t offset, std::uint64_t length) const;
  std::uint64_t integer(std::uint64_t offset, unsigned width,
                        bool big_endian = true) const;
  std::string text(std::uint64_t offset, std::uint64_t length,
                   bool require_nul = false) const;
};

struct SegmentEntry {
  std::string label;
  std::uint64_t virtual_address = 0, virtual_size = 0, file_offset = 0,
                file_length = 0;
  std::uint32_t maximum_protection = 0, initial_protection = 0,
                section_count = 0;
};
struct MachSlice {
  std::uint64_t file_offset = 0, byte_length = 0;
  std::uint32_t cpu_kind = 0, cpu_variant = 0, image_kind = 0, header_flags = 0;
  bool wide = false, big_endian = false;
  std::string architecture;
  std::vector<SegmentEntry> segments;
  std::vector<std::pair<std::uint32_t, std::string>> dependencies;
  std::vector<std::string> search_paths;
  std::optional<std::pair<std::uint64_t, std::uint64_t>> signature_range;
  ClaimNode commands = ClaimNode::array(), encryption = nullptr,
            build = nullptr;
};
class MachImageSet {
public:
  static std::vector<MachSlice> decode(ByteView input);
  static bool recognises(ByteView prefix);
};

struct CodeDirectoryEntry {
  std::uint32_t slot = 0, version = 0, attributes = 0;
  std::string identifier, team_identifier, algorithm, digest;
  std::uint8_t algorithm_code = 0, digest_width = 0, platform = 0;
  std::uint64_t page_bytes = 0, covered_bytes = 0, executable_base = 0,
                executable_limit = 0, executable_flags = 0;
  std::uint32_t code_slots = 0, special_slots = 0, encoded_bytes = 0;
  std::map<std::uint32_t, std::string> special_digests;
};
struct SignatureBlob {
  std::vector<CodeDirectoryEntry> directories;
  std::optional<std::vector<std::uint8_t>> plist_claims, der_claims;
  std::uint64_t cms_bytes = 0;
  ClaimNode entries = ClaimNode::array();
  static SignatureBlob decode(ByteView input);
  const CodeDirectoryEntry &primary() const;
  const CodeDirectoryEntry &preferred() const;
};
struct GrantDocument {
  std::optional<ClaimNode> plist, der;
  std::vector<FaultNote> errors;
  ClaimNode selected = ClaimNode::object();
  std::string source = "absent";
  bool disagree = false;
  ClaimNode differences = ClaimNode::array();
  static GrantDocument decode(const SignatureBlob &signature);
};
ClaimNode parse_plist(ByteView input);
ClaimNode parse_der(ByteView input);
std::string compute_digest(ByteView input, const std::string &algorithm);
std::string digest_of_file(const std::filesystem::path &path,
                           const std::string &algorithm);
std::vector<std::uint8_t> load_input(const std::filesystem::path &path,
                                     std::uint64_t limit = max_input_bytes);
std::string hex_encode(ByteView bytes);

enum class Severity { info, low, medium, high };
std::string severity_label(Severity severity);
Severity parse_severity(const std::string &name);
struct Remark {
  std::string code;
  Severity severity = Severity::info;
  std::string message, explanation;
  ClaimNode evidence = ClaimNode::object();
};
// The report order: strongest severity first, then code, preserving input order
// for ties. Every emitter uses this so JSON and text cannot disagree.
void sort_remarks(std::vector<Remark> &findings);
struct SliceOutcome {
  MachSlice image;
  std::optional<SignatureBlob> signing;
  GrantDocument claims;
  std::vector<Remark> observations;
  std::vector<FaultNote> errors;
};
class AuditRuleSet {
public:
  static std::vector<Remark> evaluate(const SliceOutcome &facts);
};
struct SealVerdict {
  std::string executable;
  std::string linkage = "unrecorded";
  ClaimNode checks = ClaimNode::array(), unlisted = ClaimNode::array();
  std::vector<Remark> observations;
  std::vector<FaultNote> errors;
};
struct BundleLayout {
  std::filesystem::path root, content, manifest, executable;
  bool flat = false;
  static std::optional<BundleLayout>
  discover(const std::filesystem::path &root);
};
class BundlePath {
public:
  static std::filesystem::path resolve(const std::filesystem::path &root,
                                       const std::filesystem::path &relative,
                                       bool follow_leaf = true);
};
class SealManifest {
public:
  static SealVerdict inspect(const BundleLayout &bundle,
                             const std::vector<SliceOutcome> &images);
};
struct AuditReport {
  std::string path;
  std::uint64_t byte_length = 0;
  std::vector<SliceOutcome> images;
  std::optional<SealVerdict> resources;
  std::vector<FaultNote> errors;
  bool failed() const;
  std::vector<Remark> observations() const;
};
struct AuditOptions {
  bool check_resources = true;
};
class AuditSession {
public:
  AuditReport inspect_bytes(ByteView input,
                            const std::string &label = "<memory>") const;
  AuditReport inspect_file(const std::filesystem::path &path) const;
  AuditReport inspect_path(const std::filesystem::path &path,
                           AuditOptions options = {}) const;
};
class JsonWriter {
public:
  static ClaimNode render(const std::vector<AuditReport> &results);
};
class TextWriter {
public:
  static std::string render(const std::vector<AuditReport> &results,
                            Severity minimum = Severity::info,
                            bool verbose = false, bool summary = false);
};
} // namespace signet_scan
