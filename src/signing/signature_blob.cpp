#include <set>
#include <signet_scan/audit.hpp>

namespace signet_scan {
namespace {
CodeDirectoryEntry directory(ByteWindow input, std::uint32_t slot) {
  input.require(0, 44);
  CodeDirectoryEntry record;
  record.slot = slot;
  record.encoded_bytes = static_cast<std::uint32_t>(input.size());
  auto word = [&](unsigned offset) {
    return static_cast<std::uint32_t>(input.integer(offset, 4));
  };
  record.version = word(8);
  record.attributes = word(12);
  auto hash_offset = word(16), identifier_offset = word(20);
  record.special_slots = word(24);
  record.code_slots = word(28);
  if (record.special_slots > 64 || record.code_slots > 4 * 1024 * 1024)
    throw ParseFault("signature", "signature hash-slot count exceeds limit",
                     input.origin() + 24);
  record.covered_bytes = word(32);
  record.digest_width = static_cast<std::uint8_t>(input.integer(36, 1));
  record.algorithm_code = static_cast<std::uint8_t>(input.integer(37, 1));
  record.platform = static_cast<std::uint8_t>(input.integer(38, 1));
  auto shift = input.integer(39, 1);
  if (shift > 63)
    throw ParseFault("signature", "invalid code page shift",
                     input.origin() + 39);
  record.page_bytes = shift ? std::uint64_t(1) << shift : 0;
  unsigned header = 44;
  if (record.version >= 0x20100)
    header = 48;
  if (record.version >= 0x20200)
    header = 52;
  if (record.version >= 0x20300)
    header = 64;
  if (record.version >= 0x20400)
    header = 88;
  if (record.version >= 0x20500)
    header = 96;
  if (record.version >= 0x20600)
    header = 108;
  input.require(0, header);
  auto name = [&](std::uint32_t offset) {
    if (offset < header || offset >= input.size())
      throw ParseFault("signature", "invalid identifier offset", offset);
    return input.text(offset, input.size() - offset, true);
  };
  record.identifier = name(identifier_offset);
  if (record.version >= 0x20100 && word(44))
    input.require(word(44), 24);
  if (record.version >= 0x20200 && word(48))
    record.team_identifier = name(word(48));
  if (record.version >= 0x20300) {
    auto extended = input.integer(56, 8);
    if (extended)
      record.covered_bytes = extended;
  }
  if (record.version >= 0x20400) {
    record.executable_base = input.integer(64, 8);
    record.executable_limit = input.integer(72, 8);
    record.executable_flags = input.integer(80, 8);
  }
  static const std::map<unsigned, std::pair<std::string, unsigned>> algorithms =
      {{1, {"sha1", 20}},
       {2, {"sha256", 32}},
       {3, {"sha256", 20}},
       {4, {"sha384", 48}},
       {5, {"sha512", 64}}};
  auto algorithm = algorithms.find(record.algorithm_code);
  if (record.digest_width == 0 || record.digest_width > 64)
    throw ParseFault("signature", "invalid hash slot width",
                     input.origin() + 36);
  if (algorithm != algorithms.end()) {
    if (record.digest_width != algorithm->second.second)
      throw ParseFault("signature", "hash width disagrees with algorithm",
                       input.origin() + 36);
    record.algorithm = algorithm->second.first;
    record.digest = compute_digest(input.bytes(), record.algorithm);
    // Code 3 is SHA-256 kept at the shorter declared width, so the stored
    // digest keeps exactly the bytes the directory says it has.
    if (record.algorithm_code == 3)
      record.digest.resize(std::size_t(record.digest_width) * 2);
  } else
    record.algorithm = "unknown-" + std::to_string(record.algorithm_code);
  auto special_bytes =
      std::uint64_t(record.special_slots) * record.digest_width;
  if (special_bytes > hash_offset || hash_offset - special_bytes < header)
    throw ParseFault("signature", "special hash slots overlap the header",
                     input.origin() + 16);
  input.require(hash_offset - special_bytes, special_bytes);
  input.require(hash_offset,
                std::uint64_t(record.code_slots) * record.digest_width);
  for (std::uint32_t number = 1; number <= record.special_slots; ++number) {
    auto bytes =
        input
            .region(hash_offset - std::uint64_t(number) * record.digest_width,
                    record.digest_width)
            .bytes();
    if (std::any_of(bytes.begin(), bytes.end(),
                    [](auto value) { return value != 0; }))
      record.special_digests.emplace(number, hex_encode(bytes));
  }
  return record;
}
} // namespace
const CodeDirectoryEntry &SignatureBlob::preferred() const {
  if (directories.empty())
    throw ParseFault("signature", "no CodeDirectory available");
  auto rank = [](unsigned type) {
    switch (type) {
    case 1:
      return 1;
    case 3:
      return 2;
    case 2:
      return 3;
    case 4:
      return 4;
    case 5:
      return 5;
    default:
      return 0;
    }
  };
  return *std::max_element(directories.begin(), directories.end(),
                           [&](const auto &left, const auto &right) {
                             return rank(left.algorithm_code) <
                                    rank(right.algorithm_code);
                           });
}
const CodeDirectoryEntry &SignatureBlob::primary() const {
  for (const auto &record : directories)
    if (record.slot == 0)
      return record;
  throw ParseFault("signature", "primary CodeDirectory is absent");
}
SignatureBlob SignatureBlob::decode(ByteView bytes) {
  ByteWindow outer(bytes, "signature");
  outer.require(0, 12);
  auto magic = outer.integer(0, 4);
  if (magic != 0xfade0cc0 && magic != 0xfade0b02)
    throw ParseFault("signature", "invalid signature container magic",
                     outer.origin());
  auto length = outer.integer(4, 4), count = outer.integer(8, 4);
  if (length < 12 || count > 64)
    throw ParseFault("signature",
                     "invalid signature container length or count");
  auto input = outer.region(0, length);
  auto table_end = 12 + count * 8;
  input.require(0, table_end);
  SignatureBlob signature;
  std::set<std::uint32_t> slots;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
  for (std::uint64_t index = 0; index < count; ++index) {
    auto slot = static_cast<std::uint32_t>(input.integer(12 + index * 8, 4));
    auto start = input.integer(16 + index * 8, 4);
    if (!slots.insert(slot).second)
      throw ParseFault("signature", "duplicate signature slot", start);
    if (start < table_end)
      throw ParseFault("signature", "signature child overlaps index", start);
    auto child_magic = input.integer(start, 4);
    auto extent = input.integer(start + 4, 4);
    if (extent < 8)
      throw ParseFault("signature", "invalid child length", start);
    auto child = input.region(start, extent);
    for (const auto &range : ranges)
      if (start < range.second && range.first < start + extent)
        throw ParseFault("signature", "overlapping signature children", start);
    ranges.emplace_back(start, start + extent);
    signature.entries.push_back({{"slot", slot},
                                 {"magic", child_magic},
                                 {"offset", start},
                                 {"length", extent}});
    if (slot == 0 || (slot >= 0x1000 && slot < 0x1005)) {
      if (child_magic != 0xfade0c02)
        throw ParseFault("signature", "CodeDirectory slot has wrong magic",
                         start);
      signature.directories.push_back(directory(child, slot));
    } else if (slot == 5 || slot == 7) {
      if (child_magic != (slot == 5 ? 0xfade7171U : 0xfade7172U))
        throw ParseFault("signature", "entitlement slot has wrong magic",
                         start);
      if (extent - 8 > max_document_bytes)
        throw ParseFault("signature", "entitlement document exceeds byte limit",
                         start);
      auto body = child.region(8, extent - 8).bytes();
      auto copy = std::vector<std::uint8_t>(body.begin(), body.end());
      if (slot == 5)
        signature.plist_claims = std::move(copy);
      else
        signature.der_claims = std::move(copy);
    } else if (slot == 0x10000) {
      if (child_magic != 0xfade0b01)
        throw ParseFault("signature", "CMS wrapper has wrong magic", start);
      signature.cms_bytes = extent - 8;
    }
  }
  (void)signature.primary();
  return signature;
}
} // namespace signet_scan
