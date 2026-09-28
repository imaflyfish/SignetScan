#include <bit>
#include <cmath>
#include <cstdlib>
#include <signet_scan/audit.hpp>
#include <memory>
#include <plist/plist.h>
#include <set>

namespace signet_scan {
namespace {
constexpr std::size_t maximum_nodes = 200000;
bool valid_utf8(const std::string &text) {
  try {
    (void)ClaimNode(text).dump();
    return true;
  } catch (const nlohmann::json::exception &) {
    return false;
  }
}
ClaimNode convert_node(plist_t node, unsigned depth, std::size_t &remaining) {
  if (depth > 32 || remaining == 0)
    throw ParseFault("plist", "document exceeds nesting or node limit");
  --remaining;
  switch (plist_get_node_type(node)) {
  case PLIST_BOOLEAN: {
    std::uint8_t value = 0;
    plist_get_bool_val(node, &value);
    return bool(value);
  }
  case PLIST_INT: {
    if (plist_int_val_is_negative(node)) {
      std::int64_t value = 0;
      plist_get_int_val(node, &value);
      return value;
    }
    std::uint64_t value = 0;
    plist_get_uint_val(node, &value);
    return value;
  }
  case PLIST_REAL: {
    double value = 0;
    plist_get_real_val(node, &value);
    if (!std::isfinite(value))
      throw ParseFault("plist", "non-finite real");
    return value;
  }
  case PLIST_STRING: {
    std::uint64_t length = 0;
    const char *pointer = plist_get_string_ptr(node, &length);
    if (!pointer && length)
      throw ParseFault("plist", "invalid string");
    std::string value =
        pointer ? std::string(pointer, static_cast<std::size_t>(length)) : "";
    if (!valid_utf8(value))
      throw ParseFault("plist", "invalid UTF-8");
    return value;
  }
  case PLIST_DATA: {
    std::uint64_t length = 0;
    const char *pointer = plist_get_data_ptr(node, &length);
    std::vector<std::uint8_t> content;
    if (length) {
      if (!pointer)
        throw ParseFault("plist", "invalid data");
      content.assign(pointer, pointer + length);
    }
    return ClaimNode::binary(std::move(content));
  }
  case PLIST_DATE: {
    std::int64_t seconds = 0;
    plist_get_unix_date_val(node, &seconds);
    return ClaimNode{{"$date_unix", seconds}};
  }
  case PLIST_UID: {
    std::uint64_t value = 0;
    plist_get_uid_val(node, &value);
    return ClaimNode{{"$uid", value}};
  }
  case PLIST_NULL:
    return nullptr;
  case PLIST_ARRAY: {
    ClaimNode result = ClaimNode::array();
    auto count = plist_array_get_size(node);
    if (count > remaining)
      throw ParseFault("plist", "array exceeds node limit");
    for (std::uint32_t index = 0; index < count; ++index)
      result.push_back(convert_node(plist_array_get_item(node, index),
                                    depth + 1, remaining));
    return result;
  }
  case PLIST_DICT: {
    ClaimNode result = ClaimNode::object();
    plist_dict_iter raw = nullptr;
    plist_dict_new_iter(node, &raw);
    std::unique_ptr<void, decltype(&std::free)> iterator(raw, std::free);
    for (;;) {
      char *raw_key = nullptr;
      plist_t child = nullptr;
      plist_dict_next_item(node, raw, &raw_key, &child);
      std::unique_ptr<char, decltype(&std::free)> key(raw_key, std::free);
      if (!child)
        break;
      if (!raw_key || !valid_utf8(raw_key))
        throw ParseFault("plist", "invalid dictionary key");
      if (result.contains(raw_key))
        throw ParseFault("plist", "duplicate dictionary key");
      result[raw_key] = convert_node(child, depth + 1, remaining);
    }
    return result;
  }
  default:
    throw ParseFault("plist", "unsupported property-list node");
  }
}
struct DerItem {
  unsigned tag;
  ByteWindow body;
  std::uint64_t next;
};
DerItem element(ByteWindow input, std::uint64_t offset) {
  auto tag = static_cast<unsigned>(input.integer(offset, 1));
  auto lead = input.integer(offset + 1, 1);
  auto start = offset + 2;
  std::uint64_t length = lead;
  if (lead & 0x80) {
    auto count = static_cast<unsigned>(lead & 0x7f);
    if (count == 0 || count > 4)
      throw ParseFault("der", "unsupported DER length form", offset);
    length = input.integer(start, count);
    if (length < 128 || input.integer(start, 1) == 0)
      throw ParseFault("der", "nonminimal DER length", offset);
    start += count;
  }
  return {tag, input.region(start, length), start + length};
}
ClaimNode decode_value(const DerItem &item, unsigned depth,
                        std::size_t &remaining) {
  if (depth > 32 || remaining == 0)
    throw ParseFault("der", "document exceeds nesting or node limit");
  --remaining;
  auto bytes = item.body.bytes();
  if (item.tag == 1) {
    if (bytes.size() != 1 || (bytes[0] != 0 && bytes[0] != 255))
      throw ParseFault("der", "invalid DER boolean");
    return bytes[0] != 0;
  }
  if (item.tag == 2) {
    if (bytes.empty() || bytes.size() > 8)
      throw ParseFault("der", "integer outside signed 64-bit range");
    if (bytes.size() > 1 && ((bytes[0] == 0 && !(bytes[1] & 128)) ||
                             (bytes[0] == 255 && (bytes[1] & 128))))
      throw ParseFault("der", "nonminimal DER integer");
    std::uint64_t raw =
        item.body.integer(0, static_cast<unsigned>(bytes.size()));
    if (bytes[0] & 128) {
      if (bytes.size() < 8)
        raw |= (~std::uint64_t(0)) << (bytes.size() * 8);
      return std::bit_cast<std::int64_t>(raw);
    }
    return raw;
  }
  if (item.tag == 12) {
    std::string value(bytes.begin(), bytes.end());
    if (!valid_utf8(value))
      throw ParseFault("der", "invalid UTF-8");
    return value;
  }
  if (item.tag == 0x30 || item.tag == 0x31) {
    ClaimNode values = ClaimNode::array();
    std::uint64_t offset = 0;
    while (offset < bytes.size()) {
      auto child = element(item.body, offset);
      values.push_back(decode_value(child, depth + 1, remaining));
      offset = child.next;
    }
    return values;
  }
  if (item.tag == 0xb0) {
    ClaimNode values = ClaimNode::object();
    std::uint64_t offset = 0;
    while (offset < bytes.size()) {
      auto pair = element(item.body, offset);
      if (pair.tag != 0x30)
        throw ParseFault("der", "dictionary entry must be a sequence");
      auto key = element(pair.body, 0);
      if (key.tag != 12)
        throw ParseFault("der", "dictionary key must be UTF-8");
      auto key_value =
          decode_value(key, depth + 1, remaining).get<std::string>();
      if (values.contains(key_value))
        throw ParseFault("der", "duplicate dictionary key");
      auto value = element(pair.body, key.next);
      if (value.next != pair.body.size())
        throw ParseFault("der", "trailing bytes in dictionary entry");
      values[key_value] = decode_value(value, depth + 1, remaining);
      offset = pair.next;
    }
    return values;
  }
  throw ParseFault("der", "unsupported DER tag " + std::to_string(item.tag));
}
} // namespace
ClaimNode parse_plist(ByteView bytes) {
  if (bytes.empty() || bytes.size() > max_document_bytes)
    throw ParseFault("plist", "invalid document size");
  bool binary = bytes.size() >= 8 &&
                std::equal(bytes.begin(), bytes.begin() + 8,
                           reinterpret_cast<const std::uint8_t *>("bplist00"));
  if (!binary) {
    while (!bytes.empty() && bytes.back() == 0)
      bytes = bytes.first(bytes.size() - 1);
  }
  plist_t raw = nullptr;
  plist_format_t format = PLIST_FORMAT_NONE;
  auto status = plist_from_memory(reinterpret_cast<const char *>(bytes.data()),
                                  static_cast<std::uint32_t>(bytes.size()),
                                  &raw, &format);
  std::unique_ptr<void, decltype(&plist_free)> document(raw, plist_free);
  if (status != PLIST_ERR_SUCCESS || !raw ||
      (format != PLIST_FORMAT_XML && format != PLIST_FORMAT_BINARY))
    throw ParseFault("plist", "invalid XML or binary plist");
  std::size_t remaining = maximum_nodes;
  auto result = convert_node(raw, 0, remaining);
  if (!result.is_object())
    throw ParseFault("plist", "expected dictionary at root");
  return result;
}
ClaimNode parse_der(ByteView bytes) {
  if (bytes.empty() || bytes.size() > max_document_bytes)
    throw ParseFault("der", "invalid document size");
  auto root = element(ByteWindow(bytes, "der"), 0);
  if ((root.tag != 0x70 && root.tag != 0x30) || root.next != bytes.size())
    throw ParseFault("der", "invalid outer wrapper or trailing bytes");
  auto version = element(root.body, 0);
  if (version.tag != 2 || version.body.size() != 1 ||
      version.body.integer(0, 1) != 1)
    throw ParseFault("der", "unsupported entitlement version");
  auto dictionary = element(root.body, version.next);
  if (dictionary.tag != 0xb0 || dictionary.next != root.body.size())
    throw ParseFault("der", "invalid dictionary wrapper or trailing bytes");
  std::size_t remaining = maximum_nodes;
  return decode_value(dictionary, 0, remaining);
}
GrantDocument
GrantDocument::decode(const SignatureBlob &signature) {
  GrantDocument document;
  if (signature.plist_claims)
    try {
      document.plist = parse_plist(*signature.plist_claims);
    } catch (const ParseFault &error) {
      document.errors.push_back(error.diagnostic);
    }
  if (signature.der_claims)
    try {
      document.der = parse_der(*signature.der_claims);
    } catch (const ParseFault &error) {
      document.errors.push_back(error.diagnostic);
    }
  if (document.der) {
    document.selected = *document.der;
    document.source = "der";
  } else if (document.plist) {
    document.selected = *document.plist;
    document.source = "plist";
  }
  if (document.der && document.plist) {
    std::set<std::string> keys;
    for (auto item = document.der->begin(); item != document.der->end(); ++item)
      keys.insert(item.key());
    for (auto item = document.plist->begin(); item != document.plist->end();
         ++item)
      keys.insert(item.key());
    for (const auto &key : keys) {
      if (!document.plist->contains(key))
        document.differences.push_back({{"key", key},
                                        {"kind", "der_only"},
                                        {"der", (*document.der)[key]}});
      else if (!document.der->contains(key))
        document.differences.push_back({{"key", key},
                                        {"kind", "plist_only"},
                                        {"plist", (*document.plist)[key]}});
      else if (nlohmann::json((*document.der)[key]) !=
               nlohmann::json((*document.plist)[key]))
        document.differences.push_back({{"key", key},
                                        {"kind", "value"},
                                        {"plist", (*document.plist)[key]},
                                        {"der", (*document.der)[key]}});
    }
    document.disagree = !document.differences.empty();
  }
  return document;
}
} // namespace signet_scan
