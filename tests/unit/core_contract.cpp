#include <functional>
#include <iostream>
#include <plist/plist.h>
#include <signet_scan/audit.hpp>

using namespace signet_scan;
using Buffer = std::vector<std::uint8_t>;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &name) {
  if (value) {
    ++passed;
  } else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
void rejects(const std::string &name, const std::function<void()> &operation) {
  try {
    operation();
    check(false, name);
  } catch (const ParseFault &) {
    check(true, name);
  } catch (const std::exception &error) {
    check(false, name + " unexpected exception: " + error.what());
  }
}
void word(Buffer &bytes, std::size_t offset, std::uint64_t value,
          unsigned width = 4, bool big = false) {
  if (bytes.size() < offset + width)
    bytes.resize(offset + width);
  for (unsigned index = 0; index < width; ++index)
    bytes[offset + index] = static_cast<std::uint8_t>(
        value >> (8 * (big ? width - 1 - index : index)));
}
Buffer thin(bool wide = true, bool big = false) {
  Buffer bytes(wide ? 32 : 28);
  word(bytes, 0, wide ? 0xfeedfacf : 0xfeedface, 4, big);
  word(bytes, 4, wide ? 0x100000c : 12, 4, big);
  word(bytes, 8, 0, 4, big);
  word(bytes, 12, 2, 4, big);
  word(bytes, 24, 0x200000, 4, big);
  return bytes;
}
Buffer directory() {
  Buffer bytes(80);
  word(bytes, 0, 0xfade0c02, 4, true);
  word(bytes, 4, 80, 4, true);
  word(bytes, 8, 0x20001, 4, true);
  word(bytes, 12, 2, 4, true);
  word(bytes, 16, 80, 4, true);
  word(bytes, 20, 44, 4, true);
  bytes[36] = 32;
  bytes[37] = 2;
  bytes[39] = 12;
  bytes[44] = 'x';
  return bytes;
}
Buffer envelope() {
  Buffer bytes(20);
  auto child = directory();
  word(bytes, 0, 0xfade0cc0, 4, true);
  word(bytes, 4, 100, 4, true);
  word(bytes, 8, 1, 4, true);
  word(bytes, 12, 0, 4, true);
  word(bytes, 16, 20, 4, true);
  bytes.insert(bytes.end(), child.begin(), child.end());
  return bytes;
}
Buffer der() {
  return {0x70, 0x10, 0x02, 0x01, 0x01, 0xb0, 0x0b, 0x30, 0x09,
          0x0c, 0x04, 't',  'e',  's',  't',  0x01, 0x01, 0xff};
}
} // namespace
int main() {
  for (bool wide : {false, true})
    for (bool big : {false, true}) {
      auto bytes = thin(wide, big);
      auto image = MachImageSet::decode(bytes).at(0);
      check(image.wide == wide && image.big_endian == big,
            "width and endianness");
    }
  for (std::size_t length = 0; length < 32; ++length) {
    auto bytes = thin();
    bytes.resize(length);
    rejects("truncated header " + std::to_string(length),
            [&] { MachImageSet::decode(bytes); });
  }
  auto bytes = thin();
  word(bytes, 16, 1);
  rejects("command count exceeds region", [&] { MachImageSet::decode(bytes); });
  bytes = thin();
  word(bytes, 16, 1);
  word(bytes, 20, 8);
  word(bytes, 32, 0);
  word(bytes, 36, 0);
  rejects("zero command cannot loop", [&] { MachImageSet::decode(bytes); });
  auto image = thin();
  Buffer fat(32);
  word(fat, 0, 0xcafebabe, 4, true);
  word(fat, 4, 1, 4, true);
  word(fat, 8, 0x100000c, 4, true);
  word(fat, 16, 32, 4, true);
  word(fat, 20, 32, 4, true);
  fat.insert(fat.end(), image.begin(), image.end());
  check(MachImageSet::decode(fat)[0].file_offset == 32, "fat image");
  word(fat, 20, 1024, 4, true);
  rejects("fat declared size cannot exceed file",
          [&] { MachImageSet::decode(fat); });
  word(fat, 20, 28, 4, true);
  rejects("slice header cannot borrow adjacent bytes",
          [&] { MachImageSet::decode(fat); });
  auto signing = envelope();
  auto signature = SignatureBlob::decode(signing);
  check(signature.primary().identifier == "x", "signature identifier");
  check(signature.primary().digest.size() == 64, "sha256 full digest");
  word(signing, 4, signing.size() + 4, 4, true);
  rejects("superblob length cannot exceed command",
          [&] { SignatureBlob::decode(signing); });
  signing = envelope();
  word(signing, 4, 20, 4, true);
  rejects("child cannot borrow trailing container bytes",
          [&] { SignatureBlob::decode(signing); });
  signing = envelope();
  word(signing, 28, 0x20400, 4, true);
  rejects("version tail must exist", [&] { SignatureBlob::decode(signing); });
  auto document = der();
  check(parse_der(document)["test"] == true, "DER known boolean");
  document.push_back(0);
  rejects("DER trailing bytes", [&] { parse_der(document); });
  document = der();
  document.back() = 1;
  rejects("DER noncanonical boolean", [&] { parse_der(document); });
  std::string xml =
      "<?xml version=\"1.0\"?><plist "
      "version=\"1.0\"><dict><key>zeta</key><integer>-2</integer><key>alpha</"
      "key><true/><key>bytes</key><data>AQI=</data></dict></plist>";
  auto plist = parse_plist(
      ByteView(reinterpret_cast<const std::uint8_t *>(xml.data()), xml.size()));
  check(plist.begin().key() == "zeta", "plist dictionary insertion order");
  check(plist["zeta"] == -2, "negative plist integer");
  check(plist["bytes"].is_binary() && plist["bytes"].get_binary().size() == 2,
        "typed plist data");
  plist_t native = nullptr;
  plist_format_t format;
  plist_from_memory(xml.data(), static_cast<std::uint32_t>(xml.size()), &native,
                    &format);
  char *packed = nullptr;
  std::uint32_t length = 0;
  plist_to_bin(native, &packed, &length);
  auto binary =
      parse_plist(ByteView(reinterpret_cast<std::uint8_t *>(packed), length));
  plist_mem_free(packed);
  plist_free(native);
  check(binary == plist, "binary plist preserves values and order");
  std::string abc = "abc";
  check(compute_digest(
            ByteView(reinterpret_cast<const std::uint8_t *>(abc.data()),
                     abc.size()),
            "sha256") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "published SHA256 vector");
  auto inspected = AuditSession().inspect_bytes(thin());
  check(!inspected.failed(), "unsigned is a finding, not a parser failure");
  check(inspected.observations().at(0).code == "unsigned",
        "unsigned executable finding");
  auto report = JsonWriter::render({inspected});
  check(report["schema_version"] == 1 &&
            report["inputs"][0]["images"][0]["signing"]
                  ["cryptographic_verification"] == "not_performed",
        "explicit verification contract");
  check(AuditSession().inspect_bytes({}).failed(),
        "malformed input reports an error");
  check(report["inputs"][0]["images"][0]["header_flag_names"] ==
            ClaimNode::array({"MH_PIE"}),
        "symbolic header flags");
  inspected.images[0].signing = signature;
  inspected.images[0].signing->directories[0].attributes = 0x10002;
  inspected.images[0].signing->directories[0].executable_flags = 0x41;
  inspected.images[0].observations = {
      {"z-low", Severity::low, "low", "", {}},
      {"z-high", Severity::high, "high", "", {}},
      {"a-high", Severity::high, "high", "", {}}};
  report = JsonWriter::render({inspected});
  auto encoded_directory =
      report["inputs"][0]["images"][0]["signing"]["directories"][0];
  check(encoded_directory["flag_names"] ==
            ClaimNode::array({"CS_ADHOC", "CS_RUNTIME"}),
        "symbolic signing flags");
  check(encoded_directory["executable_flag_names"] ==
            ClaimNode::array({"CS_EXECSEG_MAIN_BINARY", "CS_EXECSEG_JIT"}),
        "symbolic execution flags");
  check(report["inputs"][0]["images"][0]["observations"][0]["code"] ==
                "a-high" &&
            report["inputs"][0]["images"][0]["observations"][2]["code"] ==
                "z-low",
        "JSON severity and code ordering");
  SignatureBlob declarations;
  auto set_plist = [&](const std::string &body) {
    std::string text = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" +
                       body + "</dict></plist>";
    declarations.plist_claims = Buffer(text.begin(), text.end());
  };
  declarations.der_claims = der();
  set_plist("<key>test</key><true/>");
  check(!GrantDocument::decode(declarations).disagree,
        "independent declarations agree");
  set_plist("<key>test</key><false/>");
  auto difference = GrantDocument::decode(declarations);
  check(difference.disagree && difference.differences[0]["kind"] == "value" &&
            difference.differences[0]["key"] == "test",
        "declared value difference retained");
  set_plist("<key>other</key><true/>");
  difference = GrantDocument::decode(declarations);
  check(difference.differences.size() == 2 &&
            difference.differences[0]["kind"] == "plist_only" &&
            difference.differences[1]["kind"] == "der_only",
        "missing declaration keys retained");
  declarations.der_claims.reset();
  check(!GrantDocument::decode(declarations).disagree,
        "absent companion is not a disagreement");
  declarations.plist_claims->push_back(0);
  check(GrantDocument::decode(declarations).errors.empty(),
        "plist trailing NUL accepted");
  declarations.plist_claims = Buffer{};
  check(!GrantDocument::decode(declarations).errors.empty(),
        "empty encoded slot is invalid");
  std::string invalid_root =
      "<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>";
  rejects("plist root must be dictionary", [&] {
    parse_plist(
        ByteView(reinterpret_cast<const std::uint8_t *>(invalid_root.data()),
                 invalid_root.size()));
  });
  inspected.resources = SealVerdict{};
  inspected.resources->executable = "Contents/MacOS/demo";
  check(
      JsonWriter::render({inspected})["inputs"][0]["resources"]["executable"] ==
          "Contents/MacOS/demo",
      "bundle executable reported");
  std::cout << passed << " checks passed; " << failed << " failed\n";
  return failed ? 1 : 0;
}
