#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <signet_scan/audit.hpp>
using namespace signet_scan;
using Buffer = std::vector<std::uint8_t>;
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
void rejects(const std::string &name, const std::function<void()> &action) {
  try {
    action();
    check(false, name);
  } catch (const ParseFault &) {
    check(true, name);
  }
}
void number(Buffer &input, std::size_t start, std::uint64_t value,
            unsigned width = 4, bool big = true) {
  if (input.size() < start + width)
    input.resize(start + width);
  for (unsigned index = 0; index < width; ++index)
    input[start + index] = static_cast<std::uint8_t>(
        value >> (8 * (big ? width - 1 - index : index)));
}
Buffer thin() {
  Buffer input(32);
  number(input, 0, 0xfeedfacf, 4, false);
  number(input, 4, 0x100000c, 4, false);
  number(input, 12, 2, 4, false);
  number(input, 24, 0x200000, 4, false);
  return input;
}
Buffer command(unsigned opcode, unsigned length) {
  auto input = thin();
  number(input, 16, 1, 4, false);
  number(input, 20, length, 4, false);
  input.resize(32 + length);
  number(input, 32, opcode, 4, false);
  number(input, 36, length, 4, false);
  return input;
}
Buffer fat(bool wide, bool big) {
  unsigned table = wide ? 40 : 28;
  Buffer input(64);
  number(input, 0, wide ? 0xcafebabf : 0xcafebabe, 4, big);
  number(input, 4, 1, 4, big);
  number(input, 8, 0x100000c, 4, big);
  number(input, 16, 64, wide ? 8 : 4, big);
  number(input, wide ? 24 : 20, 32, wide ? 8 : 4, big);
  number(input, wide ? 32 : 24, 6, 4, big);
  (void)table;
  auto image = thin();
  input.insert(input.end(), image.begin(), image.end());
  return input;
}
Buffer directory() {
  Buffer bytes(80);
  number(bytes, 0, 0xfade0c02);
  number(bytes, 4, 80);
  number(bytes, 8, 0x20001);
  number(bytes, 12, 2);
  number(bytes, 16, 80);
  number(bytes, 20, 44);
  bytes[36] = 32;
  bytes[37] = 2;
  bytes[39] = 12;
  bytes[44] = 'x';
  return bytes;
}
Buffer container(std::vector<std::pair<unsigned, Buffer>> children) {
  Buffer bytes(12 + 8 * children.size());
  number(bytes, 0, 0xfade0cc0);
  number(bytes, 8, children.size());
  for (std::size_t index = 0; index < children.size(); ++index) {
    number(bytes, 12 + 8 * index, children[index].first);
    number(bytes, 16 + 8 * index, bytes.size());
    bytes.insert(bytes.end(), children[index].second.begin(),
                 children[index].second.end());
  }
  number(bytes, 4, bytes.size());
  return bytes;
}
Buffer tlv(unsigned tag, const Buffer &body) {
  Buffer output{static_cast<std::uint8_t>(tag)};
  if (body.size() < 128)
    output.push_back(static_cast<std::uint8_t>(body.size()));
  else if (body.size() < 256) {
    output.push_back(0x81);
    output.push_back(static_cast<std::uint8_t>(body.size()));
  } else {
    output.push_back(0x82);
    output.push_back(static_cast<std::uint8_t>(body.size() >> 8));
    output.push_back(static_cast<std::uint8_t>(body.size()));
  }
  output.insert(output.end(), body.begin(), body.end());
  return output;
}
Buffer key_value(const Buffer &value) {
  Buffer body = {12, 1, 'k'};
  body.insert(body.end(), value.begin(), value.end());
  return tlv(0x30, body);
}
Buffer declaration(const Buffer &dictionary) {
  Buffer body = {2, 1, 1};
  auto encoded = tlv(0xb0, dictionary);
  body.insert(body.end(), encoded.begin(), encoded.end());
  return tlv(0x70, body);
}
} // namespace
int main(int argc, char **argv) {
  Buffer small(8);
  ByteWindow cursor(small);
  rejects("overflowing offset", [&] { cursor.region(UINT64_MAX, 2); });
  rejects("overflowing length", [&] { cursor.region(1, UINT64_MAX); });
  rejects("integer width limit", [&] { cursor.integer(0, 9); });
  rejects("unterminated string", [&] {
    Buffer bytes(4, 'a');
    ByteWindow(bytes).text(0, 4, true);
  });
  for (bool wide : {false, true})
    for (bool big : {false, true})
      check(MachImageSet::decode(fat(wide, big))[0].architecture == "arm64",
            "fat width and endian combination");
  auto input = fat(false, true);
  number(input, 4, 0);
  rejects("zero fat architectures", [&] { MachImageSet::decode(input); });
  number(input, 4, 65);
  rejects("too many fat architectures", [&] { MachImageSet::decode(input); });
  input = fat(false, true);
  number(input, 8, 7);
  rejects("fat header CPU mismatch", [&] { MachImageSet::decode(input); });
  input = fat(false, true);
  number(input, 24, 64);
  rejects("fat alignment shift limit", [&] { MachImageSet::decode(input); });
  input = fat(false, true);
  number(input, 16, 28);
  rejects("fat alignment mismatch", [&] { MachImageSet::decode(input); });
  input = fat(false, true);
  number(input, 4, 2);
  number(input, 28, 0x100000c);
  number(input, 36, 64);
  number(input, 40, 32);
  rejects("overlapping fat slices", [&] { MachImageSet::decode(input); });
  input = thin();
  number(input, 16, 10001, 4, false);
  number(input, 20, 80008, 4, false);
  rejects("load command count cap", [&] { MachImageSet::decode(input); });
  input = command(0x19, 8);
  rejects("short segment command", [&] { MachImageSet::decode(input); });
  input = command(0x19, 72);
  number(input, 32 + 64, 1, 4, false);
  rejects("section table exceeds command",
          [&] { MachImageSet::decode(input); });
  input = command(0x19, 72);
  number(input, 32 + 40, 1024, 8, false);
  number(input, 32 + 48, 8, 8, false);
  rejects("segment exceeds slice", [&] { MachImageSet::decode(input); });
  input = command(0xc, 24);
  number(input, 40, 24, 4, false);
  rejects("library string outside command",
          [&] { MachImageSet::decode(input); });
  input = command(0x8000001c, 12);
  number(input, 40, 1, 4, false);
  rejects("rpath overlaps command header",
          [&] { MachImageSet::decode(input); });
  input = command(0x1d, 16);
  number(input, 40, 48, 4, false);
  number(input, 44, 16, 4, false);
  rejects("signature range exceeds slice",
          [&] { MachImageSet::decode(input); });
  input = command(0x32, 24);
  number(input, 52, 1, 4, false);
  rejects("build tool list exceeds command",
          [&] { MachImageSet::decode(input); });
  auto cd = directory();
  auto sig = container({{0, cd}});
  for (std::size_t length = 0; length < sig.size(); ++length) {
    auto truncated =
        Buffer(sig.begin(), sig.begin() + static_cast<std::ptrdiff_t>(length));
    rejects("truncated signature " + std::to_string(length),
            [&] { SignatureBlob::decode(truncated); });
  }
  sig = container({{0, cd}, {0, cd}});
  rejects("duplicate signature slot", [&] { SignatureBlob::decode(sig); });
  sig = container({{0x1000, cd}});
  rejects("missing primary directory", [&] { SignatureBlob::decode(sig); });
  sig = container({{0, cd}, {0x1000, cd}});
  number(sig, 24, 28);
  rejects("overlapping signature children",
          [&] { SignatureBlob::decode(sig); });
  sig = container({{0, cd}});
  number(sig, 16, 8);
  rejects("signature child overlaps index",
          [&] { SignatureBlob::decode(sig); });
  cd = directory();
  number(cd, 0, 0);
  sig = container({{0, cd}});
  rejects("wrong CodeDirectory magic", [&] { SignatureBlob::decode(sig); });
  cd = directory();
  number(cd, 24, 65);
  sig = container({{0, cd}});
  rejects("special-slot count cap", [&] { SignatureBlob::decode(sig); });
  cd = directory();
  number(cd, 28, 0xffffffff);
  sig = container({{0, cd}});
  rejects("code-slot count cap", [&] { SignatureBlob::decode(sig); });
  cd = directory();
  cd[36] = 20;
  sig = container({{0, cd}});
  rejects("digest width contradicts algorithm",
          [&] { SignatureBlob::decode(sig); });
  cd = directory();
  cd[39] = 64;
  sig = container({{0, cd}});
  rejects("page shift cap", [&] { SignatureBlob::decode(sig); });
  cd = directory();
  number(cd, 20, 80);
  sig = container({{0, cd}});
  rejects("identifier outside directory",
          [&] { SignatureBlob::decode(sig); });
  cd = directory();
  number(cd, 24, 1);
  number(cd, 16, 44);
  sig = container({{0, cd}});
  rejects("special slots overlap header",
          [&] { SignatureBlob::decode(sig); });
  auto valid = declaration(key_value({1, 1, 255}));
  check(parse_der(valid)["k"] == true, "DER constructed boolean");
  for (unsigned version :
       {0x20001U, 0x20100U, 0x20200U, 0x20300U, 0x20400U, 0x20500U, 0x20600U}) {
    auto gated = directory();
    gated.resize(160);
    number(gated, 4, 160);
    number(gated, 8, version);
    number(gated, 16, 160);
    number(gated, 20, 120);
    gated[120] = 'x';
    if (version >= 0x20100)
      number(gated, 44, 0);
    if (version >= 0x20200) {
      number(gated, 48, 130);
      gated[130] = 'T';
    }
    if (version >= 0x20300)
      number(gated, 56, 0x1ffffffffULL, 8);
    if (version >= 0x20400) {
      number(gated, 64, 0x40, 8);
      number(gated, 72, 0x2000, 8);
      number(gated, 80, 0x40, 8);
    }
    auto record = SignatureBlob::decode(container({{0, gated}})).primary();
    check(record.version == version && record.identifier == "x",
          "version-gated directory identifier " + std::to_string(version));
    check(record.team_identifier == (version >= 0x20200 ? "T" : ""),
          "version-gated team identifier " + std::to_string(version));
    check(record.covered_bytes == (version >= 0x20300 ? 0x1ffffffffULL : 0),
          "version-gated extended limit " + std::to_string(version));
    check(record.executable_flags == (version >= 0x20400 ? 0x40U : 0),
          "version-gated execution flags " + std::to_string(version));
  }
  auto subtyped = thin();
  number(subtyped, 4, 0x1000007, 4, false);
  number(subtyped, 8, 8, 4, false);
  check(MachImageSet::decode(subtyped)[0].architecture == "x86_64h",
        "Haswell subtype distinguished");
  number(subtyped, 8, 3, 4, false);
  check(MachImageSet::decode(subtyped)[0].architecture == "x86_64",
        "generic x86_64 subtype");
  number(subtyped, 4, 0x100000c, 4, false);
  number(subtyped, 8, 0x80000002, 4, false);
  check(MachImageSet::decode(subtyped)[0].architecture == "arm64e",
        "ARM64e capability bits masked");
  auto list = tlv(0x30, Buffer{1, 1, 255, 2, 1, 3});
  check(parse_der(declaration(key_value(list)))["k"] ==
            ClaimNode::array({true, 3}),
        "typed DER array");
  check(parse_der(declaration(key_value(tlv(0x30, {}))))["k"].empty(),
        "empty DER array");
  auto dictionary = tlv(0xb0, key_value({1, 1, 255}));
  check(parse_der(declaration(key_value(dictionary)))["k"]["k"] == true,
        "nested DER dictionary");
  check(parse_der(
            declaration(key_value(tlv(0x30, dictionary))))["k"][0]["k"] == true,
        "DER array of dictionaries");
  auto long_string = tlv(12, Buffer(180, 'q'));
  check(parse_der(declaration(key_value(long_string)))["k"]
                .get<std::string>()
                .size() == 180,
        "minimal DER long-form length");
  for (std::size_t length = 0; length < valid.size(); ++length) {
    auto truncated = Buffer(
        valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(length));
    rejects("DER truncation " + std::to_string(length),
            [&] { parse_der(truncated); });
  }
  auto pairs = key_value({1, 1, 255});
  auto duplicate = pairs;
  pairs.insert(pairs.end(), duplicate.begin(), duplicate.end());
  auto encoded = declaration(pairs);
  rejects("DER duplicate key", [&] { parse_der(encoded); });
  encoded = declaration(key_value({}));
  rejects("DER missing value", [&] { parse_der(encoded); });
  encoded = declaration(key_value({1, 1, 255, 0}));
  rejects("DER entry trailing data", [&] { parse_der(encoded); });
  encoded = declaration(key_value({5, 0}));
  rejects("DER unsupported null", [&] { parse_der(encoded); });
  encoded = declaration(key_value({2, 0}));
  rejects("DER empty integer", [&] { parse_der(encoded); });
  encoded = declaration(key_value({2, 2, 0, 1}));
  rejects("DER nonminimal integer", [&] { parse_der(encoded); });
  encoded = declaration(key_value({2, 1, 255}));
  check(parse_der(encoded)["k"] == -1, "DER signed negative integer");
  encoded = declaration(key_value({12, 2, 0xc0, 0x80}));
  rejects("DER invalid UTF8", [&] { parse_der(encoded); });
  auto deep = Buffer{1, 1, 255};
  for (unsigned index = 0; index < 34; ++index)
    deep = tlv(0x30, deep);
  encoded = declaration(key_value(deep));
  rejects("DER depth limit", [&] { parse_der(encoded); });
  std::string xml = "<?xml version=\"1.0\"?><plist "
                    "version=\"1.0\"><dict><key>x</key><true/></dict></plist>";
  sig = container({{0, directory()}});
  number(sig, 8, 65);
  rejects("signature child-count limit", [&] { SignatureBlob::decode(sig); });
  sig = container({{0, directory()}});
  number(sig, 24, 7);
  rejects("signature child length below header",
          [&] { SignatureBlob::decode(sig); });
  sig = container({{0, directory()}});
  number(sig, 16, 0xffffffffU);
  rejects("signature child offset past end",
          [&] { SignatureBlob::decode(sig); });
  sig = container({{0, directory()}});
  number(sig, 0, 0);
  rejects("signature container magic", [&] { SignatureBlob::decode(sig); });
  Buffer cms(12, 0);
  number(cms, 0, 0xfade0b01);
  number(cms, 4, 12);
  check(SignatureBlob::decode(container({{0, directory()}, {0x10000, cms}}))
                .cms_bytes == 4,
        "CMS wrapper payload counted");
  check(SignatureBlob::decode(container({{0, directory()}})).cms_bytes == 0,
        "ad-hoc container without CMS");
  auto invalid_der = valid;
  invalid_der[0] = 0x31;
  rejects("DER wrong root tag", [&] { parse_der(invalid_der); });
  invalid_der = valid;
  invalid_der[2] = 1;
  rejects("DER version must be integer", [&] { parse_der(invalid_der); });
  invalid_der = valid;
  invalid_der[4] = 2;
  rejects("DER unsupported version", [&] { parse_der(invalid_der); });
  auto bad_pair = key_value({1, 1, 255});
  bad_pair[2] = 2;
  invalid_der = declaration(bad_pair);
  rejects("DER key must be string", [&] { parse_der(invalid_der); });
  if (argc == 2) {
    std::filesystem::create_directories(argv[1]);
    auto save = [&](const std::string &name, ByteView bytes) {
      std::ofstream output(std::filesystem::path(argv[1]) / name,
                           std::ios::binary);
      output.write(reinterpret_cast<const char *>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    };
    save("thin", thin());
    save("fat64", fat(true, true));
    save("signature", container({{0, directory()}}));
    save("entitlement", valid);
    save("plist",
         ByteView(reinterpret_cast<const std::uint8_t *>(xml.data()), xml.size()));
  }
  std::cout << passed << " boundary checks passed; " << failed << " failed\n";
  return failed ? 1 : 0;
}
