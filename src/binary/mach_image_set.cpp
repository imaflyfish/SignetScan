#include <algorithm>
#include <set>
#include <signet_scan/audit.hpp>

namespace signet_scan {
namespace {
std::string architecture(std::uint32_t kind, std::uint32_t variant) {
  variant &= 0xffffff;
  if (kind == 0x100000c)
    return variant == 2 ? "arm64e" : variant == 1 ? "arm64v8" : "arm64";
  if (kind == 0x1000007)
    return variant == 8 ? "x86_64h" : "x86_64";
  if (kind == 12)
    return "arm";
  if (kind == 7)
    return "i386";
  return "cputype-" + std::to_string(kind);
}
std::string version_string(std::uint64_t version) {
  return std::to_string(version >> 16) + "." +
         std::to_string((version >> 8) & 255) + "." +
         std::to_string(version & 255);
}
MachSlice read_slice(ByteWindow input, std::uint64_t origin) {
  auto magic = input.integer(0, 4);
  bool big = magic == 0xfeedface || magic == 0xfeedfacf;
  bool wide = magic == 0xfeedfacf || magic == 0xcffaedfe;
  if (!big && magic != 0xcefaedfe && magic != 0xcffaedfe)
    throw ParseFault("macho", "invalid Mach-O magic", origin);
  auto header_bytes = wide ? 32U : 28U;
  input.require(0, header_bytes);
  auto word = [&](std::uint64_t offset) {
    return static_cast<std::uint32_t>(input.integer(offset, 4, big));
  };
  MachSlice slice;
  slice.file_offset = origin;
  slice.byte_length = input.size();
  slice.big_endian = big;
  slice.wide = wide;
  slice.cpu_kind = word(4);
  slice.cpu_variant = word(8);
  slice.image_kind = word(12);
  slice.header_flags = word(24);
  slice.architecture = architecture(slice.cpu_kind, slice.cpu_variant);
  auto command_count = word(16), command_bytes = word(20);
  if (command_count > 10000 || command_count > command_bytes / 8)
    throw ParseFault("macho", "invalid load command count", origin + 16);
  auto commands = input.region(header_bytes, command_bytes);
  std::uint64_t position = 0;
  for (std::uint32_t index = 0; index < command_count; ++index) {
    auto opcode =
        static_cast<std::uint32_t>(commands.integer(position, 4, big));
    auto extent = commands.integer(position + 4, 4, big);
    if (extent < 8 || extent % 4 != 0)
      throw ParseFault("macho", "invalid load command size",
                       origin + header_bytes + position);
    auto command = commands.region(position, extent);
    auto value = [&](unsigned offset, unsigned width = 4) {
      return command.integer(offset, width, big);
    };
    slice.commands.push_back({{"opcode", opcode},
                              {"offset", origin + header_bytes + position},
                              {"length", extent}});
    if (opcode == 1 || opcode == 0x19) {
      bool large = opcode == 0x19;
      unsigned prefix = large ? 72 : 56;
      command.require(0, prefix);
      SegmentEntry segment;
      segment.label = command.text(8, 16);
      unsigned stride = large ? 8 : 4;
      segment.virtual_address = value(24, stride);
      segment.virtual_size = value(24 + stride, stride);
      segment.file_offset = value(24 + 2 * stride, stride);
      segment.file_length = value(24 + 3 * stride, stride);
      segment.maximum_protection =
          static_cast<std::uint32_t>(value(24 + 4 * stride));
      segment.initial_protection =
          static_cast<std::uint32_t>(value(28 + 4 * stride));
      segment.section_count =
          static_cast<std::uint32_t>(value(32 + 4 * stride));
      command.require(prefix,
                      std::uint64_t(segment.section_count) * (large ? 80 : 68));
      if (segment.file_length)
        input.require(segment.file_offset, segment.file_length);
      slice.segments.push_back(std::move(segment));
    } else if (opcode == 0xc || opcode == 0x80000018 || opcode == 0x8000001f ||
               opcode == 0xd) {
      command.require(0, 24);
      auto start = value(8);
      if (start < 24 || start >= extent)
        throw ParseFault("macho", "invalid library name offset");
      slice.dependencies.emplace_back(
          opcode, command.text(start, extent - start, true));
    } else if (opcode == 0x8000001c) {
      command.require(0, 12);
      auto start = value(8);
      if (start < 12 || start >= extent)
        throw ParseFault("macho", "invalid rpath offset");
      slice.search_paths.push_back(command.text(start, extent - start, true));
    } else if (opcode == 0x1d) {
      command.require(0, 16);
      if (slice.signature_range)
        throw ParseFault("macho", "duplicate signature load command");
      auto start = value(8), length = value(12);
      input.require(start, length);
      slice.signature_range = {{start, length}};
    } else if (opcode == 0x21 || opcode == 0x2c) {
      command.require(0, opcode == 0x2c ? 24 : 20);
      input.require(value(8), value(12));
      slice.encryption = {{"offset", value(8)},
                          {"length", value(12)},
                          {"identifier", value(16)}};
    } else if (opcode == 0x32) {
      command.require(0, 24);
      command.require(24, value(20) * 8);
      slice.build = {{"platform", value(8)},
                     {"minimum_os", version_string(value(12))},
                     {"sdk", version_string(value(16))}};
    }
    position += extent;
  }
  if (position != command_bytes)
    throw ParseFault("macho",
                     "load commands do not consume their declared region",
                     origin + header_bytes + position);
  return slice;
}
} // namespace
bool MachImageSet::recognises(ByteView prefix) {
  if (prefix.size() < 4)
    return false;
  auto magic = ByteWindow(prefix).integer(0, 4);
  return magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcefaedfe ||
         magic == 0xcffaedfe || magic == 0xcafebabe || magic == 0xcafebabf ||
         magic == 0xbebafeca || magic == 0xbfbafeca;
}
std::vector<MachSlice> MachImageSet::decode(ByteView bytes) {
  ByteWindow input(bytes, "macho");
  auto magic = input.integer(0, 4);
  std::vector<MachSlice> images;
  bool fat = magic == 0xcafebabe || magic == 0xcafebabf ||
             magic == 0xbebafeca || magic == 0xbfbafeca;
  if (!fat) {
    images.push_back(read_slice(input, 0));
    return images;
  }
  bool big = magic == 0xcafebabe || magic == 0xcafebabf;
  bool wide = magic == 0xcafebabf || magic == 0xbfbafeca;
  auto count = input.integer(4, 4, big);
  if (count == 0 || count > 64)
    throw ParseFault("macho", "invalid fat architecture count", 4);
  auto entry_bytes = wide ? 32U : 20U;
  auto table_end = 8 + count * entry_bytes;
  input.require(0, table_end);
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
  for (std::uint64_t index = 0; index < count; ++index) {
    auto start = 8 + index * entry_bytes;
    auto offset = input.integer(start + 8, wide ? 8 : 4, big);
    auto length = input.integer(start + (wide ? 16 : 12), wide ? 8 : 4, big);
    if (offset < table_end || length < 28)
      throw ParseFault("macho", "fat slice overlaps header or is too short",
                       start);
    auto alignment = input.integer(start + (wide ? 24 : 16), 4, big);
    if (alignment > 63 || (offset & ((std::uint64_t(1) << alignment) - 1)))
      throw ParseFault("macho", "invalid fat slice alignment", start);
    auto view = input.region(offset, length);
    for (const auto &range : ranges)
      if (offset < range.second && range.first < offset + length)
        throw ParseFault("macho", "overlapping fat slices", start);
    ranges.emplace_back(offset, offset + length);
    auto slice = read_slice(view, offset);
    if (slice.cpu_kind != input.integer(start, 4, big) ||
        slice.cpu_variant != input.integer(start + 4, 4, big))
      throw ParseFault("macho", "fat architecture disagrees with slice header",
                       start);
    images.push_back(std::move(slice));
  }
  return images;
}
} // namespace signet_scan
