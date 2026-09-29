#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <signet_scan/audit.hpp>
#include <sys/stat.h>
#include <unistd.h>

namespace signet_scan {
namespace {
struct FileSlot {
  int descriptor;
  struct stat initial {};
  explicit FileSlot(const std::filesystem::path &path)
      : descriptor(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)) {
    if (descriptor < 0)
      throw ParseFault("input", path.string() + ": " + std::strerror(errno));
    if (fstat(descriptor, &initial) != 0 || !S_ISREG(initial.st_mode)) {
      close(descriptor);
      throw ParseFault("input", "input is not a readable regular file: " +
                                    path.string());
    }
  }
  ~FileSlot() { close(descriptor); }
  FileSlot(const FileSlot &) = delete;
  void unchanged() const {
    struct stat current {};
    if (fstat(descriptor, &current) != 0 ||
        initial.st_size != current.st_size ||
        initial.st_mtime != current.st_mtime ||
        initial.st_ctime != current.st_ctime)
      throw ParseFault("input", "file changed during inspection");
  }
  ssize_t receive(void *buffer, std::size_t length) const {
    ssize_t count;
    do {
      count = read(descriptor, buffer, length);
    } while (count < 0 && errno == EINTR);
    if (count < 0)
      throw ParseFault("input", std::strerror(errno));
    return count;
  }
};
struct HashContext {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{
      EVP_MD_CTX_new(), EVP_MD_CTX_free};
  explicit HashContext(const std::string &algorithm) {
    const auto *method = EVP_get_digestbyname(algorithm.c_str());
    if (!context || !method ||
        EVP_DigestInit_ex(context.get(), method, nullptr) != 1)
      throw ParseFault("digest", "unsupported digest: " + algorithm);
  }
  void feed(ByteView input) {
    if (EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1)
      throw ParseFault("digest", "digest update failed");
  }
  std::string finish() {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> output{};
    unsigned length = 0;
    if (EVP_DigestFinal_ex(context.get(), output.data(), &length) != 1)
      throw ParseFault("digest", "digest finalization failed");
    return hex_encode(ByteView(output).first(length));
  }
};
} // namespace
std::vector<std::uint8_t> load_input(const std::filesystem::path &path,
                                     std::uint64_t limit) {
  FileSlot input(path);
  if (input.initial.st_size < 0 ||
      static_cast<std::uint64_t>(input.initial.st_size) > limit)
    throw ParseFault("input", "input exceeds byte limit");
  std::vector<std::uint8_t> content(
      static_cast<std::size_t>(input.initial.st_size));
  std::size_t position = 0;
  while (position < content.size()) {
    auto count =
        input.receive(content.data() + position, content.size() - position);
    if (count == 0)
      throw ParseFault("input", "file was truncated during inspection");
    position += static_cast<std::size_t>(count);
  }
  input.unchanged();
  return content;
}
std::string hex_encode(ByteView bytes) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (auto value : bytes) {
    result += alphabet[value >> 4];
    result += alphabet[value & 15];
  }
  return result;
}
std::string compute_digest(ByteView bytes, const std::string &algorithm) {
  HashContext digest(algorithm);
  digest.feed(bytes);
  return digest.finish();
}
std::string digest_of_file(const std::filesystem::path &path,
                           const std::string &algorithm) {
  FileSlot input(path);
  HashContext digest(algorithm);
  std::array<std::uint8_t, 65536> block{};
  std::uint64_t total = 0;
  for (;;) {
    auto count = input.receive(block.data(), block.size());
    if (!count)
      break;
    total += static_cast<std::uint64_t>(count);
    if (total > static_cast<std::uint64_t>(input.initial.st_size))
      throw ParseFault("input", "file grew during hashing");
    digest.feed(ByteView(block).first(static_cast<std::size_t>(count)));
  }
  input.unchanged();
  if (total != static_cast<std::uint64_t>(input.initial.st_size))
    throw ParseFault("input", "file shrank during hashing");
  return digest.finish();
}
void ByteWindow::require(std::uint64_t offset, std::uint64_t length) const {
  if (offset > bytes_.size() || length > bytes_.size() - offset)
    throw ParseFault(stage_, "range exceeds enclosing structure",
                     origin_ + std::min<std::uint64_t>(offset, bytes_.size()));
}
ByteWindow ByteWindow::region(std::uint64_t offset,
                              std::uint64_t length) const {
  require(offset, length);
  return ByteWindow(bytes_.subspan(static_cast<std::size_t>(offset),
                                   static_cast<std::size_t>(length)),
                    stage_, origin_ + offset);
}
std::uint64_t ByteWindow::integer(std::uint64_t offset, unsigned width,
                                  bool big_endian) const {
  if (width == 0 || width > 8)
    throw ParseFault(stage_, "invalid integer width", origin_ + offset);
  require(offset, width);
  std::uint64_t value = 0;
  for (unsigned index = 0; index < width; ++index)
    value = (value << 8) | bytes_[static_cast<std::size_t>(offset) +
                                  (big_endian ? index : width - 1 - index)];
  return value;
}
std::string ByteWindow::text(std::uint64_t offset, std::uint64_t length,
                             bool require_nul) const {
  auto part = region(offset, length).bytes();
  auto end = std::find(part.begin(), part.end(), 0);
  if (require_nul && end == part.end())
    throw ParseFault(stage_, "unterminated string", origin_ + offset);
  return std::string(part.begin(), end);
}
} // namespace signet_scan
