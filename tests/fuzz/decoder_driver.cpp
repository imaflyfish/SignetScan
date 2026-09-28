#include <signet_scan/audit.hpp>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *bytes,
                                      std::size_t length) {
  auto input = signet_scan::ByteView(bytes, length);
  if (length > 1024 * 1024)
    return 0;
  (void)signet_scan::AuditSession().inspect_bytes(input);
  try {
    (void)signet_scan::SignatureBlob::decode(input);
  } catch (const std::exception &) {
  }
  try {
    (void)signet_scan::parse_der(input);
  } catch (const std::exception &) {
  }
  try {
    (void)signet_scan::parse_plist(input);
  } catch (const std::exception &) {
  }
  return 0;
}
