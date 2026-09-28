#include <iostream>
#include <signet_scan/audit.hpp>
int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: scan-consumer PATH\n";
    return 2;
  }
  auto result = signet_scan::AuditSession().inspect_path(argv[1]);
  std::cout << signet_scan::JsonWriter::render({result}).dump(2) << '\n';
  return result.failed() ? 2 : 0;
}
