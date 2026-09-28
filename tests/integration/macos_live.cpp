#include "../../tools/subprocess.hpp"
#include <fstream>
#include <iostream>

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
void write_text(const fs::path &path, const std::string &text) {
  fs::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary);
  output << text;
  if (!output)
    throw std::runtime_error("cannot write fixture");
}
bool contains(const AuditReport &result, const std::string &code) {
  for (const auto &item : result.observations())
    if (item.code == code)
      return true;
  return false;
}
std::string read_text(const fs::path &path) {
  auto bytes = load_input(path);
  return std::string(bytes.begin(), bytes.end());
}
} // namespace
int main(int argc, char **argv) {
#ifndef __APPLE__
  std::cerr << "Apple fixture tools unavailable on this platform\n";
  return 77;
#else
  try {
    if (argc != 2)
      throw std::runtime_error("CLI path required");
    auto cli = fs::absolute(argv[1]).string();
    std::string pattern =
        (fs::temp_directory_path() / "signet-scan-fixtures-XXXXXX").string();
    if (!mkdtemp(pattern.data()))
      throw std::runtime_error("cannot create fixture directory");
    fs::path root = pattern;
    struct Cleanup {
      fs::path path;
      ~Cleanup() {
        std::error_code ignored;
        fs::remove_all(path, ignored);
      }
    } cleanup{root};
    auto run = [&](std::vector<std::string> args) {
      return inspect_tools::execute(args);
    };
    auto must = [&](std::vector<std::string> args) {
      auto result = run(std::move(args));
      if (result.status != 0)
        throw std::runtime_error(result.output);
    };
    write_text(root / "sample.c", "int main(void) { return 0; }\n");
    must({"/usr/bin/clang", "-arch", "arm64", "-o", (root / "linked").string(),
          (root / "sample.c").string()});
    AuditSession session;
    auto linked = session.inspect_file(root / "linked");
    check(!linked.failed() && contains(linked, "linker-signed"),
          "linker-signed fixture");
    fs::copy_file(root / "linked", root / "unsigned");
    must({"/usr/bin/codesign", "--remove-signature",
          (root / "unsigned").string()});
    check(contains(session.inspect_file(root / "unsigned"), "unsigned"),
          "unsigned fixture");
    fs::copy_file(root / "linked", root / "hardened");
    must({"/usr/bin/codesign", "-f", "-s", "-", "-o", "runtime",
          (root / "hardened").string()});
    auto hardened = session.inspect_file(root / "hardened");
    check(!hardened.failed() && !contains(hardened, "no-hardened-runtime"),
          "hardened runtime fixture");
    write_text(root / "entitlements.plist",
               "<?xml version=\"1.0\"?><plist "
               "version=\"1.0\"><dict><key>com.apple.security.get-task-allow</"
               "key><true/><key>com.apple.security.cs.allow-jit</key><true/"
               "><key>com.apple.security.cs.allow-unsigned-executable-memory</"
               "key><false/><key>keychain-access-groups</"
               "key><array><string>test.group</string></array><key>test.count</"
               "key><integer>3</integer></dict></plist>");
    fs::copy_file(root / "linked", root / "entitled");
    must({"/usr/bin/codesign", "-f", "-s", "-", "--entitlements",
          (root / "entitlements.plist").string(),
          (root / "entitled").string()});
    auto entitled = session.inspect_file(root / "entitled");
    check(
        !entitled.failed() &&
            contains(entitled, "entitlement:com.apple.security.get-task-allow"),
        "declared high-risk entitlement");
    check(contains(entitled, "entitlement:com.apple.security.cs.allow-jit"),
          "JIT entitlement");
    check(!contains(entitled, "entitlement:com.apple.security.cs.allow-"
                              "unsigned-executable-memory"),
          "false entitlement is not a finding");
    check(entitled.images.at(0).claims.source == "der" &&
              !entitled.images.at(0).claims.disagree,
          "real plist and DER agreement");
    auto executable = root / "Demo.app/Contents/MacOS/demo";
    fs::create_directories(executable.parent_path());
    fs::copy_file(root / "linked", executable);
    write_text(root / "Demo.app/Contents/Info.plist",
               "<?xml version=\"1.0\"?><plist "
               "version=\"1.0\"><dict><key>CFBundleExecutable</"
               "key><string>demo</string><key>CFBundleIdentifier</"
               "key><string>test.signet-scan.demo</string></dict></plist>");
    auto resource = root / "Demo.app/Contents/Resources/data.txt";
    write_text(resource, "original resource\n");
    auto localized = resource.parent_path() / "en.lproj/message.txt";
    write_text(localized, "owned localized text\n");
    auto bundle = root / "Demo.app";
    must({"/usr/bin/codesign", "-f", "-s", "-", bundle.string()});
    check(run({"/usr/bin/codesign", "-v", bundle.string()}).status == 0,
          "signed bundle fixture is valid");
    auto clean = session.inspect_path(bundle);
    check(!clean.failed() && clean.resources &&
              clean.resources->linkage == "match" &&
              clean.resources->observations.empty(),
          "clean bundle has no resource findings");
    check(!session.inspect_path(bundle, {false}).resources,
          "resource inspection can be disabled");
    fs::remove(localized);
    check(run({"/usr/bin/codesign", "--verify", "--strict", bundle.string()})
                  .status == 0,
          "codesign permits removal of its optional localized resource");
    auto absent_optional = session.inspect_path(bundle);
    check(!absent_optional.failed() && absent_optional.resources &&
              absent_optional.resources->observations.empty() &&
              std::any_of(absent_optional.resources->checks.begin(),
                          absent_optional.resources->checks.end(),
                          [](const auto &entry) {
                            return entry["status"] == "optional-missing";
                          }),
          "optional localized absence stays visible without a finding");
    check(run({cli, "--fail-on", "high", bundle.string()}).status == 0,
          "optional resource removal does not fail the CLI threshold");
    write_text(localized, "changed localized text\n");
    check(run({"/usr/bin/codesign", "--verify", "--strict", bundle.string()})
                  .status != 0,
          "codesign rejects changed optional resource contents");
    check(contains(session.inspect_path(bundle), "resource-hash-mismatch"),
          "changed optional resource contents remain a finding");
    check(run({cli, "--fail-on", "high", bundle.string()}).status == 1,
          "changed optional resource fails the CLI threshold");
    write_text(localized, "owned localized text\n");
    write_text(resource, "modified\n");
    auto modified = session.inspect_path(bundle);
    check(!modified.failed() && contains(modified, "resource-hash-mismatch"),
          "modified resource detected");
    check(run({"/usr/bin/codesign", "-v", bundle.string()}).status != 0,
          "codesign rejects modified resource");
    check(run({cli, "--fail-on", "high", bundle.string()}).status == 1,
          "CLI threshold catches resource modification");
    write_text(resource, "original resource\n");
    write_text(resource.parent_path() / "added.txt", "added\n");
    auto added = session.inspect_path(bundle);
    check(contains(added, "resource-unsealed"), "added resource detected");
    check(run({"/usr/bin/codesign", "-v", bundle.string()}).status != 0,
          "codesign rejects added resource");
    fs::remove(resource.parent_path() / "added.txt");
    fs::remove(resource);
    check(contains(session.inspect_path(bundle), "resource-missing"),
          "missing resource detected");
    check(run({"/usr/bin/codesign", "-v", bundle.string()}).status != 0,
          "codesign rejects missing resource");
    write_text(resource, "original resource\n");
    auto manifest = root / "Demo.app/Contents/_CodeSignature/CodeResources";
    auto saved = read_text(manifest);
    write_text(manifest, saved + "\n");
    check(contains(session.inspect_path(bundle), "resource-seal-mismatch"),
          "modified manifest linkage detected");
    write_text(manifest, saved);
    fs::rename(manifest, root / "saved-manifest");
    check(contains(session.inspect_path(bundle), "resource-seal-absent"),
          "missing manifest detected");
    fs::rename(root / "saved-manifest", manifest);
    auto escaped = root / "outside.txt";
    write_text(escaped, "synthetic outside content");
    fs::remove(resource);
    fs::create_symlink(escaped, resource);
    check(contains(session.inspect_path(bundle), "resource-type-changed"),
          "sealed file becoming symlink rejected");
    fs::remove(resource);
    write_text(resource, "original resource\n");
    fs::rename(resource.parent_path(), root / "old-resources");
    fs::create_directory_symlink(root / "old-resources",
                                 resource.parent_path());
    check(contains(session.inspect_path(bundle), "resource-path-escape"),
          "parent symlink escape rejected");
    fs::remove(resource.parent_path());
    fs::rename(root / "old-resources", resource.parent_path());
    fs::rename(executable, root / "outside-executable");
    fs::create_symlink(root / "outside-executable", executable);
    check(session.inspect_path(bundle).failed(),
          "executable symlink escape rejected");
    fs::remove(executable);
    fs::rename(root / "outside-executable", executable);
    auto info = root / "Demo.app/Contents/Info.plist";
    fs::rename(info, root / "outside-info");
    fs::create_symlink(root / "outside-info", info);
    check(session.inspect_path(bundle).failed(),
          "Info.plist symlink escape rejected");
    fs::remove(info);
    fs::rename(root / "outside-info", info);
    fs::rename(manifest, root / "outside-seal");
    fs::create_symlink(root / "outside-seal", manifest);
    check(session.inspect_path(bundle).failed(),
          "manifest symlink escape rejected");
    fs::remove(manifest);
    fs::rename(root / "outside-seal", manifest);
    auto flat = root / "Flat.app";
    fs::create_directories(flat);
    fs::copy_file(root / "linked", flat / "demo");
    fs::copy_file(info, flat / "Info.plist");
    check(!session.inspect_path(flat).failed() &&
              BundleLayout::discover(flat)->flat,
          "flat bundle layout");
    auto normal = run({cli, "--json", (root / "entitled").string()});
    auto output = ClaimNode::parse(normal.output);
    check(normal.status == 0 && output["inputs"].size() == 1,
          "CLI JSON success");
    auto partial = run({cli, "--json", (root / "linked").string(),
                        (root / "missing").string()});
    auto partial_output = ClaimNode::parse(partial.output);
    check(partial.status == 2 && partial_output["inputs"].size() == 2 &&
              partial_output["summary"]["failed_inputs"] == 1,
          "partial failure preserves JSON and returns 2");
    auto invalid = run({cli, "--json", (root / "missing").string()});
    check(invalid.status == 2 &&
              ClaimNode::parse(invalid.output)["summary"]["failed_inputs"] ==
                  1,
          "all failures preserve JSON");
    check(run({cli}).status == 2, "missing CLI path rejected");
    check(run({cli, "--fail-on", "catastrophic", (root / "linked").string()})
                  .status == 2,
          "invalid threshold rejected");
    check(run({cli, "--fail-on"}).status == 2, "missing option value rejected");
    check(run({cli, "--unknown", (root / "linked").string()}).status == 2,
          "unknown option rejected");
    check(run({cli, "--version"}).status == 0, "version command");
    check(run({cli, "--help"}).status == 0, "help command");
    check(
        run({cli, "--fail-on", "high", (root / "entitled").string()}).status ==
            1,
        "high threshold finding exit");
    check(
        run({cli, "--fail-on", "high", (root / "hardened").string()}).status ==
            0,
        "high threshold clean exit");
    auto filtered =
        run({cli, "--min-severity", "high", (root / "entitled").string()});
    check(filtered.output.find("  medium [") == std::string::npos &&
              filtered.output.find("  high [") != std::string::npos,
          "minimum severity display");
    check(run({cli, "--summary", (root / "linked").string()})
                  .output.find("Inputs inspected: 1") != std::string::npos,
          "summary output");
    check(run({cli, "-v", (root / "linked").string()})
                  .output.find("identifier:") != std::string::npos,
          "verbose output");
    check(run({cli, "--no-colour", (root / "linked").string()})
                  .output.find('\033') == std::string::npos,
          "no terminal colour escapes");
    auto scan = root / "scan";
    fs::create_directories(scan);
    fs::copy_file(root / "linked", scan / "binary");
    write_text(scan / "text", "not a Mach-O");
    write_text(scan / "short-text", "hi");
    write_text(scan / "empty-text", "");
    fs::create_symlink(root / "linked", scan / "alias");
    check(run({cli, scan.string()}).status == 2,
          "directory requires recursive flag");
    auto recursive = run({cli, "-r", "--json", scan.string()});
    check(recursive.status == 0 &&
              ClaimNode::parse(recursive.output)["inputs"].size() == 1,
          "recursive scan skips text, short files and symlinks");
    auto unreadable = scan / "unreadable";
    fs::copy_file(root / "linked", unreadable);
    fs::permissions(unreadable, fs::perms::none);
    if (std::ifstream(unreadable, std::ios::binary)) {
      std::cerr << "SKIP: current user bypasses fixture read permissions\n";
    } else {
      auto incomplete = run({cli, "-r", "--json", scan.string()});
      auto incomplete_json = ClaimNode::parse(incomplete.output);
      check(incomplete.status == 2 &&
                incomplete_json["summary"]["failed_inputs"] == 1 &&
                incomplete_json["inputs"].size() == 2 &&
                std::any_of(incomplete_json["inputs"].begin(),
                            incomplete_json["inputs"].end(),
                            [&](const auto &input) {
                              return input["path"] == unreadable.string() &&
                                     input["status"] == "incomplete";
                            }),
            "recursive unreadable input preserves partial success and failure");
      fs::rename(scan / "binary", root / "saved-scan-binary");
      auto only_unreadable = run({cli, "-r", "--json", scan.string()});
      auto only_json = ClaimNode::parse(only_unreadable.output);
      check(only_unreadable.status == 2 &&
                only_json["summary"]["failed_inputs"] == 1 &&
                only_json["inputs"].size() == 1 &&
                only_json["inputs"][0]["path"] == unreadable.string(),
            "unreadable candidate is reported instead of an empty scan");
      fs::rename(root / "saved-scan-binary", scan / "binary");
    }
    fs::permissions(unreadable, fs::perms::owner_read | fs::perms::owner_write);
    fs::remove(unreadable);
    fs::create_directories(root / "empty");
    check(run({cli, "-r", (root / "empty").string()}).status == 2,
          "empty scan returns 2");
    check(run({cli, "--fail-on", "info", (root / "linked").string()}).status ==
              1,
          "info threshold catches every finding");
    auto original_info = read_text(info);
    for (const auto &name : std::vector<std::string>{
             ".", "..", "../outside", "/tmp/outside", "sub\\outside"}) {
      write_text(info,
                 "<?xml version=\"1.0\"?><plist "
                 "version=\"1.0\"><dict><key>CFBundleExecutable</key><string>" +
                     name + "</string></dict></plist>");
      check(session.inspect_path(bundle).failed(),
            "executable name rejects path: " + name);
    }
    write_text(info, original_info);
    fs::rename(manifest.parent_path(), root / "outside-seal-dir");
    fs::create_directory_symlink(root / "outside-seal-dir",
                                 manifest.parent_path());
    check(session.inspect_path(bundle).failed(),
          "manifest parent symlink escape rejected");
    fs::remove(manifest.parent_path());
    fs::rename(root / "outside-seal-dir", manifest.parent_path());
    std::cout << passed << " integration checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
#endif
}
