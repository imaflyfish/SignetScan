#include "subprocess.hpp"
#include <fstream>
#include <glob.h>
#include <iostream>
#include <regex>
#include <set>

using namespace signet_scan;
std::string capture(const std::string &input, const std::string &expression) {
  std::smatch match;
  if (std::regex_search(input, match, std::regex(expression)))
    return match[1].str();
  return "";
}
int main(int argc, char **argv) {
#ifndef __APPLE__
  std::cerr << "codesign comparison requires macOS\n";
  return 77;
#else
  try {
    std::vector<std::string> patterns;
    if (argc > 1)
      for (int index = 1; index < argc; ++index)
        patterns.push_back(argv[index]);
    else
      patterns = {"/usr/bin/*", "/usr/lib/*.dylib", "/usr/libexec/*", "/sbin/*",
                  "/bin/*"};
    std::set<std::string> paths;
    for (const auto &pattern : patterns) {
      glob_t expanded{};
      if (glob(pattern.c_str(), 0, nullptr, &expanded) == 0)
        for (std::size_t index = 0; index < expanded.gl_pathc; ++index)
          if (std::filesystem::is_regular_file(expanded.gl_pathv[index]))
            paths.insert(expanded.gl_pathv[index]);
      globfree(&expanded);
    }
    ClaimNode issues = ClaimNode::array(), skipped = ClaimNode::array();
    std::size_t files = 0, slices = 0, compared = 0, claim_pairs = 0,
                claim_compared = 0;
    AuditSession session;
    for (const auto &path : paths) {
      std::ifstream file(path, std::ios::binary);
      std::array<std::uint8_t, 4> prefix{};
      file.read(reinterpret_cast<char *>(prefix.data()), 4);
      if (file.gcount() != 4 || !MachImageSet::recognises(prefix))
        continue;
      ++files;
      auto result = session.inspect_file(path);
      if (result.failed()) {
        issues.push_back({{"path", path},
                          {"reason", "inspection failed"},
                          {"report", JsonWriter::render({result})}});
        continue;
      }
      for (const auto &slice : result.images) {
        ++slices;
        if (!slice.signing) {
          skipped.push_back({{"path", path},
                             {"architecture", slice.image.architecture},
                             {"reason", "unsigned"}});
          continue;
        }
        auto truth =
            scan_tools::execute({"/usr/bin/codesign", "-d", "-vvv", "--arch",
                                 slice.image.architecture, path});
        if (truth.status != 0) {
          issues.push_back({{"path", path},
                            {"architecture", slice.image.architecture},
                            {"reason", "codesign declined metadata query"},
                            {"status", truth.status}});
          continue;
        }
        auto chosen = std::max_element(slice.signing->directories.begin(),
                                       slice.signing->directories.end(),
                                       [](const auto &left, const auto &right) {
                                         return left.algorithm_code <
                                                right.algorithm_code;
                                       });
        ClaimNode bad = ClaimNode::array();
        auto expect = [&](std::string field, std::string observed,
                          std::string actual) {
          if (observed.empty())
            bad.push_back(field + ": missing from codesign output");
          else if (observed != actual)
            bad.push_back(field + ": codesign=" + observed +
                          " inspector=" + actual);
        };
        expect("identifier",
               capture(truth.output, "(?:^|\n)Identifier=([^\r\n]*)"),
               chosen->identifier);
        expect("team",
               capture(truth.output, "(?:^|\n)TeamIdentifier=([^\r\n]*)"),
               chosen->team_identifier.empty() ? "not set"
                                               : chosen->team_identifier);
        expect("directory-size",
               capture(truth.output, "CodeDirectory v=[0-9a-f]+ size=([0-9]+)"),
               std::to_string(chosen->encoded_bytes));
        expect("slots", capture(truth.output, "hashes=([0-9]+\\+[0-9]+)"),
               std::to_string(chosen->code_slots) + "+" +
                   std::to_string(chosen->special_slots));
        expect("algorithm", capture(truth.output, "Hash type=([^ ]+) size"),
               chosen->algorithm_code == 3 ? "sha256-truncated"
                                           : chosen->algorithm);
        auto version = capture(truth.output, "CodeDirectory v=([0-9a-f]+)");
        auto flags = capture(
            truth.output,
            "CodeDirectory v=[0-9a-f]+ size=[0-9]+ flags=(0x[0-9a-f]+)");
        if (version.empty() ||
            std::stoul(version, nullptr, 16) != chosen->version)
          bad.push_back("directory version mismatch or unavailable");
        if (flags.empty() ||
            std::stoul(flags, nullptr, 16) != chosen->attributes)
          bad.push_back("directory flags mismatch or unavailable");
        for (const auto &directory : slice.signing->directories) {
          auto algorithm = directory.algorithm_code == 3 ? "sha256-truncated"
                                                         : directory.algorithm;
          expect("digest[" + algorithm + "]",
                 capture(truth.output,
                         "CandidateCDHashFull " + algorithm + "=([0-9a-f]+)"),
                 directory.digest);
        }
        ++compared;
        if (slice.claims.plist && slice.claims.der) {
          ++claim_pairs;
          if (slice.claims.disagree)
            bad.push_back("plist/DER typed declarations disagree");
        }
        if (slice.claims.source != "absent") {
          auto entitlement = scan_tools::execute(
              {"/usr/bin/codesign", "-d", "--entitlements", ":-", "--xml",
               "--arch", slice.image.architecture, path});
          auto start = entitlement.output.find("<?xml");
          auto end = entitlement.output.find("</plist>");
          if (entitlement.status != 0 || start == std::string::npos ||
              end == std::string::npos)
            bad.push_back("codesign entitlement output unavailable");
          else {
            std::string text =
                entitlement.output.substr(start, end + 8 - start);
            auto declarations = parse_plist(
                ByteView(reinterpret_cast<const std::uint8_t *>(text.data()),
                         text.size()));
            ++claim_compared;
            if (nlohmann::json(declarations) !=
                nlohmann::json(slice.claims.selected))
              bad.push_back("codesign entitlement value mismatch");
          }
        }
        if (!bad.empty())
          issues.push_back({{"path", path},
                            {"architecture", slice.image.architecture},
                            {"differences", bad}});
      }
    }
    ClaimNode report = {{"files_scanned", paths.size()},
                        {"macho_files", files},
                        {"slices", slices},
                        {"metadata_compared", compared},
                        {"plist_der_pairs", claim_pairs},
                        {"codesign_entitlements_compared", claim_compared},
                        {"issue_count", issues.size()},
                        {"issues", issues},
                        {"skipped", skipped}};
    std::cout << report.dump(2) << '\n';
    return issues.empty() && compared ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
#endif
}
