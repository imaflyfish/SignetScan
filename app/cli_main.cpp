#include <array>
#include <fstream>
#include <iostream>
#include <set>
#include <signet_scan/audit.hpp>

namespace {
using namespace signet_scan;
namespace fs = std::filesystem;
struct CliInvocation {
  bool recursive = false, json = false, verbose = false, summary = false,
       resources = true;
  Severity minimum = Severity::info;
  std::optional<Severity> failure;
  std::vector<fs::path> paths;
};
void usage() {
  std::cout
      << "SignetScan 1.0.0 — structural Mach-O inspection\n"
         "Usage: signet-scan [options] PATH...\n"
         "  -r, --recursive          Scan directories for Mach-O files\n"
         "  -j, --json               Write a versioned JSON report\n"
         "  -v, --verbose            Include declared metadata and "
         "explanations\n"
         "  --min-severity LEVEL     Display info, low, medium or high and "
         "above\n"
         "  --fail-on LEVEL          Return 1 at threshold; default never\n"
         "  --summary                Show totals only (JSON remains complete)\n"
         "  --no-resources           Skip bundle resource inspection\n"
         "  --no-colour              Accepted; output is always plain text\n"
         "  --version                Print version\n"
         "Exit 2 means an input/parse/usage failure, including partial "
         "failures.\n"
         "CMS signatures, code pages and actual OS permissions are not "
         "verified.\n";
}
bool needs_inspection(const fs::path &path) {
  std::ifstream stream(path, std::ios::binary);
  // A failed probe cannot establish that this is a non-Mach-O file. Let the
  // normal input reader report the error alongside the other scan results.
  if (!stream)
    return true;
  std::array<std::uint8_t, 4> prefix{};
  stream.read(reinterpret_cast<char *>(prefix.data()), 4);
  return stream.bad() ||
         (stream.gcount() == 4 && MachImageSet::recognises(prefix));
}
} // namespace
int main(int argc, char **argv) {
  try {
    CliInvocation options;
    bool positional = false;
    for (int index = 1; index < argc; ++index) {
      std::string argument = argv[index];
      if (argument == "--" && !positional) {
        positional = true;
        continue;
      }
      if (positional || !argument.starts_with('-')) {
        options.paths.emplace_back(argument);
        continue;
      }
      if (argument == "--help" || argument == "-h") {
        usage();
        return 0;
      }
      if (argument == "--version") {
        std::cout << "SignetScan 1.0.0\n";
        return 0;
      }
      if (argument == "-r" || argument == "--recursive")
        options.recursive = true;
      else if (argument == "-j" || argument == "--json")
        options.json = true;
      else if (argument == "-v" || argument == "--verbose")
        options.verbose = true;
      else if (argument == "--summary")
        options.summary = true;
      else if (argument == "--no-resources")
        options.resources = false;
      else if (argument == "--no-colour" || argument == "--no-color") {
      } else if (argument == "--min-severity" || argument == "--fail-on") {
        if (index + 1 >= argc)
          throw ParseFault("options", "missing value for " + argument);
        std::string value = argv[++index];
        if (argument == "--min-severity")
          options.minimum = parse_severity(value);
        else if (value == "never")
          options.failure.reset();
        else
          options.failure = parse_severity(value);
      } else
        throw ParseFault("options", "unknown option: " + argument);
    }
    if (options.paths.empty())
      throw ParseFault("options", "at least one path is required");
    AuditSession session;
    std::vector<AuditReport> results;
    std::set<std::string> visited;
    auto inspect = [&](const fs::path &path) {
      auto key = fs::absolute(path).lexically_normal().string();
      if (visited.insert(key).second)
        results.push_back(session.inspect_path(path, {options.resources}));
    };
    for (const auto &path : options.paths) {
      try {
        if (!fs::is_directory(path) || BundleLayout::discover(path)) {
          inspect(path);
          continue;
        }
        if (!options.recursive)
          throw ParseFault("input", "directory needs -r: " + path.string());
        std::vector<fs::path> files;
        std::size_t count = 0;
        for (const auto &entry : fs::recursive_directory_iterator(path)) {
          if (++count > 250000)
            throw ParseFault("input", "directory scan limit exceeded");
          auto state = entry.symlink_status();
          if (fs::is_regular_file(state) && needs_inspection(entry.path()))
            files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto &file : files)
          inspect(file);
        if (files.empty())
          throw ParseFault("input", "no Mach-O files found: " + path.string());
      } catch (const ParseFault &error) {
        AuditReport result;
        result.path = path.string();
        result.errors.push_back(error.diagnostic);
        results.push_back(std::move(result));
      } catch (const std::exception &error) {
        AuditReport result;
        result.path = path.string();
        result.errors.push_back({"input", error.what(), 0});
        results.push_back(std::move(result));
      }
    }
    if (options.json)
      std::cout << JsonWriter::render(results).dump(
                       2, ' ', false, nlohmann::json::error_handler_t::replace)
                << '\n';
    else
      std::cout << TextWriter::render(results, options.minimum, options.verbose,
                                      options.summary);
    if (std::any_of(results.begin(), results.end(),
                    [](const auto &result) { return result.failed(); }))
      return 2;
    if (options.failure)
      for (const auto &result : results)
        for (const auto &finding : result.observations())
          if (finding.impact >= *options.failure)
            return 1;
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "signet-scan: " << error.what() << '\n';
    return 2;
  }
}
