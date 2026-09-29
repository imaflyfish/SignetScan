#include <signet_scan/audit.hpp>

namespace signet_scan {
bool AuditReport::failed() const {
  if (!errors.empty() || (resources && !resources->errors.empty()))
    return true;
  return std::any_of(images.begin(), images.end(), [](const auto &image) {
    return !image.errors.empty() || !image.claims.errors.empty();
  });
}
std::vector<Remark> AuditReport::observations() const {
  std::vector<Remark> collected;
  for (const auto &image : images)
    for (auto item : image.observations) {
      item.evidence["architecture"] = image.image.architecture;
      collected.push_back(std::move(item));
    }
  if (resources)
    collected.insert(collected.end(), resources->observations.begin(),
                     resources->observations.end());
  std::stable_sort(collected.begin(), collected.end(),
                   [](const auto &first, const auto &second) {
                     return first.severity != second.severity
                                ? first.severity > second.severity
                                : first.code < second.code;
                   });
  return collected;
}
AuditReport AuditSession::inspect_bytes(ByteView bytes,
                                        const std::string &label) const {
  AuditReport result;
  result.path = label;
  result.byte_length = bytes.size();
  try {
    if (bytes.size() > max_input_bytes)
      throw ParseFault("input", "input exceeds byte limit");
    for (auto slice : MachImageSet::decode(bytes)) {
      SliceOutcome image;
      image.image = std::move(slice);
      if (image.image.signature_range)
        try {
          auto [offset, length] = *image.image.signature_range;
          image.signing = SignatureBlob::decode(
              ByteWindow(bytes, "signature")
                  .region(image.image.file_offset, image.image.byte_length)
                  .region(offset, length)
                  .bytes());
          image.claims = GrantDocument::decode(*image.signing);
        } catch (const ParseFault &error) {
          image.errors.push_back(error.diagnostic);
        }
      image.observations = AuditRuleSet::evaluate(image);
      result.images.push_back(std::move(image));
    }
  } catch (const ParseFault &error) {
    result.errors.push_back(error.diagnostic);
  } catch (const std::exception &error) {
    result.errors.push_back({"inspection", error.what(), 0});
  }
  return result;
}
AuditReport
AuditSession::inspect_file(const std::filesystem::path &path) const {
  try {
    auto bytes = load_input(path);
    return inspect_bytes(bytes, path.string());
  } catch (const ParseFault &error) {
    AuditReport result;
    result.path = path.string();
    result.errors.push_back(error.diagnostic);
    return result;
  } catch (const std::exception &error) {
    AuditReport result;
    result.path = path.string();
    result.errors.push_back({"input", error.what(), 0});
    return result;
  }
}
AuditReport AuditSession::inspect_path(const std::filesystem::path &path,
                                       AuditOptions options) const {
  try {
    auto bundle = BundleLayout::discover(path);
    if (!bundle)
      return inspect_file(path);
    AuditReport result;
    if (!bundle->executable.empty())
      result = inspect_file(bundle->executable);
    else
      result.errors.push_back({"bundle", "no executable found in bundle", 0});
    result.path = path.string();
    if (options.check_resources)
      result.resources = SealManifest::inspect(*bundle, result.images);
    return result;
  } catch (const ParseFault &error) {
    AuditReport result;
    result.path = path.string();
    result.errors.push_back(error.diagnostic);
    return result;
  } catch (const std::exception &error) {
    AuditReport result;
    result.path = path.string();
    result.errors.push_back({"bundle", error.what(), 0});
    return result;
  }
}
} // namespace signet_scan
