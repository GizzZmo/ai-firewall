#include "Model.hpp"

#include <algorithm>
#include <cmath>

#include <spdlog/spdlog.h>

namespace aifw {

namespace {
inline float at(const FeatureVector& f, Feature x) noexcept { return f[static_cast<std::size_t>(x)]; }
inline float sigmoid(float x) noexcept { return 1.0f / (1.0f + std::exp(-x)); }
}  // namespace

float HeuristicModel::score(const FeatureVector& f) noexcept {
    // Håndlagde signaler for kjente mønstre. Vektene er bevisst konservative.
    float z = -4.0f;
    const float syn = at(f, Feature::SynCount);
    const float fwd = at(f, Feature::FwdPackets);
    const float bwd = at(f, Feature::BwdPackets);
    const float pps = at(f, Feature::PacketsPerSec);
    const float entropy = at(f, Feature::PayloadEntropyMean);
    const float rst = at(f, Feature::RstCount);

    // SYN-flom / skanning: mange SYN uten svar.
    if (syn >= 5 && bwd <= 1) z += 3.0f;
    if (syn >= 20 && bwd == 0) z += 2.0f;
    // Svært høy pakkerate med nesten bare én retning.
    if (pps > 2000 && at(f, Feature::FwdBwdRatio) > 50) z += 3.0f;
    // Mange RST (avviste forbindelser).
    if (rst >= 5) z += 1.5f;
    // Høy entropi i ukjent UDP på høy port (mulig tunnel/exfil) – svakt signal.
    // NB: entropi måles på maks 256 byte, så tilfeldige data gir ~7.2 bits/byte, ikke 8.
    if (at(f, Feature::ProtocolUdp) > 0.5f && entropy > 7.0f && at(f, Feature::DstPortNorm) > 0.5f &&
        at(f, Feature::FwdBytes) > 5e5f)
        z += 2.0f;
    // Stor utgående datamengde uten svar.
    if (fwd > 200 && bwd == 0) z += 2.0f;
    return std::clamp(sigmoid(z), 0.0f, 1.0f);
}

std::vector<float> HeuristicModel::predictBatch(std::span<const FeatureVector> rows) {
    std::vector<float> out;
    out.reserve(rows.size());
    for (const auto& r : rows) out.push_back(score(r));
    return out;
}

std::unique_ptr<IModel> createModel(const AiConfig& cfg, const std::filesystem::path& baseDir) {
#ifdef AIFW_WITH_ONNX
    std::filesystem::path p(cfg.modelPath);
    if (p.is_relative() && !baseDir.empty()) p = baseDir / p;
    std::error_code ec;
    if (std::filesystem::exists(p, ec)) {
        try {
            auto m = std::make_unique<OnnxModel>(p, cfg);
            spdlog::info("Lastet ONNX-modell: {}", p.string());
            return m;
        } catch (const std::exception& e) {
            spdlog::error("Kunne ikke laste ONNX-modell '{}': {} – bruker heuristikk", p.string(), e.what());
        }
    } else {
        spdlog::warn("Modellfil finnes ikke: {} – bruker heuristikk", p.string());
    }
#else
    (void)baseDir;
    spdlog::warn("Bygget uten ONNX Runtime (AIFW_WITH_ONNX=OFF) – bruker heuristikk. Modell '{}' ignoreres.",
                 cfg.modelPath);
#endif
    return std::make_unique<HeuristicModel>();
}

}  // namespace aifw
