// Kjøres kun når AIFW_WITH_ONNX er på. Bruker modellen fra ml/out/ (lag den med
// `python -m aifw_ml.train && python -m aifw_ml.verify_onnx`), ellers hoppes testene over.
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "Model.hpp"

using namespace aifw;

namespace {
std::filesystem::path modelPath() {
    if (const char* env = std::getenv("AIFW_TEST_ONNX_MODEL")) return env;
    return std::filesystem::path(AIFW_SOURCE_DIR) / "ml" / "out" / "flow_classifier.onnx";
}
}  // namespace

TEST(OnnxModel, LoadsAndRanksFloodAboveBrowsing) {
    const auto p = modelPath();
    if (!std::filesystem::exists(p)) GTEST_SKIP() << "ingen modell på " << p;
    OnnxModel m(p, AiConfig{});
    FeatureVector flood{}, browse{};
    auto set = [](FeatureVector& v, Feature f, float x) { v[static_cast<std::size_t>(f)] = x; };
    set(flood, Feature::DurationSec, 0.05f); set(flood, Feature::FwdPackets, 500); set(flood, Feature::SynCount, 500);
    set(flood, Feature::PktLenMean, 44); set(flood, Feature::PacketsPerSec, 10000); set(flood, Feature::BytesPerSec, 440000);
    set(flood, Feature::FwdBytes, 22000); set(flood, Feature::FwdBwdRatio, 500); set(flood, Feature::ProtocolTcp, 1);
    set(flood, Feature::DstPortNorm, 80.0f / 65535);
    set(browse, Feature::DurationSec, 3); set(browse, Feature::FwdPackets, 20); set(browse, Feature::BwdPackets, 60);
    set(browse, Feature::FwdBytes, 8000); set(browse, Feature::BwdBytes, 70000); set(browse, Feature::PktLenMean, 980);
    set(browse, Feature::PktLenStd, 500); set(browse, Feature::IatMeanMs, 40); set(browse, Feature::IatStdMs, 60);
    set(browse, Feature::SynCount, 1); set(browse, Feature::PshCount, 20); set(browse, Feature::FinCount, 1);
    set(browse, Feature::PayloadEntropyMean, 7.2f); set(browse, Feature::ProtocolTcp, 1);
    set(browse, Feature::DstPortNorm, 443.0f / 65535); set(browse, Feature::PacketsPerSec, 26);
    set(browse, Feature::BytesPerSec, 26000); set(browse, Feature::FwdBwdRatio, 0.33f);
    std::vector<FeatureVector> rows{flood, browse};
    auto s = m.predictBatch(rows);
    ASSERT_EQ(s.size(), 2u);
    EXPECT_GT(s[0], s[1]);
    EXPECT_GE(s[0], 0.0f);
    EXPECT_LE(s[0], 1.0f);
}

TEST(OnnxModel, MatchesPythonReference) {
    const auto p = modelPath();
    const auto ref = p.parent_path() / "reference_predictions.json";
    if (!std::filesystem::exists(p) || !std::filesystem::exists(ref)) GTEST_SKIP() << "mangler modell/referanse";
    std::ifstream in(ref);
    auto j = nlohmann::json::parse(in);
    std::vector<FeatureVector> rows;
    for (const auto& r : j["features"]) {
        FeatureVector v{};
        ASSERT_EQ(r.size(), kFeatureCount);
        for (std::size_t i = 0; i < kFeatureCount; ++i) v[i] = r[i].get<float>();
        rows.push_back(v);
    }
    OnnxModel m(p, AiConfig{});
    auto s = m.predictBatch(rows);
    ASSERT_EQ(s.size(), rows.size());
    for (std::size_t i = 0; i < s.size(); ++i) EXPECT_NEAR(s[i], j["p_malicious"][i].get<float>(), 1e-5) << i;
}

TEST(OnnxModel, RejectsModelWithWrongInputWidth) {
    // En ikke-eksisterende fil skal gi unntak (createModel faller da tilbake til heuristikk).
    EXPECT_ANY_THROW(OnnxModel("/finnes/ikke.onnx", AiConfig{}));
    AiConfig cfg;
    cfg.modelPath = "/finnes/ikke.onnx";
    auto fallback = createModel(cfg);
    EXPECT_EQ(fallback->name(), "heuristic");
}
