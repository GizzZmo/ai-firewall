// Modell-abstraksjon: AIDecisionEngine kjenner bare IModel, ikke ONNX Runtime direkte.
// Det gjør motoren testbar uten ONNX, og gjør det enkelt å bytte inferens-backend.
#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "Config.hpp"
#include "FeatureSchema.hpp"

namespace aifw {

class IModel {
public:
    virtual ~IModel() = default;
    /// Returnerer sannsynlighet (0-1) for "ondsinnet" for hver rad. Kan kaste ved feil.
    /// Må være trådsikker (kalles samtidig fra flere arbeidertråder).
    virtual std::vector<float> predictBatch(std::span<const FeatureVector> rows) = 0;
    [[nodiscard]] virtual std::string name() const = 0;
};

/// Enkel, deterministisk heuristikk. Brukes når ONNX ikke er bygget inn eller
/// modellfilen mangler, slik at systemet fortsatt har en "AI-lignende" vurdering.
/// Den er IKKE en erstatning for en trent modell.
class HeuristicModel final : public IModel {
public:
    std::vector<float> predictBatch(std::span<const FeatureVector> rows) override;
    [[nodiscard]] std::string name() const override { return "heuristic"; }
    static float score(const FeatureVector& f) noexcept;
};

#ifdef AIFW_WITH_ONNX
/// ONNX Runtime-modell. Én Ort::Session deles av alle tråder (Run() er trådsikker).
class OnnxModel final : public IModel {
public:
    OnnxModel(const std::filesystem::path& modelPath, const AiConfig& cfg);
    ~OnnxModel() override;
    OnnxModel(const OnnxModel&) = delete;
    OnnxModel& operator=(const OnnxModel&) = delete;

    std::vector<float> predictBatch(std::span<const FeatureVector> rows) override;
    [[nodiscard]] std::string name() const override;

private:
    struct Impl;  // pimpl: holder onnxruntime-headere ute av offentlig API
    std::unique_ptr<Impl> impl_;
};
#endif

/// Fabrikk: ONNX hvis tilgjengelig og modellen kan lastes, ellers heuristikk.
/// Feil ved lasting logges og gir heuristikk (fail-safe), aldri krasj.
std::unique_ptr<IModel> createModel(const AiConfig& cfg, const std::filesystem::path& baseDir = {});

}  // namespace aifw
