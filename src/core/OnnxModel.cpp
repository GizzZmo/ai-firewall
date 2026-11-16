// ONNX Runtime-backend. Kompileres kun når AIFW_WITH_ONNX er definert.
#ifdef AIFW_WITH_ONNX
#include <onnxruntime_cxx_api.h>

#include <algorithm>
#include <mutex>
#include <stdexcept>

#include "Model.hpp"

namespace aifw {

struct OnnxModel::Impl {
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "aifw"};
    Ort::SessionOptions options;
    std::unique_ptr<Ort::Session> session;
    std::string inputName;
    std::string outputName;
    std::size_t classIndex{1};
    std::string description;
};

OnnxModel::OnnxModel(const std::filesystem::path& modelPath, const AiConfig& cfg) : impl_(std::make_unique<Impl>()) {
    auto& im = *impl_;
    // Små modeller: én intra-op-tråd per kall; parallellitet får vi fra arbeidertrådene.
    im.options.SetIntraOpNumThreads(1);
    im.options.SetInterOpNumThreads(1);
    im.options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    // Ort::Session tar ORTCHAR_T* – wchar_t på Windows, char på Linux. path::c_str() gir riktig type.
    im.session = std::make_unique<Ort::Session>(im.env, modelPath.c_str(), im.options);

    Ort::AllocatorWithDefaultOptions alloc;
    if (im.session->GetInputCount() < 1) throw std::runtime_error("modellen har ingen input");
    im.inputName = cfg.inputName.empty() ? std::string(im.session->GetInputNameAllocated(0, alloc).get()) : cfg.inputName;

    // Valider input-dimensjon mot feature-skjemaet så vi feiler tidlig ved feil modell.
    // NB: TypeInfo må leve så lenge vi bruker shape-info (Const-view inn i TypeInfo).
    const Ort::TypeInfo typeInfo = im.session->GetInputTypeInfo(0);
    const auto shape = typeInfo.GetTensorTypeAndShapeInfo().GetShape();
    if (shape.size() != 2) throw std::runtime_error("forventet 2D-input [N, features]");
    if (shape[1] > 0 && static_cast<std::size_t>(shape[1]) != kFeatureCount)
        throw std::runtime_error("modellen forventer " + std::to_string(shape[1]) + " features, skjema har " +
                                 std::to_string(kFeatureCount));

    const std::size_t outCount = im.session->GetOutputCount();
    if (!cfg.outputName.empty()) {
        im.outputName = cfg.outputName;
    } else {
        // skl2onnx-klassifiserere: output 0 = label (int64), output 1 = probabilities (float [N,2]).
        const std::size_t idx = outCount > 1 ? 1 : 0;
        im.outputName = im.session->GetOutputNameAllocated(idx, alloc).get();
    }
    im.classIndex = cfg.outputClassIndex;
    im.description = "onnx(" + modelPath.filename().string() + ", in=" + im.inputName + ", out=" + im.outputName + ")";
}

OnnxModel::~OnnxModel() = default;

std::string OnnxModel::name() const { return impl_->description; }

std::vector<float> OnnxModel::predictBatch(std::span<const FeatureVector> rows) {
    if (rows.empty()) return {};
    auto& im = *impl_;
    // FeatureVector er std::array<float, N> – sammenhengende minne, så vi kan bruke det direkte
    // som [rows, N]-tensor uten kopiering.
    static_assert(sizeof(FeatureVector) == sizeof(float) * kFeatureCount);
    const std::array<int64_t, 2> shape{static_cast<int64_t>(rows.size()), static_cast<int64_t>(kFeatureCount)};
    auto memInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    auto input = Ort::Value::CreateTensor<float>(memInfo, const_cast<float*>(rows.front().data()),
                                                 rows.size() * kFeatureCount, shape.data(), shape.size());
    const char* inNames[] = {im.inputName.c_str()};
    const char* outNames[] = {im.outputName.c_str()};
    auto outputs = im.session->Run(Ort::RunOptions{nullptr}, inNames, &input, 1, outNames, 1);
    if (outputs.empty() || !outputs[0].IsTensor()) throw std::runtime_error("uventet output (ikke tensor – eksporter med zipmap=False)");

    auto info = outputs[0].GetTensorTypeAndShapeInfo();
    const auto outShape = info.GetShape();
    const float* data = outputs[0].GetTensorData<float>();
    std::vector<float> scores(rows.size());
    if (outShape.size() == 2 && outShape[1] >= 2) {
        const auto cols = static_cast<std::size_t>(outShape[1]);
        const std::size_t c = std::min(im.classIndex, cols - 1);
        for (std::size_t i = 0; i < rows.size(); ++i) scores[i] = data[i * cols + c];
    } else {
        // [N] eller [N,1]: allerede en sannsynlighet/score.
        for (std::size_t i = 0; i < rows.size(); ++i) scores[i] = data[i];
    }
    for (auto& s : scores) s = std::clamp(s, 0.0f, 1.0f);
    return scores;
}

}  // namespace aifw
#endif  // AIFW_WITH_ONNX
