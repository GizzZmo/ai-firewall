#pragma once
// Abstraksjon for AI-leverandører: lokal ONNX eller ekstern API (OpenAI, Azure, osv.).

#include <string>
#include <optional>

namespace aifw {

enum class AiProviderType {
    LocalOnnx,      // Lokal ONNX-modell
    OpenAI,         // OpenAI API
    AzureOpenAI,    // Azure OpenAI
    Custom          // Egendefinert endpoint
};

struct AiProviderConfig {
    AiProviderType type{AiProviderType::LocalOnnx};
    bool enabled{true};

    // Lokal ONNX
    std::string modelPath{"models/flow_classifier.onnx"};

    // Ekstern API
    std::string apiKey;           // lagres kryptert eller i Windows Credential Manager
    std::string apiEndpoint;      // f.eks. https://api.openai.com/v1/chat/completions
    std::string modelName{"gpt-4o-mini"};
    int timeoutMs{5000};

    // Felles
    double blockThreshold{0.90};
    double allowThreshold{0.30};
};

// Hjelpefunksjon for å maskere API-nøkkel i UI
inline std::string maskApiKey(const std::string& key) {
    if (key.size() <= 8) return std::string(key.size(), '*');
    return key.substr(0, 4) + std::string(key.size() - 8, '*') + key.substr(key.size() - 4);
}

} // namespace aifw
