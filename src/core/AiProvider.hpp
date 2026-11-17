#pragma once
// Abstraksjon for AI-leverandører: lokal ONNX eller ekstern API.

#include <string>
#include <optional>

namespace aifw {

enum class AiProviderType {
    LocalOnnx,      // Lokal ONNX-modell
    OpenAI,         // OpenAI API
    AzureOpenAI,    // Azure OpenAI
    Gemini,         // Google Gemini API
    Grok,           // xAI Grok API
    Custom          // Egendefinert endpoint
};

struct AiProviderConfig {
    AiProviderType type{AiProviderType::LocalOnnx};
    bool enabled{true};

    // Lokal ONNX
    std::string modelPath{"models/flow_classifier.onnx"};

    // Ekstern API
    std::string apiKey;
    std::string apiEndpoint;
    std::string modelName;
    int timeoutMs{5000};

    // Felles
    double blockThreshold{0.90};
    double allowThreshold{0.30};
};

// Standardverdier per leverandør
inline void applyProviderDefaults(AiProviderConfig& cfg) {
    switch (cfg.type) {
        case AiProviderType::OpenAI:
            if (cfg.apiEndpoint.empty())
                cfg.apiEndpoint = "https://api.openai.com/v1/chat/completions";
            if (cfg.modelName.empty())
                cfg.modelName = "gpt-4o-mini";
            break;
        case AiProviderType::AzureOpenAI:
            if (cfg.modelName.empty())
                cfg.modelName = "gpt-4o";
            break;
        case AiProviderType::Gemini:
            if (cfg.apiEndpoint.empty())
                cfg.apiEndpoint = "https://generativelanguage.googleapis.com/v1beta/models";
            if (cfg.modelName.empty())
                cfg.modelName = "gemini-2.0-flash";
            break;
        case AiProviderType::Grok:
            if (cfg.apiEndpoint.empty())
                cfg.apiEndpoint = "https://api.x.ai/v1/chat/completions";
            if (cfg.modelName.empty())
                cfg.modelName = "grok-3";
            break;
        default:
            break;
    }
}

inline std::string maskApiKey(const std::string& key) {
    if (key.size() <= 8) return std::string(key.size(), '*');
    return key.substr(0, 4) + std::string(key.size() - 8, '*') + key.substr(key.size() - 4);
}

inline const char* providerToString(AiProviderType t) {
    switch (t) {
        case AiProviderType::LocalOnnx: return "local";
        case AiProviderType::OpenAI: return "openai";
        case AiProviderType::AzureOpenAI: return "azure";
        case AiProviderType::Gemini: return "gemini";
        case AiProviderType::Grok: return "grok";
        case AiProviderType::Custom: return "custom";
    }
    return "local";
}

inline AiProviderType stringToProvider(const std::string& s) {
    if (s == "openai") return AiProviderType::OpenAI;
    if (s == "azure") return AiProviderType::AzureOpenAI;
    if (s == "gemini") return AiProviderType::Gemini;
    if (s == "grok") return AiProviderType::Grok;
    if (s == "custom") return AiProviderType::Custom;
    return AiProviderType::LocalOnnx;
}

} // namespace aifw
