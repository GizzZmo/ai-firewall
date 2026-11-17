#pragma once
// Sikker lagring av API-nøkler via Windows Credential Manager.
// Faller tilbake til filbasert lagring på ikke-Windows (kun for testing).

#include <string>
#include <optional>

namespace aifw {

class CredentialStore {
public:
    // Target-navn: "AiFirewall/<provider>" f.eks. "AiFirewall/openai"
    static constexpr const char* kTargetPrefix = "AiFirewall/";

    // Lagre API-nøkkel for en leverandør.
    // Returnerer true ved suksess.
    static bool store(const std::string& provider, const std::string& apiKey);

    // Hent API-nøkkel for en leverandør.
    // Returnerer nullopt hvis ikke funnet.
    static std::optional<std::string> load(const std::string& provider);

    // Slett lagret nøkkel.
    static bool remove(const std::string& provider);

    // Sjekk om en nøkkel er lagret (uten å hente den).
    static bool exists(const std::string& provider);

private:
    static std::wstring makeTarget(const std::string& provider);
};

} // namespace aifw
