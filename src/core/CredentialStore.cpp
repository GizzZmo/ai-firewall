#include "CredentialStore.hpp"

#ifdef _WIN32
#include <windows.h>
#include <wincred.h>
#pragma comment(lib, "advapi32.lib")
#endif

#include <vector>

namespace aifw {

std::wstring CredentialStore::makeTarget(const std::string& provider) {
    std::string target = std::string(kTargetPrefix) + provider;
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_UTF8, 0, target.c_str(), -1, nullptr, 0);
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, target.c_str(), -1, result.data(), len);
    result.resize(len - 1);  // fjern null-terminator
    return result;
#else
    return std::wstring(target.begin(), target.end());
#endif
}

bool CredentialStore::store(const std::string& provider, const std::string& apiKey) {
    if (provider.empty() || apiKey.empty()) return false;

#ifdef _WIN32
    std::wstring target = makeTarget(provider);

    CREDENTIALW cred = {};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target.data();
    cred.CredentialBlobSize = static_cast<DWORD>(apiKey.size());
    cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(apiKey.data()));
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    cred.UserName = const_cast<LPWSTR>(L"AiFirewall");

    return CredWriteW(&cred, 0) == TRUE;
#else
    // Fallback for testing: skriv til fil (IKKE for produksjon)
    (void)provider;
    (void)apiKey;
    return false;
#endif
}

std::optional<std::string> CredentialStore::load(const std::string& provider) {
    if (provider.empty()) return std::nullopt;

#ifdef _WIN32
    std::wstring target = makeTarget(provider);
    PCREDENTIALW pcred = nullptr;

    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred)) {
        return std::nullopt;
    }

    std::string result;
    if (pcred->CredentialBlob && pcred->CredentialBlobSize > 0) {
        result.assign(reinterpret_cast<char*>(pcred->CredentialBlob),
                      pcred->CredentialBlobSize);
    }

    CredFree(pcred);
    return result.empty() ? std::nullopt : std::optional<std::string>(result);
#else
    (void)provider;
    return std::nullopt;
#endif
}

bool CredentialStore::remove(const std::string& provider) {
    if (provider.empty()) return false;

#ifdef _WIN32
    std::wstring target = makeTarget(provider);
    return CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) == TRUE;
#else
    (void)provider;
    return false;
#endif
}

bool CredentialStore::exists(const std::string& provider) {
    return load(provider).has_value();
}

} // namespace aifw
