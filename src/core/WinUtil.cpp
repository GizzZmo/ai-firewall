#ifdef _WIN32
#include "WinUtil.hpp"

#include <vector>

namespace aifw::win {

std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string lastErrorMessage(DWORD code) {
    LPWSTR buf = nullptr;
    const DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring msg = len ? std::wstring(buf, len) : L"ukjent feil";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == L'\n' || msg.back() == L'\r')) msg.pop_back();
    return toUtf8(msg) + " (kode " + std::to_string(code) + ")";
}

void throwLastError(const std::string& what, DWORD code) { throw std::runtime_error(what + ": " + lastErrorMessage(code)); }

bool isElevatedAdmin() {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = nullptr;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
        return false;
    BOOL member = FALSE;
    // nullptr = trådens impersonerings-token hvis satt, ellers prosessens token.
    if (!CheckTokenMembership(nullptr, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member == TRUE;
}

std::filesystem::path exeDirectory() {
    std::vector<wchar_t> buf(MAX_PATH);
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) throwLastError("GetModuleFileNameW");
        if (n < buf.size()) return std::filesystem::path(std::wstring(buf.data(), n)).parent_path();
        buf.resize(buf.size() * 2);
    }
}

}  // namespace aifw::win
#endif  // _WIN32
