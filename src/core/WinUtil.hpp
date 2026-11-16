// Små Win32-hjelpere: RAII-håndtak, UTF-8 <-> UTF-16, feilmeldinger, admin-sjekk.
#pragma once
#ifdef _WIN32

#include <windows.h>

#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

namespace aifw::win {

std::wstring toWide(const std::string& utf8);
std::string toUtf8(const std::wstring& wide);
std::string lastErrorMessage(DWORD code = GetLastError());

/// Kaster std::runtime_error med Win32-feilmelding.
[[noreturn]] void throwLastError(const std::string& what, DWORD code = GetLastError());

/// Er prosessen (eller tråden, hvis den impersonerer) medlem av BUILTIN\Administrators
/// med aktivt (ikke "deny-only") medlemskap, dvs. kjører elevert?
bool isElevatedAdmin();

/// Mappen der exe-filen ligger.
std::filesystem::path exeDirectory();

/// RAII for vanlige HANDLE-er (CloseHandle). Kun flyttbar.
class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(UniqueHandle&& o) noexcept : h_(std::exchange(o.h_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) reset(std::exchange(o.h_, nullptr));
        return *this;
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    void reset(HANDLE h = nullptr) noexcept {
        if (valid()) CloseHandle(h_);
        h_ = h;
    }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }
    explicit operator bool() const noexcept { return valid(); }

private:
    HANDLE h_{nullptr};
};

}  // namespace aifw::win

#endif  // _WIN32
