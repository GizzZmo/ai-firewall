#include "AccessControl.hpp"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#endif

#include <vector>

namespace aifw {

AccessControl::AccessControl() {
    allowedGroups_.insert("Administrators");
}

bool AccessControl::allowGroup(const std::string& groupName) {
    if (groupName.empty()) return false;
    allowedGroups_.insert(groupName);
    return true;
}

void AccessControl::setRequireAdmin(bool require) {
    requireAdmin_ = require;
}

bool AccessControl::isAllowed(GuiCommand cmd) const {
    // Sensitive kommandoer krever alltid admin
    if (cmd == GuiCommand::Shutdown || cmd == GuiCommand::PersistRule) {
        return isCurrentUserAdmin();
    }

    if (requireAdmin_) return isCurrentUserAdmin();

    for (const auto& g : allowedGroups_) {
        if (isCurrentUserInGroup(g)) return true;
    }
    return false;
}

bool AccessControl::isCurrentUserAdmin() const {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (!AllocateAndInitializeSid(&ntAuth, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &adminGroup)) {
        return false;
    }

    if (!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
        isAdmin = FALSE;
    }
    FreeSid(adminGroup);
    return isAdmin == TRUE;
#else
    return true;
#endif
}

bool AccessControl::checkSidMembership(void* sid) const {
#ifdef _WIN32
    if (!sid) return false;
    BOOL isMember = FALSE;
    if (!CheckTokenMembership(nullptr, static_cast<PSID>(sid), &isMember)) {
        return false;
    }
    return isMember == TRUE;
#else
    (void)sid;
    return false;
#endif
}

bool AccessControl::isCurrentUserInGroup(const std::string& groupName) const {
#ifdef _WIN32
    if (groupName.empty()) return false;

    // Konverter gruppenavn → SID
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidType;

    LookupAccountNameA(nullptr, groupName.c_str(), nullptr, &sidSize,
                       nullptr, &domainSize, &sidType);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<BYTE> sidBuf(sidSize);
    std::vector<char> domainBuf(domainSize);

    if (!LookupAccountNameA(nullptr, groupName.c_str(),
                            sidBuf.data(), &sidSize,
                            domainBuf.data(), &domainSize, &sidType)) {
        return false;
    }

    return checkSidMembership(sidBuf.data());
#else
    (void)groupName;
    return false;
#endif
}

std::vector<std::string> AccessControl::listCurrentGroups() const {
    std::vector<std::string> result;
#ifdef _WIN32
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return result;
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(token);
        return result;
    }

    std::vector<BYTE> buf(needed);
    auto* groups = reinterpret_cast<PTOKEN_GROUPS>(buf.data());
    if (!GetTokenInformation(token, TokenGroups, groups, needed, &needed)) {
        CloseHandle(token);
        return result;
    }

    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        char name[256] = {};
        char domain[256] = {};
        DWORD nameLen = sizeof(name);
        DWORD domainLen = sizeof(domain);
        SID_NAME_USE type;

        if (LookupAccountSidA(nullptr, groups->Groups[i].Sid,
                              name, &nameLen, domain, &domainLen, &type)) {
            std::string full = std::string(domain) + "\\" + name;
            // Marker om SID er enabled
            if (groups->Groups[i].Attributes & SE_GROUP_ENABLED) {
                full += " [enabled]";
            } else if (groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) {
                full += " [deny-only]";
            }
            result.push_back(full);
        }
    }
    CloseHandle(token);
#endif
    return result;
}

} // namespace aifw
