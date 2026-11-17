#include "AccessControl.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace aifw {

AccessControl::AccessControl() {
    allowedGroups_.insert("Administrators");
}

void AccessControl::allowGroup(const std::string& groupName) {
    allowedGroups_.insert(groupName);
}

void AccessControl::setRequireAdmin(bool require) {
    requireAdmin_ = require;
}

bool AccessControl::isAllowed(GuiCommand cmd) const {
    // Noen kommandoer krever alltid admin
    if (cmd == GuiCommand::Shutdown || cmd == GuiCommand::PersistRule) {
        return currentUserIsAdmin();
    }

    if (requireAdmin_) return currentUserIsAdmin();

    for (const auto& g : allowedGroups_) {
        if (currentUserInGroup(g)) return true;
    }
    return false;
}

bool AccessControl::currentUserIsAdmin() const {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
#else
    return true; // ikke Windows
#endif
}

bool AccessControl::currentUserInGroup(const std::string& /*group*/) const {
    // Forenklet – i produksjon: LookupAccountName + CheckTokenMembership
    return false;
}

} // namespace aifw
