#pragma once

#include <string>
#include <unordered_set>
#include <vector>

namespace aifw {

// Gruppe-basert tilgang for GUI-kommandoer.
// Bruker Windows Access Token + CheckTokenMembership (korrekt måte).
//
// Viktig:
// - CheckTokenMembership sjekker at SID er *enabled* i tokenet
// - UAC-filtrerte tokens har Administrators som deny-only – da returnerer den false
// - For egendefinerte grupper: LookupAccountName → SID → CheckTokenMembership
enum class GuiCommand {
    ViewLogs,
    ToggleLearning,
    ReloadRules,
    ReloadModel,
    ChangeThreshold,
    PersistRule,
    Shutdown
};

class AccessControl {
public:
    AccessControl();

    bool isAllowed(GuiCommand cmd) const;

    // Legg til en gruppe ved navn (f.eks. "Administrators", "AiFirewallUsers")
    // Gruppen må eksistere på maskinen / i domenet.
    bool allowGroup(const std::string& groupName);

    void setRequireAdmin(bool require);

    // Hjelpefunksjoner
    bool isCurrentUserAdmin() const;
    bool isCurrentUserInGroup(const std::string& groupName) const;

    // List alle grupper i gjeldende token (for debugging)
    std::vector<std::string> listCurrentGroups() const;

private:
    bool requireAdmin_{true};
    std::unordered_set<std::string> allowedGroups_;

    bool checkSidMembership(void* sid) const;
};

} // namespace aifw
