#pragma once

#include <string>
#include <vector>
#include <unordered_set>

namespace aifw {

// Gruppe-basert tilgang for GUI-kommandoer.
// I stedet for «kun administrator» kan man tillate spesifikke grupper.
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

    // Sjekk om gjeldende bruker (eller oppgitt gruppe) får utføre kommandoen.
    // På Windows: sjekk token-grupper. Her: enkel konfigurasjon.
    bool isAllowed(GuiCommand cmd) const;

    // Legg til en gruppe som får lov (f.eks. "Administrators", "AiFirewallUsers")
    void allowGroup(const std::string& groupName);

    // Standard: bare Administrators
    void setRequireAdmin(bool require);

private:
    bool requireAdmin_{true};
    std::unordered_set<std::string> allowedGroups_;

    bool currentUserIsAdmin() const;
    bool currentUserInGroup(const std::string& group) const;
};

} // namespace aifw
