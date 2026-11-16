// Persistente regler via Windows Filtering Platform (WFP).
//
// WinDivert gir dynamisk, AI-drevet filtrering mens tjenesten kjører. WFP-filtre med
// FWPM_FILTER_FLAG_PERSISTENT lagres av Base Filtering Engine (BFE) og håndheves fra
// oppstart – også før/uten at tjenesten vår kjører. Vi bruker egen provider + sublayer
// slik at alle våre filtre kan listes og fjernes samlet uten å røre andres regler.
#pragma once
#ifdef _WIN32

#include <windows.h>
#include <fwpmu.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "RuleEngine.hpp"
#include "Types.hpp"

namespace aifw {

struct WfpRule {
    std::wstring name;
    std::wstring description;
    Verdict action{Verdict::Block};
    Direction direction{Direction::Outbound};
    Protocol protocol{Protocol::Any};
    std::optional<Cidr> remote;
    std::optional<PortRange> remotePort;
    std::optional<PortRange> localPort;
    std::wstring appPath;  // full sti til exe; tom = alle
    std::uint8_t weight{10};  // innen vår sublayer: høyere vekt evalueres først

    /// Oversetter en RuleEngine-regel til en eller flere WFP-regler. Returnerer tom
    /// liste hvis regelen ikke kan uttrykkes i WFP (f.eks. app-wildcard).
    static std::vector<WfpRule> fromRule(const Rule& r, std::string* whyNot = nullptr);
};

struct WfpFilterInfo {
    std::uint64_t id{0};
    std::wstring name;
    GUID layer{};
};

class WfpManager {
public:
    /// Åpner en ikke-dynamisk WFP-sesjon (kreves for persistente objekter). Krever administrator.
    WfpManager();
    ~WfpManager();  // FwpmEngineClose0
    WfpManager(const WfpManager&) = delete;
    WfpManager& operator=(const WfpManager&) = delete;

    /// Oppretter provider og sublayer (persistente) hvis de ikke finnes. Idempotent.
    void install();
    /// Fjerner alle våre filtre, sublayer og provider.
    void uninstall();

    /// Legger til filter(e) for regelen. Returnerer filter-ID-er.
    std::vector<std::uint64_t> addRule(const WfpRule& rule);
    void removeFilter(std::uint64_t id);
    /// Fjerner alle filtre som tilhører vår provider. Returnerer antall.
    std::size_t removeAllFilters();
    [[nodiscard]] std::vector<WfpFilterInfo> listFilters() const;

    /// Synkroniserer: fjerner alle våre filtre og legger inn alle regler med persistent=true.
    std::size_t syncPersistentRules(const std::vector<Rule>& rules);

    static const GUID kProviderKey;
    static const GUID kSublayerKey;

private:
    HANDLE engine_{nullptr};
};

}  // namespace aifw
#endif  // _WIN32
