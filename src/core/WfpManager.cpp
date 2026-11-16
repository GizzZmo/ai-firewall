#ifdef _WIN32
#include "WfpManager.hpp"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <fwpmu.h>
#include <rpc.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

#include <spdlog/spdlog.h>

#include "WinUtil.hpp"

#include "WfpCompat.hpp"

#ifdef _MSC_VER
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#endif

namespace aifw {

// Faste GUID-er for vår provider og sublayer (genererte, unike for AI-Firewall).
const GUID WfpManager::kProviderKey = {0x6b1f2a3c, 0x8d4e, 0x4f51, {0x9a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81}};
const GUID WfpManager::kSublayerKey = {0x7c2e3b4d, 0x9e5f, 0x4062, {0xab, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92}};

namespace {

void check(DWORD rc, const char* what) {
    if (rc != ERROR_SUCCESS) throw std::runtime_error(std::string(what) + " feilet: " + win::lastErrorMessage(rc));
}

/// RAII-transaksjon: abort hvis commit() ikke kalles (f.eks. ved unntak).
class Transaction {
public:
    explicit Transaction(HANDLE e) : e_(e) { check(FwpmTransactionBegin0(e_, 0), "FwpmTransactionBegin0"); }
    ~Transaction() {
        if (!done_) FwpmTransactionAbort0(e_);
    }
    void commit() {
        check(FwpmTransactionCommit0(e_), "FwpmTransactionCommit0");
        done_ = true;
    }

private:
    HANDLE e_;
    bool done_{false};
};

/// RAII for minne allokert av WFP (FwpmFreeMemory0).
template <typename T>
struct WfpMem {
    T* p{nullptr};
    ~WfpMem() {
        if (p) FwpmFreeMemory0(reinterpret_cast<void**>(&p));
    }
};

std::uint32_t v4HostOrder(const IpAddress& ip) {
    return (static_cast<std::uint32_t>(ip.bytes[0]) << 24) | (ip.bytes[1] << 16) | (ip.bytes[2] << 8) | ip.bytes[3];
}

std::vector<GUID> layersFor(Direction d, int ipVersion) {
    std::vector<GUID> out;
    const bool v4 = ipVersion != 6, v6 = ipVersion != 4;
    // ALE_AUTH_CONNECT = utgående forbindelsesforsøk; ALE_AUTH_RECV_ACCEPT = innkommende.
    // ALE-lagene evalueres én gang per forbindelse (ikke per pakke) og kjenner app-ID.
    if (d != Direction::Inbound) {
        if (v4) out.push_back(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
        if (v6) out.push_back(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
    }
    if (d != Direction::Outbound) {
        if (v4) out.push_back(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
        if (v6) out.push_back(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    }
    return out;
}

}  // namespace

std::vector<WfpRule> WfpRule::fromRule(const Rule& r, std::string* whyNot) {
    auto fail = [&](const char* why) {
        if (whyNot) *whyNot = why;
        return std::vector<WfpRule>{};
    };
    if (r.app.find_first_of("*?") != std::string::npos) return fail("WFP støtter ikke wildcard i app-sti");
    if (!r.app.empty() && r.app.find_first_of("\\/") == std::string::npos) return fail("WFP krever full app-sti");
    // Én WFP-regel per kombinasjon av IP-blokk og port-intervaller (WFP AND-er betingelser
    // med ulike felt, men vi holder det eksplisitt for lesbarhet i WFP-dumpen).
    std::vector<WfpRule> out;
    const std::vector<std::optional<Cidr>> ips = r.remoteIps.empty() ? std::vector<std::optional<Cidr>>{std::nullopt}
                                                                     : std::vector<std::optional<Cidr>>(r.remoteIps.begin(), r.remoteIps.end());
    const std::vector<std::optional<PortRange>> rports = r.remotePorts.empty() ? std::vector<std::optional<PortRange>>{std::nullopt}
                                                                               : std::vector<std::optional<PortRange>>(r.remotePorts.begin(), r.remotePorts.end());
    const std::vector<std::optional<PortRange>> lports = r.localPorts.empty() ? std::vector<std::optional<PortRange>>{std::nullopt}
                                                                              : std::vector<std::optional<PortRange>>(r.localPorts.begin(), r.localPorts.end());
    for (const auto& ip : ips)
        for (const auto& rp : rports)
            for (const auto& lp : lports) {
                WfpRule w;
                w.name = L"AI-Firewall: " + win::toWide(r.id);
                w.description = win::toWide(r.comment.empty() ? r.id : r.comment);
                w.action = r.action;
                w.direction = r.direction;
                w.protocol = r.protocol;
                w.remote = ip;
                w.remotePort = rp;
                w.localPort = lp;
                w.appPath = win::toWide(r.app);
                // Map prioritet (vilkårlig int) til WFP-vekt 0-15 innen sublayeren.
                w.weight = static_cast<std::uint8_t>(std::clamp(r.priority / 10, 0, 15));
                out.push_back(std::move(w));
            }
    return out;
}

WfpManager::WfpManager() {
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"AI-Firewall");
    session.displayData.description = const_cast<wchar_t*>(L"AI-Firewall WFP-sesjon");
    // IKKE FWPM_SESSION_FLAG_DYNAMIC: dynamiske objekter slettes når sesjonen lukkes,
    // og persistente objekter kan ikke opprettes i en dynamisk sesjon.
    session.flags = 0;
    session.txnWaitTimeoutInMSec = 5000;
    check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_), "FwpmEngineOpen0 (krever administrator)");
}

WfpManager::~WfpManager() {
    if (engine_) FwpmEngineClose0(engine_);
}

void WfpManager::install() {
    Transaction tx(engine_);

    FWPM_PROVIDER0 provider{};
    provider.providerKey = kProviderKey;
    provider.displayData.name = const_cast<wchar_t*>(L"AI-Firewall");
    provider.displayData.description = const_cast<wchar_t*>(L"KI-basert brannmur (persistente regler)");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    DWORD rc = FwpmProviderAdd0(engine_, &provider, nullptr);
    if (rc != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) check(rc, "FwpmProviderAdd0");

    FWPM_SUBLAYER0 sub{};
    sub.subLayerKey = kSublayerKey;
    sub.displayData.name = const_cast<wchar_t*>(L"AI-Firewall sublayer");
    sub.displayData.description = const_cast<wchar_t*>(L"Regler fra AI-Firewall");
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.providerKey = const_cast<GUID*>(&kProviderKey);
    sub.weight = 0x8000;  // midt i området; Windows Defender Firewall har egne sublayers
    rc = FwpmSubLayerAdd0(engine_, &sub, nullptr);
    if (rc != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) check(rc, "FwpmSubLayerAdd0");

    tx.commit();
    spdlog::info("WFP provider/sublayer installert");
}

void WfpManager::uninstall() {
    const auto n = removeAllFilters();
    Transaction tx(engine_);
    DWORD rc = FwpmSubLayerDeleteByKey0(engine_, &kSublayerKey);
    if (rc != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) check(rc, "FwpmSubLayerDeleteByKey0");
    rc = FwpmProviderDeleteByKey0(engine_, &kProviderKey);
    if (rc != static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND)) check(rc, "FwpmProviderDeleteByKey0");
    tx.commit();
    spdlog::info("WFP avinstallert ({} filtre fjernet)", n);
}

std::vector<std::uint64_t> WfpManager::addRule(const WfpRule& rule) {
    const int ipVersion = rule.remote ? rule.remote->network.version : 0;

    // App-ID må hentes før transaksjonen og frigjøres med FwpmFreeMemory0.
    WfpMem<FWP_BYTE_BLOB> appId;
    if (!rule.appPath.empty())
        check(FwpmGetAppIdFromFileName0(rule.appPath.c_str(), &appId.p), "FwpmGetAppIdFromFileName0");

    std::vector<std::uint64_t> ids;
    Transaction tx(engine_);
    for (const GUID& layer : layersFor(rule.direction, ipVersion)) {
        const bool isV6Layer = IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6) || IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
        std::vector<FWPM_FILTER_CONDITION0> conds;
        // Verdier må leve til FwpmFilterAdd0 har returnert.
        FWP_V4_ADDR_AND_MASK v4{};
        FWP_V6_ADDR_AND_MASK v6{};
        FWP_RANGE0 rRange{}, lRange{};

        if (rule.protocol != Protocol::Any) {
            FWPM_FILTER_CONDITION0 c{};
            c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_UINT8;
            c.conditionValue.uint8 = static_cast<UINT8>(rule.protocol);
            conds.push_back(c);
        }
        if (rule.remote) {
            FWPM_FILTER_CONDITION0 c{};
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            if (!isV6Layer) {
                v4.addr = v4HostOrder(rule.remote->network);  // WFP bruker host-rekkefølge for IPv4
                v4.mask = rule.remote->prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - rule.remote->prefix));
                c.conditionValue.type = FWP_V4_ADDR_MASK;
                c.conditionValue.v4AddrMask = &v4;
            } else {
                std::memcpy(v6.addr, rule.remote->network.bytes.data(), 16);  // nettverksrekkefølge
                v6.prefixLength = rule.remote->prefix;
                c.conditionValue.type = FWP_V6_ADDR_MASK;
                c.conditionValue.v6AddrMask = &v6;
            }
            conds.push_back(c);
        }
        auto addPort = [&](const std::optional<PortRange>& pr, const GUID& field, FWP_RANGE0& range) {
            if (!pr) return;
            FWPM_FILTER_CONDITION0 c{};
            c.fieldKey = field;
            if (pr->first == pr->last) {
                c.matchType = FWP_MATCH_EQUAL;
                c.conditionValue.type = FWP_UINT16;
                c.conditionValue.uint16 = pr->first;
            } else {
                range.valueLow.type = FWP_UINT16;
                range.valueLow.uint16 = pr->first;
                range.valueHigh.type = FWP_UINT16;
                range.valueHigh.uint16 = pr->last;
                c.matchType = FWP_MATCH_RANGE;
                c.conditionValue.type = FWP_RANGE_TYPE;
                c.conditionValue.rangeValue = &range;
            }
            conds.push_back(c);
        };
        addPort(rule.remotePort, FWPM_CONDITION_IP_REMOTE_PORT, rRange);
        addPort(rule.localPort, FWPM_CONDITION_IP_LOCAL_PORT, lRange);
        if (appId.p) {
            FWPM_FILTER_CONDITION0 c{};
            c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_BYTE_BLOB_TYPE;
            c.conditionValue.byteBlob = appId.p;
            conds.push_back(c);
        }

        FWPM_FILTER0 f{};
        f.displayData.name = const_cast<wchar_t*>(rule.name.c_str());
        f.displayData.description = const_cast<wchar_t*>(rule.description.c_str());
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        f.providerKey = const_cast<GUID*>(&kProviderKey);
        f.layerKey = layer;
        f.subLayerKey = kSublayerKey;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = rule.weight;
        f.action.type = rule.action == Verdict::Allow ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
        f.numFilterConditions = static_cast<UINT32>(conds.size());
        f.filterCondition = conds.empty() ? nullptr : conds.data();

        UINT64 id = 0;
        check(FwpmFilterAdd0(engine_, &f, nullptr, &id), "FwpmFilterAdd0");
        ids.push_back(id);
    }
    tx.commit();
    spdlog::info("WFP: la til {} filter(e) for '{}'", ids.size(), win::toUtf8(rule.name));
    return ids;
}

void WfpManager::removeFilter(std::uint64_t id) { check(FwpmFilterDeleteById0(engine_, id), "FwpmFilterDeleteById0"); }

std::vector<WfpFilterInfo> WfpManager::listFilters() const {
    std::vector<WfpFilterInfo> out;
    const std::array<GUID, 4> layers{FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                     FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    for (const GUID& layer : layers) {
        FWPM_FILTER_ENUM_TEMPLATE0 tmpl{};
        tmpl.providerKey = const_cast<GUID*>(&kProviderKey);
        tmpl.layerKey = layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFFFFFF;
        HANDLE enumHandle = nullptr;
        check(FwpmFilterCreateEnumHandle0(engine_, &tmpl, &enumHandle), "FwpmFilterCreateEnumHandle0");
        for (;;) {
            WfpMem<FWPM_FILTER0*> entries;
            UINT32 n = 0;
            const DWORD rc = FwpmFilterEnum0(engine_, enumHandle, 256, &entries.p, &n);
            if (rc != ERROR_SUCCESS) {
                FwpmFilterDestroyEnumHandle0(engine_, enumHandle);
                check(rc, "FwpmFilterEnum0");
            }
            for (UINT32 i = 0; i < n; ++i) {
                const FWPM_FILTER0* f = entries.p[i];
                out.push_back({f->filterId, f->displayData.name ? f->displayData.name : L"", f->layerKey});
            }
            if (n < 256) break;
        }
        FwpmFilterDestroyEnumHandle0(engine_, enumHandle);
    }
    return out;
}

std::size_t WfpManager::removeAllFilters() {
    const auto filters = listFilters();
    Transaction tx(engine_);
    for (const auto& f : filters) check(FwpmFilterDeleteById0(engine_, f.id), "FwpmFilterDeleteById0");
    tx.commit();
    return filters.size();
}

std::size_t WfpManager::syncPersistentRules(const std::vector<Rule>& rules) {
    const auto removed = removeAllFilters();
    std::size_t added = 0;
    for (const auto& r : rules) {
        if (!r.persistent || !r.enabled) continue;
        std::string why;
        const auto wfpRules = WfpRule::fromRule(r, &why);
        if (wfpRules.empty()) {
            spdlog::warn("Regel '{}' kan ikke legges i WFP: {}", r.id, why);
            continue;
        }
        for (const auto& w : wfpRules) added += addRule(w).size();
    }
    spdlog::info("WFP synkronisert: {} gamle filtre fjernet, {} nye lagt til", removed, added);
    return added;
}

}  // namespace aifw
#endif  // _WIN32
