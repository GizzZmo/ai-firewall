// Eier og kobler sammen alle komponenter i tjenesten. Rekkefølgen på medlemmene styrer
// destruksjon (omvendt rekkefølge): pakkemotoren stoppes før kjernen den kaller inn i.
#pragma once
#ifdef _WIN32

#include <filesystem>
#include <memory>

#include "Config.hpp"
#include "FirewallCore.hpp"
#include "PacketEngine.hpp"
#include "PipeServer.hpp"
#include "ProcessResolver.hpp"
#include "WfpManager.hpp"
#include "WfpRuleSink.hpp"

namespace aifw {

class ServiceHost {
public:
    explicit ServiceHost(std::filesystem::path baseDir);
    ~ServiceHost();
    ServiceHost(const ServiceHost&) = delete;
    ServiceHost& operator=(const ServiceHost&) = delete;

    void start();
    void stop();

private:
    std::filesystem::path baseDir_;
    Config cfg_;
    std::unique_ptr<WfpManager> wfp_;           // valgfri
    std::unique_ptr<WfpRuleSink> sink_;
    std::unique_ptr<FirewallCore> core_;
    std::unique_ptr<PipeServer> pipe_;
    std::unique_ptr<ProcessResolver> resolver_;
    std::unique_ptr<PacketEngine> engine_;      // sist: destrueres først
};

}  // namespace aifw
#endif  // _WIN32
