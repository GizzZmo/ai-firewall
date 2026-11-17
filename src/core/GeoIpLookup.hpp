// Valgfri GeoIP-oppslag med MaxMind GeoLite2 (libmaxminddb).
// Hvis databasen ikke er tilgjengelig eller AIFW_WITH_GEOIP er av, returnerer alle oppslag tom streng.
#pragma once

#include <string>
#include <string_view>

#include "Types.hpp"

namespace aifw {

class GeoIpLookup {
public:
    GeoIpLookup() = default;
    explicit GeoIpLookup(const std::string& mmdbPath);
    ~GeoIpLookup();

    GeoIpLookup(const GeoIpLookup&) = delete;
    GeoIpLookup& operator=(const GeoIpLookup&) = delete;
    GeoIpLookup(GeoIpLookup&&) noexcept;
    GeoIpLookup& operator=(GeoIpLookup&&) noexcept;

    /// Returnerer ISO-landkode (f.eks. "NO", "US") eller tom streng hvis ukjent / ikke tilgjengelig.
    [[nodiscard]] std::string country(const IpAddress& ip) const;

    [[nodiscard]] bool available() const noexcept { return available_; }

private:
    struct Impl;
    Impl* impl_{nullptr};
    bool available_{false};
};

}  // namespace aifw
