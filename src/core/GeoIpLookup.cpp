#include "GeoIpLookup.hpp"

#include <cstring>

#include <spdlog/spdlog.h>

#ifdef AIFW_WITH_GEOIP
#include <maxminddb.h>
#endif

namespace aifw {

#ifdef AIFW_WITH_GEOIP

struct GeoIpLookup::Impl {
    MMDB_s mmdb{};
    bool open{false};

    Impl() = default;
    ~Impl() {
        if (open) MMDB_close(&mmdb);
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
};

GeoIpLookup::GeoIpLookup(const std::string& mmdbPath) : impl_(new Impl) {
    if (mmdbPath.empty()) return;
    int status = MMDB_open(mmdbPath.c_str(), MMDB_MODE_MMAP, &impl_->mmdb);
    if (status != MMDB_SUCCESS) {
        spdlog::warn("GeoIP: kunne ikke åpne {}: {}", mmdbPath, MMDB_strerror(status));
        return;
    }
    impl_->open = true;
    available_ = true;
    spdlog::info("GeoIP: lastet {}", mmdbPath);
}

GeoIpLookup::~GeoIpLookup() { delete impl_; }

GeoIpLookup::GeoIpLookup(GeoIpLookup&& other) noexcept
    : impl_(other.impl_), available_(other.available_) {
    other.impl_ = nullptr;
    other.available_ = false;
}

GeoIpLookup& GeoIpLookup::operator=(GeoIpLookup&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        available_ = other.available_;
        other.impl_ = nullptr;
        other.available_ = false;
    }
    return *this;
}

std::string GeoIpLookup::country(const IpAddress& ip) const {
    if (!available_ || !impl_ || !impl_->open || !ip.isValid()) return {};

    int mmdb_error = 0;
    MMDB_lookup_result_s result{};
    if (ip.version == 4) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        std::memcpy(&sa.sin_addr, ip.bytes.data(), 4);
        result = MMDB_lookup_sockaddr(&impl_->mmdb, reinterpret_cast<const sockaddr*>(&sa), &mmdb_error);
    } else {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        std::memcpy(&sa.sin6_addr, ip.bytes.data(), 16);
        result = MMDB_lookup_sockaddr(&impl_->mmdb, reinterpret_cast<const sockaddr*>(&sa), &mmdb_error);
    }

    if (mmdb_error != MMDB_SUCCESS || !result.found_entry) return {};

    MMDB_entry_data_s entry{};
    int status = MMDB_get_value(&result.entry, &entry, "country", "iso_code", nullptr);
    if (status != MMDB_SUCCESS || !entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) return {};

    return std::string(entry.utf8_string, entry.data_size);
}

#else  // !AIFW_WITH_GEOIP

struct GeoIpLookup::Impl {};

GeoIpLookup::GeoIpLookup(const std::string&) {}
GeoIpLookup::~GeoIpLookup() = default;
GeoIpLookup::GeoIpLookup(GeoIpLookup&& other) noexcept : impl_(other.impl_), available_(other.available_) {
    other.impl_ = nullptr;
    other.available_ = false;
}
GeoIpLookup& GeoIpLookup::operator=(GeoIpLookup&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        available_ = other.available_;
        other.impl_ = nullptr;
        other.available_ = false;
    }
    return *this;
}

std::string GeoIpLookup::country(const IpAddress&) const { return {}; }

#endif

}  // namespace aifw
