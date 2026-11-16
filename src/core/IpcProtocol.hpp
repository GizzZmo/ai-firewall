// IPC-protokoll mellom tjenesten og GUI: newline-separerte JSON-meldinger (JSON Lines)
// over named pipe \\.\pipe\<pipe_name>. Portabel kode (ingen Win32) slik at den kan testes.
//
// GUI -> tjeneste:  {"cmd":"get_status"} | {"cmd":"set_learning","enabled":true}
//                   {"cmd":"get_suggestions"} | {"cmd":"apply_suggestions"}
//                   {"cmd":"reload_rules"} | {"cmd":"get_events"} | {"cmd":"ping"}
// Tjeneste -> GUI:  {"type":"reply","cmd":...,"ok":true,...}
//                   {"type":"event","event":{...}}   (push ved blokkering o.l.)
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace aifw::ipc {

inline constexpr std::size_t kMaxMessageBytes = 64 * 1024;
inline constexpr int kProtocolVersion = 1;

/// Kommandoer som endrer tilstand og derfor krever administrator-klient.
bool isMutatingCommand(std::string_view cmd) noexcept;

std::string encode(const nlohmann::json& msg);  // legger til '\n'

/// Inkrementell dekoder: tål vilkårlig oppdelte lesinger fra pipen.
class LineDecoder {
public:
    /// Mater inn rå bytes; returnerer ferdige, gyldige meldinger. Ugyldig JSON
    /// eller for lange linjer forkastes og telles (beskytter mot ondsinnede klienter).
    std::vector<nlohmann::json> feed(std::string_view bytes);
    [[nodiscard]] std::size_t rejected() const noexcept { return rejected_; }

private:
    std::string buffer_;
    bool discarding_{false};
    std::size_t rejected_{0};
};

nlohmann::json makeReply(std::string_view cmd, bool ok, nlohmann::json body = nlohmann::json::object());
nlohmann::json makeError(std::string_view cmd, std::string_view message);

}  // namespace aifw::ipc
