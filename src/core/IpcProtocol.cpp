#include "IpcProtocol.hpp"

#include <array>

namespace aifw::ipc {

bool isMutatingCommand(std::string_view cmd) noexcept {
    constexpr std::array<std::string_view, 3> mutating{"set_learning", "apply_suggestions", "reload_rules"};
    for (auto m : mutating)
        if (m == cmd) return true;
    return false;
}

std::string encode(const nlohmann::json& msg) {
    std::string s = msg.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    s.push_back('\n');
    return s;
}

std::vector<nlohmann::json> LineDecoder::feed(std::string_view bytes) {
    std::vector<nlohmann::json> out;
    for (char c : bytes) {
        if (c == '\n') {
            if (!discarding_ && !buffer_.empty()) {
                auto j = nlohmann::json::parse(buffer_, nullptr, /*allow_exceptions=*/false);
                if (j.is_discarded() || !j.is_object()) ++rejected_;
                else out.push_back(std::move(j));
            }
            buffer_.clear();
            discarding_ = false;
            continue;
        }
        if (discarding_) continue;
        if (c == '\r') continue;
        buffer_.push_back(c);
        if (buffer_.size() > kMaxMessageBytes) {
            buffer_.clear();
            discarding_ = true;
            ++rejected_;
        }
    }
    return out;
}

nlohmann::json makeReply(std::string_view cmd, bool ok, nlohmann::json body) {
    body["type"] = "reply";
    body["cmd"] = cmd;
    body["ok"] = ok;
    body["v"] = kProtocolVersion;
    return body;
}

nlohmann::json makeError(std::string_view cmd, std::string_view message) {
    return makeReply(cmd, false, {{"error", message}});
}

}  // namespace aifw::ipc
