// Bygger avvisningspakker som WinDivert injiserer når en flyt blokkeres.
// Rå nettverks-byte-rekkefølge, med korrekte sjekksummer. Ingen WinDivert-avhengighet,
// slik at Linux-tester kan dumpe og verifisere pakkene.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "Types.hpp"

namespace aifw {

/// TCP RST tilbake til avsenderen (RFC 793 §3.4).
/// Har originalen ACK: seq = ack, bare RST. Ellers: seq = 0, ACK = seq + lengde (SYN/FIN teller som 1).
[[nodiscard]] std::optional<std::vector<std::uint8_t>> buildTcpRst(const PacketInfo& info);

/// UDP «port unreachable»: ICMP type 3/kode 3 (IPv4) eller ICMPv6 type 1/kode 4.
/// `original` er den avskårne pakken som siteres i ICMP-kroppen.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> buildPortUnreachable(
    const PacketInfo& info, std::span<const std::uint8_t> original);

}  // namespace aifw
