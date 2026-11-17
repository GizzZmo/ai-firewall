// libFuzzer-target for pakkeparseren.
// Bygg: clang++ -fsanitize=fuzzer,address,undefined -std=c++20 \
//       -I../src/core packet_parser_fuzzer.cpp -o fuzzer
// Kjør: ./fuzzer corpus/ -max_len=1500 -timeout=5

#include <cstddef>
#include <cstdint>
#include <cstring>

// Minimal parser som etterligner FeatureExtractor-logikken
// (uten avhengigheter – for ren fuzzing)

namespace {

bool looksLikeIpv4(const uint8_t* data, size_t size) {
    if (size < 20) return false;
    if ((data[0] >> 4) != 4) return false;
    uint8_t ihl = (data[0] & 0x0F) * 4;
    if (ihl < 20 || size < ihl) return false;
    return true;
}

bool looksLikeIpv6(const uint8_t* data, size_t size) {
    if (size < 40) return false;
    if ((data[0] >> 4) != 6) return false;
    return true;
}

void parseTcp(const uint8_t* tcp, size_t len) {
    if (len < 20) return;
    uint8_t dataOff = (tcp[12] >> 4) * 4;
    if (dataOff < 20 || len < dataOff) return;
    // flags
    volatile uint8_t flags = tcp[13];
    (void)flags;
    // seq/ack
    volatile uint32_t seq = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
    (void)seq;
}

void parseUdp(const uint8_t* udp, size_t len) {
    if (len < 8) return;
    volatile uint16_t src = (udp[0] << 8) | udp[1];
    volatile uint16_t dst = (udp[2] << 8) | udp[3];
    (void)src; (void)dst;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 20 || size > 65535) return 0;

    if (looksLikeIpv4(data, size)) {
        uint8_t ihl = (data[0] & 0x0F) * 4;
        uint8_t proto = data[9];
        const uint8_t* payload = data + ihl;
        size_t payloadLen = size - ihl;

        if (proto == 6) {          // TCP
            parseTcp(payload, payloadLen);
        } else if (proto == 17) {  // UDP
            parseUdp(payload, payloadLen);
        }
    } else if (looksLikeIpv6(data, size)) {
        uint8_t next = data[6];
        const uint8_t* payload = data + 40;
        size_t payloadLen = size - 40;

        // Enkel extension header-walk (maks 8 hopp)
        for (int i = 0; i < 8 && payloadLen > 0; ++i) {
            if (next == 6) {
                parseTcp(payload, payloadLen);
                break;
            } else if (next == 17) {
                parseUdp(payload, payloadLen);
                break;
            } else if (next == 0 || next == 43 || next == 60) {
                // Hop-by-Hop, Routing, Dest Options
                if (payloadLen < 2) break;
                uint8_t hdrLen = (payload[1] + 1) * 8;
                if (payloadLen < hdrLen) break;
                next = payload[0];
                payload += hdrLen;
                payloadLen -= hdrLen;
            } else {
                break;
            }
        }
    }

    return 0;
}
