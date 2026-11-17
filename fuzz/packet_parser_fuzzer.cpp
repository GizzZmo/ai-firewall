// libFuzzer-target for pakkeparseren.
// Bygg: clang++ -fsanitize=fuzzer,address -I../src/core packet_parser_fuzzer.cpp ...
// Kjør: ./packet_parser_fuzzer corpus/

#include <cstddef>
#include <cstdint>
#include <vector>

// Inkluder parser-headerne dine her
// #include "FeatureExtractor.hpp"
// #include "Types.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 20 || size > 65535) return 0;

    // Eksempel: prøv å parse som IPv4/IPv6-pakke
    // aifw::PacketInfo pkt;
    // pkt.data.assign(data, data + size);
    // aifw::FeatureExtractor fx;
    // fx.extract(pkt);   // skal ikke krasje

    // Minimal sjekk som alltid kjører
    volatile uint8_t version = data[0] >> 4;
    if (version == 4 && size >= 20) {
        uint8_t ihl = (data[0] & 0x0F) * 4;
        if (ihl >= 20 && size >= ihl) {
            // gyldig nok til å fortsette
            (void)ihl;
        }
    } else if (version == 6 && size >= 40) {
        // IPv6
        (void)data[6]; // next header
    }

    return 0;
}
