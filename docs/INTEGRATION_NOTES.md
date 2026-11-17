# Integrasjonsnotater

## DNS i hendelser

`FirewallEvent` kan utvides med `remoteHost`. Anbefalt mønster:

```cpp
// I DecisionCoordinator::enrichEvent eller Notifier
aifw::DnsResolver dns;
auto host = dns.reverseLookup(dstIp);
if (host) {
    event.message += " (" + *host + ")";
}
```

Kjør oppslaget **etter** at pakken er reinjisert, eller i en egen tråd.

## App-prompt via IPC

Ny meldingstype for GUI:

```json
{"type": "app_prompt", "app": "C:\\Program Files\\chrome.exe", "name": "chrome.exe", "suggested": "allow"}
```

GUI svarer:

```json
{"cmd": "app_prompt_reply", "app": "...", "allowed": true, "remember": true}
```

Se `src/core/FirewallEventExt.hpp`.

## Fuzzing

Oppdatert fuzzer håndterer:
- IPv4 + TCP/UDP
- IPv6 med enkel extension header-walk

```bash
clang++ -fsanitize=fuzzer,address,undefined -std=c++20 \
    fuzz/packet_parser_fuzzer.cpp -o fuzzer
mkdir -p corpus && ./fuzzer corpus/ -max_len=1500
```
