# Fremdrift på veikartet

## 1. DNS-integrasjon
`DnsResolver` er klar. For å koble den inn i `DecisionCoordinator`:

```cpp
// I DecisionCoordinator (eller Notifier)
aifw::DnsResolver dns;
// ...
auto name = dns.reverseLookup(key.dstIp);
if (name) {
    event.remoteHost = *name;
}
```

Anbefaling: kjør oppslaget i en bakgrunnstråd eller etter at pakken er reinjisert.

## 2. Per-app-statistikk + «spør brukeren»
`AppStats` tracker pakker/bytes per exe-sti.

```cpp
aifw::AppStats appStats;
appStats.record(processPath, allowed, packetSize, nowMs);

if (appStats.shouldPrompt(processPath)) {
    // Send IPC-melding til GUI: "Ny app: chrome.exe – tillat?"
    // GUI svarer → appStats.markPrompted(processPath, userSaidYes);
}
```

## 3. Fuzzing
Se `fuzz/packet_parser_fuzzer.cpp`.

```bash
clang++ -fsanitize=fuzzer,address,undefined -I src/core \
    fuzz/packet_parser_fuzzer.cpp src/core/FeatureExtractor.cpp -o fuzzer
./fuzzer corpus/ -max_len=1500
```

## 4. Gruppe-basert tilgang
`AccessControl` sjekker om gjeldende bruker får utføre GUI-kommandoer.

```cpp
aifw::AccessControl acl;
acl.allowGroup("AiFirewallUsers");
acl.setRequireAdmin(false);

if (acl.isAllowed(aifw::GuiCommand::ToggleLearning)) {
    // tillat
}
```

På Windows brukes `CheckTokenMembership` for Administrators.
Utvid `currentUserInGroup` med `LookupAccountName` for egendefinerte grupper.
