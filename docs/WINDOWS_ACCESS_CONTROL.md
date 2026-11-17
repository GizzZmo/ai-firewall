# Windows Access Control – for AI-Firewall

## Grunnleggende konsepter

### Access Token
Når en bruker logger på, lager LSA et **access token** som inneholder:
- **User SID** – brukerens identitet
- **Group SIDs** – alle grupper brukeren er medlem av
- **Privileges** – rettigheter (SeDebugPrivilege, SeLoadDriverPrivilege, osv.)

Tokenet er det som brukes ved alle tilgangssjekker.

### SID (Security Identifier)
- `S-1-5-32-544` = BUILTIN\Administrators
- `S-1-5-32-545` = BUILTIN\Users
- `S-1-5-18` = LocalSystem

### SID-attributter i token
| Attributt | Betydning |
|-----------|-----------|
| `SE_GROUP_ENABLED` | SID brukes i access checks |
| `SE_GROUP_USE_FOR_DENY_ONLY` | Kun for deny-ACE (UAC-filtrert admin) |
| `SE_GROUP_MANDATORY` | Kan ikke deaktiveres |

**Viktig:** Under UAC er Administrators-gruppen ofte **deny-only** i det filtrerte tokenet. Da returnerer `CheckTokenMembership` **false** selv om brukeren er admin.

## Riktig måte å sjekke gruppemedlemskap

```cpp
// 1. Alltid bruk CheckTokenMembership (ikke bare se etter SID i listen)
BOOL isAdmin = FALSE;
PSID adminSid = nullptr;
AllocateAndInitializeSid(..., DOMAIN_ALIAS_RID_ADMINS, ..., &adminSid);
CheckTokenMembership(nullptr, adminSid, &isAdmin);
FreeSid(adminSid);

// 2. For egendefinerte grupper: LookupAccountName → SID → CheckTokenMembership
LookupAccountNameA(nullptr, "AiFirewallUsers", sidBuf, ...);
CheckTokenMembership(nullptr, sidBuf, &isMember);
```

## Hva AI-Firewall bør gjøre

1. **Tjenesten** kjører som SYSTEM (eller med høy integritet).
2. **GUI** kjører som vanlig bruker.
3. Sensitive kommandoer (persistente regler, shutdown) krever admin.
4. Andre kommandoer kan tillates for en egendefinert gruppe (`AiFirewallUsers`).

### Anbefalt oppsett
```powershell
# Opprett gruppe
net localgroup AiFirewallUsers /add
net localgroup AiFirewallUsers %USERNAME% /add
```

I kode:
```cpp
aifw::AccessControl acl;
acl.allowGroup("AiFirewallUsers");
acl.setRequireAdmin(false);

if (acl.isAllowed(aifw::GuiCommand::ToggleLearning)) {
    // tillat
}
```

## Debugging
```cpp
auto groups = acl.listCurrentGroups();
for (const auto& g : groups) {
    std::cout << g << "\n";  // viser [enabled] eller [deny-only]
}
```

## Referanser
- [CheckTokenMembership](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership)
- [SID Attributes in an Access Token](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token)
- [How Access Tokens Work](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
