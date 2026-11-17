# ACL-replikering i Windows

## 1. Active Directory – Security Descriptor-replikering

Hvert AD-objekt har en **security descriptor** lagret i attributtet `nTSecurityDescriptor`.

### Hva som replikeres
- Hele security descriptoren (owner, DACL, SACL) følger objektet
- Endringer i ACL-er replikeres som vanlige attributtendringer (multimaster)
- Tombstones beholder `nTSecurityDescriptor` (slik at objekter kan reanimeres med riktige rettigheter)

### SDProp (Security Descriptor Propagation)
- Bakgrunnsprosess som **gjenoppretter** ACL-er på beskyttede objekter
- Bruker `AdminSDHolder` som mal
- Kjører periodisk (standard hver time)
- Hindrer at noen permanent endrer ACL på Domain Admins, Enterprise Admins, osv.

### Farlige rettigheter (relevant for brannmur/sikkerhet)
| Rettighet | Risiko |
|-----------|--------|
| GenericAll | Full kontroll |
| WriteDACL | Kan gi seg selv alle rettigheter |
| WriteOwner | Kan ta eierskap |
| DS-Replication-Get-Changes-All | DCSync – hente passordhasher |

## 2. DFS Replication – NTFS ACL-replikering

DFS Replication (DFSR) replikerer **filer og deres NTFS-rettigheter**.

### Hvordan det virker
- Når ACL endres på en fil, replikeres bare ACL-delen (ikke hele filen)
- Med RDC (Remote Differential Compression) overføres bare endringen
- Staging-området må likevel lese hele filen

### Viktige merknader
- **Ikke** sett Group Policy file system policies på replikerte mapper – de overskriver ACL-er ved hver refresh
- Endring av ACL på mange filer kan belaste replikering
- Pre-seeding med `robocopy /COPYALL` bevarer ACL-er ved første synk

### Best practices
```powershell
# Pre-seed med ACL-er
robocopy \\source\share D:\target /COPYALL /MIR /R:2 /W:2 /MT

# Sjekk backlog
Get-DfsrBacklog -GroupName "RG-Files" -FolderName "Shared"
```

## 3. Relevans for AI-Firewall

Hvis brannmuren skal distribuere konfigurasjon eller regler på tvers av flere maskiner:

| Metode | ACL-håndtering | Anbefaling |
|--------|------------------|------------|
| DFS-R | Replikerer NTFS ACL automatisk | Bra for config-filer |
| AD (GPO) | Kan distribuere regler via Group Policy | For persistente WFP-regler |
| Manuell kopi | Må sette ACL eksplisitt | Unngå for produksjon |

### Anbefalt ACL for config-mappe
```powershell
# Bare SYSTEM og Administrators får skrive
icacls C:\ProgramData\AiFirewall /inheritance:r
icacls C:\ProgramData\AiFirewall /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
icacls C:\ProgramData\AiFirewall /grant:r "Users:(OI)(CI)RX"
```

## Referanser
- [Security Descriptor Propagation (SDProp)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [DFS Replication FAQ](https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-faq)
- [How Security Descriptors and ACLs Work](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
