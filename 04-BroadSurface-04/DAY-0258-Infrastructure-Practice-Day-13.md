---
title: "Infrastructure Practice Day 13 — Mixed Windows and Linux CTF Sprint"
tags: [practice, CTF, Windows, Linux, mixed, HackTheBox, TryHackMe,
       privilege-escalation, speed, methodology, ATT&CK]
module: 04-BroadSurface-04
day: 258
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Windows PrivEsc Enumeration (Day 238)
  - Infrastructure Practice Day 12 (Day 257)
  - Module Review and Gate Preparation (Day 259)
---

# Day 258 — Infrastructure Practice Day 13: Mixed CTF Sprint

> "You do not get to choose the OS on a real engagement. You walk in and
> whatever is there is what you deal with. Today you do two machines —
> one Windows, one Linux — back to back. Different techniques, same
> methodology. The methodology is the constant."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Completed one Windows HTB machine (Easy or Medium) root to SYSTEM.
2. Completed one Linux HTB machine (Easy or Medium) to root.
3. Applied the same enumeration methodology to both operating systems.
4. Written a combined timing log for both machines.

**Time budget:** 8 hours (4 per machine).

---

## Machine Selection

### Windows Machine

Choose from retired Easy/Medium:

| Machine | Primary Technique |
|---|---|
| Blue | EternalBlue (MS17-010) |
| Devel | FTP upload + impersonation |
| Grandpa / Granny | IIS WebDAV + token impersonation |
| Bastard | Drupal RCE + token escalation |
| Bounty | Upload bypass + potato |

### Linux Machine

Choose from retired Easy/Medium (different from Days 247–248):

| Machine | Primary Technique |
|---|---|
| Sense | pfSense CVE + sudo |
| SolidState | JAMES mail server + rbash escape |
| Popcorn | File upload + dirty cow |
| Legacy | MS08-067 (Linux + Wine — different challenge) |
| Mirai | Default creds + USB drive forensics |

---

## Structured Sprint

### Windows Machine

```
Nmap started: T+0:00
Services identified: ___
Initial foothold at: T+___ (technique: ___)
User shell as: ___
Enumeration complete: T+___ (top 3 findings: ___)
SYSTEM obtained at: T+___
Total time: ___ min
```

Key technique used:

```
Path: ___
Detection artefact: ___
```

### Linux Machine (start immediately after Windows machine)

```
Nmap started: T+0:00 (reset timer)
Services identified: ___
Initial foothold at: T+___ (technique: ___)
User shell as: ___
Enumeration complete: T+___ (top 3 findings: ___)
Root obtained at: T+___
Total time: ___ min
```

Key technique used:

```
Path: ___
Detection artefact: ___
```

---

## Comparative Analysis

```
Did the same enumeration methodology work on both OS? ___

What is different about Linux PrivEsc vs Windows PrivEsc enumeration? ___

On which machine did you spend more time in enumeration vs exploitation? ___

What technique appeared on both machines (if any)? ___
```

---

## Combined Timing

| Activity | Windows | Linux |
|---|---|---|
| Initial recon | ___ | ___ |
| Foothold | ___ | ___ |
| Enumeration | ___ | ___ |
| PrivEsc execution | ___ | ___ |
| Total | ___ | ___ |

---

## Questions

> Add your questions here. Each question gets a Global ID (Q258.1, Q258.2 …).

---

## Navigation

← Previous: [Day 257 — Infrastructure Practice Day 12](DAY-0257-Infrastructure-Practice-Day-12.md)
→ Next: [Day 259 — Module Review and Gate Preparation](DAY-0259-Infrastructure-Practice-Day-14.md)
