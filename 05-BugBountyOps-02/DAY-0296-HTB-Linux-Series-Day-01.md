---
title: "HTB Linux Series Day 1 — Easy Linux Box: Enumeration and Basic PrivEsc"
tags: [HTB, HackTheBox, CTF, Linux, privilege-escalation, enumeration, practice,
       methodology, SUID, sudo]
module: 05-BugBountyOps-02
day: 296
related_topics:
  - HTB Web Series Day 5 (Day 295)
  - Linux PrivEsc Enumeration (Day 234)
  - Linux PrivEsc Lab SUID Sudo (Day 235)
---

# Day 296 — HTB Linux Series Day 1: Easy Linux Box

> "Linux privilege escalation in a bug bounty context means: you found RCE
> as www-data. Now what? Understanding PrivEsc end-to-end makes your findings
> more credible and your impact assessments more accurate. A P2 RCE where
> you can demonstrate root access in the PoC is more compelling than a P2
> with a reverse shell that lands as a low-privilege user."
>
> — Ghost

---

## Goals

Complete an Easy-rated HTB Linux machine from initial foothold to root.

**Time budget:** 3–4 hours.

---

## Pre-Engagement Plan

```
Machine selected: ___
My approach (write before starting):
  Initial foothold vector: ___
  Expected PrivEsc path: ___
```

---

## Engagement Log

### Initial Foothold

```
Service exploited: ___
Vulnerability: ___
Landing as: www-data / user: ___
```

### Enumeration

```
LinPEAS run: Y/N
Key findings:
  SUID binaries: ___
  Sudo entries: ___
  Cron jobs: ___
  Interesting files: ___
  Running services: ___
```

### Privilege Escalation

```
Path chosen: ___
Exploit steps:
  1. ___
  2. ___
Root obtained: Y/N
```

### Flags

```
user.txt: ___
root.txt: ___
Total time: ___ min
```

---

## Debrief

```
PrivEsc path found quickly or after 30+ min? ___
One check I missed that I should have run first: ___
Reference card update (add to Day 259 Card 1): ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q296.1, Q296.2 …).

---

## Navigation

← Previous: [Day 295 — HTB Web Series Day 5](DAY-0295-HTB-Web-Series-Day-05.md)
→ Next: [Day 297 — HTB Linux Series Day 2](DAY-0297-HTB-Linux-Series-Day-02.md)
