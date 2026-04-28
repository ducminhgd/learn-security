---
title: "Infrastructure Practice Day 4 — Linux PrivEsc HTB Machine (Medium)"
tags: [practice, linux, privilege-escalation, HTB, medium, kernel, capabilities,
       path-injection, T1548, T1068, ATT&CK, hands-on]
module: 04-BroadSurface-04
day: 248
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Kernel Exploits (Day 237)
  - Infrastructure Practice Day 3 (Day 247)
  - Infrastructure Practice Day 5 (Day 249)
---

# Day 248 — Infrastructure Practice Day 4: Linux PrivEsc HTB Machine (Medium)

> "Medium machines do not hand you a single clean path. They hand you five
> paths and four dead ends. The skill being tested is not: can you execute the
> exploit? It is: can you identify the right path without wasting an hour on
> the wrong ones?"
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Rooted a Medium-rated Linux HackTheBox machine.
2. Identified and discarded at least two dead-end escalation paths before
   finding the correct one.
3. Documented the escalation chain with the specific misconfigurations involved.
4. Estimated what a competent defender would need to detect your path.

**Time budget:** 6–8 hours.

---

## Target Selection

Recommended HTB Medium Linux machines (retired):

| Machine | Key technique | Challenge type |
|---|---|---|
| **Cronos** | SQL injection → cron injection | Multiple vulnerabilities required |
| **Valentine** | Heartbleed + SSH key → sudo | CVE + credential pivoting |
| **Scriptkiddie** | Command injection → user pivot + cron | Path from low to medium to high |
| **Paper** | WordPress CVE + path traversal + polkit | Multi-step exploitation |
| **Traceback** | Web shell + Lua sudo + SSH backdoor | Creative enumeration required |

---

## Structured Approach

### Phase 1 — Initial Access

Document before moving on:
- What service was vulnerable?
- What CVE or technique did you use?
- What user did you land as?
- What are the first 3 things you check?

### Phase 2 — Enumeration with Priority

The medium difficulty usually means the obvious checks return nothing. Work
down the full enumeration checklist methodically:

```
[ ] id, groups — any interesting group membership?
[ ] sudo -l — any NOPASSWD? Any unusual commands?
[ ] find / -perm -4000 2>/dev/null — any non-standard SUID?
[ ] getcap -r / 2>/dev/null — any dangerous capabilities?
[ ] /tmp/pspy (run for 3+ minutes) — any root cron jobs?
[ ] find / -writable -not -path "*/proc/*" 2>/dev/null — any writable sensitive locations?
[ ] cat ~/.bash_history — any credentials?
[ ] find / -name "*.conf" -readable 2>/dev/null — any creds in config?
[ ] netstat / ss — any local services not exposed externally?
[ ] uname -a — kernel version, any public exploits?
```

### Phase 3 — Dead End Documentation

For each escalation path you attempted that did not work:

```
Path attempted: ___
Reason it failed: ___
Time wasted: ___ min
```

This is not failure — it is data. Track which checks produce dead ends so
you calibrate which to deprioritise in future engagements.

### Phase 4 — Successful Escalation

```
[ ] Correct path identified: ___
[ ] Root obtained
[ ] root.txt: ___
[ ] Time from foothold to root: ___ min
```

---

## Post-Mortem

```
Machine: ___
Escalation path (specific misconfiguration): ___
Dead ends explored: ___ (list them)
Total time foothold → root: ___ min

If I had done this engagement again with what I know now:
  I would have skipped: ___
  I would have checked first: ___

The one thing this machine taught me: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q248.1, Q248.2 …).

---

## Navigation

← Previous: [Day 247 — Infrastructure Practice Day 3](DAY-0247-Infrastructure-Practice-Day-3.md)
→ Next: [Day 249 — Infrastructure Practice Day 5](DAY-0249-Infrastructure-Practice-Day-5.md)
