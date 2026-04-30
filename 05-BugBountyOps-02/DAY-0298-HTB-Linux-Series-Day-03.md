---
title: "HTB Linux Series Day 3 — Hard Linux Box: CVE-Based Initial Access"
tags: [HTB, HackTheBox, CTF, Linux, CVE, exploit-development, privilege-escalation,
       hard, practice, methodology]
module: 05-BugBountyOps-02
day: 298
related_topics:
  - HTB Linux Series Day 2 (Day 297)
  - Kernel Exploits Linux (Day 237)
  - CVE Reproduction from Patch Diff (Day 457)
---

# Day 298 — HTB Linux Series Day 3: Hard Linux Box (CVE-Based Initial Access)

> "Hard boxes test whether you can reproduce a known exploit without being
> spoon-fed. You have the CVE identifier. Now find the vulnerable service,
> find the matching exploit, adapt it to the target, and get a shell.
> This is the bug bounty researcher's workflow when a new CVE drops and
> they want to be the first to test it on a live programme."
>
> — Ghost

---

## Goals

Complete a Hard HTB Linux machine where initial access requires CVE exploitation.

**Time budget:** 5–6 hours.

---

## Pre-Engagement Plan

```
Machine: ___
Nmap initial scan strategy: ___
Expected initial access vector: ___
```

---

## Engagement Log

### Service Discovery

```
Open ports: ___
Services: ___
Version information: ___
```

### CVE Research

```
Vulnerable service/version: ___
CVE identified: ___
CVE description: ___
Exploit source: searchsploit / GitHub / ExploitDB
```

### Exploit Adaptation

```
Did the exploit work out of the box? Y/N
Modifications needed: ___
```

### Post-Exploitation

```
Landing user: ___
PrivEsc path: ___
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
What is the CVE number and vulnerability class?
___

How would you detect exploitation of this CVE in a SIEM?
___

What version patch resolved this?
___

Is this CVE a common finding in bug bounty? Why or why not?
___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q298.1, Q298.2 …).

---

## Navigation

← Previous: [Day 297 — HTB Linux Series Day 2](DAY-0297-HTB-Linux-Series-Day-02.md)
→ Next: [Day 299 — HTB Linux Series Day 4](DAY-0299-HTB-Linux-Series-Day-04.md)
