---
title: "HTB Web Series Day 1 — SQL Injection Focus"
tags: [HTB, HackTheBox, CTF, web, SQL-injection, practice, methodology, bug-bounty]
module: 05-BugBountyOps-02
day: 291
related_topics:
  - BugBountyOps-1 Competency Check (Day 290)
  - SQL Injection Fundamentals (Day 076)
  - SQLi Lab Manual Exploitation (Day 077)
  - Blind SQLi and sqlmap (Day 078)
---

# Day 291 — HTB Web Series Day 1: SQL Injection Focus

> "CTF is compressed practice. In a CTF, someone designed the vulnerability
> and hid the flag to make you work for it. That constraint forces precision.
> When you can exploit a CTF SQLi in 20 minutes, exploiting a real SQLi
> becomes methodical, not uncertain."
>
> — Ghost

---

## Goals

Complete one HackTheBox web machine with a primary SQLi component.
Debrief the technique and connect it to real bug bounty contexts.

**Time budget:** 4–5 hours.

---

## Pre-Engagement Plan

Before starting the machine, write your approach:

```
Recommended machine: Choose from HTB web challenges with "SQL Injection" tag
  (e.g., "Templated", "Injection", "Toxic", "BabySQL" — check current availability)

My hypothesis for this machine type:
  Primary surface: ___
  Entry point I will check first: ___
  SQLi variant I expect to encounter: error-based / blind / time-based / UNION

Tools I will use:
  Manual testing: Burp Suite Repeater
  Automated: sqlmap (after manual confirmation)
  Wordlists: ___
```

---

## Engagement Log

### Phase 1 — Recon and Application Understanding

```
Machine name/URL: ___
Application type: ___
Login present: Y/N
Input fields found: ___
```

### Phase 2 — Vulnerability Discovery

```
First indicator of SQLi: ___
Parameter vulnerable: ___
Database type (from errors/behaviour): ___
SQLi type: ___
```

### Phase 3 — Exploitation

```
Payload used for detection: ___
UNION/Blind/Time method chosen: ___
Data extracted:
  - Databases: ___
  - Tables: ___
  - Flag: ___
```

### Phase 4 — Flag

```
FLAG{___}
Time to flag: ___ minutes
```

---

## Debrief — Real World Connection

```
1. What type of application would have this vulnerability in production?
   ___

2. What would the vulnerable line of code look like?
   ___

3. What log entry would indicate this attack in a SIEM?
   ___

4. One line fix:
   ___

5. Would this qualify for a bug bounty? What severity? Why?
   ___
```

---

## Technique Reinforcement

Write these from memory (no references):

```bash
# 1. Basic SQLi error-based detection:
___

# 2. UNION-based column count detection:
___

# 3. Extract database name (MySQL):
___

# 4. Minimal sqlmap command to dump a specific table:
___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q291.1, Q291.2 …).

---

## Navigation

← Previous: [Day 290 — BugBountyOps-1 Competency Check](../05-BugBountyOps-01/DAY-0290-BugBountyOps-1-Check.md)
→ Next: [Day 292 — HTB Web Series Day 2](DAY-0292-HTB-Web-Series-Day-02.md)
