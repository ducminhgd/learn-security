---
title: "Gate Preparation Day 4 — Final Rest and Logistics"
tags: [gate-prep, Year-1, logistics, rest, review, final-prep]
module: 05-BugBountyOps-03
day: 364
related_topics:
  - Gate Preparation Day 3 (Day 363)
  - Bug Bounty Hunter Gate (Day 365)
---

# Day 364 — Gate Preparation Day 4: Final Rest and Logistics

> "The night before the gate, you do not cram. You rest. The knowledge is
> already there. What you need now is a clear head and a working environment.
> Set up. Check tools. Sleep."
>
> — Ghost

---

## Goals

Verify gate environment and tools. Light review only — no new material.
Prepare mentally and logistically for Day 365.

**Time budget:** 2–3 hours maximum. Anything more is counterproductive.

---

## Environment Verification Checklist

```
Lab environment:
  [ ] VPN / HTB / TryHackMe account accessible
  [ ] Target environment confirmed working (spin up test instance)
  [ ] Burp Suite licensed and configured
  [ ] Kali / Parrot / attack VM accessible and up-to-date

Tools verified working:
  [ ] subfinder     — subfinder -version
  [ ] httpx         — httpx -version
  [ ] ffuf          — ffuf -V
  [ ] nuclei        — nuclei -version
  [ ] jwt_tool      — python3 jwt_tool.py --help
  [ ] sqlmap        — sqlmap --version
  [ ] curl          — basic SSRF test to a known endpoint
  [ ] aws cli       — aws --version

Notes system:
  [ ] Obsidian / notes app open and accessible
  [ ] Report template loaded and ready
  [ ] CVSS calculator bookmarked: https://www.first.org/cvss/calculator/3.1
  [ ] CWE lookup bookmarked: https://cwe.mitre.org/

Wordlists:
  [ ] /opt/SecLists/ present
  [ ] /wordlists/api-endpoints.txt present
  [ ] jwt_tool default wordlist present
```

---

## Light Review (30 minutes max)

No drilling. Just read these lists:

```
OWASP API Top 10 (from memory — fill in blanks):
  API1: Broken Object Level Authorization (BOLA)
  API2: Broken Authentication
  API3: ___
  API4: ___
  API5: ___
  API6: ___
  API7: ___
  API8: ___
  API9: ___
  API10:___

JWT attack names:
  alg:none, alg confusion (HS256/RS256), weak secret, KID injection, JWK injection

AWS IAM escalation paths (first three that come to mind):
  ___  ___  ___
```

---

## Gate Day Format Reminder

```
Day 365 structure:
  Part 1 — Oral (30 min): Concept questions. No reference.
  Part 2 — Live target (3 hours): Unknown target. Find and exploit.
  Part 3 — Report (90 min): Write a complete report.
  Part 4 — Defensive (20 min): Detect and fix your own finding.
  Part 5 — Reflection (15 min): Answer: "What would Year-2 you do differently?"

Pass criteria:
  Part 1: ≥ 6/8 questions answered correctly
  Part 2: At least one P1–P3 finding confirmed
  Part 3: Report passes professional quality standard
  Part 4: Detection and fix technically correct
  All parts must pass — no weighted average

If any part fails: targeted remediation, then re-gate on that part only.
```

---

## Pre-Gate Mental Checklist

```
I understand the scope of what I built in Year 1: Y/N
I have demonstrated each skill at least once in a real or lab engagement: Y/N
I know what I don't know — and I have a Year 2 plan for it: Y/N
I am rested and my environment is ready: Y/N
```

---

## Final Commitment

```
"I have trained for 364 days. Tomorrow I demonstrate what I have learned.
Not what I have memorised — what I have built into my process.

The gate is not the end. It is the checkpoint.

Tomorrow, I operate."
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q364.1, Q364.2 …).

---

## Navigation

← Previous: [Day 363 — Gate Preparation Day 3](DAY-0363-Gate-Preparation-Day-03.md)
→ Next: [Day 365 — Bug Bounty Hunter Gate](DAY-0365-Bug-Bounty-Hunter-Gate.md)
