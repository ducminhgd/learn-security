---
title: "Second Programme Sprint Day 1 — New Programme Setup and Recon"
tags: [live-programme, bug-bounty, second-sprint, recon, setup, practice]
module: 05-BugBountyOps-03
day: 341
related_topics:
  - First Programme Sprint Day 10 (Day 340)
  - Recon Pipeline Automation (Day 265)
  - Choosing the Right Program (Day 263)
---

# Day 341 — Second Programme Sprint Day 1: New Programme Setup and Recon

> "Every programme is a new system to understand. The recon is not a formality.
> It is the work. If you skip it, you are testing blind. Blind testers find
> the same bugs everyone else found."
>
> — Ghost

---

## Goals

Set up the second programme and complete initial recon.
Apply lessons from Sprint 1 to improve recon efficiency and target selection.

**Time budget:** 5–6 hours.

---

## Programme 2 Record

```
Programme: ___
Platform: ___
Type: Public / Private / VDP

Sprint 1 lesson applied to selection:
  In Sprint 1 I found most bugs via: ___
  This programme has that surface: Y/N

Technology stack: ___
  My confidence rating in this stack: ___/5

Scope:
  In-scope: ___
  Out-of-scope: ___
  Explicit exclusions I must memorise: ___
```

---

## Recon — Improved Pipeline (Sprint 2 Lessons Applied)

```bash
# Sprint 1 lesson: always check for forgotten staging domains first
subfinder -d TARGET.com -all -o p2-subs.txt
cat p2-subs.txt | grep -E 'staging|dev|beta|old|test|admin'

# Sprint 1 lesson: JS file analysis yielded endpoints missed in recon
httpx -l p2-subs.txt -status-code -title -mc 200,301,302 -o p2-live.txt

# Extract all JS URLs from live hosts
katana -list p2-live.txt -js-crawl -d 3 -silent -o p2-js.txt

# Secret scanning across all JS
cat p2-js.txt | while read url; do
  curl -s "$url" | grep -oE '(AKIA[A-Z0-9]{16}|eyJ[a-zA-Z0-9]+\.[a-zA-Z0-9]+|[a-z_]+_key["'"'"'\s]*[:=]["'"'"'\s]*[A-Za-z0-9_-]{20,})'
done | sort -u
```

```
Subdomains found: ___
Live hosts: ___
Staging/dev environments: ___
Secrets in JS: ___
```

---

## Priority Attack Surface (Sprint 2 — Informed Selection)

```
Based on Sprint 1 experience + this programme's tech stack:

Priority 1 (highest confidence this will yield results):
  Surface: ___   Technique: ___
  Why: ___

Priority 2:
  Surface: ___   Technique: ___

Priority 3:
  Surface: ___   Technique: ___

Surfaces to SKIP early (low-yield based on Sprint 1):
  ___
```

---

## Burp Suite Project Setup

```
Project created: Y/N
Scope configured:
  Include: ___
  Exclude: ___

Extensions loaded:
  [ ] Autorize — two-session headers configured
  [ ] Param Miner
  [ ] Active Scan++ (if Pro)
  [ ] J2EEScan (if Java target)

Test account created: Y/N  |  Account 1: ___  |  Account 2 (for IDOR): ___
```

---

## Day 1 Deliverables

```
[ ] Programme policy documented
[ ] Scope map created
[ ] Recon pipeline complete
[ ] Top 5 attack surfaces identified and prioritised
[ ] Burp project set up and scoped
[ ] Testing starts: Day 342
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q341.1, Q341.2 …).

---

## Navigation

← Previous: [Day 340 — First Programme Sprint Day 10](DAY-0340-First-Programme-Sprint-Day-10.md)
→ Next: [Day 342 — Second Programme Sprint Day 2](DAY-0342-Second-Programme-Sprint-Day-02.md)
