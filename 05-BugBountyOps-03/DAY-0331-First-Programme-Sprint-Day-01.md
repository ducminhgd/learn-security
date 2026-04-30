---
title: "First Programme Sprint Day 1 — Programme Setup and Initial Recon"
tags: [live-programme, bug-bounty, recon, setup, first-submission, practice]
module: 05-BugBountyOps-03
day: 331
related_topics:
  - Write-Up Sprint Day 5 (Day 330)
  - Recon Pipeline Automation (Day 265)
  - Choosing the Right Program (Day 263)
---

# Day 331 — First Programme Sprint Day 1: Programme Setup and Initial Recon

> "The first day on a real programme is not about finding bugs. It is about
> understanding the terrain. Rush past recon and you will spend the next nine
> days retesting the same endpoints everyone else already tested."
>
> — Ghost

---

## Goals

Select and set up your first real bug bounty programme.
Complete full automated and manual reconnaissance.
Map the attack surface before touching any endpoint with a payload.

**Time budget:** 5–6 hours.

---

## Programme Selection Record

```
Programme selected: ___
Platform: HackerOne / Bugcrowd / Intigriti / YesWeHack / Direct VDP
Programme type: Public / Private / VDP
Launch date: ___  (older = more tested, newer = more fresh surface)

Scoring:
  Scope breadth:      ___ / 5
  Technology match:   ___ / 5
  Response speed:     ___ / 5
  Payout potential:   ___ / 5
  Competition level:  ___ / 5  (lower = better for new testers)
  Total: ___ / 25

Why this programme specifically:
  ___
```

---

## Scope Analysis

```
In-scope domains / wildcards:
  ___
  ___
  ___

Out-of-scope explicit:
  ___
  ___

Out-of-scope implicit (inferred — document assumptions):
  ___

Safe harbour quality: Strong / Weak / None
  Notes: ___

Rate limiting / DoS testing: Allowed / Not allowed
Account creation for testing: Required / Allowed / Not allowed
```

---

## Automated Recon Run

```bash
# Subdomain enumeration
subfinder -d TARGET.com -o subdomains.txt -silent
amass enum -passive -d TARGET.com >> subdomains.txt
sort -u subdomains.txt > subdomains-unique.txt
wc -l subdomains-unique.txt

# Live host filtering
cat subdomains-unique.txt | httpx -silent -status-code \
  -title -tech-detect -o live-hosts.json

# Summary
echo "Total subdomains: $(wc -l < subdomains-unique.txt)"
echo "Live hosts: $(jq length live-hosts.json)"
```

```
Subdomains found:       ___
Live hosts:             ___
Technologies detected:  ___
Interesting subdomains: ___
```

---

## Manual Recon

```
Interesting subdomains to investigate first (ordered by interest):
  1. ___  — reason: ___
  2. ___  — reason: ___
  3. ___  — reason: ___

Admin panels / staging / internal services found:
  ___

Login forms found:
  ___

API endpoints visible from JS files:
  ___  (use: getallurls, katana, or LinkFinder)

Version information leaked:
  Server: ___
  X-Powered-By: ___
  Other: ___
```

---

## Initial Attack Surface Map

```
Priority 1 — test immediately:
  [ ] ___  (reason: ___)
  [ ] ___

Priority 2 — test if P1 surfaces fail:
  [ ] ___
  [ ] ___

Priority 3 — low-value, test last:
  [ ] ___
```

---

## Day 1 Checklist

```
[ ] Programme policy read completely (not skimmed)
[ ] Scope documented with explicit OOS traps noted
[ ] Automated recon pipeline completed
[ ] Live host list reviewed manually
[ ] Top 3 interesting targets identified
[ ] Test account created (if required by programme)
[ ] Burp Suite project created for this programme
[ ] Folder structure created in notes (Programme name / Targets / Findings)
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q331.1, Q331.2 …).

---

## Navigation

← Previous: [Day 330 — Write-Up Sprint Day 5](../05-BugBountyOps-02/DAY-0330-Write-Up-Sprint-Day-05.md)
→ Next: [Day 332 — First Programme Sprint Day 2](DAY-0332-First-Programme-Sprint-Day-02.md)
