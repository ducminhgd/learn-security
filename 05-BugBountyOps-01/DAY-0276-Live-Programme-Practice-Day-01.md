---
title: "Live Programme Practice Day 1 — Programme Selection and Initial Recon"
tags: [practice, live-programme, recon, programme-selection, bug-bounty, methodology,
       reconnaissance, scope-analysis, operations]
module: 05-BugBountyOps-01
day: 276
related_topics:
  - Bug Bounty Methodology Synthesis (Day 275)
  - Reading Program Policies and Scope (Day 262)
  - Choosing the Right Program (Day 263)
  - Recon Pipeline Automation (Day 265)
---

# Day 276 — Live Programme Practice Day 1: Programme Selection and Initial Recon

> "From today, the labs are real. The targets are real. The reports go to actual
> triage teams. This is not practised. This is not simulated. The only rules
> are the programme policy and the law — both of which you now understand.
> Start carefully. Run your scope checklist first. Then hunt."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Selected a live programme using the scoring framework from Day 263.
2. Completed a full policy analysis and written your scope document.
3. Completed passive recon and produced an initial attack surface document.
4. Populated your target profile template (Day 268).

**Time budget:** 5–6 hours.

---

## Block 1 — Programme Selection (45 min)

Apply your scoring framework:

```
[ ] Check HackerOne for programmes launched in the last 30 days
[ ] Check Bugcrowd for new/recently expanded programmes
[ ] Score 3–5 candidate programmes on the 6-dimension matrix (Day 263)
[ ] Select the highest-scoring programme
[ ] Write down your selection rationale:
```

Selected programme: ___
Platform: ___
Score: ___/30
Rationale: ___

---

## Block 2 — Policy Analysis (60 min)

Read the full programme policy. Complete your scope document:

```
[ ] In-scope assets listed: ___
[ ] Out-of-scope assets listed: ___
[ ] Excluded vulnerability classes: ___
[ ] Testing constraints (rate limits, account rules): ___
[ ] Safe harbour assessment: Strong / Weak / None
[ ] Quote from safe harbour: "___"
[ ] OOS edge cases identified: 1.___ 2.___ 3.___
```

---

## Block 3 — Passive Recon (90 min)

Run passive recon only — no active scanning yet.

```bash
# Step 1: Subdomain enumeration (passive):
subfinder -d $TARGET -silent -o passive-subs.txt
# crt.sh query:
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> passive-subs.txt
cat passive-subs.txt | sort -u > all-passive-subs.txt
echo "Passive subdomains: $(wc -l < all-passive-subs.txt)"

# Step 2: Archive and historical data:
echo "$TARGET" | gau --blacklist png,jpg,gif,css,svg | \
  grep -v "=http" | sort -u > historical-urls.txt
echo "Historical URLs: $(wc -l < historical-urls.txt)"

# Step 3: JavaScript and GitHub recon:
# Search GitHub: "site:github.com $TARGET" in browser
# Note any public repos, exposed configs, CI/CD files
```

Passive recon findings:
```
Subdomains found: ___
Notable subdomains: ___
Historical URLs of note: ___
GitHub/public exposure findings: ___
```

---

## Block 4 — Initial Active Recon (90 min)

```bash
# Validate live hosts:
cat all-passive-subs.txt | httpx -silent -status-code -title -tech-detect \
  -threads 50 -o live-hosts.txt
echo "Live hosts: $(wc -l < live-hosts.txt)"

# Fingerprint technology stack:
cat live-hosts.txt | head -20  # review first 20

# Prioritise 3–5 highest-interest hosts based on:
# - Status code 200 (not just redirects to main domain)
# - Interesting title (admin, api, dashboard, portal)
# - Tech stack that matches your specialisation
```

Priority targets from initial recon:
```
Host 1: ___  Status: ___  Tech: ___  Why interesting: ___
Host 2: ___  Status: ___  Tech: ___  Why interesting: ___
Host 3: ___  Status: ___  Tech: ___  Why interesting: ___
```

---

## Block 5 — Target Profile Document

Complete the full target profile template (Day 268 format) and save it to
your notes system. This document is the foundation of all future sessions
on this programme.

---

## Session Debrief

```
Total time spent: ___
Programme selected: ___
Subdomains found: ___
Live hosts identified: ___
Priority targets: ___
Most interesting finding so far: ___
Questions raised by the recon: ___
Plan for tomorrow (Day 277): ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q276.1, Q276.2 …).

---

## Navigation

← Previous: [Day 275 — Bug Bounty Methodology Synthesis](DAY-0275-Bug-Bounty-Methodology-Synthesis.md)
→ Next: [Day 277 — Live Programme Practice Day 2](DAY-0277-Live-Programme-Practice-Day-02.md)
