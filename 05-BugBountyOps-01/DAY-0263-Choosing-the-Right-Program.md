---
title: "Choosing the Right Program — VDP vs Paid, Private vs Public, Signal-to-Noise"
tags: [bug-bounty, program-selection, VDP, paid, private, public, signal-to-noise,
       strategy, target-selection, operations, earnings]
module: 05-BugBountyOps-01
day: 263
related_topics:
  - Bug Bounty Platforms Overview (Day 261)
  - Reading Program Policies and Scope (Day 262)
  - Earnings Optimisation (Day 273)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 263 — Choosing the Right Program

> "Most researchers lose before they start — by picking the wrong target. A
> programme that has been public for three years, with thousands of researchers
> hammering it daily, has almost no low-hanging fruit left. You will spend 40
> hours and find nothing. Pick the target correctly and the same 40 hours
> produces a P1. Programme selection is its own skill."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Apply a scoring framework to evaluate programme attractiveness.
2. Identify programmes with favourable signal-to-noise ratios.
3. Recognise newly launched programmes and act on them within the first 48 hours.
4. Match your current skill set to the right programme category.
5. Build a personal programme shortlist and rotation strategy.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Bug bounty platforms overview | Day 261 |
| Reading program policies and scope | Day 262 |

---

## Part 1 — The Signal-to-Noise Problem

Every bug bounty programme has a signal-to-noise ratio. "Signal" is the
probability that your testing effort produces a valid, unpaid finding.
"Noise" is everything that eats your time without paying: duplicates,
OOS issues, N/A reports, and already-known vulnerabilities.

### Factors That Raise Noise

| Factor | Why it raises noise |
|---|---|
| Programme has been public > 2 years | Surface has been tested thousands of times |
| Large researcher pool on platform | More competition, more duplicates |
| Simple technology stack | Basic checks have been exhausted |
| Narrow scope | Less surface area = fewer opportunities |
| Heavy automation by others | Common vulnerabilities auto-found daily |

### Factors That Raise Signal

| Factor | Why it raises signal |
|---|---|
| Newly launched (< 90 days old) | Untested surface |
| Recently expanded scope | New assets, potentially untested |
| Complex application with many features | More attack surface, harder to automate |
| Niche technology stack (custom frameworks, unusual backends) | Less tooling coverage |
| Recent acquisition integrated into scope | New assets often less hardened |
| Wildcard scope with many subdomains | Large attack surface |
| Strong payout table (P1 ≥ $5,000) | Attracts serious researchers, but also indicates the company values findings |

---

## Part 2 — Programme Scoring Framework

Score each candidate programme on these dimensions:

| Dimension | Score | How to assess |
|---|---|---|
| Scope breadth | 1–5 | More assets/subdomains = higher score |
| Programme age | 1–5 | Newer = higher score (5 = < 90 days old) |
| Payout density | 1–5 | P1 ≥ $5k = 5; P1 < $500 = 1 |
| Technology complexity | 1–5 | Custom stack, microservices, rich APIs = higher |
| Triage quality | 1–5 | Platform-triaged or known-good company = 5; solo triage = lower |
| Safe harbour strength | 1–5 | Strong explicit legal protection = 5; none = 1 |

**Target: Choose programmes scoring ≥ 20 / 30.**

---

## Part 3 — Programme Categories by Researcher Skill Level

### New Bug Bounty Hunter (Days 261–280)

Best targets for building your first 5–10 accepted reports:

**Public VDPs with broad scope:**
- US government agencies (HackerOne's government programme list)
- Large tech companies' VDP programmes (Google VRP, Microsoft MSRC,
  Apple Security Bounty — all have VDP tracks)
- Open-source project security reporting channels

Why: Low competition on VDP. Less financial pressure per report. Safe to
practise your reporting methodology.

**Low-competition public paid programmes:**
- Newly launched programmes (< 90 days old) on any platform
- Programmes in industries with few specialist researchers
  (manufacturing, logistics, healthcare IT)

### Active Bug Bounty Hunter (Your current target range)

You have 5–10 accepted reports. Your goal is earning:

**Private programmes via platform invitation:**
- Your first private invitations will arrive once HackerOne Signal > 5.
- Private programmes have 5–50x fewer researchers than equivalent public ones.
- A P3 that would be an instant duplicate on a public programme is a clean
  finding on a private one.

**Specialist programmes matching your skills:**
- If you are strong on API exploitation (Days 146–160): Look for programmes
  with explicit API scope and complex REST/GraphQL endpoints.
- If you are strong on auth attacks (Days 166–180): Target programmes with
  complex SSO, OAuth, or SAML implementations.

---

## Part 4 — Identifying New Programme Launches

A newly launched programme is the highest-signal opportunity you can get.

### How to Track New Launches

```bash
# HackerOne newly launched — check the public programmes list sorted by "new"
# https://hackerone.com/programs?sorted_by=launched_at&order=desc

# Bugcrowd new programmes
# https://bugcrowd.com/programs?sort=launched

# Platform email/notification subscription:
# HackerOne: Settings → Notifications → New programmes
# Bugcrowd: Settings → Notifications

# Community monitoring:
# Twitter/X: follow #bugbounty — new launches are announced immediately
# Discord: bug bounty community servers share new launches in real time
```

### First 48 Hours Protocol

When a new programme launches:

```
Hour 1–4:  Read the full policy. Map the complete scope.
           Set up Burp Suite proxy for the primary domain.
           Run passive recon (subfinder, crt.sh) — do NOT run active scans yet.

Hour 4–8:  Active recon — subdomain enumeration + directory fuzzing.
           Identify technology stack and all endpoints.
           Register one test account.

Hour 8–24: Systematic testing — start with high-impact, low-hanging fruit:
           1. Authentication and account management
           2. IDOR / access control on user data
           3. SSRF on any URL-fetching features
           4. File upload functionality
           5. API endpoints not referenced in the frontend

Hour 24–48: Chain findings. Draft reports. Submit.
```

Submitting within 48 hours is not about speed — it is about freshness.
After 72 hours, the most obvious bugs will be duplicated by other researchers.

---

## Part 5 — Technology Stack as a Selection Filter

Match your skill set to the technology stack.

### Skill → Target mapping

| Your strength | Target profile |
|---|---|
| PHP/SQL injection depth | PHP applications, WordPress ecosystems, Laravel apps |
| JWT/OAuth abuse | Node.js or Go APIs, SPA-heavy apps using React/Vue |
| SSRF and cloud infrastructure | AWS/Azure-hosted applications; any app with URL fetching |
| GraphQL exploitation | Modern SaaS products; startups; anything with React frontend |
| Android/iOS | Mobile programmes with app in scope |
| Smart contract | DeFi protocols on Immunefi |

### How to Identify a Technology Stack Quickly

```bash
# Wappalyzer (browser extension) — instant tech detection on any page
# whatweb (CLI)
whatweb -a 3 https://target.example.com

# Check response headers for framework leakage:
curl -s -I https://target.example.com | grep -iE 'server|x-powered|x-aspnet'

# JS files often reveal framework versions:
# Source: React, Next.js, Vue, Angular, etc.
# API clients: axios, fetch patterns reveal API structure
```

---

## Part 6 — When to Move On

The hardest skill in bug bounty is knowing when a target is exhausted.

**Stop and switch when:**
- You have spent > 20 hours and found nothing in 3+ sessions.
- Every endpoint you probe returns either 403 (blocked) or N/A.
- Your last 5 report drafts were duplicates.
- The programme has not updated scope in > 12 months.

**Do not stop when:**
- You found something small — one P3 often hides a P1 nearby.
- The programme just expanded scope.
- You have a new technique you have not applied to this target yet.

Track time per target. If your $/hour is consistently zero on a target
after 30+ hours, rotate.

---

## Key Takeaways

1. **Programme age is the single best signal for finding bugs.** A three-year-old
   public programme with 5,000 researchers has been scoured. A 30-day-old
   programme has not. Same effort, dramatically different outcome.
2. **The first 48 hours of a new programme are the most valuable time in bug
   bounty.** Set up platform notifications. Show up when it matters.
3. **Match your stack to the target.** A researcher who specialises in
   JWT/OAuth attacks will find more bugs on a React SPA with an OAuth flow
   than on a PHP monolith. Play to your strengths.
4. **Private invitations compound.** One accepted report improves your
   reputation score, which unlocks more private programme invitations, which
   produce more accepted reports. The early investment in Signal pays forward.
5. **Rotation is a strategy.** Having a primary target (deep, familiar) and
   a rotation of secondary targets (fresh, unexplored) maximises both income
   and skill development.

---

## Exercises

1. Score five programmes from HackerOne using the scoring framework in Part 2.
   Rank them. Which is the best target for a researcher at your current skill
   level? Justify your answer.

2. Set up notifications on HackerOne and Bugcrowd for new programme launches.
   For the next newly launched programme you observe, apply the First 48 Hours
   Protocol from Part 4 and document what you find (even if you find nothing).

3. Research the HackerOne public statistics page. Find:
   (a) The average time-to-first-response across all programmes.
   (b) The average time-to-bounty.
   (c) The percentage of resolved vs N/A reports on the platform.
   What do these numbers tell you about platform-wide signal-to-noise?

4. Pick one programme from each of these categories:
   (a) A VDP you would use for report-building practice.
   (b) A public paid programme that matches your current skill set.
   (c) A private programme you aspire to be invited to.
   Write a one-paragraph justification for each choice.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q263.1, Q263.2 …).
> Follow-up questions use hierarchical numbering (Q263.1.1, Q263.1.2 …).

---

## Navigation

← Previous: [Day 262 — Reading Program Policies and Scope](DAY-0262-Reading-Program-Policies-and-Scope.md)
→ Next: [Day 264 — Nuclei Templates and Automation](DAY-0264-Nuclei-Templates-and-Automation.md)
