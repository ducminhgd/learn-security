---
title: "Bug Bounty Platforms Overview — HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, Synack"
tags: [bug-bounty, platforms, HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, Synack,
       VDP, triage, reputation, payout, operations]
module: 05-BugBountyOps-01
day: 261
related_topics:
  - Bug Bounty Reporting (Days 161–165)
  - Reading Program Policies and Scope (Day 262)
  - Choosing the Right Program (Day 263)
  - Responsible Disclosure Process (Day 269)
---

# Day 261 — Bug Bounty Platforms Overview

> "You have spent 260 days learning how to break things. Today we talk about
> getting paid to do it. Platforms are not the point — the bugs are the point.
> But knowing the difference between HackerOne and Intigriti, between a VDP and
> a paid programme, between a private invite and a public queue — that knowledge
> determines whether you are earning or wasting your time."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Describe the core model and differentiation of each major bug bounty platform.
2. Distinguish VDP (Vulnerability Disclosure Programme) from paid bug bounty.
3. Explain the reputation/ranking systems and how they affect access to targets.
4. Identify which platform to register on first based on your profile and goals.
5. Understand platform fees, payout structures, and triage models.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Web exploitation methodology | Days 76–165 |
| Bug bounty report writing | Days 161–164 |
| Web exploitation competency gate | Day 165 |

---

## Part 1 — The Platform Landscape

### What Bug Bounty Platforms Do

Platforms serve as intermediaries between security researchers and companies:

- **Scope management:** Define what can and cannot be tested.
- **Triage:** First-level validation of incoming reports.
- **Mediation:** Dispute resolution between researcher and programme.
- **Payment processing:** Hold and release bounties; manage tax forms.
- **Reputation:** Track researcher history, rank, and trust level.

You are not required to use a platform — direct disclosure is legal. But
platforms provide safe harbour, streamlined triage, and payment infrastructure
that makes the process substantially more reliable.

---

## Part 2 — Major Platforms

### HackerOne

The largest public bug bounty platform. Launched 2012.

| Property | Details |
|---|---|
| Model | Paid bounty + VDP |
| Public programmes | ~3,000+ active |
| Private programmes | Invitation-only; largest pool |
| Triage model | Hybrid — platform triage + company triage |
| Reputation system | Signal (positive: resolved reports, negative: N/A/spam) |
| Min payout | $50–$100 typical floor; P1 can be $10k–$50k |
| Tax forms | W-9 (US) / W-8BEN (non-US) required before payment |

**Signal score:** Every accepted report raises Signal. Every N/A (not
applicable) or spam report lowers it. Signal < 0 locks you out of applying
to new private programmes. Protect your Signal — never spray reports.

**Hacktivity:** Public feed of disclosed reports. This is your daily reading.
Study it every morning. It is the best real-world exploit curriculum that exists.

```
Platform URL: https://hackerone.com
Account setup: https://hackerone.com/users/sign_up
Hacktivity:   https://hackerone.com/hacktivity
```

### Bugcrowd

Second-largest platform. Strong in corporate and government sectors.

| Property | Details |
|---|---|
| Model | Paid bounty + VDP + pen testing marketplace |
| Public programmes | ~1,000+ |
| Trust score | "Researcher Level" 1–5 based on accepted reports |
| Triage model | Bugcrowd Application Security Engineers (ASEs) do first triage |
| Priority levels | P1 (Critical) → P5 (Informational) |
| Unique feature | CrowdControl — managed pen test engagements |

Bugcrowd's triage quality is generally higher than self-triaged programmes.
An ASE who does not understand your report will ask — they do not auto-reject.

```
Platform URL: https://bugcrowd.com
Disclosure feed: https://bugcrowd.com/programs (filter: disclosed)
```

### Intigriti

European-focused platform. Strong in financial services and enterprise targets.

| Property | Details |
|---|---|
| Headquarters | Belgium — GDPR-compliant operations |
| Model | Paid bounty + VDP |
| Triage | Platform-assisted triage with faster SLAs |
| Reputation | Point-based leaderboard |
| Unique | Strong European company presence (banks, telecoms) |

If you want to work on European targets (GDPR-sensitive scope, IBAN systems,
EU fintech), Intigriti has programmes that HackerOne does not.

```
Platform URL: https://intigriti.com
```

### YesWeHack

French platform. Second-largest European platform after Intigriti.

| Property | Details |
|---|---|
| Headquarters | France |
| Scope | European + Asian programmes |
| Triage | Hybrid |
| Notable | Active government and defence sector programmes in France |

Less competitive than HackerOne for equivalent targets. Good entry point for
researchers building reputation without competing against top-tier hunters.

```
Platform URL: https://yeswehack.com
```

### Immunefi

Specialist platform — blockchain and Web3 only.

| Property | Details |
|---|---|
| Scope | Smart contracts, DeFi protocols, blockchain infrastructure |
| Payout range | $1,000 → $10,000,000 (protocol-level bugs) |
| Median P1 payout | $50,000–$200,000 |
| Triage model | Platform-assisted; heavily technical reviewers |
| Prerequisite knowledge | Solidity, EVM, common DeFi patterns, reentrancy |

If you have smart contract knowledge or plan to acquire it, Immunefi offers
the highest payouts in the industry. A single critical finding in a large DeFi
protocol can pay more than 12 months of traditional bug bounty.

```
Platform URL: https://immunefi.com
```

### Synack Red Team (SRT)

Invitation-only, vetted researcher platform. Works differently from all others.

| Property | Details |
|---|---|
| Access | Application + technical vetting + background check |
| Model | Platform selects targets for you; you work on demand |
| Payout | Fixed rates per vulnerability class + bonuses |
| Advantages | No racing other researchers on the same target; pre-scoped |
| Disadvantages | Less freedom; platform controls what you test |

Synack is appropriate when you have a consistent track record (30+ accepted
reports across other platforms) and want steady predictable income.

---

## Part 3 — VDP vs Paid Programmes

### Vulnerability Disclosure Programme (VDP)

A VDP is a legal channel for reporting vulnerabilities. It does **not** pay you.

| Property | VDP |
|---|---|
| Payment | None |
| Scope | Usually broad — company wants reports, not just bounties |
| Competition | Lower — fewer researchers hunt VDP-only targets |
| Value | Build report volume, Signal score, and reputation |
| Example | US government agencies, many non-profit organisations |

**Use VDPs when:**
- You are new and need accepted reports to build reputation.
- The target is interesting technically but has no bounty.
- You want to practise without financial pressure on each report.

### Paid Bug Bounty

Money for valid, in-scope, non-duplicate vulnerabilities.

| Severity | HackerOne typical range | Bugcrowd typical range |
|---|---|---|
| P1 / Critical | $5,000–$50,000 | $5,000–$25,000 |
| P2 / High | $1,000–$10,000 | $1,500–$8,000 |
| P3 / Medium | $250–$2,500 | $500–$2,000 |
| P4 / Low | $50–$500 | $100–$500 |
| P5 / Informational | $0–$100 | $0 |

These are **ranges** — actual payout depends on the programme's policy,
impact on that specific target, and your negotiation of severity.

---

## Part 4 — Private vs Public Programmes

### Public Programmes

Open to any registered researcher on the platform.

- Higher competition — more researchers = more duplicates.
- Lower signal-to-noise — scripts run against public programmes constantly.
- Good for building initial report history.

### Private (Invitation-Only) Programmes

Accessible only to researchers invited by the company or platform.

- Lower competition — typically 10–100 researchers vs thousands public.
- Higher payout potential — less noise means more unique findings.
- **How to get invited:** Platform reputation score + past accepted reports.

On HackerOne: researchers with Signal > 5 and 5+ resolved reports start
receiving private invitations automatically. Protect your Signal aggressively.

---

## Part 5 — Platform Registration Checklist

Do all of this before Day 276 when live programme practice begins.

```
[ ] Register on HackerOne
[ ] Complete your HackerOne profile (bio, handles, timezone, skills)
[ ] Register on Bugcrowd
[ ] Register on Intigriti
[ ] Set up a payment method on each platform (PayPal or bank transfer)
[ ] Submit W-9 or W-8BEN tax form on HackerOne if applicable
[ ] Read the HackerOne Code of Conduct
[ ] Read the Bugcrowd Researcher Agreement
[ ] Bookmark Hacktivity (https://hackerone.com/hacktivity)
[ ] Subscribe to at least one platform's public disclosure feed
```

---

## Key Takeaways

1. **Signal is your most valuable asset on HackerOne.** A negative Signal
   score is an account death sentence. Never report something you are not
   reasonably confident is a valid vulnerability. One N/A is painful.
   Five N/As can lock you out of private programmes for months.
2. **VDPs are not inferior — they are training.** The companies are real,
   the bugs are real, the reports must be professional. VDP volume builds the
   reputation that opens private programme doors.
3. **Private programmes pay better per hour of effort.** Fewer researchers,
   less duplicate risk, often larger scope. Getting invited to private programmes
   is a higher-value milestone than finding your first paid bug.
4. **Immunefi if you know Solidity.** The payout density in Web3 is
   categorically higher than traditional web bounty. One critical DeFi bug
   can exceed a year of traditional bug bounty income.
5. **Platform is not the ceiling.** Some of the highest-paying engagements
   are direct relationships built through disclosed reports and reputation.
   The platform is the on-ramp, not the destination.

---

## Exercises

1. Register on HackerOne and Bugcrowd. Complete your profile fully. Read the
   programme policies for three public programmes: one technology company,
   one financial institution, one government/public sector target.

2. Browse Hacktivity for 30 minutes. Find one disclosed report that used a
   technique you have practised (Days 76–260). Write a one-paragraph summary:
   (a) What was the vulnerability? (b) How was it found? (c) What made it
   high-severity? (d) How was it fixed?

3. Find a programme on HackerOne that offers both a VDP scope and a paid
   scope. Compare the two: What is in-scope for VDP but not for paid? What
   does this tell you about the company's risk appetite?

4. Research the current Immunefi leaderboard. What are the top three assets
   (protocols) by total payout? What vulnerability classes appear most
   frequently in the critical findings?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q261.1, Q261.2 …).
> Follow-up questions use hierarchical numbering (Q261.1.1, Q261.1.2 …).

---

## Navigation

← Previous: [Day 260 — BroadSurface Competency Check](../04-BroadSurface-04/DAY-0260-BroadSurface-Competency-Check.md)
→ Next: [Day 262 — Reading Program Policies and Scope](DAY-0262-Reading-Program-Policies-and-Scope.md)
