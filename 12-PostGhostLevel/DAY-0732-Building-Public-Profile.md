---
title: "Building Your Public Security Profile — Write-Ups, CVEs, Talks, and Research Identity"
tags: [career, public-profile, write-ups, cve, conference-talks, community, module-12-postghost]
module: 12-PostGhostLevel
day: 732
prerequisites:
  - Day 731 — Career Path Planning
related_topics:
  - Day 733 — CVE Credits and Disclosure Pipeline
  - Day 743 — Writing Security Research Papers
---

# Day 732 — Building Your Public Security Profile

> "Two people can have identical skills. The one with a public record of their work
> gets the call. Not because the other person is less capable — because no one knows
> they exist. In security, reputation is compounding interest. Start early, invest
> consistently, and in three years the gap between you and someone who started at
> the same time but stayed private is enormous."
>
> — Ghost

---

## Goals

Understand why a public technical profile matters in security. Know the specific
high-value assets to build. Start at least one public output before the end of
this day.

**Prerequisites:** Day 731.
**Estimated study time:** 2 hours + 1–2 hours writing your first output.

---

## 1 — Why Public Work Compounds

```
THE COMPOUNDING EFFECT

Year 1:
  You write 6 CTF write-ups and 1 CVE advisory.
  ↓
  A recruiter Googles your name. They find concrete evidence you can do
  the work. You skip the phone screen filter and go straight to technical.

Year 2:
  You publish a blog post about a new fuzzing technique.
  ↓
  Three people at DEFCON reference it in talks.
  A FAANG security team reaches out to you directly.

Year 3:
  You give a 20-minute talk at a regional conference.
  ↓
  You are on the programme committee for the following year.
  You now have network access to the top 200 practitioners in your domain.

PUBLIC WORK DOES NOT REPLACE SKILL.
PUBLIC WORK MAKES YOUR SKILL VISIBLE.
```

---

## 2 — The High-Value Public Assets

### 2.1 Technical Blog

The single most valuable long-term asset. Ranking by value:

```
BLOG RANKING (by career impact per hour invested)

HIGH VALUE:
  Bug class deep-dive   "How tcache poisoning actually works in glibc 2.34"
  Novel technique       "Fuzzing TLS handshakes with Boofuzz state machines"
  CVE walkthrough       "CVE-2024-XXXXX: heap overflow in libpng — PoC to patch"
  Tool release          "I built a CodeQL query for detecting format strings"

MEDIUM VALUE:
  CTF write-up (hard)   "DEFCON CTF 2025 — Pwn: kernel UAF chain"
  HTB write-up          Useful, common. Differentiate with exceptional depth.

LOW VALUE:
  Tool tutorial         "How to use Burp Suite" — already covered 1000 times
  Opinion pieces        Don't build a research reputation on opinions

PLATFORM OPTIONS:
  Self-hosted           GitHub Pages, Zola/Hugo static site — own your content
  Medium                Easy to start; you do not own the platform
  GitHub Gists          Good for small technical snippets

RECOMMENDATION:
  Self-hosted static site (Jekyll/Hugo) linked from GitHub.
  Custom domain. Total cost: $12/year for domain.
```

### 2.2 GitHub Profile

```
YOUR GITHUB SHOULD SHOW:

1. Fuzz targets (libFuzzer/AFL++ harnesses for real projects)
2. CodeQL / Semgrep queries
3. PoC code for CVEs you discovered or reproduced
4. CTF solutions with clean, commented code
5. A personal toolkit (your scripts, not copies of popular tools)

WHAT NOT TO DO:
  Do not fork 100 tools and star them — it reads as hoarding, not building
  Do not push messy CTF code without cleaning it up
  Do not leave empty repos or repos with just a README

PROFILE README:
  One paragraph: who you are, what you specialise in
  Links to: blog, CVEs, notable write-ups
  Keep it technical — this is not LinkedIn
```

### 2.3 CVE Credits

```
ONE CVE CREDIT > 50 CTFS on a resume.

Why:
  A CVE means you found a previously unknown vulnerability in real software.
  That is the actual job of a vulnerability researcher. It proves you can do
  the work in the wild, not just in a controlled challenge environment.

How to get your first CVE:
  1. Run the Day 666–670 audit campaign methodology on a new target
  2. Find a candidate bug (confirmed crash OR documented taint path)
  3. Draft the advisory (Day 659 format)
  4. Submit to the vendor (email security@[vendor].com or HackerOne)
  5. Follow the disclosure timeline (90 days standard)
  6. CVE ID assigned by MITRE via the vendor or directly

Fast path:
  Audit projects with small security teams:
  - Network daemons written in C with <50K LOC
  - IoT firmware from small vendors
  - Open-source parsers with limited fuzzing history
```

### 2.4 Conference Talks and Papers

```
TALK PIPELINE (shortest to longest path)

Lightning talks (5 min) at local BSides
  → Requirement: one interesting technical finding or technique
  → Acceptance rate: very high (~60-70% at local events)

BSides (30 min talk)
  → Requirement: a clear novel contribution or case study
  → CFP typical deadline: 3–6 months before event

DEF CON / Black Hat (45–60 min)
  → Requirement: significant novel research, strong PoC
  → Acceptance rate: 5–15%
  → CFP deadline: 6–9 months before event

Papers (USENIX, IEEE S&P, CCS)
  → Requirement: formal evaluation, related work section, writing quality
  → Acceptance rate: 10–20% (top venues)
  → Submission deadline: 6–12 months before conference

GHOSTLEVEL STUDENTS: aim for a BSides or regional security conference talk
within 12 months of completing the programme. That is the right target.
```

### 2.5 Platform Presence

```
PRIORITISED PLATFORM LIST

Essential:
  GitHub        Technical credibility, code portfolio
  Blog          Primary research publication channel

Valuable:
  X (Twitter)   Real-time community, CTF announcements, research discourse
  LinkedIn      Professional network, inbound recruiter channel
                Keep it minimal — security people hate performative LinkedIn

Optional:
  Discord       Community engagement (VX Underground, bug bounty discords)
  Mastodon      Growing security community, privacy-conscious alternative

Skip:
  TikTok, Instagram  Wrong audience for deep technical work
  YouTube            High production cost for limited security research ROI
                     (exception: tool demos / conference talk recordings)
```

---

## 3 — Writing Your First Technical Post

### 3.1 The Minimum Viable Write-Up

You do not need a breakthrough research result for your first post. You need:

```
MINIMUM VIABLE WRITE-UP FORMULA

Section 1: What problem or question you investigated (2 paragraphs)
Section 2: What you expected to find vs. what you actually found (1-2 paragraphs)
Section 3: The technical core — code, screenshots, commands (the body)
Section 4: What you learned and what you would do differently (1 paragraph)

Length: 600–2000 words
Code: inline or GitHub gist, properly syntax-highlighted
Screenshots: annotated with arrows if showing specific findings

VALID FIRST TOPICS:
  - A CTF challenge you solved with an interesting technique
  - A CVE you reproduced and understand deeply
  - A fuzzing campaign and what you found (even if no bugs)
  - A tool you wrote that solved a specific problem
  - A debugging session that taught you something non-obvious
```

### 3.2 The One Rule That Matters

```
RULE: Show the work.

Not: "I used AFL++ to fuzz the target and found a crash."
But: "Here is the harness. Here is the corpus. Here is the crash.
     Here is the GDB output. Here is why the crash is exploitable."

Readers who understand the topic will trust you.
Readers who are learning will learn from you.
Recruiters will know the difference between
someone who did the work and someone who read about it.
```

---

## 4 — Today's Action

Do not finish today without publishing something publicly. Options in order of
effort:

1. **Easiest:** Add a `README.md` to your best CTF solution on GitHub with
   a 300-word walkthrough.
2. **Medium:** Write a 600-word technical post about a technique you mastered
   during this programme. Publish it.
3. **Hardest (highest value):** Draft the vulnerability advisory for any finding
   from your Module 10 or Ghost Level engagement. Upload to GitHub.

---

## Key Takeaways

1. **Public technical work is compounding; private work depreciates.** The effort
   you put into a write-up today pays dividends for years. The technique you
   practiced and never documented is forgotten in 18 months.
2. **One deep post > ten shallow ones.** Depth is the differentiator. Anyone can
   summarise a tool's README. Few people can explain *why* the bug works at the
   assembly level.
3. **CVE credits are the strongest signal of real VR capability.** Even one CVE
   in a non-critical project proves you can do the work unsupervised.
4. **Start today.** The enemy of a public profile is waiting for the right time.
   The right time is now. Write the imperfect post. Ship it.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q732.1, Q732.2 …).

---

## Navigation

← Previous: [Day 731 — Career Path Planning](DAY-0731-Career-Path-Planning.md)
→ Next: [Day 733 — CVE Credits and Disclosure Pipeline](DAY-0733-CVE-Credits-Disclosure-Pipeline.md)
