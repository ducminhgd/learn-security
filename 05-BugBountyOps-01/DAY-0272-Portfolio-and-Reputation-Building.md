---
title: "Portfolio and Reputation Building — Write-ups, CVE Credits, Conference Talks, Hall of Fame"
tags: [portfolio, reputation, write-ups, CVE, conference-talks, hall-of-fame,
       personal-brand, bug-bounty, community, career, credibility]
module: 05-BugBountyOps-01
day: 272
related_topics:
  - Studying Public Disclosures (Day 271)
  - Community and Resources (Day 274)
  - Bug Bounty Methodology Synthesis (Day 275)
  - Write-Up Sprint (Days 326–330)
---

# Day 272 — Portfolio and Reputation Building

> "The bug you found but never published is invisible. The bug you found,
> wrote up clearly, and published is a public demonstration of your skill.
> Over time, a portfolio of good write-ups is worth more than any certification.
> It shows what you actually found, how you found it, and how clearly you
> think. That is what gets you private programme invitations, job offers,
> and speaking slots."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Plan a write-up that communicates technique depth, not just the exploit.
2. Set up and maintain a technical blog as a portfolio centrepiece.
3. Understand the CVE assignment process and when to pursue a CVE credit.
4. Identify entry points for speaking at security conferences.
5. Leverage hall-of-fame credits and platform rankings strategically.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Report structure and format | Day 161 |
| Studying public disclosures | Day 271 |

---

## Part 1 — Writing Quality Write-ups

A write-up is different from a bug report. A bug report tells one company
about one bug. A write-up teaches the entire community about a vulnerability
class by narrating how you found and exploited a specific instance of it.

### Write-up Structure

```markdown
# [Technique] — How I Found [Vulnerability] in [Target/Context]

## TL;DR
[2–3 sentence summary for readers who want to know the punchline first]

## Background
[What is this vulnerability class? Why does it exist?]
[Link to prior work, relevant CVEs, or academic research]

## Target Context
[Describe the application type, technology stack, and scope]
[Never identify a live programme that has not yet fixed the bug]

## Discovery
[Step-by-step narrative of how you found it]
[Include the tool commands, the Burp request, the observation that
triggered your suspicion]

## Exploitation
[Walk through the exploit from first payload to full impact]
[Include exact requests and responses — the reader must be able
to reproduce this in a lab setting]

## Impact
[What could an attacker do? Be specific. Numbers matter:
"all 500,000 user records" is more powerful than "user data"]

## Remediation
[What fix closes this vulnerability? One specific answer]

## Lessons Learned
[What would have missed this? What made you look here?
What would you check on every future target as a result?]

## References
[CVE, CWE, related write-ups, MITRE ATT&CK techniques]
```

### What Makes a Write-up Stand Out

**Show the thinking, not just the result.** "I checked this parameter
because it seemed to accept user-controlled input" is more valuable than
"I used sqlmap and got RCE."

**Include the dead ends.** "I initially tried X, which failed because Y.
That told me Z, which led me to the actual approach." Dead ends make the
write-up honest and more educational.

**Calibrate detail to the audience.** Assume the reader knows HTTP and
basic web vulnerabilities. Do not explain what a cookie is. Do explain why
this specific application's cookie format was exploitable.

---

## Part 2 — Building Your Blog

Choose a platform that you control:

| Platform | Advantages | Disadvantages |
|---|---|---|
| GitHub Pages + Jekyll | Free, fully owned, Markdown | Setup time |
| Ghost.io | Clean, professional, free tier | Limited customisation |
| Hashnode | Dev community, free | Not owned by you |
| Medium | Distribution, free | Medium controls your content |
| Self-hosted (Hugo/VPS) | Full control | Maintenance overhead |

**Minimum viable setup:**

```bash
# GitHub Pages with Jekyll (10 minutes):
# 1. Create a repo named: yourusername.github.io
# 2. Initialize with a Jekyll theme
# 3. Write posts in Markdown under _posts/

# Folder structure for a security blog:
_posts/
  2024-03-15-ssrf-to-aws-rce.md
  2024-04-02-jwt-kid-injection.md
  2024-05-10-graphql-mass-assignment.md
assets/
  screenshots/
  payloads/
```

**Write-up publishing checklist:**

```
[ ] Bug is fully resolved by the programme
[ ] Programme has approved public disclosure (or 90 days have passed)
[ ] You have not disclosed anything that could harm users who are not yet patched
[ ] Programme and company name: include if disclosed on Hacktivity, omit if undisclosed
[ ] No live credentials, API keys, or sensitive data in screenshots
[ ] Technical accuracy: another researcher should be able to replicate in a lab
[ ] Linked from your HackerOne/Bugcrowd profile
```

---

## Part 3 — CVE Credits

A CVE on your record is permanent. It signals: "This person found a
vulnerability significant enough to warrant a global tracking identifier."

### When to Pursue a CVE

- Vulnerability is in open-source software used by many.
- Vulnerability is in a commercial product (especially COTS software).
- The programme/vendor is not a bug bounty programme — direct disclosure.
- You found the same class of bug across multiple instances of the same
  software product (not just one organisation's deployment).

### How to Get a CVE

```
Option 1: Request through MITRE directly
URL: https://cveform.mitre.org/
Required: Product name, version, description, impact, CVSS estimate

Option 2: Through a CNA (CVE Numbering Authority)
If the vendor is a CNA (most large software companies are):
  - Report directly to them
  - They assign the CVE in their own namespace
  - Examples: GitHub (GitHub Advisory Database), Microsoft, Apple, Google

Option 3: Through a root CNA
If the vendor is unresponsive: contact CERT/CC or a regional CNA
who can assign a CVE on your behalf after documenting the attempts.
```

### CVE vs Bug Bounty

You can have both. A bug bounty pays you. A CVE credits you globally.
Many top researchers have hundreds of CVEs + substantial bounty earnings.

---

## Part 4 — Conference Talks

Security conferences are the fastest reputation amplifier in the industry.
One good talk reaches thousands of defenders and attackers simultaneously.

### Entry Points for New Speakers

| Conference | Type | Difficulty to get speaking slot |
|---|---|---|
| BSides events (global) | Regional, community | Low — submit a CFP |
| DC44932 / Local DEF CON groups | Community | Low |
| OWASP chapter meetings | Local chapter talks | Very low |
| DEF CON (Las Vegas) | Major | High — very competitive CFP |
| Black Hat (US/EU/Asia) | Major | High — needs significant original research |
| Hack In The Box | Major | Medium |
| BruCON, 44CON, x33fcon | European mid-tier | Medium |

**Starting point:** Submit to 3 BSides events with a proposal based on a
technique you discovered or a unique approach to a known vulnerability class.

### What a Good CFP (Call for Papers) Proposal Covers

```
Title: [Technique/finding name — should be specific enough to be interesting]
Abstract (200 words): What is the talk about? What will attendees learn?
Key takeaways (3 bullet points): What does the audience walk away with?
Research basis: Is this original research? A case study? A novel application?
Speaker bio: Who are you? What qualifies you?
Slides preview (optional): Helps selection committees.
```

---

## Part 5 — Platform Rankings and Hall of Fame

### HackerOne Reputation

```
Reputation score = sum of points from accepted reports
Points per report:
  Critical:  +7
  High:      +5
  Medium:    +3
  Low:       +1
  Informational: +0.5
  N/A:       -5 (harmful)
  Spam:      -10 (very harmful)
```

Reputation above specific thresholds unlocks private programme invitations
and the "Hacker of the Month" recognition.

### Programme Hall of Fame

Most large programmes maintain a public acknowledgement page:
- Google Hall of Fame
- Apple Security Research Device Programme
- Microsoft Security Response Centre (MSRC) leaderboard
- Meta's Bug Bounty Hall of Fame

**Getting onto a hall of fame:** Submit to their VDP or bounty programme.
Valid, acknowledged findings qualify for acknowledgement on their public page.

### Building a Profile Summary

Your professional security profile should include:

```markdown
## Security Research Portfolio

### Platforms
- HackerOne: @handle — Signal: N, Reputation: N, Accepted reports: N
- Bugcrowd: @handle — Trust level: N

### Notable Disclosures
- CVE-2024-XXXX — [Affected Product] — [Severity]
- [Programme] — [Vulnerability type] — [Severity] — HackerOne disclosed #NNNNN

### Conference Talks
- [Conference] YYYY — "[Talk title]"

### Publications / Write-ups
- "[Title]" — [blog.yourdomain.com]
- "[Title]" — [blog.yourdomain.com]

### Hall of Fame Credits
- [Company] — [Year]
- [Company] — [Year]
```

This profile goes on your personal website, LinkedIn, and researcher profiles.

---

## Key Takeaways

1. **Write-ups compound long after you publish them.** A write-up from two
   years ago that explains a technique clearly continues to drive
   reputation, job inquiries, and speaking invitations. A bug you never
   wrote up is gone the moment you move on.
2. **The quality of one write-up beats the quantity of ten mediocre ones.**
   A 3,000-word write-up that explains exactly why a JWT validation bug existed
   and how you found it will be read and cited for years. Ten "I ran sqlmap
   and got RCE" posts will not be remembered.
3. **CVEs are permanent and public.** Unlike a resolved bug bounty report that
   only the company sees, a CVE is in every security database forever. Prioritise
   CVEs for findings in software that affects many organisations.
4. **Conference talks open doors that cold emails cannot.** A 20-minute BSides
   talk in front of 200 people introduces you to recruiters, security team leads,
   and other researchers simultaneously. Start small. Submit to BSides.
5. **Your public reputation determines your access.** Private programme
   invitations, direct company outreach, interview fast-tracks — they all
   come from people who found you through a write-up, a conference talk,
   or a disclosed HackerOne report.

---

## Exercises

1. Select one technique you have practised in the labs (any from Days 76–260).
   Write a complete write-up using the template from Part 1, using the lab
   environment as the "target." Polish it to publication-ready quality.

2. Set up a personal blog using one of the platforms in Part 2. Publish
   your first write-up from Exercise 1.

3. Find a security conference with an open CFP in the next 6 months.
   Write a CFP proposal for a talk based on something you learned in
   Days 76–260. You do not have to submit it — the exercise is writing it.

4. Review your current HackerOne or Bugcrowd profile. What is your reputation
   score? What is your acceptance rate? Based on today's lesson, what are
   the top three things you will do in the next 30 days to strengthen your
   public profile?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q272.1, Q272.2 …).
> Follow-up questions use hierarchical numbering (Q272.1.1, Q272.1.2 …).

---

## Navigation

← Previous: [Day 271 — Studying Public Disclosures](DAY-0271-Studying-Public-Disclosures.md)
→ Next: [Day 273 — Earnings Optimisation](DAY-0273-Earnings-Optimisation.md)
