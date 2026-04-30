---
title: "Studying Public Disclosures — HackerOne Hacktivity, Bugcrowd Disclosures, Pattern Analysis"
tags: [public-disclosures, Hacktivity, Bugcrowd, pattern-analysis, write-ups,
       technique-research, bug-bounty, learning, real-world, methodology]
module: 05-BugBountyOps-01
day: 271
related_topics:
  - Bug Bounty Platforms Overview (Day 261)
  - Portfolio and Reputation Building (Day 272)
  - Bug Bounty Methodology Synthesis (Day 275)
  - Write-Up Sprint (Days 326–330)
---

# Day 271 — Studying Public Disclosures

> "Every disclosed report is a free lesson from someone who already solved
> the problem. The researchers who dominate leaderboards spend 30 minutes
> every morning reading Hacktivity. Not to copy techniques — to understand
> the thinking. Why did they look there? What was the first clue? How did
> they turn a P4 into a P1? That is the education no course teaches."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Locate and filter public disclosures efficiently on HackerOne and Bugcrowd.
2. Extract technique patterns from disclosed reports systematically.
3. Identify current high-frequency vulnerability classes across programmes.
4. Build a personal "technique radar" from disclosure analysis.
5. Apply disclosed patterns to your own active targets.

**Time budget:** 4–5 hours (reading + analysis).

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Web exploitation techniques | Days 076–165 |
| Bug bounty platforms overview | Day 261 |

---

## Part 1 — Where to Find Public Disclosures

### HackerOne Hacktivity

```
URL: https://hackerone.com/hacktivity

Filter options:
  Type:     Bug bounty (paid) | VDP
  Sort:     Most recent | Most upvoted | Largest bounty
  Severity: Critical | High | Medium | Low | None
  Time:     Last week | Last month | Last 6 months | Last year | All time
```

**Daily reading habit:** Filter to "Last 7 days" + "High + Critical" + sorted
by "Largest bounty." Read 5 reports every morning before starting your own
testing. 15–20 minutes. Non-negotiable.

### Bugcrowd Disclosures

```
URL: https://bugcrowd.com/programs?sort=disclosed
(Filter to programmes with disclosed findings)
```

### External Disclosure Repositories

- **HackerOne disclosed reports GitHub mirror:**
  `https://github.com/reddelexc/hackerone-reports`
  (Searchable by keyword, programme, severity, bounty amount)

- **PayloadsAllTheThings Methodology:**
  `https://github.com/swisskyrepo/PayloadsAllTheThings`
  (Not disclosures, but technique documentation with real examples)

- **Pentester Land writeups list:**
  `https://pentester.land/list-of-bug-bounty-writeups.html`
  (Curated external write-ups from researchers' blogs)

- **ngalongc/bug-bounty-reference:**
  `https://github.com/ngalongc/bug-bounty-reference`
  (Categorised write-ups by vulnerability type)

---

## Part 2 — How to Read a Disclosure Report

Do not just read the exploit. Read the *thinking*.

### What to Extract From Every Report

```markdown
## Disclosure Analysis: [Title]
Programme: [Name]
Severity / Bounty: [P1 / $5,000]
Date: YYYY-MM-DD
Source: [HackerOne / blog URL]

### Vulnerability class
[IDOR / SSRF / XSS / SQLi / etc.]

### How it was discovered
[What made the researcher look here?]
[What was the first indicator?]
[Was this found manually or via automation?]

### Why it worked
[What design flaw or assumption was violated?]

### Impact chain
[Finding alone → what could an attacker do?]
[Finding + other findings → what could an attacker do?]

### Technique I can apply to my current targets
[Specific endpoint type, parameter pattern, or behaviour to look for]

### What I would have missed
[What part of this approach was non-obvious?]
```

This analysis takes 10 minutes per report. After 50 reports, you will
start seeing patterns you cannot unsee.

---

## Part 3 — Pattern Analysis at Scale

### Running a 90-Day Disclosure Analysis

Once per month, do a deeper analysis:

```bash
# Clone the HackerOne reports mirror:
git clone https://github.com/reddelexc/hackerone-reports /tmp/h1-reports

# Count vulnerability classes in the last 90 days of reports:
ls /tmp/h1-reports/reports/ | \
  xargs -I{} cat /tmp/h1-reports/reports/{} 2>/dev/null | \
  grep -oiE "(IDOR|SSRF|XSS|SQLi|RCE|XXE|CSRF|open redirect|race condition|CORS|JWT|OAuth)" | \
  sort | uniq -c | sort -rn

# Count by bounty range (from filenames that include bounty):
ls /tmp/h1-reports/reports/ | grep -oP '\d+' | \
  awk '$1 >= 5000' | wc -l
```

### Manual Pattern Analysis

Read 20 disclosed Critical/High reports in a week. For each, note:
- **Vulnerability class**
- **Technology stack** (frontend, backend, auth method)
- **Discovery method** (manual vs automated, which tool)
- **First indicator** (what was the clue that led to the finding)

After 20 reports:
1. Which vulnerability class appears most often? Is this your strongest area?
2. Which technology stack appears most often? Do you test targets with this stack?
3. Which discovery method leads to the highest-value findings?

---

## Part 4 — High-Impact Patterns (Current Landscape)

Based on publicly available data from HackerOne Hacktivity (2023–2024):

### Most Frequent Critical Findings

| Vulnerability | Why it appears frequently |
|---|---|
| IDOR / BOLA | Access control is hard; every API endpoint is a candidate |
| SSRF + Cloud metadata | Cloud deployments expose metadata APIs; SSRF vectors are everywhere |
| Authentication bypass | OAuth/JWT complexity creates edge cases |
| SQL injection | Legacy apps and ORMs with raw queries persist |
| Stored XSS to ATO | Rich text editors, comment fields, user profiles |

### Highest Average Payout Patterns

| Pattern | Why it pays well |
|---|---|
| SSRF → cloud credential → account takeover | Multi-step attack with real business impact |
| IDOR on financial data (balance, transactions) | Direct monetary impact |
| Mass assignment → admin privilege escalation | Immediate privilege gain |
| Subdomain takeover on CORS-trusted origin | Combines two medium bugs into a critical chain |
| JWT algorithm confusion → admin account | Authentication bypass at high-value applications |

### Underexplored (Currently Low Competition)

| Area | Why it is underexplored |
|---|---|
| Webhook endpoints | Rarely tested systematically |
| Batch API operations | Rate limiting bypasses via batch |
| Mobile deep links | Most researchers focus on web only |
| WebSocket input handling | Burp proxy needed; fewer researchers invest |
| GraphQL subscriptions | Newer technology; limited tooling |

---

## Part 5 — Building Your Technique Radar

After studying disclosures, maintain a technique radar:

```markdown
# Technique Radar

## Strong (apply confidently, high hit rate)
- IDOR via sequential numeric IDs
- SSRF via URL parameters in image loading / webhook endpoints
- JWT alg:none + RS256→HS256
- Mass assignment via undocumented POST body fields

## Emerging (learning, starting to apply)
- GraphQL field-level authorisation bypass
- WebSocket cross-site hijacking
- HTTP/2 request splitting

## Assess (aware of, not yet practised)
- Cache deception via path traversal
- DNS rebinding SSRF bypass
- SAML signature wrapping

## Hold (not worth time investment now)
- Reflected XSS on GET parameters (too high competition, low payout)
- Missing security headers without impact (N/A territory)
- Clickjacking without sensitive action
```

Review and update monthly based on disclosure reading.

---

## Key Takeaways

1. **Hacktivity is the best curriculum that exists for advanced techniques.**
   Real targets, real impact, real payouts. Every hour you spend reading it
   is invested directly into your earning potential.
2. **Read the thinking, not just the exploit.** The step from "I noticed this
   parameter existed" to "I tried this payload" is often more educational than
   the payload itself.
3. **Patterns repeat.** The same vulnerability appears in different programmes
   for the same underlying reasons. Finding a subdomain takeover report on a
   fintech programme tells you to check subdomains on every fintech programme
   you test.
4. **High-value chains are built from low-value individual findings.**
   Many critical disclosures are two or three Medium findings chained together.
   When you find a P3, the first question is: "What does this enable that I
   could chain with something else on this target?"
5. **The technique radar makes you deliberate.** Instead of randomly applying
   techniques, you apply them in order of your demonstrated success rate.
   Strong techniques first, emerging techniques when the surface fits them.

---

## Exercises

1. Read 10 disclosed reports from Hacktivity using the analysis template
   in Part 2. After all 10: (a) What was the most common vulnerability class?
   (b) What was the most common first indicator? (c) What is one technique
   you will try in your next testing session?

2. Search the HackerOne reports GitHub mirror for your strongest vulnerability
   class. Read 5 reports in that class. How does each researcher's approach
   differ from yours? What would you incorporate?

3. Build your initial technique radar using the template from Part 5. Be honest
   about which techniques you are actually strong in vs. which you have only
   read about.

4. Find one disclosed report that demonstrates a vulnerability chain (two or
   more individual bugs combined). Break down the chain: (a) What were the
   individual findings? (b) What was each finding's individual severity?
   (c) What was the combined severity? (d) What was the insight that connected
   the two?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q271.1, Q271.2 …).
> Follow-up questions use hierarchical numbering (Q271.1.1, Q271.1.2 …).

---

## Navigation

← Previous: [Day 270 — Bug Bounty Legal and Ethics](DAY-0270-Bug-Bounty-Legal-and-Ethics.md)
→ Next: [Day 272 — Portfolio and Reputation Building](DAY-0272-Portfolio-and-Reputation-Building.md)
