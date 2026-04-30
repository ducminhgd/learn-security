---
title: "Earnings Optimisation — High-Reward Target Selection, P1 vs P5, Severity Negotiation"
tags: [earnings, optimisation, target-selection, P1, P5, severity, negotiation,
       CVSS, payout, ROI, bug-bounty, strategy]
module: 05-BugBountyOps-01
day: 273
related_topics:
  - Choosing the Right Program (Day 263)
  - Tracking Findings and Notes (Day 268)
  - CVSS Scoring and Risk Rating (Day 162)
  - PoC Writing and Impact Analysis (Day 163)
---

# Day 273 — Earnings Optimisation

> "Every hour you spend testing is an opportunity cost. Spending 10 hours
> finding P5 findings on a programme that caps at $100 is a different decision
> than spending 10 hours hunting P1 candidates on a programme that pays $20k
> for critical. Neither is wrong. But you should be making that decision
> consciously, not by accident."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Calculate $/hour across your portfolio and identify optimisation opportunities.
2. Apply a target selection matrix that maximises payout density.
3. Understand the mechanics of severity negotiation with evidence.
4. Identify when a P3 finding can be escalated to P2 or P1 with chaining.
5. Avoid common time-wasting patterns that eat earnings.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Tracking findings and notes | Day 268 |
| CVSS scoring and risk rating | Day 162 |
| Vulnerability chaining | Day 139 |

---

## Part 1 — The Earnings Calculation

Track this for every programme engagement:

```
Metric                      Formula
──────────────────────────────────────────────────────────────────
Total time invested         Sum of all hours across all sessions
Total accepted payouts      Sum of all paid bounties
Earnings per hour           Total payouts / Total time invested
Acceptance rate             Accepted reports / Total submitted
Duplicate rate              Duplicates / Total submitted
Average payout per finding  Total payouts / Accepted findings
```

**Realistic benchmarks:**

| Level | $/hour | Acceptance rate | Notes |
|---|---|---|---|
| New researcher (0–6 months) | $0–$10 | 20–40% | Building skills and Signal |
| Developing researcher | $15–$50 | 40–60% | First private invitations |
| Consistent researcher | $50–$150 | 60–80% | Private programmes, good target selection |
| Top researcher | $200–$500+ | 80%+ | Elite private programmes, P1 focus |

If your $/hour is below target, the root cause is usually:
1. Wrong target (too competitive, too limited scope)
2. Wrong technique focus (hunting P5s when your skills support P1s)
3. Duplicate-heavy targeting (testing obvious bugs everyone else checked)
4. Poor severity calibration (under-selling findings in reports)

---

## Part 2 — Target Selection for Maximum Earnings

### The Payout Density Matrix

| Programme type | Competition | Avg payout | $/hour potential |
|---|---|---|---|
| Old public programme (> 2 years) | Very high | Medium | Low |
| New public programme (< 90 days) | Low | Medium | High |
| Private programme | Low | High | High |
| Private + wildcard scope | Very low | High | Very high |
| VDP (no payout) | Low | $0 | $0 (but Signal gain) |

**Optimal portfolio allocation (target for Days 276–330):**

```
60% effort → One primary private or low-competition programme
30% effort → New programme launched in last 30 days
10% effort → VDP for Signal maintenance and technique practice
```

### Identifying High-Value Targets

Characteristics of programmes with high payout per finding:

```
[ ] Wildcard scope with 100+ live subdomains
[ ] Complex authentication system (OAuth, SSO, SAML, custom JWT)
[ ] Rich API surface (REST + GraphQL + webhook endpoints)
[ ] Financial functionality (payments, balances, transfers)
[ ] Healthcare or PII-sensitive data (regulatory impact = higher CVSS scores)
[ ] Recent scope expansion (new assets, potentially untested)
[ ] Private or invitation-only status
[ ] P1 maximum bounty ≥ $10,000
```

---

## Part 3 — P1 vs P5: Focus Matters

Many researchers distribute effort evenly across severity levels.
High earners do not.

### Why P1 Focus Is More Profitable

```
Example calculation:
  Option A: Find 10 × P4 findings ($200 each) = $2,000 / 40 hours = $50/hour
  Option B: Find 1 × P1 finding ($10,000) = $10,000 / 40 hours = $250/hour
```

**P1 is not harder to find — it requires different searching.**

P1/Critical findings typically come from:
- Authentication bypass (no credentials needed to access data)
- Account takeover chains (CSRF + XSS + auth bypass, or JWT attacks)
- RCE via file upload or injection
- SSRF → cloud metadata → credential extraction → admin access
- SQL injection with data extraction capability (PII/financial data)
- Mass privilege escalation (one API call makes you admin)

These are not rare. They exist in programmes that have never had a researcher
look specifically for them, or where the researcher found the individual
components but did not chain them.

### P4 and P5 Opportunity Cost

P4/Low and P5/Informational findings take real time:
- Finding them: 30 minutes to 2 hours
- Writing the report: 30 minutes
- Triage back-and-forth: 1–2 hours
- Total investment: 2–5 hours for $50–$200

That same time hunting a P1 chain has a positive expected value:
- A P1 in your current programme is worth $2,000–$20,000
- Expected value (even at 10% success rate): $200–$2,000

**Practical rule:** Only report P4s and P5s if:
1. They are on your primary programme and they chain to something higher.
2. They are easy to report and you have spare time.
3. You are new and need accepted reports to build Signal.

---

## Part 4 — Severity Negotiation

Triage teams regularly downgrade severity. This costs you money directly.

### How Severity Downgrading Happens

Common triage logic errors:

| Triage downgrade | Real situation |
|---|---|
| "XSS requires user interaction — P3" | XSS is stored, triggers for every visitor — P2/P1 |
| "IDOR only shows non-sensitive data — P4" | IDOR exposes email and role, enabling targeted attacks — P3/P2 |
| "SSRF only hits internal hosts — P3" | SSRF hits AWS metadata API, exposes credentials — P1/Critical |
| "SQLi behind auth — P3" | SQLi behind any auth gives access to all user records — P2/P1 |

### How to Counter a Downgrade

1. **Add a business impact statement the triage team missed.**

```
"The response contains role information for all users (including admin
accounts), not just PII. An attacker who extracts role information can
specifically target admin accounts for phishing or credential attacks,
providing a clear escalation path. This elevates the impact beyond the
initial assessment."
```

2. **Demonstrate a chain that raises severity.**

```
"I'd like to demonstrate how this P3 IDOR chains with the open redirect
I found separately to create a P2 account takeover. Here is the chain:

Step 1: [P3 IDOR] — Extract victim's email address
Step 2: [Open redirect] — Craft a convincing phishing URL using the
        target domain's trusted open redirect
Step 3: Targeted phishing email to victim using their real email
        extracted in step 1
Step 4: Victim clicks → attacker captures session token

Combined impact: Full account takeover of any targeted user."
```

3. **Reference a comparable disclosed report at higher severity.**

```
"This is comparable to HackerOne report #XXXXXXX where a similar
IDOR on [type of application] was triaged as High ($X,XXX bounty)
because of the volume of accessible records (all users, not just
individual records). Our case is similar: any authenticated user
can access any other user's profile data."
```

### CVSS Precision

Know your CVSS vector strings. Triage teams respond to precise technical
language more than vague severity descriptions.

```
# P1 example:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 (High)

AV:N  = Network (exploitable remotely)
AC:L  = Low complexity (repeatable, no special conditions)
PR:L  = Low privileges (any authenticated user can exploit)
UI:N  = No user interaction required
C:H   = High confidentiality impact (all user records accessible)
I:H   = High integrity impact (attacker can modify any user's data)
A:N   = No availability impact
```

If the triage team assigns C:L (low) instead of C:H, dispute it with specifics:
"The confidentiality impact is High because the response includes the full
user object for any user in the system — name, email, phone, address, and
subscription status. This is not partial information — it is the complete record."

---

## Part 5 — Common Earnings Anti-Patterns

| Anti-pattern | Cost | Fix |
|---|---|---|
| Hunting only on stale public programmes | Near-zero findings | Rotate to new or private programmes |
| Reporting every P4/P5 without chain potential | Time + Signal risk | Focus on P2/P1 candidates |
| Underwriting severity in reports | Direct payout reduction | Learn CVSS; negotiate with evidence |
| Never requesting disclosure | Missed portfolio value | Request disclosure on every resolved bug |
| Not reading triage feedback | Repeat the same mistakes | Study every N/A and downgrade for pattern |
| Testing alone in first 2 years | Slower skill development | Find a research partner or group |

---

## Key Takeaways

1. **Track $/hour per programme, not just total earnings.** A programme
   that paid $500 in 40 hours ($12.50/hr) is a worse allocation than one
   that paid $2,000 in 20 hours ($100/hr). The data tells you where to spend
   your time.
2. **P1 focus requires P1 thinking.** Do not look for P1s by running more
   scans — look for them by reasoning about what gives an attacker the most
   power: account takeover, data at scale, RCE. Then systematically probe
   for the vulnerabilities that enable those outcomes.
3. **Severity is negotiable with evidence.** "I disagree" without evidence
   goes nowhere. "Here is the CVSS vector I calculated, here is why the
   confidentiality impact is High, and here is the comparable disclosed
   report at this severity" is a legitimate technical argument.
4. **Chaining P3s into P1s is a skill.** One IDOR, one open redirect, and
   one XSS individually pay $500. Chained, they pay $5,000. The chain is
   visible if you map the attack surface correctly.
5. **Earnings optimisation is a quarterly discipline.** Every three months,
   review your metrics, update your programme allocation, and identify the
   one technical skill gap that is most limiting your earnings.

---

## Exercises

1. If you have any existing submissions, calculate your $/hour for each
   programme you have tested. Which was your most profitable? Which was
   your least profitable? What was the primary reason for the difference?

2. Review your last five submitted reports (or five practice reports from
   previous labs). Recalculate the CVSS for each from scratch.
   Did you arrive at the same severity? If different, why?

3. Take any P3 finding from your notes (or from a Hacktivity example).
   Map three ways you could potentially chain it with other vulnerabilities
   to raise the effective severity. What additional bugs would you need to
   find to complete each chain?

4. Calculate the expected value of your next 40 hours:
   (a) Estimate the probability of finding at least one P1/Critical finding.
   (b) Multiply by the programme's P1 maximum bounty.
   (c) Compare to the expected value of finding P3s at your current rate.
   Which has higher expected value? How does this affect your testing focus?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q273.1, Q273.2 …).
> Follow-up questions use hierarchical numbering (Q273.1.1, Q273.1.2 …).

---

## Navigation

← Previous: [Day 272 — Portfolio and Reputation Building](DAY-0272-Portfolio-and-Reputation-Building.md)
→ Next: [Day 274 — Community and Resources](DAY-0274-Community-and-Resources.md)
