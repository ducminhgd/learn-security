---
title: "Tracking Findings and Notes — Obsidian, Notion, Bug Tracking, When to Stop"
tags: [bug-bounty, operations, note-taking, Obsidian, Notion, bug-tracking, workflow,
       productivity, findings, methodology, time-management]
module: 05-BugBountyOps-01
day: 268
related_topics:
  - Bug Bounty Methodology Synthesis (Day 275)
  - Choosing the Right Program (Day 263)
  - Report Structure and Format (Day 161)
  - Earnings Optimisation (Day 273)
---

# Day 268 — Tracking Findings and Notes

> "A bug you find but cannot reproduce a week later is a bug you lost. An
> endpoint you annotated is one you will not test twice. The researchers who
> earn consistently have a system — not because organisation is fun, but
> because memory is lossy and targets are large. The system is the difference
> between a $0 session and a $500 session revisiting your own notes."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Set up a structured note-taking system for bug bounty research.
2. Maintain a consistent target profile document for every programme.
3. Build a finding log that accelerates report writing.
4. Implement a decision framework for when to stop on a target.
5. Track your own performance metrics to optimise effort allocation.

**Time budget:** 2–3 hours (setup and practice).

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Bug bounty report structure | Day 161 |
| Choosing the right program | Day 263 |

---

## Part 1 — Note-Taking Systems

The tool matters less than the consistency. Pick one and commit.

### Option A: Obsidian (Recommended for offline / privacy)

Obsidian stores notes as plain Markdown files. No cloud sync by default.
Your research stays on your machine.

```
Folder structure:
bug-bounty/
├── programmes/
│   ├── programme-a/
│   │   ├── 00-overview.md      ← Policy, scope, payout table
│   │   ├── 01-recon.md         ← Subdomains, tech stack, endpoints
│   │   ├── 02-findings/
│   │   │   ├── FIND-001.md     ← Each finding as a separate note
│   │   │   └── FIND-002.md
│   │   └── 03-report-drafts/   ← Draft reports before submission
│   └── programme-b/
├── knowledge-base/             ← Technique notes, payloads, cheatsheets
└── templates/
    ├── finding-template.md
    └── programme-template.md
```

Plugins to install:
- **Dataview** — Query your notes like a database (find all P2 findings across programmes)
- **Templater** — Auto-fill templates on note creation
- **Calendar** — Track daily research sessions

### Option B: Notion (Recommended for team / cross-device)

Notion's database view is excellent for tracking findings across programmes.

```
Database columns for a Findings database:
  Name         (title)       ← Short description
  Programme    (select)      ← Programme name
  Severity     (select)      ← Critical / High / Medium / Low
  Status       (select)      ← Draft / Submitted / Triaged / Resolved / Dup
  Date Found   (date)
  Report URL   (URL)
  Payout       (number)
  CVE/CWE      (text)
  Tags         (multi-select) ← idor, xss, ssrf, sqli, auth-bypass, etc.
```

---

## Part 2 — Target Profile Template

Create this document at the start of every programme engagement:

```markdown
# Programme: [Programme Name]
Platform: HackerOne | Bugcrowd | Intigriti
Started: YYYY-MM-DD
Status: Active | Completed | Paused

## Scope

### In-Scope
- *.example.com
- api.example.com
- iOS app: com.example.app

### Out-of-Scope
- third-party services (Salesforce, Zendesk)
- *.dev.example.com (staging)

### Excluded Vulnerability Classes
- Rate limiting without auth impact
- Self-XSS
- Missing security headers (no demonstrated impact)

## Payout Table
| Severity | Amount |
|---|---|
| Critical | $5,000 |
| High | $2,000 |
| Medium | $500 |
| Low | $100 |

## Safe Harbour Assessment
Strong / Weak / None
Quote: "..."

## Technology Stack
- Frontend: React 18, Next.js
- Backend: Node.js, Express
- Database: PostgreSQL
- Auth: JWT (RS256), OAuth 2.0 / Google SSO
- CDN: Cloudflare
- Hosting: AWS (us-east-1)

## Subdomains Discovered
Total: [N]
Live: [N]
High-interest:
- api.example.com (exposed Swagger docs)
- admin.example.com (login page, different auth flow)
- dev.example.com (OOS — staging)

## Endpoints of Interest
- POST /api/v1/users — creates users
- GET /api/v1/users/{id} — user profile (IDOR candidate)
- POST /api/v1/reports — URL parameter (SSRF candidate)
- /admin/users — admin-only; tested with low-priv account

## Session Log
| Date | Duration | What I did | Findings |
|---|---|---|---|
| YYYY-MM-DD | 2h | Recon, subdomain enum | 47 subdomains |
| YYYY-MM-DD | 3h | API endpoint testing | 1 IDOR draft |
```

---

## Part 3 — Finding Log Template

Every potential finding gets its own note the moment you find it:

```markdown
# FIND-001: [Short descriptive title]

## Status
Draft | Ready to submit | Submitted | Duplicate | Resolved

## Details
- Programme: example.com
- Date found: YYYY-MM-DD
- Severity: High (estimated)
- Endpoint: GET /api/v1/users/{id}
- Vulnerability class: IDOR / BOLA

## Evidence
Request:
```
GET /api/v1/users/1337 HTTP/1.1
Host: api.example.com
Authorization: Bearer [my-own-JWT]
```

Response:
```
HTTP/1.1 200 OK
{"id": 1337, "email": "victim@example.com", "role": "admin", ...}
```

## Reproduction Steps
1. Log in as any user
2. Note your user ID (e.g., 1234)
3. Modify the user ID parameter to any other value (e.g., 1337)
4. Observe that the response returns another user's full profile
5. No authorization check is performed

## Impact
- Attacker can enumerate all user profiles
- PII exposure (email, name, phone, address)
- Role information leakage enables privilege targeting

## CVSS
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)
Or if admin info revealed: 8.1 (High)

## Chain Potential
- IDOR + user enumeration → targeted phishing
- Role disclosure → targeted privilege escalation attempts

## Notes
- Tested with test account pair: account-a vs account-b
- Did NOT access real user data
- Confirmed by testing 3 sequential IDs around my own
```

---

## Part 4 — When to Stop on a Target

One of the hardest judgment calls in bug bounty.

### Stop Signals

| Signal | Meaning |
|---|---|
| 3+ sessions with zero new leads | Surface is exhausted for your current techniques |
| Last 5 report drafts were all duplicates | Others have found all the obvious bugs |
| Every interesting endpoint returns 403 | Effective WAF / IP-based blocking |
| Programme not updated in > 12 months | Stale scope; mature surface |
| Programme SLA consistently > 60 days | Low company engagement; deprioritise |

### Continue Signals

| Signal | Meaning |
|---|---|
| You just found a P3 | P3 findings cluster; look for the P2 or P1 nearby |
| Programme expanded scope this week | New assets, potentially untested |
| You just learned a new technique | Apply it before switching targets |
| Triage team responded quickly | Engaged programme; worth continued effort |
| You found a pattern but not the full exploit | Don't leave a half-chain |

### The Time Budget Rule

Assign a time budget to each target before starting:

```
Primary target (deep focus):     20 hours / week max
Secondary target (parallel):     8 hours / week
Exploration target (new, quick): 4 hours to assess, then decide
```

Track actual hours per target. If a target has consumed 30+ hours with
no valid findings, rotate it to "low priority" and replace it.

---

## Part 5 — Performance Tracking

Track your own metrics to improve:

```markdown
## Monthly Performance Log — [Month YYYY]

| Metric | Value |
|---|---|
| Hours spent on research | N |
| Programmes tested | N |
| Findings submitted | N |
| Accepted | N |
| Duplicates | N |
| N/A (not applicable) | N |
| Earnings | $N |
| $/hour (accepted only) | $N |

## Analysis
- Acceptance rate: [accepted / submitted]%
- Duplicate rate: [duplicates / submitted]%
- Best performing programme: [name]
- Technique with highest acceptance rate: [technique]
- Technique with highest duplicate rate: [technique]

## Adjustments for Next Month
1. ...
2. ...
```

A 30–40% acceptance rate on submitted reports is reasonable for a developing
researcher. If your duplicate rate exceeds 40%, you are testing too-popular
targets or too-slow on new programmes.

---

## Key Takeaways

1. **Notes compound.** A target profile you built 3 months ago, revisited today
   when the company expanded scope, starts you at 70% of the recon work already
   done. No notes = start from zero every time.
2. **Log potential findings immediately.** The moment you see something
   interesting, write it down — even if you are not sure it is a real bug.
   The act of writing forces you to articulate why it is interesting.
3. **Metrics reveal your real patterns.** If you discover you have a 60%
   duplicate rate but a 100% acceptance rate on the findings that are not
   duplicates, you are skilled but slow. That is a different problem than
   a 20% acceptance rate.
4. **"When to stop" is a strategy, not a feeling.** Researchers who stay
   on exhausted targets out of sunk cost lose time they could spend on
   fresh targets. Assign time budgets before you start. Honour them.
5. **Your finding log is your report head start.** Every field in the
   finding template maps directly to a section of the final report.
   A good finding log turns report writing from 2 hours to 45 minutes.

---

## Exercises

1. Set up your chosen note-taking system (Obsidian or Notion) with the
   folder structure from Part 1. Create the templates for programme profile
   and finding log.

2. Backfill one complete target profile for any programme you have explored
   previously. Use the template from Part 2. How much do you remember vs.
   how much would you need to re-discover?

3. Start tracking your research time with a simple log. After your next three
   sessions, calculate your $/hour for each. What does the data tell you?

4. Write a "stop criteria" document for a specific programme you plan to test
   in the coming weeks. Define: (a) Maximum hours before rotation decision.
   (b) Three specific signals that would extend your time on the target.
   (c) Three signals that would immediately trigger rotation.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q268.1, Q268.2 …).
> Follow-up questions use hierarchical numbering (Q268.1.1, Q268.1.2 …).

---

## Navigation

← Previous: [Day 267 — ffuf and Custom Wordlists](DAY-0267-ffuf-and-Custom-Wordlists.md)
→ Next: [Day 269 — Responsible Disclosure Process](DAY-0269-Responsible-Disclosure-Process.md)
