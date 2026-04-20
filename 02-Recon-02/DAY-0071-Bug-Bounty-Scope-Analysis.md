---
title: "Bug Bounty Scope Analysis — Reading Policies, In-Scope vs Out-of-Scope, Safe Harbour"
tags: [bug-bounty, scope, policy, HackerOne, Bugcrowd, Intigriti, safe-harbour,
       CFAA, responsible-disclosure, wildcards, rules-of-engagement]
module: 02-Recon-02
day: 71
related_topics:
  - Passive vs Active Recon and OpSec (Day 052)
  - Recon Mindset and Kill Chain (Day 051)
  - Bug Bounty Recon Methodology (Day 072)
  - Bug Bounty Platforms Overview (Day 261)
---

# Day 071 — Bug Bounty Scope Analysis

## Goals

By the end of this lesson you will be able to:

1. Parse a bug bounty programme policy and extract the precise scope boundaries.
2. Distinguish between wildcard scope, explicit scope, and out-of-scope entries —
   and understand how each constrains your testing.
3. Identify the most common scope traps that get researchers banned or flagged.
4. Explain what a safe harbour clause is and what it does (and does not) protect.
5. Handle scope edge cases: acquired companies, shared infrastructure, third-party
   dependencies.

---

## Prerequisites

- [Day 051 — Recon Mindset and Kill Chain](../02-Recon-01/DAY-0051-Recon-Mindset-and-Kill-Chain.md)
- [Day 052 — Passive vs Active Recon and OpSec](../02-Recon-01/DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)

---

## Main Content

> "The fastest way to get banned from a programme — and possibly prosecuted —
> is to test something out of scope. Read the policy. Then read it again."
>
> — Ghost

### 1. Why Scope Analysis Is a Security Skill

Scope analysis is not bureaucratic box-ticking. It is a risk management activity
that protects you legally and professionally.

```
In scope + valid bug = money, reputation, career advancement
In scope + not a bug = time wasted, but no harm
Out of scope + valid bug = warning, ban, or prosecution
Out of scope + no bug = definite ban, possible prosecution

The asymmetry is extreme. One out-of-scope action ends your career.
```

---

### 2. Programme Policy Structure

Most bug bounty policies on HackerOne, Bugcrowd, and Intigriti follow the same
structure:

```
Policy sections:
1. Programme description    — what the company does, general goals
2. Scope table              — IN scope assets and OUT of scope assets
3. Reward structure         — bounty amounts by severity
4. Rules of engagement      — what testing is allowed/prohibited
5. Safe harbour clause      — legal protections for good-faith researchers
6. Disclosure policy        — when/how to disclose, timeline
7. Contact information      — how to report
```

The **scope table** and **rules of engagement** are what determine what you
can legally test.

---

### 3. Scope Types

#### 3.1 Wildcard Scope

```
*.target.com
```

This means: all subdomains of `target.com` are in scope.

**What it includes:**
- `api.target.com`
- `admin.target.com`
- `staging.target.com`
- `dev-internal.target.com`
- Any subdomain you discover via enumeration

**Common misconception:** A wildcard does NOT include:
- `target.com` itself (unless explicitly listed)
- `target.co.uk` (different TLD)
- `target-staging.com` (different domain entirely)
- APIs hosted on third-party platforms (`target.api.gateway.io`)

#### 3.2 Explicit Scope

```
www.target.com
api.target.com
app.target.com
```

Only the listed assets are in scope. Nothing else.

**Testing `admin.target.com` when only `api.target.com` is listed = out of scope.**
This is a common trap.

#### 3.3 IP Range Scope

```
10.0.0.0/8 (internal — only via VPN connection)
203.0.113.0/24
```

All IPs in the range are in scope. Individual services within those IPs may
still have limitations (see rules of engagement for DoS restrictions).

#### 3.4 Exclusions Within Wildcard Scope

Many programmes list wildcard scope but explicitly exclude certain subdomains:

```
IN SCOPE:    *.target.com
OUT OF SCOPE:
  - blog.target.com (run by third-party Wordpress, no security responsibility)
  - cdn.target.com (Cloudflare managed, testing would affect their infrastructure)
  - careers.target.com (managed by Workday)
  - mail.target.com (testing could cause email disruption)
```

When you see this pattern, the exclusions override the wildcard. **Always read
the full out-of-scope list before testing anything.**

---

### 4. Out-of-Scope Traps

These are the most common situations that get researchers in trouble:

#### 4.1 Third-Party Infrastructure

```
POLICY: "Do not test third-party services"
TRAP:   target.com embeds Intercom chat widget
        You find an XSS in the Intercom widget
        → This is Intercom's bug, not target.com's bug
        → Reporting to target.com: at best WONTFIX, at worst flagged for testing
          a third-party service
        → Correct action: report to Intercom's own disclosure programme
```

#### 4.2 Acquired Companies

```
POLICY: "In scope: *.target.com"
TRAP:   target.com acquired CompanyX last year
        companyX.com has vulnerable login
        companyX.com is NOT *.target.com
        → Even if CompanyX is now part of the business, it is NOT in scope
        → Ask the programme team via their contact channel before testing
```

#### 4.3 Shared Infrastructure

```
POLICY: "In scope: api.target.com"
TRAP:   api.target.com runs on the same server as partner.differentcompany.com
        Exploiting the server would also affect differentcompany.com
        → Even if the vulnerability is on api.target.com, exploitation that
          affects a third party is out of scope
```

#### 4.4 DoS Testing

Almost all programmes prohibit denial-of-service testing:

```
COMMON RULE: "Do not conduct DoS or DDoS attacks"
TRAP:   Mass fuzzing with ffuf at 10,000 req/sec crashes the server
        → This is a DoS, even if accidental
        → Rate-limit all tools. Always.

        A SQLi time-based injection with a 30-second sleep on a production
        query is also a DoS on that query.
```

#### 4.5 Automated Scanning of Out-of-Scope Assets

```
TRAP:   Your automated pipeline runs subfinder → httpx → nuclei on *.target.com
        It discovers mail.target.com (explicitly out of scope)
        nuclei sends probes to mail.target.com anyway
        → Your automation tested an out-of-scope asset
        → You are responsible for what your tools do
```

**Fix:** Build scope filtering into your pipeline.

```bash
# Filter subdomains against out-of-scope list before probing
OUT_OF_SCOPE="mail.target.com careers.target.com blog.target.com"
grep -vFf <(echo "$OUT_OF_SCOPE" | tr ' ' '\n') all_subs.txt > in_scope_subs.txt
```

---

### 5. Rules of Engagement

Beyond scope, programmes specify what you can DO with in-scope assets.

#### 5.1 Common Rules

```
ALLOWED (typical):
  ✓ Vulnerability scanning with non-destructive tools
  ✓ Manual testing
  ✓ Intercepting your own traffic to the application
  ✓ Creating test accounts for testing purposes
  ✓ Port scanning (usually — confirm per programme)

PROHIBITED (typical):
  ✗ DoS / DDoS attacks
  ✗ Accessing other users' data (even to prove IDOR — demonstrate with your own accounts)
  ✗ Modifying or deleting data you do not own
  ✗ Social engineering employees of the company
  ✗ Physical security testing
  ✗ Automated scanning at rates that degrade service
  ✗ Reporting publicly before receiving programme response
```

#### 5.2 Handling IDOR Without Accessing Other Users' Data

A common rule: "Do not access data belonging to other users."
A common misunderstanding: "I cannot test IDOR without accessing other user data."

**The correct approach:**

```
1. Create two test accounts: account_A and account_B
2. Create a resource with account_A (e.g., an order)
3. Note the resource ID (e.g., order_id=12345)
4. Log in as account_B
5. Attempt to access /api/orders/12345
6. If successful: you have proved IDOR using only accounts YOU OWN
7. Report the vulnerability with these steps to reproduce
```

You demonstrated the vulnerability without touching any real user's data.

---

### 6. Safe Harbour Clauses

A safe harbour clause is a legal statement from the company saying they will
not pursue legal action against researchers who:
- Act in good faith
- Follow the programme's rules of engagement
- Report findings responsibly

**Example safe harbour text (HackerOne standard):**

> "We will not pursue civil action or initiate a complaint to law enforcement
> for accidental, good-faith violations of this policy. We consider activities
> conducted consistent with this policy to constitute 'authorized' conduct
> under the Computer Fraud and Abuse Act. If legal action is initiated by a
> third party against you in connection with activities conducted under this
> policy, we will take steps to make it known that your actions were conducted
> in compliance with this policy."

**What safe harbour does NOT cover:**

```
✗ Testing out-of-scope assets
✗ Exfiltrating user data beyond what is needed to demonstrate a vulnerability
✗ Wilful destruction of data
✗ Exploitation for personal gain (stealing money, extracting PII to sell)
✗ Continued testing after receiving a cease-and-desist
✗ Activities that violate laws other than CFAA (e.g., wiretapping laws
  when intercepting third-party traffic)
```

**No safe harbour = higher risk.** Government bug bounty programmes (DoD VDP),
some corporate VDPs, and non-US programmes may not have formal safe harbour.
Treat these with extra caution.

---

### 7. Scope Analysis Workflow

Before testing any target, complete this checklist:

```markdown
## Pre-Test Scope Checklist

### Step 1 — Read the full programme policy
[ ] Read the entire policy, not just the scope table
[ ] Note any unusual or restrictive rules

### Step 2 — Define in-scope assets
[ ] List all wildcard scopes
[ ] List all explicit URLs/IPs
[ ] List all excluded subdomains/services
[ ] Confirm: does *.target.com include target.com itself?

### Step 3 — Resolve scope ambiguities
[ ] Is my target IP within a listed IP range?
[ ] Is this subdomain under a wildcard or explicitly excluded?
[ ] Is this service hosted by target.com or a third party?
[ ] If unclear: ask programme team BEFORE testing

### Step 4 — Rules of engagement
[ ] Is port scanning explicitly allowed?
[ ] Is automated scanning allowed? At what rate?
[ ] Can I create test accounts?
[ ] What is the DoS prohibition — is slow scanning exempted?

### Step 5 — Safe harbour
[ ] Does this programme have a safe harbour clause?
[ ] Does it reference specific laws (CFAA, Computer Misuse Act)?
[ ] Is this a VDP (no payout) or paid programme?

### Step 6 — Build a scope filter
[ ] Create in_scope.txt with confirmed in-scope assets
[ ] Create out_of_scope.txt with exclusions
[ ] Configure pipeline tools to use these files
```

---

### 8. Real Programme Examples

#### Example 1 — Simple Wildcard (Common)

```
SCOPE TABLE:
In Scope:
  *.acmecorp.com

Out of Scope:
  blog.acmecorp.com
  careers.acmecorp.com
  Any third-party services

Analysis:
  - api.acmecorp.com      → IN SCOPE
  - staging.acmecorp.com  → IN SCOPE
  - blog.acmecorp.com     → OUT OF SCOPE (explicitly excluded)
  - acmecorp.io           → OUT OF SCOPE (different domain)
  - acmecorp.com          → AMBIGUOUS (wildcard usually does not cover apex)
  Action: ask programme team about apex domain before testing
```

#### Example 2 — Explicit Scope + IP Range (More Complex)

```
SCOPE TABLE:
In Scope:
  app.acmecorp.com
  api.acmecorp.com
  203.0.113.0/28

Out of Scope:
  Everything else

Analysis:
  - staging.acmecorp.com  → OUT OF SCOPE (not listed, wildcard not used)
  - 203.0.113.5           → IN SCOPE (within /28 range)
  - 203.0.113.20          → OUT OF SCOPE (outside /28 = .16 to .31)
  - admin.acmecorp.com    → OUT OF SCOPE even if it resolves to 203.0.113.5
    (the IP is in scope but admin.acmecorp.com is not listed by hostname)
```

#### Example 3 — Broad Wildcard + Acquired Domains

```
SCOPE TABLE:
In Scope:
  *.acmecorp.com
  *.acmecorp.io
  *.acquired-startup.com   ← acquired company added to scope

Notes:
  - The acquisition of XYZ Corp last year means *.xyzstartup.com is now
    part of our infrastructure but is NOT in scope for this programme.
    Please do NOT test xyzstartup.com domains.

Analysis:
  - xyzstartup.com → OUT OF SCOPE (explicitly noted even though same company)
  - acquired-startup.com → IN SCOPE (explicitly added)
```

---

### 9. When You Find Out-of-Scope Bugs

This happens. Here is the correct response:

```
Scenario: You discover a critical vulnerability on a subdomain that is
          out of scope for the current programme.

Correct response:
  1. STOP testing immediately.
  2. Do not exploit further.
  3. Contact the programme team:
     "While testing in-scope assets, I incidentally discovered a potential
      vulnerability on [oos-subdomain.target.com]. This appears to be outside
      your current programme scope. Would you like me to report the details,
      or should I submit through a separate channel?"
  4. Most programmes will either expand scope or create a separate report.
  5. Some will say "not in scope, discard" — respect that answer.

Wrong responses:
  ✗ Test it anyway because "it's still target.com"
  ✗ Ignore it and not tell anyone
  ✗ Post it publicly as a "disclosure"
  ✗ Use it for personal gain
```

---

## Key Takeaways

1. **Scope analysis is the most legally critical step in bug bounty.** Testing
   out-of-scope assets is not a grey area — it is a CFAA violation regardless
   of how valid the vulnerability is.
2. **Wildcard scope (`*.target.com`) does not mean "everything."** It excludes
   explicitly listed subdomains, the apex domain (unless separately listed),
   and third-party hosted services.
3. **Build scope enforcement into your automation.** Your pipeline will run
   on out-of-scope assets if you do not explicitly filter. You are responsible
   for what your tools do.
4. **When in doubt, ask.** Most programme teams will answer scope questions
   through their platform's ask-a-question feature. A 24-hour wait for a
   scope clarification is better than a ban.
5. **Safe harbour is valuable but conditional.** It protects good-faith
   researchers who follow the rules. It does not protect boundary-pushing
   or deliberate rule violations.

---

## Exercises

### Exercise 1 — Parse a Real Programme Policy

Find a public bug bounty programme on HackerOne or Bugcrowd:

1. Read the full policy (not just the scope table).
2. Answer: What is in scope? What is explicitly out of scope?
3. Are there any unusual rules of engagement?
4. Does the programme have a safe harbour clause?
5. Identify one scope ambiguity that would require asking the team for
   clarification before testing.

---

### Exercise 2 — Scope Decision Matrix

For the following target list (assume programme scope: `*.target.com`,
excluding `blog.target.com`):

1. `api.target.com` — in or out?
2. `blog.target.com` — in or out?
3. `staging.target.com` — in or out?
4. `target.com` — in or out?
5. `target.co.uk` — in or out?
6. `api.target.com.s3.amazonaws.com` — in or out?
7. `partner.otherdomain.com` (hosted on the same server as `api.target.com`) — in or out?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 070 — Recon Automation Pipeline](DAY-0070-Recon-Automation-Pipeline.md)*
*Next: [Day 072 — Bug Bounty Recon Methodology](DAY-0072-Bug-Bounty-Recon-Methodology.md)*
