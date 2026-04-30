---
title: "Reading Program Policies and Scope — Scope Tables, Wildcards, OOS Traps, Safe Harbour"
tags: [bug-bounty, scope, policy, safe-harbour, VDP, wildcard, OOS, in-scope,
       responsible-disclosure, legal, operations]
module: 05-BugBountyOps-01
day: 262
related_topics:
  - Bug Bounty Platforms Overview (Day 261)
  - Choosing the Right Program (Day 263)
  - Responsible Disclosure Process (Day 269)
  - Bug Bounty Legal and Ethics (Day 270)
---

# Day 262 — Reading Program Policies and Scope

> "Scope is not a technicality. Scope is the line between a paid researcher
> and a criminal. I have seen talented researchers get legal letters — not
> because they found a bad bug, but because they tested something out of scope.
> Read every word. Every. Word."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Parse a bug bounty programme policy document completely and correctly.
2. Distinguish in-scope from out-of-scope targets using explicit and wildcard scope.
3. Identify common OOS traps that catch researchers who skim policies.
4. Assess the quality of a programme's safe harbour language.
5. Build a personal scope checklist to run before starting any programme.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Bug bounty platforms overview | Day 261 |
| Active recon and scope analysis | Day 071 |

---

## Part 1 — Anatomy of a Programme Policy

A typical bug bounty programme policy contains these sections:

```
1. Programme Overview       — Who is running it, what is the goal
2. Scope (In-Scope Assets)  — What you can test
3. Out-of-Scope (OOS)       — What you cannot test
4. Rules of Engagement      — How you must conduct testing
5. Bounty Table             — How much each severity pays
6. Response SLAs            — How fast they promise to respond
7. Safe Harbour             — Legal protection language
8. Disclosure Policy        — When/how you can publish findings
```

You must read all eight sections before touching the target.

---

## Part 2 — Scope Tables

### Explicit Scope

Explicit scope lists specific assets by name:

```
In-scope:
  *.example.com
  api.example.com
  admin.example.com
  iOS app: com.example.app (App Store ID: 12345678)
  Android app: com.example.app
```

Every asset listed here can be tested. Assets **not listed** cannot be tested,
even if they are technically reachable from a listed target.

### Wildcard Scope

`*.example.com` covers:
- `www.example.com` ✓
- `api.example.com` ✓
- `dev.example.com` ✓
- `staging-01.internal.example.com` ✓ (subdomain of example.com)

`*.example.com` does **NOT** cover:
- `example.com` (bare domain — no subdomain) ✗
- `sub.subdomain.example.com` ✗ (two levels deep — unless policy says otherwise)
- `example.co.uk` ✗ (different TLD)

**When in doubt about a wildcard:** Test only the explicit subdomain you found.
If your methodology discovers `payments.example.com` and the scope is `*.example.com`,
that subdomain is in-scope. If you find a reference to `payments.examplepartner.com`,
stop — that is a different domain, even if the company owns it.

### Third-Party Services (Common OOS Trap)

Many programmes explicitly state:

```
Out-of-scope:
  Third-party services (Salesforce, Zendesk, Cloudflare, etc.)
  Shared infrastructure not exclusively operated by Example Corp
```

A vulnerability in the company's Zendesk instance is **out of scope** even if
you can reach it from an in-scope domain. Report it directly to Zendesk, not
the programme. The company does not control Zendesk's security — they cannot
fix it.

---

## Part 3 — Common OOS Traps

### Trap 1: Subdomain Scope vs Domain Scope

```
Scope: *.api.example.com
```

This covers `v1.api.example.com` and `v2.api.example.com`.
It does **not** cover `www.example.com` or `api.example.com` itself.

### Trap 2: Excluded Vulnerability Classes

Many programmes exclude entire categories regardless of target:

```
Out-of-scope vulnerability classes:
  - Self-XSS (XSS requiring attacker-controlled account, no victim interaction)
  - CSV injection
  - Clickjacking on pages with no sensitive actions
  - Missing security headers (without demonstrated impact)
  - Rate limiting on non-authentication endpoints
  - Software version disclosure
  - SSL/TLS configuration issues without exploitation impact
  - SPF/DKIM/DMARC misconfiguration without phishing PoC
```

Finding a `TRACE` method enabled is not a vulnerability in most programmes.
Finding clickjacking on a login page usually is. **Read the exclusions list.**

### Trap 3: Staging and Development Environments

```
Out-of-scope: staging.example.com, *.dev.example.com, *.internal.example.com
```

Staging environments often have different vulnerability profiles — sometimes
worse. But testing them when explicitly OOS is a policy violation.

Conversely, some programmes explicitly include staging:

```
In-scope: staging.example.com (include findings, no bounty for staging-only bugs)
```

Read which case applies.

### Trap 4: Acquired Subsidiaries

A company may scope-limit to their primary product, excluding recent acquisitions:

```
Out-of-scope:
  All assets owned by AcquiredCo (acquired 2023) — not yet within programme scope
```

Running `amass` and finding `acq.example.com` pointing to AcquiredCo
infrastructure does not make it in-scope. Check acquisition dates against
scope update history.

### Trap 5: Social Engineering and Physical Testing

Unless a programme explicitly includes it:

```
Out-of-scope:
  Social engineering of employees
  Physical security testing
  DDoS / stress testing
  Automated testing generating > N requests per second
```

A rate-limiting bypass that requires sending 10,000 requests per second to
demonstrate is OOS if automated high-volume testing is prohibited. Demonstrate
with a small number of requests and note the theoretical scale.

---

## Part 4 — Rules of Engagement

Every programme has RoE. These are the most common constraints:

### Test Account Requirements

```
You must only test against accounts you own or have explicit permission to test.
Creating multiple test accounts is permitted. Testing against accounts of
real users without their consent is not permitted.
```

**Implication:** For IDOR testing, create two test accounts (attacker + victim).
Never access a real user's data even if the vulnerability makes it possible.
Document that the IDOR exists using your own controlled accounts.

### Impact Limitation

```
Stop testing immediately upon demonstrating impact. Do not extract more data
than is necessary to prove the vulnerability exists.
```

For a SQL injection that returns all user emails: extract 3–5 rows (your own
test account rows plus an obviously dummy row). Do not dump the entire database.
Screenshot the output showing the vulnerability is real. Stop there.

### Notification Requirement

```
If testing could cause availability impact (service interruption, data corruption),
contact the security team before proceeding.
```

Testing a DoS vector on production without prior contact = OOS, regardless
of whether the vulnerability is real.

---

## Part 5 — Safe Harbour Language

Safe harbour is the legal protection the programme grants you for testing
in compliance with the policy. Quality varies significantly.

### Strong Safe Harbour (Good Programme)

```
Example Corp authorises security research on the assets listed in this programme
under the terms stated here. Security research conducted in accordance with
these policies will not result in Example Corp initiating legal action against
you or referring you to law enforcement. We consider activities conducted
consistent with this policy to constitute "authorised access" under the Computer
Fraud and Abuse Act and other applicable computer crime laws.

If legal action is initiated by a third party against you for activities
conducted in accordance with this policy, we will take steps to make known
that your activities were conducted with our authorisation.
```

This is strong. It explicitly invokes CFAA authorised access language and
commits to third-party intervention.

### Weak Safe Harbour (Caution)

```
We appreciate researchers who report vulnerabilities responsibly and will
not pursue legal action against good-faith reporters.
```

"Appreciate" and "good-faith" are undefined. This is not a legal commitment.
A prosecutor does not care what a company "appreciates." This language is
better than nothing, but you are not fully protected.

### No Safe Harbour (Avoid for New Researchers)

Some VDPs are simply:

```
Please report vulnerabilities to security@example.com
```

No scope. No protection. Report only clear, non-controversial bugs here.

---

## Part 6 — Scope Decision Framework

Before every testing session:

```
[ ] 1. Download or print the full programme policy
[ ] 2. Mark every in-scope asset explicitly
[ ] 3. Mark every OOS asset and vulnerability class explicitly
[ ] 4. Note any rate limits or volume constraints
[ ] 5. Note any test account requirements
[ ] 6. Read the safe harbour language — is it adequate?
[ ] 7. Write down three scenarios where you might accidentally go OOS
        and define how you will avoid them
[ ] 8. Never start testing until these 7 steps are done
```

---

## Key Takeaways

1. **Scope is binary.** Either the asset is in-scope or it is not. There is
   no "close enough." Testing OOS assets is a policy violation and potentially
   a legal issue — regardless of how interesting the vulnerability is.
2. **Third-party services are almost always OOS.** The target company cannot
   fix Salesforce. Reporting to them wastes everyone's time. File a separate
   disclosure with the third party directly.
3. **Safe harbour quality matters.** Before dedicating serious time to a
   programme, assess whether its safe harbour language gives you real legal
   protection. Weak or absent safe harbour is a flag.
4. **The OOS trap is asymmetric.** The cost of testing OOS (policy violation,
   potential legal action, platform ban) far exceeds the cost of being
   conservative and missing a bug. When uncertain, do not test — ask the
   programme.
5. **Exclusion lists are as important as inclusion lists.** A programme
   might scope `*.example.com` but exclude 20 subdomain types. Read both
   directions before running a single scan.

---

## Exercises

1. Find three different programmes on HackerOne with different levels of
   safe harbour language quality. Classify each as Strong, Weak, or None.
   Justify your classification with a quote from each policy.

2. Read the policy for one public programme of your choice. Create a
   structured scope document:
   - In-scope assets (explicit and wildcard)
   - OOS assets
   - Excluded vulnerability classes
   - Rate limits / testing constraints
   - Safe harbour assessment (Strong / Weak / None + quote)

3. You discover during recon that `cdn.example.com` resolves to a Cloudflare
   IP and `payments.example.com` resolves to a Stripe-hosted page. The scope
   is `*.example.com`. Are either of these in-scope? What do you do?
   Write a one-paragraph answer.

4. A programme says: "Testing must not affect other users." You find a
   stored XSS in a public comment field. To prove impact, you would normally
   fire a cookie-stealer. How do you demonstrate the vulnerability without
   affecting other users? Describe your exact methodology.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q262.1, Q262.2 …).
> Follow-up questions use hierarchical numbering (Q262.1.1, Q262.1.2 …).

---

## Navigation

← Previous: [Day 261 — Bug Bounty Platforms Overview](DAY-0261-Bug-Bounty-Platforms-Overview.md)
→ Next: [Day 263 — Choosing the Right Program](DAY-0263-Choosing-the-Right-Program.md)
