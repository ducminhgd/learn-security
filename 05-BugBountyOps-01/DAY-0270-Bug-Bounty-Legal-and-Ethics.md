---
title: "Bug Bounty Legal and Ethics — CFAA, Computer Misuse Act, Safe Harbour, OOS Actions"
tags: [legal, ethics, CFAA, Computer-Misuse-Act, safe-harbour, OOS, bug-bounty,
       responsible-disclosure, authorisation, jurisdiction, law]
module: 05-BugBountyOps-01
day: 270
related_topics:
  - Responsible Disclosure Process (Day 269)
  - Reading Program Policies and Scope (Day 262)
  - Bug Bounty Platforms Overview (Day 261)
---

# Day 270 — Bug Bounty Legal and Ethics

> "The law does not care whether you meant well. The CFAA does not have a
> 'good hacker' exception. One researcher ended up with a federal indictment
> for testing a system they thought was in scope — the scope document was
> ambiguous, the company called the FBI instead of paying the bounty. This
> is not theoretical. Read the law. Know the limits."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Understand the core computer crime laws applicable to bug bounty research.
2. Identify the specific actions that cross the legal line even within a programme.
3. Assess the quality of safe harbour language in any programme policy.
4. Make correct decisions when you discover something out of scope.
5. Understand your rights and options when a company acts in bad faith.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Responsible disclosure process | Day 269 |
| Reading program policies and scope | Day 262 |

---

## Part 1 — Computer Crime Law Overview

### United States — Computer Fraud and Abuse Act (CFAA)

The CFAA (18 U.S.C. § 1030) criminalises:

```
(a)(2): Accessing a computer without authorisation (or exceeding authorisation)
        and obtaining information.
(a)(5): Knowingly causing damage to a protected computer.
(a)(7): Threatening to damage a computer to extort.
```

**"Without authorisation"** is the critical phrase. A bug bounty programme's
policy is what grants authorisation. Testing inside scope = authorised.
Testing outside scope = potentially unauthorised = potentially CFAA violation.

**"Exceeding authorisation"** is the dangerous edge. You may be authorised
to test, but not authorised to:
- Extract data beyond what is needed for PoC
- Access systems beyond the listed scope
- Share findings with third parties before disclosure

**Penalties:** Up to 10 years federal prison for first offence accessing
computer without authorisation and obtaining information. Fine and forfeiture
on top.

### United Kingdom — Computer Misuse Act 1990 (CMA)

```
Section 1:  Unauthorised access to computer material.
            (Max: 12 months, unlimited fine)
Section 2:  Unauthorised access with intent to commit further offence.
            (Max: 5 years)
Section 3:  Unauthorised acts with intent to impair / hinder access.
            (Max: 10 years)
Section 3ZA: Unauthorised acts causing serious damage.
            (Max: life imprisonment for national infrastructure damage)
```

The CMA has **no good faith exception** in law. Safe harbour from a company
is not a legal defence under the CMA — it is a promise the company will not
cooperate with prosecution. This is practically protective, but not legally
bulletproof.

### European Union — NIS2 Directive + National Laws

Most EU member states have computer misuse laws implementing Directive
2013/40/EU. Safe harbour language in EU programmes is significant because:
- GDPR adds a data access layer: accessing another person's data, even
  to demonstrate a bug, can trigger GDPR Article 83 penalties.
- "Minimal access" is not just good practice — in the EU it is legally safer.

### Key International Principle

Authorisation requires:
1. **Explicit permission** from the owner of the computer system.
2. **Clear scope** defining what is permitted.
3. **Compliance with stated terms** (you cannot exceed the permission granted).

---

## Part 2 — What Crosses the Line Within a Programme

A bug bounty programme grants authorisation — but that authorisation has limits.
These actions remain illegal even with a programme in place:

### Accessing Real User Data

```
LEGAL: Demonstrating an IDOR using two test accounts you control.
ILLEGAL: Actually accessing any real user's data to prove the bug exists.
```

CFAA charges have been filed for "unauthorised access" even where the bug
was real and the programme later acknowledged it. The data accessed was not
theirs to access, regardless of the vulnerability.

**Practice:** Always demonstrate with controlled test accounts. Screenshot
the structure of the vulnerability. Do not read actual user data.

### Testing Out-of-Scope Systems

```
LEGAL: Testing *.example.com where *.example.com is explicitly in scope.
ILLEGAL: Testing partner.example-vendor.com because you found a link there.
```

Programme scope does not extend by implication to linked third parties.

### Denial of Service / Degradation

```
LEGAL: Sending the minimal requests needed to confirm a rate-limit bypass.
ILLEGAL: Running an actual DoS attack to prove it works.
```

Even a brief service interruption can trigger Section 3 of the CMA or the
damage provision of CFAA.

### Accessing Production Data for Bounty Leverage

```
ILLEGAL: "I have access to your user database. Pay me or I'll release it."
```

This is extortion. It does not matter that the underlying vulnerability is real.
CFAA (a)(7) + extortion statute = federal felony.

### Socially Engineering Employees

Unless explicitly in scope:

```
LEGAL: Testing authentication systems technically.
ILLEGAL: Calling a support agent and pretending to be IT to get credentials.
```

Social engineering of humans involves fraud statutes beyond just computer law.

---

## Part 3 — Evaluating Safe Harbour Language

### What Strong Safe Harbour Covers

A legally meaningful safe harbour should address:

1. **Authorised access under CFAA** — explicitly states testing per policy
   constitutes "authorised access."
2. **Civil liability waiver** — company will not sue you for tort or contract
   claims arising from in-scope testing.
3. **Third-party defence** — company will intervene if a third party
   (ISP, a partner, law enforcement) initiates action.
4. **Good-faith commitment** — company defines what good-faith means
   (no data exfiltration, no social engineering, etc.).

### What Weak Safe Harbour Fails to Cover

- No explicit CFAA/CMA language.
- "We will not pursue legal action" — binding only on that company.
  If law enforcement is called by a third party, the company's promise
  does not help you.
- "Good-faith researchers" — undefined term. What does the company
  consider good faith? Is an SSRF attempt that triggers an external request
  "good faith"?

### Safe Harbour Red Flags

```
[ ] No explicit mention of computer crime law authorisation
[ ] Vague "good faith" language without definition
[ ] "We reserve the right to modify this policy at any time without notice"
[ ] No third-party intervention commitment
[ ] No explicit timeframe or process for resolving disputes
[ ] Policy hosted at a URL that has changed/moved — older cached version may not apply
```

---

## Part 4 — OOS Discovery: What to Do

You are testing in scope and discover something clearly OOS — a vulnerability
in a third-party service, an acquired subsidiary, or a system that is explicitly
excluded.

**Decision tree:**

```
You discover a vulnerability outside the programme scope.

Is it in a third-party service (Cloudflare, Stripe, Salesforce)?
  → Yes: Contact the third party directly. Report to their security@.
         Do not report to the bug bounty programme — they cannot fix it.

Is it in a subsidiary explicitly excluded from scope?
  → Yes: Contact the programme and say: "I found X during research on
         your programme. It is in [excluded subsidiary]. What is the
         correct reporting channel?" Let them guide you.

Is it in a domain that is similar to, but not explicitly included in, scope?
  → Yes: Do not test further. Contact the programme for clarification.
         "Is *.example-staging.com in scope? I found a reference to it
         during my testing of *.example.com."

Did you accidentally access something OOS before realising it was OOS?
  → Yes: Stop immediately. Document exactly what you did and what you accessed.
         Report it to the programme immediately: "I accidentally accessed
         [X] while investigating [in-scope target]. I stopped immediately.
         Here is what happened." This transparency protects you.
```

---

## Part 5 — When a Company Acts in Bad Faith

It happens. A company receives a valid report, does not pay, threatens legal
action, or contacts law enforcement.

### Your Protections

1. **Documentation.** Every email, every timestamp, every scope reference.
   This is your defence.
2. **Platform mediation.** If submitted through HackerOne or Bugcrowd, request
   mediation. The platform has financial and reputational incentives to resolve
   disputes fairly.
3. **Community.** The bug bounty community documents bad-faith programmes.
   @Hacker0x01, @BugcrowdResearch, and the community Twitter/Discord will
   amplify a legitimate case of researcher mistreatment.
4. **Legal advice.** If a company sends legal threats, consult a lawyer before
   responding. Electronic Frontier Foundation (EFF) has resources and sometimes
   provides assistance.

### Things Not to Do

- Do not publish the vulnerability as retaliation.
- Do not escalate to the press without legal advice.
- Do not contact the CISO and threaten them.
- Do not discuss the case publicly until you have legal advice and the
  situation is resolved.

---

## Key Takeaways

1. **Authorisation is specific and bounded.** A programme policy is a
   legal document. What it says you can test, you can test. What it does
   not say, you cannot. There are no implicit permissions in computer law.
2. **The CMA has no good faith exception.** In the UK, your protection
   from prosecution is the company's promise not to cooperate with law
   enforcement — not a legal exemption. Strong safe harbour language is
   the practical substitute for a legal exemption that does not exist.
3. **Real user data is never part of your PoC.** Not even to prove the
   vulnerability exists. Use controlled test accounts. This is both the
   ethical standard and the legal standard. Accessing real user data is
   a computer crime regardless of the vulnerability's validity.
4. **Document everything from the moment of discovery.** The researcher
   who gets into legal trouble is the one who cannot prove when they found
   it, what they accessed, and how they attempted to report it.
5. **The ecosystem depends on good-faith behaviour from both sides.** When
   researchers act within bounds and companies honour safe harbour commitments,
   everyone benefits. One bad-faith actor on either side degrades trust for
   the entire community.

---

## Exercises

1. Find three real-world cases where researchers faced legal action from
   organisations despite believing they were acting in good faith. What were
   the legal theories used? What was the outcome? What could each researcher
   have done differently?

2. Read the full text of CFAA Section 1030(a)(2). Identify the three elements
   the prosecution must prove. For each element, write one scenario from bug
   bounty research where that element is clearly not met (protected) and one
   where it could be argued to be met (at risk).

3. Assess the safe harbour language of five programmes using the evaluation
   framework from Part 3. Rank them from strongest to weakest protection.

4. Write a decision tree for the following scenario: You are testing a wildcard
   scope `*.example.com`. Your subdomain enumeration discovers `payments.example.com`
   which responds with Stripe-branded pages. While probing, you find a URL
   parameter on `example.com` that makes a server-side request to `payments.example.com`.
   Map the legal questions, the decisions you must make, and the correct actions
   at each step.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q270.1, Q270.2 …).
> Follow-up questions use hierarchical numbering (Q270.1.1, Q270.1.2 …).

---

## Navigation

← Previous: [Day 269 — Responsible Disclosure Process](DAY-0269-Responsible-Disclosure-Process.md)
→ Next: [Day 271 — Studying Public Disclosures](DAY-0271-Studying-Public-Disclosures.md)
