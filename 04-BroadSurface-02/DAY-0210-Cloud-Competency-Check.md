---
title: "Cloud Security Competency Check — Self-Assessment and Gate Submission"
tags: [cloud, competency-check, AWS, IAM, S3, SSRF, privilege-escalation,
       gate, self-assessment, report-submission, ATT&CK, CVSS, LocalStack]
module: 04-BroadSurface-02
day: 210
related_topics:
  - Cloud Threat Model (Day 181)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Security Review (Day 196)
  - Cloud Kill Chain Speed Run (Day 207)
  - Cloud Report Writing (Day 209)
  - Mobile Security (Day 211)
---

# Day 210 — Cloud Security Competency Check

> "Thirty days of cloud. Today you prove what you actually learned — not what
> you read. There are no notes here. No hints. No kill chain reference on the
> wall. Just you, a terminal, and a target. If you have done the work, the gate
> opens. If it does not open — you know exactly what to fix. Either way,
> you leave knowing where you stand."
>
> — Ghost

---

## Structure

| Section | Format | Time |
|---|---|---|
| Part 1: Conceptual Questions | Written, no notes | 40 min |
| Part 2: IAM Enumeration Sprint | Hands-on, LocalStack | 30 min |
| Part 3: Kill Chain Execution | Hands-on, timed | 45 min |
| Part 4: Finding Report | Written submission | 30 min |
| Part 5: Detection Query | Written, no notes | 15 min |
| **Total** | | **~2.5–3 hours** |

---

## Part 1 — Conceptual Questions

Answer all 10. No notes. No browser. Write answers in the Questions section.

**Q1.** An EC2 instance is running with IMDSv1 enabled and has an IAM role
attached with the following policy:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
    "Resource": "arn:aws:iam::*:policy/*"
  }]
}
```

(a) What is the attack path from SSRF on this instance to
    AdministratorAccess?  
(b) What is the exact sequence of AWS API calls?  
(c) What single configuration change closes the IMDS exposure
    (not the IAM exposure)?

---

**Q2.** Explain the difference between these two S3 bucket configurations
and the security implication of each:

```json
// Configuration A — Bucket Policy
{
  "Principal": "*",
  "Action": "s3:GetObject",
  "Effect": "Allow",
  "Resource": "arn:aws:s3:::example-bucket/*"
}

// Configuration B — Bucket ACL
{
  "Grantee": {"Type": "Group",
    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
  "Permission": "READ"
}
```

(a) Which configuration grants public read access to objects?  
(b) Which grants public read access to the bucket listing?  
(c) Which can remain effective even when the account-level
    "Block Public Access" setting is enabled (under certain conditions)?

---

**Q3.** You run the following command against a LocalStack environment:

```bash
aws sts get-caller-identity
```

The output is:

```json
{
  "UserId": "AROAEXAMPLEID:i-0abc123def456",
  "Account": "000000000000",
  "Arn": "arn:aws:sts::000000000000:assumed-role/ec2-backup-role/i-0abc123def456"
}
```

(a) What type of credential is this?  
(b) How was this credential obtained?  
(c) What does the `AROA` prefix tell you about the principal?  
(d) What does the session name `i-0abc123def456` tell you?

---

**Q4.** List the 5 IAM privilege escalation techniques covered in this module.
For each one, state: (a) the IAM permission(s) required and (b) the AWS API
call(s) that execute the escalation.

---

**Q5.** A Lambda function has this resource-based policy:

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::000000000000:role/ec2-app-role"},
  "Action": "lambda:InvokeFunction",
  "Resource": "arn:aws:lambda:us-east-1:000000000000:function:AdminHelper"
}
```

The `ec2-app-role` also has `iam:PassRole` for the Lambda execution role, and
the Lambda execution role has `iam:*` permissions.

(a) Describe the PassRole + Lambda privilege escalation path step by step.  
(b) What is the ATT&CK technique ID for this pattern?  
(c) What is the fix?

---

**Q6.** You are performing a cloud threat model on a new architecture. The
design includes:

- An ECS Fargate task running a web application
- The task has an IAM task role with `s3:*` on all buckets
- The application accepts URLs from users and fetches their content
- No IMDSv2 enforcement is configured

(a) Identify 3 attack paths from an external attacker to S3 data
    exfiltration.  
(b) For each path, name the ATT&CK technique.  
(c) For each path, name the control that closes it.

---

**Q7.** Explain what CloudTrail records and what it does NOT record.

Specifically answer:
(a) Are `s3:GetObject` calls logged in CloudTrail by default?  
(b) If not, what must be enabled to capture them?  
(c) What is the retention period for CloudTrail logs in S3, and who controls it?  
(d) Name 2 ways an attacker can attempt to reduce CloudTrail visibility
    without disabling it outright.

---

**Q8.** Match each Kubernetes RBAC resource + verb to the privilege
escalation or impact it enables:

| RBAC Permission | Impact |
|---|---|
| `secrets:list` (cluster-wide) | ? |
| `clusterrolebindings:create` | ? |
| `pods/exec` | ? |
| `configmaps:get` (kube-system) | ? |
| `serviceaccounts/token:create` | ? |

---

**Q9.** A container is started with `docker run --privileged -v /:/host ubuntu`.

(a) What does `--privileged` do that makes this dangerous?  
(b) What does `-v /:/host` expose to the container?  
(c) Write the 3-command sequence to escalate from inside this container to
    full root on the host without using the cgroup release_agent technique.  
(d) What Falco rule would detect this container launch?

---

**Q10.** You find an S3 bucket named `nimbus-financial-exports` that is
publicly accessible (no authentication required) and contains files named
`customer-export-2024-01-01.csv`.

(a) What is the CVSS 3.1 vector and score for this finding?  
(b) What three AWS controls would prevent this misconfiguration?  
(c) Write the AWS CLI command an attacker uses to list and download the
    contents without authentication.  
(d) What CloudTrail or S3 log event would show this access, and what must
    be enabled to capture it?

---

## Part 2 — IAM Enumeration Sprint (30 min)

Start the lab. Timer begins now.

```bash
cd 04-BroadSurface-02/samples/competency-lab/
docker compose up -d
source .env
# You start with: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY set
# These are low-privilege credentials. Your goal is to:
# 1. Determine what role/user you are
# 2. Enumerate all attached policies and their permissions
# 3. Identify every privilege escalation path available to you
# 4. Document the highest-privilege action you can perform
# Stop when you have documented the escalation path — do NOT execute it yet
```

Record in the Questions section:

```
Caller identity (ARN): ___
Attached policies: ___
Permissions found: ___
Escalation path identified: ___
Time taken: ___ min
```

---

## Part 3 — Kill Chain Execution (45 min)

Using the same lab environment. Timer begins now.

**Objective:** Execute the full kill chain from your current low-privilege
credentials to persistence. No notes, no kill chain reference, no history.

```bash
history -c
# Start timer
```

Checkpoints (mark each as you complete it):
```
[ ] 1. Identity confirmed (sts:GetCallerIdentity)
[ ] 2. Permissions fully enumerated
[ ] 3. Escalation path identified
[ ] 4. Admin access achieved (confirmed by successful iam:ListUsers)
[ ] 5. Sensitive data exfiltrated (S3 file or Secrets Manager value)
[ ] 6. Persistence planted (backdoor user created + key verified)
```

Record:
- Phase 1–2 (recon): ___ min
- Phase 3 (escalation): ___ min
- Phase 4 (exfil): ___ min
- Phase 5 (persistence): ___ min
- **Total: ___ min**

Pass threshold: under 30 minutes.

---

## Part 4 — Finding Report (30 min)

Write one complete, submission-ready report for the SSRF → IMDS → PrivEsc
chain from Part 3.

Requirements:
- Title in impact-first format
- CVSS 3.1 vector + score
- CWE + ATT&CK citation
- Description: root cause + attack scenario (3 paragraphs)
- Steps to reproduce: exact commands, expected output shown
- Evidence: at least 2 pieces
- Impact: specific and quantified
- Remediation: one actionable fix, not a principle

Paste the report into the Questions section.

---

## Part 5 — Detection Query (15 min)

Write, from memory, the jq query that extracts from a CloudTrail log file
(array at `.Records[]`) all events matching this pattern:

- User identity is a role credential (ARN contains `assumed-role`)
- The event occurred within a 10-minute window
- The event names are any of: `GetCallerIdentity`, `ListAttachedRolePolicies`,
  `GetPolicyVersion`, `CreatePolicyVersion`, `ListUsers`

The query should output: `eventTime`, `userIdentity.arn`, `eventName`.

Write the query. Then write, in 2 sentences, why this query is insufficient
as a production detection rule (i.e., what would cause false positives
or false negatives).

---

## Competency Gate Criteria

You pass this gate when:

| Criterion | Minimum bar |
|---|---|
| Conceptual questions | ≥ 8/10 correct without notes |
| IAM enumeration sprint | Escalation path identified in ≤ 15 min |
| Kill chain execution | Full chain in ≤ 30 min with no notes |
| Finding report | Reproducible by a stranger; CVSS vector correct |
| Detection query | Syntactically valid jq; limitations correctly identified |

If you do not pass: identify which criterion you failed. Return to the
specific practice day and re-do that exercise before re-taking the check.

| Failure | Return to |
|---|---|
| Conceptual Q1–Q3 (IMDS, IAM basics) | Day 183 — IAM Misconfiguration Attacks |
| Conceptual Q4–Q5 (PrivEsc techniques) | Day 197 — Cloud Practice: IAM PrivEsc |
| Conceptual Q6–Q7 (threat model, CloudTrail) | Day 196 — Cloud Security Review |
| Conceptual Q8–Q9 (container, K8s) | Day 206 — Cloud Practice: Container + K8s |
| Enumeration sprint over 15 min | Day 197 — repeat enumeration drills |
| Kill chain over 30 min | Day 207 — repeat speed runs |
| Report quality insufficient | Day 209 — re-do report writing sprint |
| Detection query incorrect | Day 203 — CloudTrail detection |

---

## What Comes Next

Module 04-BroadSurface-02 is complete.

You now have a working cloud security toolkit:

- AWS threat modelling (IAM, S3, EC2, Lambda, ECS, Secrets Manager)
- Attack techniques (SSRF → IMDS, IAM PrivEsc, S3 misconfiguration)
- Container and Kubernetes exploitation
- Cloud persistence and detection evasion
- CloudTrail log analysis and detection engineering
- Bug bounty methodology for cloud targets
- Kill chain execution under time pressure

The next module moves to **mobile security**:
Android static and dynamic analysis, certificate pinning bypass, Frida,
insecure storage, iOS app security, mobile API testing, and bug bounty
methodology for mobile programmes.

---

## Questions and Competency Check Answers

> Part 1 — Write your answers below. Label Q1 through Q10.

> Part 2 — Paste your IAM enumeration sprint results.

> Part 3 — Record your kill chain phase times and total.

> Part 4 — Paste your complete finding report.

> Part 5 — Paste your jq detection query and limitations analysis.

> General questions use numbering Q210.1, Q210.2 …

---

## Navigation

← Previous: [Day 209 — Cloud Practice: Report Writing Sprint](DAY-0209-Cloud-Practice-Report-Writing.md)
→ Next: [Day 211 — Mobile Security Overview](../04-BroadSurface-03/DAY-0211-Mobile-Security-Overview.md)
