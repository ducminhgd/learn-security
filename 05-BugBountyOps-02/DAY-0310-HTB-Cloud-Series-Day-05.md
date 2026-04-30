---
title: "HTB Cloud Series Day 5 — Full Cloud Kill Chain"
tags: [HTB, HackTheBox, CTF, cloud, AWS, kill-chain, full-assessment, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 310
related_topics:
  - HTB Cloud Series Day 4 (Day 309)
  - HTB API Series Day 5 (Day 305)
  - Cloud Exploitation (R-09)
---

# Day 310 — HTB Cloud Series Day 5: Full Cloud Kill Chain

> "The cloud kill chain is reconnaissance → access → enumeration → escalation →
> lateral movement → objective. Same structure as on-prem. Different tools.
> Same patience required."
>
> — Ghost

---

## Goals

Complete a full cloud attack chain challenge with no pre-selected technique.
Apply all cloud techniques from Days 306–309 end-to-end.

**Time budget:** 5–6 hours.

---

## Kill Chain Log

### Stage 1 — External Reconnaissance

```
Recon output:
  Domains / subdomains found: ___
  Cloud provider identified by: ___
    [ ] CNAME to *.amazonaws.com
    [ ] Response headers (Server: AmazonS3, x-amz-*)
    [ ] SSL certificate (*.s3.amazonaws.com)
    [ ] HTML source (bucket URLs)
    [ ] JS files (SDK config with region/bucket)

  S3 bucket names identified: ___
  API endpoints identified: ___
  IAM role hints: ___
```

### Stage 2 — Initial Access

```
Method:
  [ ] Public S3 bucket — credentials found in object
  [ ] SSRF → metadata endpoint
  [ ] Exposed IAM key in JS / source code
  [ ] Publicly exposed AWS access keys in GitHub (if in scope)
  [ ] Misconfigured Cognito identity pool (unauthenticated role)

Initial credential:
  Type:   IAM user / EC2 role / Lambda role / ECS task role
  ARN:    ___
  AKID:   AKIA___
```

### Stage 3 — Enumeration

```bash
# Permission enumeration
python3 enumerate-iam.py \
  --access-key AKID \
  --secret-key SECRET \
  [--session-token TOKEN]

# Key permissions found:
  iam:   ___
  s3:    ___
  ec2:   ___
  sts:   ___
  ssm:   ___
  lambda:___
  Other: ___

# Service inventory
aws s3 ls
aws ec2 describe-instances
aws lambda list-functions
aws rds describe-db-instances
aws ecs list-clusters
```

```
Services with access: ___
Most permissive finding: ___
```

### Stage 4 — Privilege Escalation

```
Path chosen: ___
Commands executed:
  ___
  ___

Final identity after escalation:
  ARN:         ___
  Permissions: AdministratorAccess / partial / ___
```

### Stage 5 — Lateral Movement

```
From initial access to new account/resource:
  Path: ___
  e.g.:
    EC2 role → S3 bucket with Lambda code → modify Lambda env → get RDS password
    EC2 role → SSM Parameter Store → RDS admin creds
    IAM user → cross-account role assumption
    Lambda execution role → Secrets Manager

Commands:
  ___
```

### Stage 6 — Objective / Flag

```bash
# Common flag locations
aws s3 ls s3://TARGET-FLAG/
aws ssm get-parameter --name /flag --with-decryption
aws secretsmanager get-secret-value --secret-id prod/flag
aws dynamodb scan --table-name flags
```

```
FLAG{___}
Total chain length (stages used): ___
Total time: ___ min
```

---

## Cloud Series Retrospective (Days 306–310)

```
Cloud provider most challenged: AWS / Azure / GCP
Technique I am now confident in: ___
Technique I still need to practise: ___

Most important CloudTrail event to alert on for each technique:
  IAM escalation:      ___
  SSRF to metadata:    ___
  S3 misconfiguration: ___
  Cross-account:       ___

Defender recommendation I would include in a real pentest report:
  1. ___
  2. ___
  3. ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q310.1, Q310.2 …).

---

## Navigation

← Previous: [Day 309 — HTB Cloud Series Day 4](DAY-0309-HTB-Cloud-Series-Day-04.md)
→ Next: [Day 311 — CTF Web Competition Day 1](DAY-0311-CTF-Web-Competition-Day-01.md)
