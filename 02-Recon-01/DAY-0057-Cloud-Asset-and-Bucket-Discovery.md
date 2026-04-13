---
title: "Cloud Asset and Bucket Discovery — S3, Azure Blob, GCP, Firebase"
tags: [recon, cloud, s3, azure-blob, gcp-bucket, firebase, bucket-discovery, misconfig,
       cloud-metadata, T1592, T1596, cloud-osint]
module: 02-Recon-01
day: 57
related_topics:
  - GitHub Code Recon and Secret Hunting (Day 056)
  - Social Media and Job Posting Intel (Day 058)
  - Cloud Exploitation — IAM Misconfiguration (later module)
  - MITRE ATT&CK T1592 (Gather Victim Host Information)
---

# Day 057 — Cloud Asset and Bucket Discovery

## Goals

By the end of this lesson you will be able to:

1. Explain cloud object storage naming conventions for AWS S3, Azure Blob, and GCP.
2. Enumerate public S3 buckets belonging to a target using brute force and
   naming pattern enumeration.
3. Use GrayhatWarfare to find open buckets without sending requests to the target.
4. Identify exposed Firebase Realtime Databases and Elasticsearch clusters.
5. Understand the cloud metadata endpoint risk even in a passive-recon context.
6. Assess the impact of a public bucket and write a clear finding.

---

## Prerequisites

- [Day 056 — GitHub Code Recon and Secret Hunting](DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md)

---

## Main Content

### 1. Cloud Storage as an Attack Surface

Public cloud storage — S3 buckets, Azure Blob containers, GCP buckets — is one
of the most consistently exploited categories in bug bounty programmes. The core
problem:

> Storage services default to public or have confusingly complex permission models.
> Developers create buckets for a specific purpose (website assets, backups, logs)
> and forget they are public. The data remains accessible indefinitely.

**Notable incidents involving public cloud storage:**

| Year | Organisation | Exposure | Records |
|---|---|---|---|
| 2017 | Verizon | S3 bucket with 14M customer records | 14M |
| 2017 | Booz Allen Hamilton | US government contracts, credentials | Classified |
| 2019 | Capital One | 100M customer applications (via SSRF) | 100M |
| 2020 | Microsoft | 250M customer service records in public S3 | 250M |
| 2021 | Ford Motor | Internal documents, marketing materials | Sensitive |
| 2022 | Toyota | Source code and access keys on GitHub | Critical |

---

### 2. AWS S3 — Naming and Discovery

#### S3 Bucket Naming Rules

AWS S3 bucket names must be:
- 3–63 characters
- Lowercase letters, numbers, hyphens
- Start with a letter or number
- Globally unique across ALL AWS customers

**Attacker implication:** Bucket names are globally enumerable. You can check
if a name is taken — and if it is, access it if it is public.

#### Naming Patterns to Guess

Organisations follow predictable naming conventions:

```
{company}
{company}-{env}          → acmecorp-prod, acmecorp-staging, acmecorp-dev
{env}-{company}          → prod-acmecorp, staging-acmecorp
{company}-{purpose}      → acmecorp-backups, acmecorp-logs, acmecorp-assets
{company}-{app}-{env}    → acmecorp-api-prod, acmecorp-web-staging
{company}-{region}       → acmecorp-us-east-1
{company}-{year}         → acmecorp-2023, acmecorp-2022
{company}-public         → acmecorp-public, acmecorp-cdn
{company}-internal       → acmecorp-internal  ← often misconfigured
{company}-data           → acmecorp-data, acmecorp-db-backups
```

#### Checking a Bucket — Manual

```bash
# Check if a bucket exists and is public
# Method 1: HTTPS URL
curl -s "https://acmecorp.s3.amazonaws.com/"

# Method 2: Virtual-hosted style (required for buckets in non-us-east-1)
curl -s "https://acmecorp.s3.us-west-2.amazonaws.com/"

# Possible responses:
# 200 OK with XML → Public bucket, list contents
# 403 Forbidden   → Exists but not public (still interesting — may be world-writable)
# 404 NoSuchBucket → Does not exist

# List contents of a public bucket
aws s3 ls s3://acmecorp --no-sign-request

# Download a specific file from a public bucket
aws s3 cp s3://acmecorp/backup.sql . --no-sign-request

# Recursively list a public bucket
aws s3 ls s3://acmecorp --recursive --no-sign-request
```

**The `--no-sign-request` flag** skips AWS authentication — critical for
accessing public buckets without an AWS account.

---

#### s3scanner — Automated Bucket Discovery

```bash
# Install
pip install s3scanner

# Check a single bucket name
s3scanner scan --bucket acmecorp

# Scan from a wordlist of bucket name candidates
s3scanner scan --bucket-file bucket_names.txt

# Generate wordlist from target name
python3 - <<'EOF'
import itertools

company = "acmecorp"
envs = ["prod", "production", "staging", "dev", "development", "test", "qa"]
purposes = ["assets", "backups", "backup", "logs", "data", "static", "cdn",
            "uploads", "files", "media", "internal", "public", "private"]

names = set()
names.add(company)
for env in envs:
    names.add(f"{company}-{env}")
    names.add(f"{env}-{company}")
for purpose in purposes:
    names.add(f"{company}-{purpose}")
    names.add(f"{company}.{purpose}")
for env, purpose in itertools.product(envs, purposes):
    names.add(f"{company}-{env}-{purpose}")

with open("bucket_candidates.txt", "w") as f:
    f.write("\n".join(sorted(names)))

print(f"Generated {len(names)} bucket name candidates")
EOF
```

---

### 3. Passive Bucket Discovery — GrayhatWarfare

GrayhatWarfare indexes the contents of public S3 buckets, Azure Blob containers,
and GCP buckets. You search their database — **no requests reach the target.**

```
URL: https://grayhatwarfare.com/

Free tier: Basic search, limited results
Paid: Full search, download capability

Search examples:
  Search: "acmecorp"
  → Returns all known open buckets containing "acmecorp"
  → Shows file listing, bucket URL, last indexed date
```

GrayhatWarfare also indexes file contents for searchable file types — you can
search for specific patterns within bucket contents.

---

### 4. Azure Blob Storage

Azure uses a different URL structure:

```
https://{storage-account}.blob.core.windows.net/{container}/{blob}
```

#### Naming discovery

```bash
# Check if a storage account exists
curl -s "https://acmecorp.blob.core.windows.net/"
# 400 Bad Request with XML → storage account exists
# "StorageAccountNotFound" → does not exist

# Check for public containers
curl -s "https://acmecorp.blob.core.windows.net/$web?restype=container&comp=list"

# Common Azure storage account name patterns
# (same naming constraints as S3 — lowercase, numbers, no hyphens, max 24 chars)
# acmecorp, acmecorpprod, acmecorpdev, acmecorpstg, acmecorpassets
```

#### Tools for Azure

```bash
# MicroBurst — Azure recon toolkit
git clone https://github.com/NetSPI/MicroBurst
Import-Module ./MicroBurst.psm1  # PowerShell

# Enumerate storage accounts for a company
Invoke-EnumerateAzureBlobs -Base acmecorp

# Python alternative
pip install azure-storage-blob
```

---

### 5. Google Cloud Platform (GCP) Buckets

GCP uses a similar URL structure to S3:

```
https://storage.googleapis.com/{bucket-name}/
```

```bash
# Check if a bucket is public
curl -s "https://storage.googleapis.com/acmecorp-assets/"

# Same naming patterns as S3 — use the same wordlist
# GCP-specific: bucket names can contain dots
# acmecorp.prod, acmecorp.assets, acmecorp.backups

# GCP bucket brute force
pip install gcptool
# or use s3scanner with GCP flag:
s3scanner scan --bucket acmecorp --provider gcp
```

---

### 6. Firebase Realtime Database Exposure

Firebase Realtime Database is a NoSQL database hosted at:

```
https://{project-id}.firebaseio.com
```

Many Firebase databases are configured with no authentication rules (defaulting
to public read/write during development and never changed).

```bash
# Check if a Firebase database exists and is public
# Append .json to query the root
curl -s "https://acmecorp-app.firebaseio.com/.json"

# Response is unindented JSON containing the entire database
# If you get {"error": "Permission denied"} → exists but private
# If you get null → exists but empty
# If you get actual data → full read access

# Enumerate Firebase project IDs
# Common patterns: {company}-app, {company}-prod, {company}-{service}
# Find in: Android APK (strings analysis), iOS IPA, web app JavaScript files
```

**Bug bounty value:** Firebase database fully exposed = Critical severity.
The finding is often called "Unauthenticated Firebase Database Access."

---

### 7. Shodan for Cloud Misconfigurations

Use Shodan to find exposed cloud services (passive — Shodan's data, not your probe):

```
# Exposed Elasticsearch clusters (no auth)
product:"Elastic" port:9200 org:"Amazon"

# Exposed Kibana dashboards
http.title:"Kibana" port:5601 org:"Amazon"

# MongoDB without authentication
product:"MongoDB" port:27017 org:"Amazon"

# Redis without authentication
product:"Redis" port:6379 org:"Amazon"

# Cassandra without authentication
port:9042 org:"Amazon"
```

---

### 8. Assessing Impact — What to Do With a Public Bucket

When you find a public bucket, do not stop at "it's public." Assess what is in it.

**Impact assessment framework:**

```
1. ENUMERATE CONTENTS
   aws s3 ls s3://found-bucket --recursive --no-sign-request | head -100
   Note: file count, size, file types

2. CATEGORISE DATA
   Personal data (PII)?      → Critical / GDPR implications
   Credentials or keys?      → Critical
   Source code?              → High
   Database backups?         → Critical
   Internal documents?       → High-Medium
   Public marketing assets?  → Informational

3. SAMPLE — DO NOT EXFILTRATE
   Download ONE file as a representative sample for your PoC.
   Do NOT download the entire bucket.
   Do NOT read user data beyond what proves the vulnerability.

4. REPORT IMMEDIATELY
   Do not sit on a Critical finding. Report same day.
   Include: bucket URL, access method (list + read), sample filename,
   data classification, remediation steps.
```

---

## Key Takeaways

1. **Cloud storage misconfigurations are consistently among the most severe
   bug bounty findings.** A misconfigured S3 bucket leaking database backups
   is a Critical finding at any programme.
2. **Naming pattern guessing works.** Organisations follow predictable naming
   conventions. A wordlist of 200 candidates will hit the target's buckets
   more often than you expect.
3. **GrayhatWarfare is fully passive.** Before you guess bucket names, check
   if someone already found the open buckets and indexed them.
4. **Firebase is routinely misconfigured.** Find the project ID in the Android
   APK or web app JavaScript, then check `.json` endpoint. This takes 2 minutes
   and often produces Critical findings.
5. **Impact assessment matters more than discovery.** Finding a public bucket
   with a marketing PDF is Informational. Finding one with a database backup
   containing 1M customer records is Critical. Know the difference before
   you submit.

---

## Exercises

### Exercise 1 — S3 Bucket Enumeration

1. Generate a wordlist of 50 S3 bucket name candidates for the company
   "testcorp" using the naming patterns from Section 2.
2. Run `s3scanner scan --bucket-file bucket_candidates.txt`.
3. For any bucket that returns an accessible result, list its contents.

---

### Exercise 2 — Firebase Discovery

1. Search for an Android app for a company of your choice on APKPure or
   the Google Play Store.
2. Download the APK and use `apktool d app.apk` to decompile it.
3. Search for `firebaseio.com` in the decompiled files:
   `grep -r "firebaseio" app_decompiled/`
4. If found, test the `.json` endpoint.
5. Is the database public? What data is accessible?

---

### Exercise 3 — GrayhatWarfare Search

1. Go to GrayhatWarfare and search for a well-known company's name.
2. What buckets does it return?
3. Click on a result — what files are indexed?
4. Classify the exposure: Public assets (expected), or sensitive data (finding)?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 056 — GitHub Code Recon and Secret Hunting](DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md)*
*Next: [Day 058 — Social Media and Job Posting Intel](DAY-0058-Social-Media-and-Job-Posting-Intel.md)*
