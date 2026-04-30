---
title: "ADCS Attack Surface — ESC1 through ESC8, Certificate Abuse in AD"
tags: [red-team, ADCS, certificates, ESC1, ESC8, Certipy, PKI, active-directory,
  ATT&CK, T1649, T1550]
module: 08-RedTeam-03
day: 511
related_topics:
  - Red Team Reporting (Day 510)
  - ADCS ESC1 Lab (Day 512)
  - ADCS ESC8 PetitPotam Lab (Day 513)
  - Domain Dominance (Day 499)
---

# Day 511 — ADCS Attack Surface

> "Active Directory Certificate Services is the most underestimated attack
> surface in enterprise AD. It has been there for twenty years. Most
> defenders have never audited it. Most red teamers walked past it for
> a decade before SpecterOps published ESC1 through ESC8. Now it is one
> of the fastest paths to Domain Admin I know — and it leaves almost
> nothing in the traditional detection logs."
>
> — Ghost

---

## Goals

Understand the ADCS architecture and why it is a high-value attack target.
Learn the ESC1 through ESC8 vulnerability classes.
Use Certipy to enumerate and identify vulnerable certificate templates.
Map ADCS attacks to ATT&CK and understand their detection gap.

**Prerequisites:** Day 499 (domain dominance), Day 501 (BloodHound), Active
Directory fundamentals, understanding of PKI basics.
**Time budget:** 5 hours.

---

## Part 1 — What Is ADCS and Why Does It Matter

Active Directory Certificate Services (ADCS) is the Microsoft PKI solution
built into Windows Server. It issues X.509 certificates for authentication,
encryption, and code signing within the domain.

```
What ADCS does in a typical enterprise:
  → Issues smart card certificates for user authentication
  → Issues machine certificates for 802.1X network access
  → Issues certificates for VPN authentication
  → Issues SSL/TLS certificates for internal services
  → Issues code-signing certificates for internal applications

Why it is dangerous:
  → A certificate issued for "Client Authentication" can authenticate
    as the certificate's subject — just like a password
  → Kerberos PKINIT: present a certificate → receive a Kerberos TGT
  → Certificates have long lifetimes (often 1–2 years)
  → Certificate theft or forging bypasses password rotation and MFA
  → Most SIEM rules do not monitor certificate issuance events
```

### ADCS Component Map

```
Enterprise CA (Certificate Authority)
  → Issues certificates based on certificate templates
  → Typically running on a dedicated server (or the DC itself — bad practice)

Certificate Templates
  → Define: who can enrol, what EKU (Extended Key Usage) is allowed,
    subject name source, approval required or auto-approve

Web Enrolment (certsrv)
  → HTTP interface for requesting certificates
  → Target of ESC8 (NTLM relay to ADCS web enrolment)

OCSP / CRL
  → Certificate revocation — if this is offline, revocation checking fails
    (some environments: fail-open, making revoked certs still usable)
```

---

## Part 2 — ESC Vulnerability Classes (ESC1–ESC8)

The ESC (Escalation) findings were published by Will Schroeder and Lee Christensen
(SpecterOps) in the 2021 "Certified Pre-Owned" whitepaper.

### ESC1 — Misconfigured Certificate Template (User-Controlled SAN)

```
Vulnerable condition:
  Certificate template:
    → EKU includes "Client Authentication" (OID 1.3.6.1.5.5.7.3.2)
    → CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag is set
    → Low-privilege users have Enrol or AutoEnroll rights

What it means:
  A low-privilege user can request a certificate and specify ANY subject
  name in the Subject Alternative Name (SAN) field — including
  Administrator@corp.local.
  → Request a certificate as Administrator → use it to authenticate as DA.

Exploitation: (Day 512 lab)
  Any domain user → request cert with SAN=Administrator@corp.local
  → Use cert to get Administrator's TGT via PKINIT
  → Full DA access
```

### ESC2 — Misconfigured Certificate Template (Any-Purpose EKU)

```
Vulnerable condition:
  Template has EKU set to "Any Purpose" or no EKU (SubCA template pattern)

What it means:
  The certificate can be used for any purpose including Client Authentication.
  Combined with ESC3 or directly for authentication.

Less common than ESC1. Same detection gap.
```

### ESC3 — Enrolment Agent Template Abuse

```
Vulnerable condition:
  A template with "Certificate Request Agent" EKU exists and is
  open to low-privilege users.

What it means:
  The requester gets an Enrolment Agent certificate.
  This certificate allows enrolling in other templates ON BEHALF OF other users.
  → Enrolment Agent cert + second vulnerable template → certificate for any user.

Two-step attack:
  1. Enrol for Enrolment Agent certificate (ESC3 template)
  2. Use that cert to enrol in a "User" template on behalf of Administrator
  → Result: certificate for Administrator without ESC1 flag needed
```

### ESC4 — Vulnerable Certificate Template Access Control

```
Vulnerable condition:
  A low-privilege user has Write rights (GenericWrite, WriteDacl, WriteProperty)
  on a certificate template object in AD.

What it means:
  The attacker can modify the template to add the ESC1 flag (ENROLLEE_SUPPLIES_SUBJECT)
  or add themselves to the enrolment rights.
  → Convert a non-vulnerable template into an ESC1 template on demand.

Detection: AD object modification events (Event 5136) on certificate template objects.
```

### ESC5 — Vulnerable PKI Object Access Control

```
Vulnerable condition:
  A low-privilege user has Write rights on the CA server computer object,
  the CA container in AD, or the NTAuthCertificates object.

What it means:
  Allows adding rogue certificates to the trusted CA store, or manipulating
  the CA configuration to trust attacker-signed certificates.
  → Most impactful but also most complex.
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA

```
Vulnerable condition:
  The CA is configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag.

What it means:
  Any template (not just those with ENROLLEE_SUPPLIES_SUBJECT) allows
  the requester to specify a SAN in the certificate request.
  → All templates effectively become ESC1.

Check:
  certutil -config "CA_SERVER\CA_NAME" -getreg policy\EditFlags
  If bit 0x00040000 (EDITF_ATTRIBUTESUBJECTALTNAME2) is set: vulnerable.
```

### ESC7 — Vulnerable CA Permissions

```
Vulnerable condition:
  A low-privilege user has ManageCA or ManageCertificates rights on the CA.

What it means:
  ManageCA: can change CA configuration (enable ESC6 flag).
  ManageCertificates: can approve pending certificate requests (bypass approval).
  → Combined: issue arbitrary certificates without restriction.
```

### ESC8 — NTLM Relay to ADCS Web Enrolment

```
Vulnerable condition:
  ADCS web enrolment (certsrv) is enabled and accepts NTLM authentication.

What it means:
  Relay a machine account's NTLM authentication to certsrv HTTP endpoint.
  → Receive a certificate for that machine account.
  → Use the machine certificate to get a TGT for the machine account.
  → Extract NTLM hash via PKINIT UnPAC-the-Hash technique.
  → If relayed machine account is a DC: extract the DC's NTLM hash
    → use for DCSync or Shadow Credentials attack.

Trigger: PetitPotam, PrinterBug, or any coerce technique.
Lab: Day 513
```

---

## Part 3 — Enumerating ADCS with Certipy

```bash
# Certipy: the standard ADCS enumeration and exploitation tool
pip3 install certipy-ad

# Enumerate all certificate templates and find vulnerable ones:
certipy find -u jsmith@corp.local -p 'Password123' -dc-ip DC_IP
# → Creates: corp.local_Certipy.json (full template data)
# → Creates: corp.local_Certipy.txt (summary of vulnerabilities found)
# → Creates: corp.local_Certipy.bloodhound.zip (for BloodHound)

# Output summary shows ESC findings:
# [!] Vulnerable to ESC1: Template "UserTemplate" (Enabled, ENROLLEE_SUPPLIES_SUBJECT)
# [!] Vulnerable to ESC8: Web Enrollment enabled, NTLM authentication
```

### Reading Certipy Output

```
Certificate Template:
  Name:    UserTemplate
  Enabled: True

  [!] Vulnerabilities
    ESC1: ENROLLEE_SUPPLIES_SUBJECT flag is set
    -> Users can request certificates with arbitrary SANs

  Client Authentication:  True
  Enrollee Supplies Subject: True
  Extended Key Usage: Client Authentication
  Enrolment Rights:   Domain Users (Everyone can enrol)
  Requires Management Approval: False
  Authorized Signatures Required: 0

Interpretation:
  Any domain user → request cert as Administrator → DA
```

### Importing Certipy BloodHound Data

```bash
# Import the Certipy BloodHound zip into BloodHound:
# → Adds ADCS nodes: Enterprise CAs, Certificate Templates, CRLs
# → Adds edges: Enroll, AutoEnroll, GenericWrite on templates
# → BloodHound now shows ADCS paths to DA
```

---

## Part 4 — Quick Reference: ESC Detection Matrix

| ESC | Root Cause | Privilege Needed | Detection |
|---|---|---|---|
| ESC1 | ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU | Domain User | Event 4886 (cert issued) + SAN mismatch |
| ESC2 | Any Purpose EKU + low enrol rights | Domain User | Event 4886 |
| ESC3 | Enrolment Agent cert open to low-priv | Domain User | Two Event 4886 (agent then user cert) |
| ESC4 | WriteProperty on template object | Domain User + Write | Event 5136 (template modified) |
| ESC5 | Write on PKI AD objects | Domain User + Write | Event 5136 on NTAuthCertificates |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | Domain User | Event 4886 + any SAN in any template |
| ESC7 | ManageCA / ManageCertificates right | Domain User | CA audit logs (not default) |
| ESC8 | NTLM relay to certsrv | Network access | IIS logs + Event 4886 from machine acct |

### Why ADCS Attacks Are Hard to Detect

```
Standard AD detection tools watch:
  LSASS access, Kerberos events, LDAP queries, group changes

ADCS attacks generate:
  Certificate events (4886, 4887, 4888) — almost never alerted on
  PKINIT authentication looks like normal Kerberos (Event 4768)
  The certificate issued to "Administrator" by "jsmith" appears legitimate
    because the CA was misconfigured to allow it

Most SIEM deployments:
  Do NOT collect certificate services events
  Do NOT have rules for Event 4886 with suspicious SANs
  Do NOT alert on PKINIT followed by access from an unusual source

This is the detection gap. Most ESC1 attacks in production would not fire
a single alert in a standard SOC environment.
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Notes |
|---|---|---|
| Certificate template abuse (ESC1–ESC7) | T1649 (Steal or Forge Authentication Certs) | Forge/request certs for privilege |
| NTLM relay to ADCS (ESC8) | T1557.001 (NTLM Relay) | Relay to certsrv |
| PKINIT auth with forged cert | T1550 (Use Alternate Auth Material) | Cert as TGT source |

---

## Key Takeaways

1. ADCS is present in the majority of enterprise AD environments and is
   almost universally misconfigured. ESC1 requires only a misplaced checkbox
   on a certificate template — and templates are rarely audited after creation.
2. ESC8 (NTLM relay to certsrv) is the most exploitable finding because it
   requires no template misconfiguration — only that web enrolment is enabled
   with NTLM authentication, which is the default. Trigger: one coerce call.
3. Certificates are more durable credentials than passwords. A certificate
   forged via ESC1 is valid for the template's lifetime (often 1–2 years).
   Rotating the compromised account's password does not invalidate the cert.
4. Certipy finds and exploits ADCS vulnerabilities in a single tool. Run
   `certipy find` on every AD engagement before deciding the attack path.
   ADCS paths are often shorter than BloodHound's traditional AD paths.
5. Detection requires enabling CA audit logging (not default) and collecting
   Event 4886 (certificate issued) with an alert rule that catches SANs
   that do not match the requesting account. Most environments have this gap.

---

## Exercises

1. Run `certipy find` against the lab AD. List every vulnerable template
   found with its ESC class. Identify which ESC class would be exploited first
   based on available privileges.
2. Manually check the ADCS web enrolment endpoint: browse to
   `http://CA_SERVER/certsrv/`. Does it prompt for NTLM authentication?
   Does it accept basic auth? This is the ESC8 surface.
3. Check the CA for the EDITF_ATTRIBUTESUBJECTALTNAME2 flag:
   `certutil -config "CA\NAME" -getreg policy\EditFlags`. Calculate whether
   bit 0x00040000 is set.
4. Write a Sigma rule for Windows Security Event 4886 (Certificate Services
   received a certificate request) that alerts when the certificate's SAN
   contains a domain admin account name but the requesting user is a standard
   domain user.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q511.1, Q511.2 …).

---

## Navigation

← Previous: [Day 510 — Red Team Reporting](DAY-0510-Red-Team-Reporting.md)
→ Next: [Day 512 — ADCS ESC1 Lab](DAY-0512-ADCS-ESC1-Lab.md)
