---
title: "Auth Attacks Review — Complete Map of Days 166–177"
tags: [review, authentication, credential-stuffing, password-spray, JWT, OAuth, SAML,
       Kerberoasting, Pass-the-Hash, ATO, MITRE-ATT&CK, CWE-mapping, hardening]
module: 04-BroadSurface-01
day: 178
related_topics:
  - All lessons in Days 166–177
  - Auth Attacks Competency Check (Day 180)
---

# Day 178 — Auth Attacks Review

> "You have seen every attack class. Now prove you own the map. If I point to
> any node in this module and ask 'How does it work, how do you detect it, how
> do you fix it?' — you answer in 60 seconds without notes. That is the standard.
> Today you build that map."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Describe the mechanism of every attack class from Days 166–177 in one
   or two sentences.
2. Name the specific log event or detection indicator for each attack.
3. State the single most effective mitigation for each attack.
4. Trace multi-step attack chains (ATO chains, Kerberoast-to-DA) end to end.
5. Map every attack class to its MITRE ATT&CK technique and CWE.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All authentication attack lessons | Days 166–177 |

---

## Complete Attack Class Reference Table

| Day | Attack | Mechanism | ATT&CK | CWE | Detect | Fix |
|---|---|---|---|---|---|---|
| 166 | Credential Stuffing | Breach list replayed against login endpoint | T1110.004 | CWE-307 | Volume 401s per IP; UA anomalies | HIBP check; bot-resistant rate limit |
| 166 | Password Spray | One password across many accounts; stays below lockout | T1110.003 | CWE-307 | Low failures per account, many accounts | Spray-aware detection; MFA |
| 167 | Rate Limit Bypass | XFF rotation, path variation, proxy pool | T1110 | CWE-307 | Distributed 401 spike; header anomalies | Identity-bound rate limiting |
| 169 | JWT alg:none | `alg: "none"` → unsigned token accepted | T1550 | CWE-347 | jwt_algorithm=none in logs | Hard-code algorithm server-side |
| 169 | JWT RS256→HS256 | HMAC with public key as secret | T1550 | CWE-347 | Expected RS256, got HS256 in JWT validation log | Reject non-RS256; never negotiate |
| 169 | JWT kid traversal | `kid: "../../dev/null"` → HMAC with empty key | T1550 | CWE-22 | kid contains `..` or `/` | Pre-load key registry; reject unknown kids |
| 169 | JWT kid SQLi | `kid: "x' UNION SELECT 'secret'--"` → arbitrary key | T1550 | CWE-89 | SQL chars in kid field | Allowlist kid values; parameterised query |
| 169 | JWK header injection | Embed attacker RSA public key in `jwk` header | T1550 | CWE-347 | jwk header present in token | Reject `jwk` header unconditionally |
| 169 | jku / x5u injection | Point key URL to attacker-controlled JWKS | T1550 | CWE-918 | Outbound HTTP to unexpected JWKS URL | Reject `jku`/`x5u` unconditionally |
| 171 | OAuth implicit leak | access_token in fragment visible to third-party scripts | T1550 | CWE-200 | Token in URL fragment; referrer leakage | Disable implicit flow |
| 171 | OAuth PKCE downgrade | Omit or use `plain` code_challenge | T1550 | CWE-346 | code_challenge absent for public client | Require PKCE S256; reject omission |
| 171 | OAuth open redirect + code theft | prefix redirect_uri + open redirect → code in Referer | T1550 | CWE-601 | redirect_uri mismatch; unusual Referer for token endpoint | Exact redirect_uri match |
| 171 | OAuth state CSRF | Missing or reused state parameter | T1550 | CWE-352 | state absent; state value reuse | Validate state before code exchange |
| 173 | SAML XSW | Unsigned assertion inserted before signed one | T1550 | CWE-345 | Multiple Assertion elements in response | Validate signed element; SAMLraider |
| 173 | SAML XXE | DTD injection in SAML XML | T1190 | CWE-611 | Outbound DNS/HTTP from XML parser | Disable external entities in parser |
| 173 | SAML comment injection | `<!---->` in NameID changes parsed identity | T1550 | CWE-345 | Comment chars in NameID attribute | Use canonical text extraction; library patch |
| 173 | SAML replay | Captured assertion resubmitted | T1550 | CWE-294 | Duplicate AssertionID in logs | Track used AssertionIDs; reject duplicates |
| 174 | Host header injection → reset poison | `Host: attacker.com` in password reset request | T1606 | CWE-640 | Reset URL domain ≠ application domain | Use hardcoded BASE_URL in config |
| 174 | CSRF email change | Forged form submission changes victim email | T1110 | CWE-352 | Email change without CSRF token / SameSite | CSRF token + SameSite=Lax |
| 174 | IDOR → reset token | Unauthenticated `/reset/initiate` with user_id param | T1110 | CWE-639 | Reset token returned without authentication | Authenticate reset endpoint |
| 175 | Kerberoasting | Any domain user requests TGS for SPN account; cracks offline | T1558.003 | CWE-916 | Event 4769 RC4 tickets; multi-SPN per account | gMSA; AES-only tickets |
| 175 | Pass-the-Hash | NTLM hash used directly without cracking | T1550.002 | CWE-836 | Event 4624 LogonType 3 without prior LogonType 2 | Credential Guard; Protected Users |
| 175 | NTLM Relay | Captured NTLM auth forwarded to a different target | T1557.001 | CWE-294 | Responder activity; unexpected NetNTLMv2 traffic | SMB signing required |

---

## Attack Chain Map

### Chain A — Web App ATO (Unauthenticated → Account Owner)

```
OSINT → victim email confirmed
  │
  ├── Branch 1: Password Reset Poison
  │   POST /forgot-password Host: attacker.com
  │   → Reset link to attacker domain
  │   → Click → token extracted
  │   → Password reset → login
  │
  ├── Branch 2: CSRF Email Change + Password Reset
  │   Phish victim → CSRF form auto-submits
  │   → Victim email → attacker@evil.com
  │   → Normal password reset → email to attacker
  │   → Login as victim
  │
  └── Branch 3: IDOR → Reset Token
      GET /api/users?email=victim@company.com → user_id
      POST /api/reset/initiate {"user_id": N} → token in response
      POST /api/reset/complete {token, new_password}
      → Login as victim
```

**Highest severity version:** Branch 3 — unauthenticated, no user interaction.
CVSS: 9.9 (Critical).

---

### Chain B — JWT Lab (User → Admin → RCE)

```
Step 1 — Get a valid user JWT (register or login)
Step 2 — Decode header → kid = "keys/hs256-key"
Step 3 — kid traversal → "../../dev/null"
          HMAC with b"" → forge admin token
          {"sub": "admin", "role": "admin", "kid": "../../dev/null"}
Step 4 — POST /admin/exec {"cmd": "id"}
          → RCE as www-data or root
```

**Stopped by:** Pre-loaded key registry. kid `../../dev/null` not in registry
→ ValueError → 401.

---

### Chain C — OAuth Lab (User → Steal Admin Token → Admin Access)

```
Step 1 — AS metadata → implicit flow enabled; no PKCE
Step 2 — redirect_uri validation: startsWith(registered_uri)
Step 3 — /logout?next= accepts any URL
Step 4 — Craft:
          redirect_uri = http://app.com/callback/../logout?next=http://attacker.com
Step 5 — Victim (alice, admin) visits malicious /authorize URL
Step 6 — AS redirects with code appended → /logout → attacker
Step 7 — Code in Referer header → exchange for alice's access token
Step 8 — GET /admin with alice's token → admin access
```

**Stopped by:** Exact redirect_uri matching + open redirect fixed with allowlist.

---

### Chain D — Kerberoast to Domain Admin

```
Step 1 — Authenticate as any domain user (even low-privilege)
Step 2 — impacket-GetUserSPNs → list SPN accounts
Step 3 — Request TGS tickets (saved to hashes.txt)
Step 4 — hashcat -m 13100 hashes.txt rockyou.txt
Step 5 — Crack svc_backup password in < 1 minute
Step 6 — svc_backup has Domain Admin rights (common mistake)
Step 7 — evil-winrm -i DC -u svc_backup -p CrackedPass → SYSTEM on DC
```

**Stopped by:** gMSA for svc_backup (240-char auto-rotating password).

---

## Detection Summary

| Attack | Log source | Key indicator |
|---|---|---|
| Credential stuffing | Web server | >20 distinct usernames per IP per minute with 401 |
| Password spray | Application auth | >50 distinct accounts, <5 failures each, per IP in 30 min |
| Password spray (AD) | Windows Security | Event 4625, LogonType 3, >50 distinct TargetUserName per IP in 30 min |
| JWT alg:none | Application auth | jwt_algorithm = "none" in validation log |
| JWT kid traversal | Application auth | kid contains `..`, `/`, `etc`, `dev/null` |
| OAuth open redirect | AS audit log | redirect_uri not in registered set |
| SAML replay | SAML audit | Duplicate assertion_id in saml_sso_success within 60 min |
| SAML XSW | SAML audit | assertion_count ≥ 2 in saml_parse event |
| Kerberoasting | Windows Security | Event 4769, TicketEncryptionType = 0x17, multiple SPNs per account |
| Pass-the-Hash | Windows Security | Event 4624 LogonType 3 with NTLM, no prior LogonType 2 from same host |

---

## CWE Quick Reference

| CWE | Name | Attack classes |
|---|---|---|
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | Stuffing, spray, brute force |
| CWE-347 | Improper Verification of Cryptographic Signature | JWT alg:none, JWK injection, RS256→HS256 |
| CWE-22 | Path Traversal | JWT kid traversal |
| CWE-89 | SQL Injection | JWT kid SQL injection |
| CWE-918 | Server-Side Request Forgery | jku/x5u injection, SAML XXE SSRF |
| CWE-346 | Origin Validation Error | OAuth state CSRF |
| CWE-601 | URL Redirection to Untrusted Site | OAuth open redirect |
| CWE-345 | Insufficient Verification of Data Authenticity | SAML XSW, comment injection |
| CWE-611 | Improper Restriction of XML External Entity Reference | SAML XXE |
| CWE-294 | Authentication Bypass by Capture-Replay | SAML replay, NTLM relay |
| CWE-640 | Weak Password Recovery Mechanism | Password reset poisoning |
| CWE-352 | Cross-Site Request Forgery | CSRF email change |
| CWE-639 | Authorization Bypass Through User-Controlled Key | IDOR → reset token |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | Kerberoasting (RC4) |
| CWE-836 | Use of Password Hash Instead of Password for Authentication | Pass-the-Hash |

---

## Hardening Controls Reference

| Attack | Kill it with |
|---|---|
| Credential stuffing | HIBP check at login; bot score; MFA |
| Password spray | Progressive lockout; spray detection (cross-account); MFA |
| JWT all attacks | Hard-code alg; pre-loaded key registry; reject jku/jwk/x5u |
| OAuth code theft | Exact redirect_uri; fix open redirects; PKCE S256 |
| SAML XSW | Validate signed element; update library; disable unsolicited IdP auth |
| Password reset poisoning | Config-based BASE_URL; 15-minute token expiry |
| CSRF email change | CSRF token + SameSite=Lax + current password confirmation |
| Kerberoasting | gMSA; AES-only tickets; remove unnecessary SPNs |
| Pass-the-Hash | Credential Guard; Protected Users group; disable NTLM |
| NTLM relay | SMB signing required; disable LLMNR/NBT-NS |

---

## Self-Assessment

Work through these without looking at your notes. If you cannot answer in
60 seconds, that topic needs another pass before the competency check.

1. What is the difference between credential stuffing and password spraying?
   How does each one evade the other's detection rule?
2. Walk through the JWT kid path traversal attack from first principles.
   What key does it HMAC with? Why does that work?
3. In the OAuth open redirect chain: why does the `state` parameter NOT
   protect against the attack?
4. What is XML Signature Wrapping? Which element does the signature cover,
   and which element does the vulnerable SP process?
5. What is the difference between Kerberoasting and AS-REP Roasting?
   Which Windows attribute controls each vulnerability?
6. Why does Pass-the-Hash work? What does the authentication challenge-response
   protocol send instead of the password?
7. Name the single most effective control for each: Kerberoasting, PtH,
   and NTLM relay.
8. A Sigma rule fires on Event 4625 with `SubStatus: 0xC000006A` for >50
   distinct TargetUserName in 30 minutes. What attack is this detecting?
   What attack does it miss? Write the rule for the one it misses.
9. An ATO chain produces CVSS 9.9. The individual bugs are: BOLA (6.5),
   IDOR on reset (7.5), and unauthenticated reset endpoint (8.1). Explain
   why the chain score exceeds all components. Which CVSS metric changes
   most significantly?
10. What is the NIST SP 800-63B recommendation on account lockout policy?
    How does it differ from the traditional 3-strike lockout?

---

## Key Takeaways

1. **Every attack from this module targets a single flawed assumption.**
   Stuffing: "breach passwords are not in our user base." JWT traversal: "kid
   can be any file path." SAML XSW: "the signed element is the one we process."
   Know the assumption; the exploit follows automatically.
2. **Detection and hardening are symmetric.** Every attack has a log
   indicator because the attacker must send different input from a legitimate
   user. Find the difference; write the rule; close the gap.
3. **Multi-step chains are the highest-value skills in bug bounty.** A
   Medium BOLA + Medium IDOR = Critical ATO chain. Map the tree, not just the
   individual bugs.
4. **Active Directory attacks are scope-expansive.** Web access → domain user
   credentials → Kerberoast → domain admin. Know the path, even in a web-focused
   engagement. A service account with DA rights behind a web app is a critical
   finding.
5. **MFA is not a silver bullet.** TOTP does not stop real-time phishing
   proxies (Evilginx2, Modlishka). WebAuthn does. Know the threat model before
   recommending a control.

---

## Exercises

1. Without notes: reproduce the JWT kid traversal exploit from Day 170 in
   a Python script. Time yourself — target under 10 minutes. If you need
   to look up the HMAC construction, that is the gap to close.
2. Draw the full ATO attack tree from Day 174 from memory. Label each node
   with its standalone CVSS score and the combined chain score.
3. Write Sigma rules for two attacks not covered in Day 176: (a) SAML comment
   injection — what field would you log? (b) OAuth PKCE downgrade — what
   field in the AS audit log indicates the attack?
4. On a test system: configure a service account with AES-only Kerberos
   (`msDS-SupportedEncryptionTypes = 24`). Kerberoast it. What encryption
   type does impacket request? What hashcat mode is required? Run the crack.
   Document the performance difference vs RC4.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q178.1, Q178.2 …).
> Follow-up questions use hierarchical numbering (Q178.1.1, Q178.1.2 …).

---

## Navigation

← Previous: [Day 177 — Auth Hardening](DAY-0177-Auth-Hardening.md)
→ Next: [Day 179 — Auth Attacks Practice](DAY-0179-Auth-Attacks-Practice.md)
