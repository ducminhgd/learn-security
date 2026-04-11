---
title: "Foundation Complete Review"
tags: [foundation, review, synthesis, OSI, TCP, HTTP, TLS, Linux, cryptography,
       auth, session, JWT, OAuth, OIDC, access-control]
module: 01-Foundation-05
day: 48
related_topics:
  - Auth Detection, Logging and Hardening (Day 047)
  - Foundation CTF Day (Day 049)
  - Foundation Competency Gate (Day 050)
---

# Day 048 — Foundation Complete Review

## Goals

No new content today. This is synthesis. By the end of this session you will
be able to:

1. Draw the complete attack surface of an HTTP request from browser to database.
2. Map every topic from F-01 through F-05 to at least one real attack.
3. Identify which layer (network, transport, application, auth) is responsible
   for each class of vulnerability.
4. Explain the chain that connects a network-layer weakness to an application
   compromise.

---

## Prerequisites

- All of modules 01-Foundation-01 through 01-Foundation-05 (Days 001–047)

---

## The Full Stack — Attack Surface Map

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER                                  │
│  XSS, CSRF, clickjacking, cookie theft, localStorage theft,    │
│  CSP bypass, CSWSH, client-side token storage                  │
└─────────────────────────────┬───────────────────────────────────┘
                              │ DNS lookup
┌─────────────────────────────▼───────────────────────────────────┐
│                          DNS                                    │
│  DNS cache poisoning, subdomain takeover,                       │
│  DNS-based C2, zone transfer                                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │ TCP connection
┌─────────────────────────────▼───────────────────────────────────┐
│                     NETWORK / TRANSPORT                         │
│  ARP spoofing, MITM, session hijacking (unencrypted),           │
│  TLS downgrade, weak cipher, expired cert, BEAST/POODLE        │
└─────────────────────────────┬───────────────────────────────────┘
                              │ TLS + HTTP
┌─────────────────────────────▼───────────────────────────────────┐
│                     CDN / LOAD BALANCER / PROXY                 │
│  Host header injection, X-Forwarded-For bypass,                 │
│  cache poisoning, request smuggling, CDN origin bypass         │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTP request
┌─────────────────────────────▼───────────────────────────────────┐
│                    WEB APPLICATION                              │
│  SQLi, XSS, CSRF, SSRF, XXE, IDOR, path traversal,             │
│  mass assignment, open redirect, file upload, SSTI             │
└─────────────────────────────┬───────────────────────────────────┘
                              │ auth check
┌─────────────────────────────▼───────────────────────────────────┐
│                   AUTHENTICATION & AUTHORISATION                │
│  Brute force, credential stuffing, session fixation,            │
│  JWT attacks, OAuth CSRF, SAML XSW, IDOR, broken RBAC,         │
│  MFA bypass, password reset exploitation                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │ query
┌─────────────────────────────▼───────────────────────────────────┐
│                    DATABASE / FILE SYSTEM                       │
│  SQL injection (data exfil, auth bypass, RCE via xp_cmdshell), │
│  NoSQL injection, IDOR on file paths                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module-by-Module Synthesis

### F-01 — How the Internet Actually Works (Days 001–008)

| Concept | Attack it enables | Day |
|---|---|---|
| OSI model | Layer-specific attacks: ARP (L2), TCP SYN flood (L4), HTTP (L7) | 001 |
| IP addressing / subnetting | Network reconnaissance, CIDR scanning | 002 |
| TCP three-way handshake | SYN flood, session hijacking, TCP reset | 003 |
| DNS resolution | DNS poisoning, subdomain takeover, domain fronting | 004 |
| TLS handshake | Downgrade (POODLE/BEAST), weak cipher, cert pinning bypass | 005 |
| HTTP request/response | Header injection, verb tampering, smuggling | 006 |
| HTTP cookies and sessions | Cookie theft, CSRF, session fixation | 007 |
| Wireshark lab | Traffic analysis, credential capture in cleartext | 008 |

---

### F-02 — Linux Fundamentals for Hackers (Days 009–016)

| Concept | Attack it enables | Day |
|---|---|---|
| Filesystem and permissions | World-writable files, SUID abuse, path hijacking | 009 |
| Processes and signals | /proc enumeration, process injection | 010 |
| Cron and environment variables | Cron job exploitation, LD_PRELOAD hijack | 011 |
| SUID, sudo, GTFOBins | Shell escapes: `sudo find -exec /bin/sh`, vim, cp | 012 |
| Logs, named pipes, sockets | Log tampering, mkfifo reverse shell, Docker socket | 013 |
| Lab: enumeration | Methodical recon for privesc vectors | 014 |
| Lab: privilege escalation | Full root via cron/sudo/capability chain | 015 |
| Hardening and forensics | auditd rules, sysctl, timeline from artefacts | 016 |

---

### F-03 — Web Architecture Deep Dive (Days 017–028)

| Concept | Attack it enables | Day |
|---|---|---|
| Full web stack architecture | Attack surface at every hop | 017 |
| HTTP security headers | Missing HSTS → MITM; no CSP → XSS; no X-Frame → clickjack | 018 |
| SOP and CORS | CORS misconfiguration → credential exfil | 019 |
| REST APIs and GraphQL | IDOR, mass assignment, introspection, nested DoS | 020 |
| WebSockets and client storage | CSWSH, XSS → localStorage token theft | 021 |
| Burp Suite | Intercept, replay, fuzz, tamper | 022–024 |
| CSP and web cache | CSP bypass, cache poisoning, cache deception | 025 |
| Proxies and Host headers | Host header injection, CDN origin bypass, smuggling | 026 |
| Web hardening | nginx config, secure cookies, CORS policy | 027 |
| Competency check | All F-03 concepts verified | 028 |

---

### F-04 — Cryptography Essentials (Days 029–038)

| Concept | Attack it enables | Day |
|---|---|---|
| Symmetric crypto (ECB/CBC/CTR/GCM) | ECB pattern leak, cut-and-paste; nonce reuse → plaintext XOR | 029 |
| Hashing and length extension | Flickr-style MAC forgery with `hashpumpy` | 030 |
| MACs, HMACs, timing attacks | Timing attack on `==`, length extension on `H(k‖m)` | 031 |
| RSA and asymmetric crypto | ROBOT attack, small exponent, common modulus | 032 |
| TLS and PKI | CT log recon, POODLE/BEAST, OCSP stapling bypass | 033 |
| Password hashing | hashcat attack on MD5/bcrypt, rainbow tables | 034 |
| PRNG attacks | MT19937 state recovery, time-seeded token prediction | 035 |
| Frequency analysis lab | Break Vigenère, single-byte XOR, Cryptopals | 036 |
| CVE review | Heartbleed, ROBOT, DROWN, POODLE, BEAST | 037 |
| Crypto competency check | All F-04 concepts verified | 038 |

---

### F-05 — Authentication and Authorisation (Days 039–047)

| Concept | Attack it enables | Day |
|---|---|---|
| Auth vs Authz and password storage | SQL injection bypass, credential stuffing, MD5 crack | 039 |
| Session management | Session fixation, flask-unsign, XSS cookie theft | 040 |
| MFA and bypass | OTP relay, SIM swap, step skip, brute force | 041 |
| JWT attacks | `alg:none`, RS256→HS256 confusion, weak secret crack | 042 |
| OAuth 2.0 attacks | CSRF on OAuth (no state), redirect_uri exfil, Implicit flow | 043 |
| OIDC and SAML attacks | ID token validation skip, XSW attack | 044 |
| Access control (RBAC, IDOR) | IDOR enumeration, forced browsing, role escalation | 045 |
| Password reset flaws | Host header injection, predictable token, race condition | 046 |
| Detection and hardening | Sigma rules, auth log structure, full hardening checklist | 047 |

---

## Cross-Layer Attack Chains

The most dangerous compromises chain vulnerabilities across layers:

**Chain 1 — Network → Application → Database:**
```
MITM on unencrypted HTTP → capture session cookie
→ Replay session cookie → access authenticated application
→ Use stolen session to inject SQL via admin panel
→ Dump entire user database
```

**Chain 2 — OSINT → Auth → Lateral Movement:**
```
LinkedIn recon → find employee emails
→ Check HaveIBeenPwned breach data → 30% reuse passwords
→ Credential stuffing → compromise 3 accounts
→ One account has admin JWT → JWT secret weak
→ Forge admin JWT → full application access
```

**Chain 3 — XSS → Session → OAuth:**
```
Stored XSS in profile field
→ Victim admin loads profile → XSS fires
→ XSS sends OAuth state token + code from browser to attacker
→ Attacker completes OAuth flow → gains access to linked service
```

**Chain 4 — Linux → Web → Database:**
```
Low-privilege web shell via file upload
→ Read /etc/passwd + /etc/shadow via cap_dac_read_search
→ Crack shadow hash offline
→ Password reused on web admin panel
→ Admin SQL execution → full database dump
```

---

## Self-Assessment — Answer Without Notes

### Network and Transport (F-01)

1. Draw a TCP three-way handshake. Where can an attacker inject?
2. What is the TLS 1.3 handshake sequence? What is ECDHE?
3. A site uses `Set-Cookie: session=abc; Path=/`. What flags are missing
   and what attack does each missing flag enable?
4. What is DNS cache poisoning? What property of modern DNS makes it harder?

### Linux (F-02)

5. A binary has SUID set. How do you exploit it with GTFOBins?
6. You find `/usr/local/bin/backup.sh` owned by root and world-writable,
   running every minute. What do you do?
7. What does `getcap -r / 2>/dev/null` tell you?
8. Name three artefacts that survive a `history -c` operation.

### Web Architecture (F-03)

9. CORS response has `Access-Control-Allow-Origin: *` and
   `Access-Control-Allow-Credentials: true`. What is the problem?
10. A site has `Content-Security-Policy: default-src 'self'; script-src cdn.com`.
    `cdn.com` hosts JSONP endpoints. What is the bypass?
11. How do you detect web cache poisoning? What is the first canary test?
12. A password reset email contains `https://app.com/reset?token=abc`.
    The `Host` header was `evil.com` in the reset request. What happened?

### Cryptography (F-04)

13. Two files encrypted with AES-ECB look different. How do you confirm ECB?
14. An API authenticates with `sha256(secret + message)`. What attack applies?
15. You have an RSA public key with `e=3`. A ciphertext is `c`. If `c < n`,
    how do you decrypt?
16. `$2b$12$LQv3c1yq...` — what algorithm, what cost, what is the `12`?

### Authentication (F-05)

17. A JWT header is `{"alg":"HS256","typ":"JWT"}`. The server uses RS256.
    You have the public key. What do you do?
18. An OAuth callback does not validate `state`. What is the attack?
19. A password reset token is `md5(email + str(time.time()))`. What is the
    attack and what is the cracking time?
20. An access control check is: `if user.role == 'admin': allow`. You are a
    regular user. The endpoint takes `user_id`. What access control flaw is
    present?

---

## Key Takeaways

1. **Security is not a feature — it is the absence of exploitable mistakes.**
   Every topic in F-01 through F-05 represents a class of mistake that real
   attackers exploit in real systems, today.
2. **The layers interact.** A TLS misconfiguration plus a session cookie without
   `Secure` plus no `HttpOnly` is a three-layer failure enabling a single
   credential theft. Fix all three.
3. **Understanding the attack is required to build the defence.** You cannot
   write a detection rule for an attack you cannot explain. You cannot fix a
   vulnerability you have not seen exploited.
4. **Most vulnerabilities are design failures, not implementation bugs.**
   ECB mode, no state in OAuth, HTTP session cookies — these are wrong design
   choices. The fix is not a patch; it is a redesign.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 047 — Auth Detection, Logging and Hardening](DAY-0047-Auth-Detection-Logging-and-Hardening.md)*
*Next: [Day 049 — Foundation CTF Day](DAY-0049-Foundation-CTF-Day.md)*
