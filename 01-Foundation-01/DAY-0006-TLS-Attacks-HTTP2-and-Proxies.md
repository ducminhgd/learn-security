---
title: "TLS Attacks, HTTP/2, HTTP/3 and Proxies"
tags: [foundation, networking, tls, beast, poodle, hsts, http2, http3, quic,
       proxy, cdn, forward-proxy, reverse-proxy]
module: 01-Foundation-01
day: 6
related_topics:
  - TLS Handshake (Day 005)
  - Burp Suite setup (Day 022)
  - SSL stripping
  - CDN bypass techniques
---

# Day 006 — TLS Attacks, HTTP/2, HTTP/3 and Proxies

## Goals

By the end of this lesson you will be able to:

1. Describe BEAST, CRIME, BREACH, POODLE, FREAK, LOGJAM, and DROWN — the mechanism of
   each and its practical exploitability today.
2. Explain HSTS and describe the HSTS preload bypass technique via initial HTTP request.
3. Explain certificate validation errors — what each error means and what an attacker does with it.
4. Describe how HTTP/2 differs from HTTP/1.1 and identify its expanded attack surface.
5. Explain what QUIC is and why HTTP/3 changes the network security model.
6. Distinguish forward proxies from reverse proxies and explain each from an attacker's lens.
7. Explain CDN origin IP discovery and why it undermines WAF protection.
8. Explain the `X-Forwarded-For` header and how it is abused to bypass IP-based controls.

---

## Prerequisites

- [Day 005 — HTTP Cookies, Sessions and TLS](DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)

---

## Main Content — Part 1: TLS Attacks

### 1. Historical TLS Attacks — Still Relevant for Two Reasons

These attacks are mostly mitigated in modern configurations. You still need to know them:
1. **Legacy servers** still run vulnerable configurations — it is a real bug bounty finding.
2. **Understanding the attack** teaches you what the TLS design assumptions were and why
   they failed — pattern recognition that applies to new vulnerabilities.

---

### 2. BEAST (Browser Exploit Against SSL/TLS) — 2011

**Target:** TLS 1.0, CBC mode ciphers.

**How it works:** TLS 1.0 uses the previous ciphertext block as the IV for the next block
(CBC chaining). An attacker with a MITM position and the ability to inject JavaScript
(same-origin with the target) can choose plaintexts, observe ciphertexts, and use a
chosen-plaintext attack to recover the session token byte by byte.

**Practical exploitability today:** Very low. TLS 1.0 is deprecated; most browsers and
servers have disabled it. But servers still advertising TLS 1.0 support are flagged.

**Detection:** Check cipher suites with `nmap --script ssl-enum-ciphers -p 443 target`.

---

### 3. CRIME (Compression Ratio Info-leak Made Easy) — 2012

**Target:** TLS compression (`DEFLATE`) or HTTP/2 header compression (SPDY).

**How it works:** TLS/SPDY offered optional compression before encryption. If the request
includes attacker-controlled data alongside a secret (e.g. a CSRF token), and compression
is applied before encryption, the compressed + encrypted length leaks information about how
much the attacker-controlled data overlaps with the secret (identical bytes compress better).
By brute-forcing one character at a time, the attacker recovers the secret.

**BREACH** (2013) is the HTTP-level variant: if HTTP response compression is enabled and
reflects user input, secrets in responses can be leaked. Still partially relevant when
applications reflect input near secrets in compressed HTTP responses.

**Fix:** Disable TLS-level compression (universally done now). For BREACH: avoid compressing
secrets alongside user-controlled data; use per-request CSRF tokens.

---

### 4. POODLE (Padding Oracle On Downgraded Legacy Encryption) — 2014

**Target:** SSLv3, CBC padding.

**How it works:** SSLv3's CBC mode has a design flaw — the padding verification only checks
the last byte of padding, not all padding bytes. An attacker can selectively flip bits in the
ciphertext to learn whether a decrypted byte matches any padding pattern. By repeating this
with a MITM position (and forcing TLS to downgrade to SSLv3 via connection failure), the
attacker can decrypt one byte of a cookie per ~256 requests.

**Key lesson:** Padding oracles arise whenever an application's error responses differ based
on whether padding is valid or not. You will exploit a padding oracle on Day 562 (Year 2).

**Fix:** Disable SSLv3 entirely. All major servers have done this.

---

### 5. FREAK (Factoring RSA Export Keys) — 2015

**Target:** Servers still supporting `EXPORT` cipher suites (40-56 bit RSA).

**How it works:** Cold War era US export restrictions required RSA keys to be limited to
512 bits for "export" cipher suites. These can be factored in hours with modern hardware.
FREAK exploited the fact that some servers still accepted `EXPORT` downgrade requests even
in 2015. An attacker forces the client to negotiate `EXPORT` grade crypto, then factors the
512-bit key, decrypts the session.

**LOGJAM** (2015) is the DHE equivalent — `EXPORT` grade Diffie-Hellman parameters (512-bit)
were used by many servers; an attacker could downgrade the key exchange and break the session.

---

### 6. DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) — 2016

**Target:** Servers sharing an RSA private key between a modern TLS endpoint and an SSLv2
endpoint.

**How it works:** SSLv2 is catastrophically broken. If the same private key is used on both
an SSLv2 server and a TLS 1.2 server (even different IP addresses or hostnames), DROWN allows
decrypting TLS 1.2 sessions using SSLv2 as an oracle. Roughly 17% of HTTPS servers were
vulnerable at disclosure.

**Lesson:** Key reuse across security domains is dangerous. Rotating to a new key pair
when a weaker protocol is decommissioned matters.

---

### 7. HSTS and the Initial-Request Problem

**HSTS (HTTP Strict Transport Security):** A response header that tells the browser to
only ever use HTTPS for this domain for a specified duration:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Once set, the browser will not make HTTP requests to this domain — it upgrades them locally.
This defeats SSL stripping attacks… after the first HTTPS visit.

**The attack surface:**
- **First visit problem:** The very first visit may be over HTTP (before the HSTS header is
  received). An SSL strip attacker intercepts this first request and prevents the HSTS header
  from being cached.
- **HSTS preload:** The solution — submit your domain to the browser-maintained HSTS preload
  list. Browsers ship with a hardcoded list of domains that are always HTTPS. No first-visit
  risk.

**Check if a domain is preloaded:** `https://hstspreload.org`

**Bug bounty:** A site without HSTS or without preloading is worth noting, especially if
it handles authentication. Combined with missing `Secure` on session cookies, it is an
exploitable MITM scenario.

---

### 8. Certificate Validation Errors — Attacker Perspective

When a certificate validation fails, the browser shows a warning. Most users click through it.
Understanding each error helps you recognise what is happening:

| Error | Cause | Attacker opportunity |
|---|---|---|
| `ERR_CERT_AUTHORITY_INVALID` | Self-signed or unknown CA | MITM using self-signed cert (Burp Suite, mitmproxy) |
| `ERR_CERT_DATE_INVALID` | Expired certificate | Application still running on expired cert — misconfigured |
| `ERR_CERT_COMMON_NAME_INVALID` | CN/SAN doesn't match hostname | Misconfiguration; possible cert reuse across services |
| `ERR_CERT_REVOKED` | Certificate was revoked by CA | Compromised certificate still in use |
| `NET::ERR_CERT_PINNING_VIOLATION` | Cert doesn't match pinned key | Bypass needed (Day 215 — mobile security) |

Burp Suite acts as a MITM proxy — it presents its own CA certificate for every HTTPS site.
This is why installing the Burp CA certificate in your browser is the first step in every
Burp setup. Without it, every HTTPS page shows a certificate error.

---

## Main Content — Part 2: HTTP/2 and HTTP/3

### 9. HTTP/2 — What Changed and Why Attackers Care

HTTP/2 (RFC 7540, 2015) was a major overhaul motivated by performance:

**Key changes from HTTP/1.1:**

| Feature | HTTP/1.1 | HTTP/2 |
|---|---|---|
| Connections | Multiple TCP connections per host | Single connection, multiplexed |
| Header format | Plain text | Binary framing, HPACK compressed |
| Request ordering | Sequential (FIFO) | Parallel streams |
| Server push | No | Yes (server can proactively send assets) |

**New attack surface introduced by HTTP/2:**

1. **HTTP/2 Request Smuggling:** Because HTTP/2 uses a binary framing layer but is often
   downgraded to HTTP/1.1 at the reverse proxy, the frontend (HTTP/2) and backend
   (HTTP/1.1) can interpret the same request differently — creating request smuggling
   opportunities. This is covered in depth at Day 126.

2. **HPACK Compression Oracle:** HPACK compresses headers. In theory this reintroduces
   CRIME-style compression oracles on headers — though practical exploitation requires
   specific conditions.

3. **Stream multiplication abuse:** An attacker can send thousands of requests over a
   single connection, bypassing per-IP rate limits based on connection counts.

4. **Server push poisoning:** HTTP/2 server push could be abused by intermediaries to inject
   responses for resources the client didn't request.

**Checking HTTP/2 support:**
```bash
curl -sI --http2 https://target.com | grep -i "http/2"
# Or:
nmap --script http2-* -p 443 target.com
```

---

### 10. HTTP/3 and QUIC

HTTP/3 (RFC 9114, 2022) replaces TCP with **QUIC** (Quick UDP Internet Connections):

```
HTTP/1.1 → TCP → IP
HTTP/2   → TCP → IP
HTTP/3   → QUIC → UDP → IP
```

**Why QUIC?**

TCP head-of-line blocking: if one TCP packet is lost, all streams in an HTTP/2 connection
wait for retransmission. QUIC implements multiplexing at the protocol level — a lost packet
only affects the stream it belongs to.

QUIC also integrates TLS 1.3 natively — connection establishment AND TLS handshake happen
simultaneously (1-RTT or 0-RTT).

**Security implications:**

1. **UDP-based:** Existing firewalls and IDS/IPS rules written for TCP port 443 may not
   inspect UDP/QUIC traffic. QUIC traffic to port 443 may bypass network-layer detection.

2. **Encrypted connection metadata:** QUIC encrypts more of the connection metadata than
   TLS over TCP — the connection ID, for example, is obfuscated to prevent correlation.

3. **0-RTT replay risk:** HTTP/3 0-RTT resumption can replay requests. If idempotency is
   not enforced, state-changing GET requests could be replayed by a network attacker.

4. **Fallback:** Most HTTP/3 servers fall back to HTTP/2 or HTTP/1.1 if QUIC is blocked.
   Checking `Alt-Svc` header reveals HTTP/3 capability:
   ```
   Alt-Svc: h3=":443"; ma=86400
   ```

---

## Main Content — Part 3: Proxies and CDNs

### 11. Forward vs Reverse Proxies

**Forward proxy:** Sits between the client and the internet. The client knows about it and
sends requests through it. Used for:
- Corporate web filtering (Squid, Zscaler)
- Anonymisation (Tor)
- Burp Suite (intercept proxy — you use this every day)

```
Client → [Forward Proxy] → Internet
```

**Reverse proxy:** Sits in front of the server. The client does not know about it; they think
they are talking directly to the origin server. Used for:
- Load balancing (nginx, HAProxy)
- WAF (Cloudflare, AWS WAF, ModSecurity)
- Caching (Varnish, Nginx)
- TLS termination

```
Client → [Reverse Proxy / WAF / CDN] → Origin Server
```

---

### 12. CDN Origin IP Discovery

A CDN like Cloudflare hides the origin server's real IP. If you bypass the CDN, you bypass
the WAF. Finding the origin IP is therefore high-value for attackers:

**Techniques to find the origin IP:**

1. **Historical DNS records:** The origin IP may have been in DNS before the CDN was deployed.
   Services like SecurityTrails, Shodan, and Censys store historical DNS resolution data.
   ```bash
   # Shodan search: look for the server banner on the origin IP
   shodan search "Server: Apache title:Example Corp"
   ```

2. **Certificate Transparency:** The origin server may have its own TLS certificate visible
   in CT logs, issued for a different hostname pointing directly to it.

3. **Email headers:** Emails sent from the organisation's servers often contain the origin
   IP in `Received` headers.

4. **Subdomain not behind CDN:** Internal APIs or admin panels may not be routed through
   the CDN. `mail.example.com`, `api.example.com`, `vpn.example.com` — each is a candidate.
   ```bash
   # Check each subdomain for Cloudflare headers
   curl -sI https://api.example.com | grep -i "cf-ray\|x-cache\|via"
   ```

5. **SSRF from within the target:** If you find an SSRF vulnerability, the request from
   the server will come from the origin network, revealing its internal/external IP.

---

### 13. The X-Forwarded-For Header and IP Bypass

When a request passes through a proxy or CDN, the original client IP is added to the
`X-Forwarded-For` (XFF) header:

```
X-Forwarded-For: 203.0.113.195, 10.0.0.1, 172.16.0.254
                 ▲ Original IP   ▲ First proxy  ▲ CDN node
```

**The vulnerability:** If an application trusts `X-Forwarded-For` without validation, an
attacker can spoof their IP address:

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

If the application blocks admin access unless the request comes from `127.0.0.1` (localhost)
and trusts XFF, this bypasses the IP restriction.

**Variants:**
- `X-Real-IP`
- `X-Originating-IP`
- `X-Client-IP`
- `True-Client-IP`
- `CF-Connecting-IP` (Cloudflare-specific)

**In bug bounty:** Testing these headers against IP-restricted admin panels, rate limiting
mechanisms, or geo-blocking controls frequently yields findings.

---

## Key Takeaways

1. **Historical TLS attacks (BEAST, POODLE, DROWN) are largely mitigated** on modern
   servers but TLS 1.0/1.1 support and SSLv2/SSLv3 are still finding-worthy misconfigurations.
2. **HSTS does not protect the first request.** Preloading solves this. A site without HSTS
   or without the `Secure` cookie flag is vulnerable to SSL stripping on first visit.
3. **HTTP/2 introduced request smuggling** by creating interpretation ambiguities between
   HTTP/2 frontend and HTTP/1.1 backend. This will be your most complex web attack category.
4. **HTTP/3 over QUIC runs on UDP port 443** — it may bypass TCP-based network inspection.
   0-RTT is a replay risk.
5. **CDN ≠ WAF bypass immunity.** Finding the origin IP bypasses both. Historical DNS,
   CT logs, and non-CDN subdomains are your tools.
6. **`X-Forwarded-For` is attacker-controlled** unless the application validates it properly.
   Testing it against IP-restricted endpoints is a quick win.

---

## Exercises

### Exercise 1 — TLS Configuration Audit

Run this against any live target (e.g. `example.com`):

```bash
# Check supported protocols and ciphers
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for HSTS
curl -sI https://example.com | grep -i strict

# Full TLS audit
testssl.sh https://example.com
```

For each finding, identify:
1. Is TLS 1.0 or 1.1 supported? What is the risk?
2. Is HSTS set? With what max-age?
3. Are any weak ciphers present (RC4, 3DES, EXPORT)?
4. Does the server support TLS 1.3?

---

### Exercise 2 — HTTP/2 and CDN Analysis

1. Check whether `https://cloudflare.com` supports HTTP/2 and HTTP/3:
   ```bash
   curl -sI --http2 https://cloudflare.com | head -5
   curl -sI https://cloudflare.com | grep -i "alt-svc"
   ```
2. For a target behind Cloudflare, enumerate its subdomains and identify which ones are NOT
   behind Cloudflare (no `cf-ray` header in response).
3. Use Shodan to search for a known server banner and try to identify the origin IP of a
   CDN-protected site.

---

### Exercise 3 — Proxy Header Testing

Using Burp Suite (or curl), test a target endpoint with the following headers and document
the difference in response:

1. `X-Forwarded-For: 127.0.0.1`
2. `X-Forwarded-For: 10.0.0.1`
3. `X-Real-IP: 127.0.0.1`
4. `True-Client-IP: 127.0.0.1`

Do any of these change the response? Does the application behave differently? This is a
manual test you should run on every IP-restricted endpoint you find.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 005 — HTTP Cookies, Sessions and TLS](DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)*
*Next: [Day 007 — Wireshark Lab: Network Traffic Analysis](DAY-0007-Wireshark-Lab-Network-Analysis.md)*
