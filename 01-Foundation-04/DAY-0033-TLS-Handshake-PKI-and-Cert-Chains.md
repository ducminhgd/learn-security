---
title: "TLS Handshake, PKI, and Certificate Chains"
tags: [foundation, cryptography, TLS, PKI, certificate, CA, OCSP,
       pinning, handshake, forward-secrecy, mTLS]
module: 01-Foundation-04
day: 33
related_topics:
  - HTTP Cookies Sessions and TLS (Day 005)
  - TLS Attacks HTTP2 and Proxies (Day 006)
  - Asymmetric Encryption and RSA Attacks (Day 032)
  - Crypto in the Wild CVE Review (Day 037)
---

# Day 033 — TLS Handshake, PKI, and Certificate Chains

## Goals

By the end of this lesson you will be able to:

1. Trace every step of a TLS 1.3 handshake with the cryptographic
   operation at each step.
2. Explain the PKI trust chain: root CA → intermediate CA → leaf cert.
3. Explain OCSP and CRL: certificate revocation and its limitations.
4. Explain certificate transparency (CT logs) and how attackers use them.
5. Explain certificate pinning and how to bypass it (preview for Day 403).
6. Use `openssl` and `testssl.sh` to audit a TLS configuration.

---

## Prerequisites

- [Day 005 — HTTP Cookies, Sessions and TLS](../01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)
- [Day 032 — Asymmetric Encryption and RSA Attacks](DAY-0032-Asymmetric-Encryption-and-RSA-Attacks.md)

---

## Main Content — Part 1: TLS 1.3 Handshake

### 1. TLS 1.3 Step-by-Step

TLS 1.3 (RFC 8446, 2018) was a major redesign. It's faster (1-RTT, 0-RTT)
and stronger (removed all weak algorithms).

```
Client                                          Server
  │                                                │
  │── ClientHello ───────────────────────────────► │
  │   - TLS version: 1.3                           │
  │   - Random: 32 bytes                           │
  │   - Cipher suites: [TLS_AES_128_GCM_SHA256...] │
  │   - Extensions:                                │
  │     - key_share: client DH public key          │
  │     - supported_versions: [1.3]                │
  │     - server_name: target.com (SNI)            │
  │                                                │
  │◄── ServerHello ────────────────────────────── │
  │   - Selected cipher suite                      │
  │   - Random: 32 bytes                           │
  │   - key_share: server DH public key            │
  │                                                │
  │  [Both sides compute: shared_secret = ECDH(client_priv, server_pub)]
  │  [Derive: handshake_secret, traffic_keys using HKDF]
  │                                                │
  │◄── {EncryptedExtensions} ─────────────────── │
  │◄── {Certificate} ──────────────────────────── │
  │   - Server's X.509 certificate chain           │
  │◄── {CertificateVerify} ───────────────────── │
  │   - Signature over the handshake transcript    │
  │◄── {Finished} ──────────────────────────────  │
  │   - HMAC over handshake transcript             │
  │                                                │
  │── {Finished} ───────────────────────────────► │
  │                                                │
  │◄── [Application Data (encrypted)] ─────────── │
  │── [Application Data (encrypted)] ──────────►  │
```

`{}` = encrypted with handshake keys
`[]` = encrypted with application traffic keys

**Key exchange:** ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- Both sides generate ephemeral key pairs.
- They exchange public keys.
- Each independently computes the shared secret: `shared = ECDH(my_priv, peer_pub)`.
- The shared secret is never transmitted — only derived independently.

**Forward secrecy:** Because the key pair is ephemeral (generated fresh
per session), compromising the server's long-term private key in the future
cannot decrypt past sessions. This is a critical security property.

---

### 2. Key Derivation in TLS 1.3

TLS 1.3 uses **HKDF** (HMAC-based Key Derivation Function) to derive
multiple keys from the shared secret:

```
early_secret = HKDF-Extract(0, PSK or 0)
handshake_secret = HKDF-Extract(early_secret, ECDH_shared_secret)
master_secret = HKDF-Extract(handshake_secret, 0)

From master_secret, derive:
- client_write_key    → AES-GCM key for client→server data
- server_write_key    → AES-GCM key for server→client data
- client_write_iv     → IV/nonce for client→server
- server_write_iv     → IV/nonce for server→client
```

This multi-step derivation ensures that compromising one key doesn't
reveal others. Each direction has its own key — preventing replay attacks.

---

## Main Content — Part 2: PKI and Certificate Chains

### 3. X.509 Certificate Structure

```
Certificate:
  Version: 3
  Serial Number: 12345678
  Signature Algorithm: sha256WithRSAEncryption
  Issuer: CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert
  Subject: CN=*.example.com, O=Example Inc, C=US
  Validity:
    Not Before: Jan 1 00:00:00 2025
    Not After:  Jan 1 00:00:00 2026
  Subject Public Key Info:
    Algorithm: rsaEncryption
    Public Key: (4096-bit RSA public key)
  Extensions:
    Subject Alternative Names: *.example.com, example.com
    Key Usage: Digital Signature, Key Encipherment
    Extended Key Usage: TLS Web Server Authentication
    CRL Distribution Points: http://crl3.digicert.com/...
    Authority Information Access: OCSP: http://ocsp.digicert.com
    Certificate Transparency: (SCT list)
  Signature: (signed by DigiCert intermediate CA's private key)
```

---

### 4. The PKI Trust Chain

```
Root CA (self-signed, pre-installed in OS/browser)
    ↓ signs
Intermediate CA (cross-signed by root)
    ↓ signs
Leaf Certificate (your domain's cert)
```

**Why intermediates?**
- Root CA private keys are kept offline in HSMs (Hardware Security Modules)
  in air-gapped facilities.
- Intermediates can be revoked without revoking the root.
- Different intermediates for different purposes (TLS, code signing, email).

**Verifying the chain:**

```bash
# Download the server's certificate chain
openssl s_client -connect target.com:443 -showcerts < /dev/null 2>/dev/null

# Verify the chain manually
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
    -untrusted intermediate.pem server.pem

# Extract certificate fields
openssl x509 -in cert.pem -noout -text | \
    grep -E "Subject:|Issuer:|Not Before:|Not After:|Subject Alt"
```

---

### 5. Certificate Revocation: OCSP and CRL

Certificates can be revoked before they expire (compromised private key,
fraudulent issuance, etc.). Two revocation mechanisms:

**CRL (Certificate Revocation List):**
- A file listing all revoked serial numbers, signed by the CA.
- Published at a URL in the certificate (`CRL Distribution Points`).
- Downside: large files, downloaded infrequently, can be stale.

**OCSP (Online Certificate Status Protocol):**
- Query the CA's OCSP responder in real time to check status.
- Faster than CRL; response is valid for a short window.
- Downside: privacy leak (CA learns what you're connecting to), latency,
  OCSP responder availability.

**OCSP Stapling:**
- The server queries its own OCSP status and attaches the signed response
  to the TLS handshake.
- Eliminates client-side privacy leak and latency.
- The stapled response has a short validity (usually 24–48 hours).

**The revocation gap problem:**
Most browsers use "soft-fail" — if the OCSP responder is unreachable,
they proceed anyway. An attacker who MITM's the connection can also MITM
the OCSP check → certificate with compromised key remains usable.

---

### 6. Certificate Transparency (CT Logs)

Every publicly trusted CA must submit certificates to public, append-only
CT logs before browsers will trust them.

**Why CT logs matter for attackers:**
- Any certificate issued for your domain is public.
- `crt.sh` aggregates CT logs.
- Attackers use CT to discover subdomains before you've even deployed them.

```bash
# Find all certificates for a domain using crt.sh:
curl "https://crt.sh/?q=%.example.com&output=json" 2>/dev/null | \
    python3 -c "
import sys, json
certs = json.load(sys.stdin)
names = set()
for c in certs:
    for name in c.get('name_value','').split('\n'):
        names.add(name.strip())
for n in sorted(names): print(n)
"
```

This reveals:
- All issued subdomains (for recon).
- Historical subdomains (may still be active, or dangling CNAMEs).
- Certificate issuance dates (when was the domain first registered?).

---

### 7. TLS Audit Tools

```bash
# Full TLS configuration audit (cipher suites, protocols, vulnerabilities)
testssl.sh https://target.com

# Or install testssl.sh:
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh target.com:443

# Quick cipher suite check:
openssl s_client -connect target.com:443 -tls1_2 2>/dev/null | \
    grep "Cipher"

# Check for TLS 1.0 (should be disabled):
openssl s_client -connect target.com:443 -tls1 2>&1 | \
    grep "handshake failure\|no protocols"

# Certificate expiry check:
openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -dates
```

---

## Key Takeaways

1. **TLS 1.3 has forward secrecy by default** (ECDHE in every handshake).
   Recorded traffic cannot be decrypted even if the server's private key
   is stolen later. TLS 1.2 without ECDHE does not have this property.
2. **Certificate chains require validation at every step.** A broken chain
   (missing intermediate) or an expired intermediate causes connection
   failures — and attackers exploit misconfigured chains.
3. **CT logs are public.** Every subdomain you issue a certificate for is
   visible. Use CT monitoring to detect fraudulent certificates issued for
   your domain (`crt.sh` alerts).
4. **OCSP revocation is soft-fail.** Certificate revocation is not reliable
   for real-time protection. CT log monitoring and CAA DNS records (restrict
   which CAs can issue for your domain) are stronger controls.
5. **`testssl.sh` is the fastest way to audit a TLS config.** Run it on
   every target before testing. Weak cipher suites, SSLv3/TLS 1.0, expired
   certs, and ROBOT/POODLE vulnerabilities all show up immediately.

---

## Exercises

### Exercise 1 — Certificate Chain Analysis

```bash
# Inspect the cert chain for any HTTPS site you own (or a lab)
openssl s_client -connect your-domain.com:443 -showcerts < /dev/null \
    2>/dev/null | awk '/BEGIN CERT/,/END CERT/' | \
    csplit - '/END CERTIFICATE/' '{*}' 2>/dev/null

# For each certificate file generated:
openssl x509 -in xx00 -noout -subject -issuer -dates
openssl x509 -in xx01 -noout -subject -issuer -dates
# Trace the chain: leaf → intermediate → root
```

### Exercise 2 — CT Log Subdomain Discovery

Run the `crt.sh` query against a domain you are authorised to test.
How many subdomains are revealed? Are any unexpected or potentially
vulnerable to subdomain takeover (CNAME to a service you don't control)?

### Exercise 3 — testssl.sh Audit

Run `testssl.sh` against DVWA or any lab server running TLS.
Interpret the output:
- Which TLS versions are enabled?
- Are weak cipher suites offered?
- Is OCSP stapling enabled?
- What is the key size of the certificate?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 032 — Asymmetric Encryption and RSA Attacks](DAY-0032-Asymmetric-Encryption-and-RSA-Attacks.md)*
*Next: [Day 034 — Password Hashing and Cracking](DAY-0034-Password-Hashing-and-Cracking.md)*
