---
title: "Crypto CTF Sprint — Day 5: Multi-Attack Challenges"
tags: [cryptography, CTF, RSA, ECDSA, padding-oracle, GCM, PRNG, MT19937,
  multi-attack, sprint, SageMath, module-09-crypto-02]
module: 09-Crypto-02
day: 602
prerequisites:
  - Day 601 — Crypto CTF Sprint Day 4
  - Days 561–599 — Full crypto attack module
related_topics:
  - Crypto CTF Sprint Day 6 (Day 603)
  - All crypto days (561–599)
---

# Day 602 — Crypto CTF Sprint: Day 5 (Multi-Attack Challenges)

> "The real world does not label vulnerabilities. You get a black box and
> a flag. Today's problems do not announce which technique to use. Each one
> requires you to look at what you have, identify what class of problem it is,
> and apply the right tool. No hints. No labels. Figure it out."
>
> — Ghost

---

## Goals

Solve five mixed-category crypto CTF challenges without technique hints.
Each problem combines two or more techniques from the full Module 09 curriculum.

**Prerequisites:** All of Days 561–600.
**Estimated time:** 6–7 hours (aim for 5).

---

## Problem 1 — "Oracle Relay" (Padding Oracle + CBC-MAC Forgery)

**Prompt:**
```
A service accepts AES-128-CBC encrypted messages and processes them as
admin commands if valid.

POST /command
  Body: { "ciphertext": "<hex>", "mac": "<hex>" }
  → If padding invalid: HTTP 400 with "Padding error"
  → If mac invalid:     HTTP 403 with "Auth failed"
  → If valid:           HTTP 200 with command output

The MAC is CBC-MAC over the plaintext using a different (unknown) key.
You have one valid (ciphertext, mac) pair for the command "ping".

Goal: forge a (ciphertext, mac) pair for the command "exec:cat /flag".
```

**Analysis steps:**

```
Step 1: Padding oracle is available (400 vs 403 gives you the side channel).
Step 2: Use CBC padding oracle (Day 561) to DECRYPT the "ping" ciphertext.
Step 3: Now you know the plaintext. Construct a new plaintext for "exec:cat /flag".
Step 4: CBC-R (Day 585): use the padding oracle as an encryption oracle to
        produce a valid CBC ciphertext for the new plaintext.
Step 5: CBC-MAC forgery (Day 580): if the MAC key is the same as the enc key,
        a length-extension forgery applies. If different, you cannot forge
        without the MAC key — but look: the server gives you a 403, not 400,
        which means it DECRYPTS before checking MAC. So you can iterate
        CBC-R to produce valid padding + use the decrypted command to infer MAC.

Key insight: The oracle order (decrypt first, then MAC check) enables a
chosen-plaintext oracle via CBC-R. This is exactly how POODLE works.
```

```python
# Skeleton solve
import requests, os

BASE = "http://localhost:9001"

def padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    """Returns True if padding is valid (200 or 403, not 400)."""
    import base64
    r = requests.post(f"{BASE}/command", json={
        "ciphertext": (iv + ciphertext).hex(),
        "mac": "00" * 16
    })
    return r.status_code != 400   # 400 = padding error; 403 = auth (valid padding)


# Your CBC padding oracle (Day 561) + CBC-R (Day 585) here
# Then construct the forged (ciphertext, mac) pair
print("Implement: padding_oracle → decrypt → CBC-R encrypt new plaintext")
```

---

## Problem 2 — "Mersenne Leak" (MT19937 + AES-CTR Nonce Reuse)

**Prompt:**
```
An API server generates session tokens using Python's random.getrandbits(256).
The same MT19937 RNG also generates AES-CTR nonces for encrypting responses.

You can:
  - Register accounts → observe 624 session tokens (32-bit chunks each)
  - After cloning the RNG, predict the AES-CTR nonce for the admin session
  - You have a ciphertext of the admin's encrypted response

Goal: Decrypt the admin response and find the flag.
```

```python
#!/usr/bin/env python3
"""
Solve: predict AES-CTR nonce after MT19937 state recovery.
"""
from __future__ import annotations
import requests, random
from Crypto.Cipher import AES


BASE  = "http://localhost:9002"

def untemper(y: int) -> int:
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp & 0xFFFFFFFF
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    return tmp & 0xFFFFFFFF


def clone_mt(outputs: list[int]) -> random.Random:
    state  = [untemper(o) for o in outputs[:624]]
    cloned = random.Random()
    cloned.setstate((3, tuple(state) + (624,), None))
    return cloned


# Step 1: Register 624 accounts, observe 32-bit token fragments
# tokens = [int.from_bytes(requests.post(f"{BASE}/register",
#           json={"user": f"u{i}"}).json()["token"][:4], "big") for i in range(624)]
# (Simulated):
target_rng = random.Random()
tokens     = [target_rng.getrandbits(32) for _ in range(624)]

# Step 2: Clone RNG
cloned = clone_mt(tokens)

# Step 3: The admin's AES-CTR nonce was generated AFTER the 624 tokens
# AES-CTR nonce = 16 bytes = 4 × 32-bit words
nonce_words = [cloned.getrandbits(32) for _ in range(4)]
nonce       = b"".join(w.to_bytes(4, "big") for w in nonce_words)

# Step 4: Decrypt admin response with predicted nonce
# admin_ct = bytes.fromhex(requests.get(f"{BASE}/admin-encrypted").text)
admin_ct   = b"CHALLENGE_CIPHERTEXT_BYTES_HERE"   # replace with actual

# AES-CTR key is fixed (different from nonce — assume known from source leak)
aes_key    = b"STATIC_KEY_12345"   # from static analysis of the server

if admin_ct != b"CHALLENGE_CIPHERTEXT_BYTES_HERE":
    cipher     = AES.new(aes_key, AES.MODE_CTR, nonce=nonce[:8],
                         initial_value=nonce[8:])
    plaintext  = cipher.decrypt(admin_ct)
    print(f"[+] Decrypted: {plaintext}")
else:
    print("[*] Replace CHALLENGE_CIPHERTEXT_BYTES_HERE with actual ciphertext")
    print(f"[*] Predicted nonce: {nonce.hex()}")
    print(f"[*] Verify: actual nonce should be {target_rng.getrandbits(32):08x} ...")
```

---

## Problem 3 — "Two Keys" (Franklin-Reiter + Wiener)

**Prompt:**
```
You intercept two RSA-encrypted messages. Both use the SAME N (1024-bit) and
different values of e:
  e1 = 3,    c1 = <256-byte hex>
  e2 = 65537 (but d is small — hint: key generation tool used d < N^0.25)

Message m1 was encrypted with e1.
Message m2 was the same m1 with a 4-byte suffix appended: m2 = m1 * 2^32 + suffix.

Recover both m1 and m2.
```

```python
# Step 1: Wiener's attack on (N, e2=65537) to recover d2 → decrypt c2 → get m2
# Step 2: From m2 = m1 * 2^32 + suffix, and knowing suffix from Wiener output,
#         verify m2 relation, then use Franklin-Reiter to recover m1 from c1
# (or just compute m1 = m2 // 2^32 once m2 is known from Wiener)

from sage.all import ZZ, Zmod, PolynomialRing, Integer

def wiener_attack(N: int, e: int) -> int | None:
    """From Day 592."""
    def cf(num, den):
        while den:
            q    = num // den
            num, den = den, num - q * den
            yield q
    def convergents(cf_iter):
        p, pp, q, qp = 1, 0, 0, 1
        for a in cf_iter:
            p, pp = a * p + pp, p
            q, qp = a * q + qp, q
            yield p, q
    import math
    for k, d in convergents(cf(e, N)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b   = N - phi + 1
        disc = b * b - 4 * N
        if disc < 0:
            continue
        sq = int(disc ** 0.5)
        for sq2 in [sq - 1, sq, sq + 1]:
            if sq2 * sq2 == disc:
                p = (b + sq2) // 2
                if p * (b - sq2 + p - p) == N:   # check
                    pass
                q = N // p
                if p * q == N:
                    return d
    return None

# d2 = wiener_attack(N, 65537)
# m2 = pow(c2, d2, N)
# m1 = m2 >> 32  (assuming suffix is last 4 bytes)
# Verify: pow(m1, 3, N) == c1
print("Chain: Wiener → d2 → m2 → m1 via suffix extraction → verify with c1")
```

---

## Problem 4 — "Repeated GCM" (GCM Nonce Reuse → Forgery)

**Prompt:**
```
An API signs all responses with AES-128-GCM.
The nonce counter resets every 65536 requests (implementation bug).
After making 65537 requests, you get two responses encrypted with the same nonce.

Response 65536: { "user": "alice", "balance": 1000 }  → (C1, T1, AAD1)
Response 65537: { "user": "alice", "balance": 9000 }  → (C2, T2, AAD2)
  (Different plaintexts, same key+nonce — the bug)

Forge a response: { "user": "alice", "balance": 999999 } with a valid tag.
```

```python
# GCM Forbidden Attack (from Day 585)
# Given (C1, T1, AAD1) and (C2, T2, AAD2) with same nonce:
# Recover H (GHASH key) then forge tag for any (C_forge, AAD_forge)
# Full implementation: see Day 585 code. Adapt here.

# Challenge-specific:
# The responses have structure: encrypt(json_bytes)
# C_forge = encrypt(target_json) using the recovered keystream
# C_forge = C1 XOR keystream = C1 XOR P1 XOR P_target
# Then forge T_forge using recovered H and S

import json

P1     = json.dumps({"user": "alice", "balance": 1000}).encode()
P2     = json.dumps({"user": "alice", "balance": 9000}).encode()
P_tgt  = json.dumps({"user": "alice", "balance": 999999}).encode()

# Keystream K = C1 XOR P1 (since C1 = P1 XOR K)
# C_tgt     = P_tgt XOR K = P_tgt XOR C1 XOR P1
# Then: apply GCM Forbidden Attack to get T_tgt from H and S

# C1, T1, C2, T2 come from actual challenge data
# (Full implementation in Day 585)
print("Apply GCM Forbidden Attack → recover H, S → forge tag for P_tgt")
print("C_forge = P_tgt XOR C1 XOR P1 (keystream reuse)")
```

---

## Problem 5 — "Correlated Nonces" (ECDSA + Lattice)

**Prompt:**
```
A service uses secp256k1 ECDSA. The nonce is generated as:
  k = HMAC-SHA256(static_secret, counter)[:16] concatenated with random[:16]

This means the top 128 bits of each k are deterministic (but unknown to you).
You observe 150 signatures. The top 128 bits are CORRELATED across signatures
(same static_secret, different counter).

Describe (or implement) the attack that recovers the private key d.
```

**Analysis:**

```
This is a variant of HNP where the bias is not in the magnitude of k but in
the RELATIONSHIP between nonces. All nonces share the same top 128 bits
structure (deterministic from HMAC).

Two approaches:
  A) Treat top 128 bits of k as unknown constant + random bottom 128 bits.
     Each k = K_top_i + r_i where K_top_i = HMAC(secret, i)[:16].
     This is NOT standard HNP because K_top_i varies per signature.

  B) Difference attack: k_i - k_{i-1} = (K_top_i - K_top_{i-1}) + (r_i - r_{i-1})
     = ΔK_top + Δr where ΔK_top is deterministic and Δr is small (128-bit range).
     This IS a biased nonce problem on the DIFFERENCE.

Concrete steps:
  1. Compute k_i - k_{i-1} for consecutive pairs.
  2. The differences have known top bits (0 — because both tops are from HMAC
     of sequential counters, typically close in value).
  3. Apply HNP to the differences.
```

---

## Sprint Scoring

| Problem | Points | Notes |
|---|---|---|
| 1 — Oracle Relay | 25 | Padding oracle + CBC-R chain |
| 2 — Mersenne Leak | 20 | MT19937 clone + CTR nonce prediction |
| 3 — Two Keys | 20 | Wiener + Franklin-Reiter chain |
| 4 — Repeated GCM | 20 | GCM Forbidden Attack |
| 5 — Analysis | 15 | Correct approach description |
| **Total** | **100** | |

**Pass criterion:** ≥ 65 points.

---

## Key Takeaways

1. **Multi-step attacks require chaining.** Problem 1 (padding oracle →
   CBC-R → execute) and Problem 3 (Wiener → Franklin-Reiter) both require
   the output of one attack to feed the next. Build the chain before writing
   code.
2. **PRNG attacks are practical.** Problem 2 shows that MT19937 state recovery
   translates directly to AES key stream prediction if the same RNG generates
   nonces. This is a real vulnerability pattern in web frameworks.
3. **GCM nonce reuse is a complete break.** Problem 4 — once two messages
   share a nonce, both confidentiality AND authenticity are broken.
4. **Novel variants require analysis.** Problem 5 has no standard solution
   in literature — it requires thinking through the structure of the bias.
   This is the skillset that makes a vulnerability researcher.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q602.1, Q602.2 …).

---

## Navigation

← Previous: [Day 601 — Crypto CTF Sprint Day 4](DAY-0601-Crypto-CTF-Sprint-Day-4.md)
→ Next: [Day 603 — Crypto CTF Sprint Day 6](DAY-0603-Crypto-CTF-Sprint-Day-6.md)
