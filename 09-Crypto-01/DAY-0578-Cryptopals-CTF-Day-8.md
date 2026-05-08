---
title: "Cryptopals CTF Practice — Day 8: Set 6 Part 3 (DSA Tampering + RSA Parity Oracle)"
tags: [cryptography, cryptopals, CTF, DSA, parameter-tampering, magic-signature,
  RSA, parity-oracle, binary-search, set-6, challenge-45, challenge-46]
module: 09-Crypto-01
day: 578
prerequisites:
  - Day 577 — Cryptopals CTF Day 7 (DSA key recovery)
  - Day 567 — RSA Attack Lab
related_topics:
  - Cryptopals CTF Day 9 (Day 579)
  - DSA key recovery (Day 577)
---

# Day 578 — Cryptopals CTF Practice: Day 8

> "Challenge 45 is the most elegant attack in the entire Cryptopals series.
> One bad parameter — g = p+1 — and a single signature verifies against
> every message ever written. That is not a corner case. That is a trapdoor
> built into the group structure."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 6 Challenges 45 and 46: DSA parameter tampering
(the "magic signature" attack), and RSA decryption via the parity oracle —
the binary search that reduces any RSA ciphertext to plaintext using only
the last bit of each decryption.

**Prerequisites:** Sets 1–5 + Challenges 41–44 complete; Day 567.
**Estimated lab time:** 4 hours.
**Resource:** https://cryptopals.com/sets/6

---

## Challenge 45 — DSA Parameter Tampering

DSA's domain parameters `(p, q, g)` are typically shared and trusted. If an
attacker can substitute `g`, the signature scheme breaks completely.

### Case 1: g = 0 (mod p)

Any signature `(r, s)` with `r = 0` verifies for any message, because:

```
r = (g^k mod p) mod q = 0^k mod q = 0
```

Most implementations correctly reject `r = 0` as invalid. But…

### Case 2: g = p + 1 (≡ 1 mod p)

This is the real attack. When `g ≡ 1 mod p`:

```
y  = g^x mod p = (p+1)^x mod p = 1^x = 1
r  = (g^k mod p) mod q = 1 mod q = 1   (for any k)
```

The magic signature `(r=1, s=1)` verifies for **every message**:

```
Verify(m, y=1, r=1, s=1):
  w  = s⁻¹ mod q = 1
  u1 = H(m) · w mod q = H(m) mod q
  u2 = r · w mod q    = 1
  v  = (g^u1 · y^u2 mod p) mod q
     = ((p+1)^H(m) · 1^1 mod p) mod q
     = (1^H(m) · 1 mod p) mod q   ← since p+1 ≡ 1 mod p
     = 1 mod q
     = 1 = r  ✓
```

```python
#!/usr/bin/env python3
"""
Challenge 45: DSA parameter tampering — magic signature.
With g = p+1, the signature (1, 1) verifies for any message.
"""
from __future__ import annotations

import hashlib
import gmpy2

# Standard DSA domain parameters
P = int(
    "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
    "1a584471bb1",
    16,
)
Q = 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
G_MALICIOUS = P + 1    # g ≡ 1 mod p

# Key pair with malicious g
# x: any private key — y will always be 1
x = 42
y = pow(G_MALICIOUS, x, P)     # = 1
print(f"[*] Public key y with g=p+1: {y}  (expected 1: {y == 1})")


def dsa_verify(msg: bytes, r: int, s: int, y_pub: int, g: int) -> bool:
    """Standard DSA verification."""
    if not (0 < r < Q and 0 < s < Q):
        return False
    w  = int(gmpy2.invert(s, Q))
    h  = int(hashlib.sha1(msg).hexdigest(), 16)
    u1 = (h * w) % Q
    u2 = (r * w) % Q
    v  = (pow(g, u1, P) * pow(y_pub, u2, P)) % P % Q
    return v == r


# Magic signature: (r=1, s=1) verifies for any message
r_magic = 1
s_magic = 1

for msg in (b"Hello, world", b"ATTACK AT DAWN", b"Buy 1000 shares"):
    valid = dsa_verify(msg, r_magic, s_magic, y, G_MALICIOUS)
    print(f"  [+] '{msg.decode()}' → {valid}")
    assert valid, f"Expected True for '{msg.decode()}'"

print("[+] Challenge 45 passed — (1, 1) is a universal signature when g=p+1")


# ── Generalised magic signature for any r ────────────────────────────────────
# For challenge 45 variant: forge (r, s) where r = (y^z mod p) mod q
# Choose any z. Then r = y^z mod p mod q, s = r * z^-1 mod q.
# Verification:
#   w  = s^-1 = z * r^-1 mod q
#   u1 = H(m) * w  mod q  — doesn't matter with g=p+1
#   u2 = r * w = r * z * r^-1 = z mod q
#   v  = g^u1 * y^z mod p mod q = 1 * y^z mod p mod q = r ✓

def forge_signature_for_any_message(z: int, y_pub: int, q: int) -> tuple[int, int]:
    """Forge a valid DSA signature under g=p+1 for any message."""
    r = pow(y_pub, z, P) % Q
    s = (r * int(gmpy2.invert(z, Q))) % Q
    return r, s

r_forged, s_forged = forge_signature_for_any_message(7, y, Q)
for msg in (b"Authorised", b"Transfer $1000000", b"Random garbage 9!@"):
    valid = dsa_verify(msg, r_forged, s_forged, y, G_MALICIOUS)
    print(f"  [+] Forged sig for '{msg.decode()}': {valid}")
    assert valid
```

---

## Challenge 46 — RSA Parity Oracle

An RSA parity oracle is any system that, given a ciphertext `c`, reveals
whether `decrypt(c) mod 2 == 0` (even) or `1` (odd). With nothing but this
single bit per query, you can recover the full plaintext in `log₂(n)` iterations
using a binary search.

**The key insight:** multiplying the ciphertext by `2^e mod n` doubles the
plaintext (mod n). Since `n` is odd, doubling a plaintext `m`:
- If `2m < n`: result is even → `m < n/2` → narrow search to lower half.
- If `2m ≥ n`: result wraps to `2m - n` which is odd (n is odd, 2m even) →
  `m ≥ n/2` → narrow search to upper half.

After `k` iterations (where `2^k > n`), the interval `[lo, hi)` collapses to `m`.

```python
#!/usr/bin/env python3
"""
Challenge 46: RSA parity oracle — binary search decryption.
"""
from __future__ import annotations

import base64
from fractions import Fraction

import gmpy2
from Crypto.Util.number import getPrime


def gen_rsa(bits: int = 1024) -> tuple[tuple[int, int], tuple[int, int]]:
    """Return ((e, n), (d, n))."""
    e = 65537
    while True:
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        if p == q:
            continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) == 1:
            d = int(gmpy2.invert(e, phi))
            return (e, n), (d, n)


pub, priv = gen_rsa(1024)
e, n       = pub
d, _       = priv

# Challenge plaintext (base64 encoded in the challenge)
plaintext_b64 = (
    "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFy"
    "b3VuZCB3aXRoIHRoZSBFdmlsIEV5ZQ=="
)
plaintext_bytes = base64.b64decode(plaintext_b64)
m_original      = int.from_bytes(plaintext_bytes, "big")
ciphertext      = pow(m_original, e, n)


def parity_oracle(c: int) -> int:
    """Return 0 if decrypt(c) is even, 1 if odd."""
    return pow(c, d, n) % 2


def rsa_parity_attack(c: int, pub_key: tuple[int, int]) -> bytes:
    """
    Recover plaintext using the parity oracle.
    Each iteration: multiply ciphertext by 2^e mod n → plaintext doubles mod n.
    Oracle bit tells us whether we overflowed n (upper half) or not (lower half).
    """
    e_key, n_key = pub_key
    lo = Fraction(0)
    hi = Fraction(n_key)

    # Multiplier: 2^e mod n (applied cumulatively to ciphertext)
    f_exp   = pow(2, e_key, n_key)
    c_curr  = c
    bits    = n_key.bit_length()

    for i in range(bits):
        c_curr  = (c_curr * f_exp) % n_key
        mid     = (lo + hi) / 2
        if parity_oracle(c_curr) == 0:
            # Even → 2*m mod n is in lower half → m < hi/2 relative to current range
            hi = mid
        else:
            # Odd  → 2*m mod n wrapped → m ≥ mid
            lo = mid

        # Progress indicator every 128 bits
        if (i + 1) % 128 == 0:
            partial = int(hi).to_bytes(len(plaintext_bytes) + 1, "big")
            print(f"  [{i+1:4d}/{bits}] partial: {partial[-30:]!r}")

    # hi is the plaintext as a Fraction; take ceiling and convert to bytes
    recovered_int   = int(hi)
    recovered_bytes = recovered_int.to_bytes(len(plaintext_bytes), "big")
    return recovered_bytes


print("[*] Starting RSA parity oracle attack …")
print(f"[*] Key: {n.bit_length()} bits → {n.bit_length()} oracle queries needed")

recovered = rsa_parity_attack(ciphertext, pub)
print(f"\n[+] Recovered plaintext: {recovered!r}")
assert recovered == plaintext_bytes, f"Mismatch!\n{recovered!r}\n{plaintext_bytes!r}"
print("[+] Challenge 46 passed — RSA plaintext recovered with one bit per query")
```

**Complexity:** `O(log₂ n)` oracle queries — 1024 queries for a 1024-bit key.
Against a remote server with 1 ms per query, that is roughly 1 second. Against
a system where "parity" is any detectable 1-bit leak (response time, error type,
padding validity), this attack scales to real-world RSA without padding.

**Fix:** OAEP or any semantically secure padding. The oracle cannot exist
when plaintext is randomised by the padding scheme.

---

## Set 6 / Challenges 45–46 Self-Assessment

```
[ ] 1. Challenge 45 requires g = p+1. What prevents an attacker from just
        sending g=p+1 in a DSA key exchange? In what real-world scenario
        is this parameter substitution feasible?

[ ] 2. In the parity oracle attack, why do we use Fraction arithmetic rather
        than floating-point? What goes wrong with float at high precision?

[ ] 3. The parity oracle attack requires exactly bit_length(n) queries.
        Can you think of a variant that uses the least-significant 2 bits
        (i.e. modulo 4) per query to halve the number of iterations?

[ ] 4. RSA-OAEP is the standard fix. But why does OAEP eliminate the oracle —
        not just make it harder? What property of OAEP breaks the homomorphism?
```

---

## Key Takeaways

1. **Parameter validation is a first-class security control.** DSA's security
   relies on the group structure being correct. Accepting caller-supplied
   parameters without validating them against trusted domain parameters
   completely destroys the scheme.
2. **A single bit of oracle output is enough.** The parity oracle needs only
   one bit per decryption. Any system that leaks one bit of information about
   plaintext — error codes, timing, response size — can be attacked this way.
3. **RSA without padding is homomorphic in a dangerous way.** Both challenge 41
   (multiplicative blinding) and challenge 46 (parity oracle) exploit the fact
   that unpadded RSA preserves algebraic structure in the plaintext. OAEP removes
   this structure by randomising every encryption.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q578.1, Q578.2 …).

---

## Navigation

← Previous: [Day 577 — Cryptopals CTF Day 7](DAY-0577-Cryptopals-CTF-Day-7.md)
→ Next: [Day 579 — Cryptopals CTF Day 9](DAY-0579-Cryptopals-CTF-Day-9.md)
