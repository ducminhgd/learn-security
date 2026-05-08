---
title: "Crypto CTF Sprint — Day 1: RSA Challenges"
tags: [cryptography, CTF, RSA, small-exponent, CRT, common-modulus,
  low-private-exponent, Wiener-attack, Boneh-Durfee, Coppersmith,
  partial-key-recovery, sprint]
module: 09-Crypto-01
day: 583
prerequisites:
  - Day 582 — Cryptopals CTF Day 12 (hash multicollisions)
  - Day 567 — RSA Attack Lab (foundational RSA attacks)
  - Day 576 — Cryptopals Set 6 Part 1 (unpadded oracle, e=3 forgery)
related_topics:
  - Crypto CTF Sprint Day 2 (Day 584)
  - RSA Attack Lab (Day 567)
---

# Day 583 — Crypto CTF Sprint: Day 1 (RSA)

> "RSA is the attack surface that keeps giving. Small e, small d, shared n,
> common factor, LSB oracle, parity oracle — each one is a failed exam on the
> mathematical underpinnings of the scheme. By the end of today you will have
> a toolkit that solves 90% of RSA CTF challenges on first sight."
>
> — Ghost

---

## Goals

Sprint through the most common RSA attack categories in CTF competitions:
low private exponent (Wiener's attack), Coppersmith's small-roots theorem,
common-factor attacks, and broadcast attacks. For each, implement the core
attack and learn to recognise the vulnerability from challenge parameters.

**Prerequisites:** RSA fundamentals through Day 579; Day 567 (small-exponent attacks).
**Estimated lab time:** 5 hours.

---

## RSA CTF Vulnerability Fingerprint

Before writing a single line of code, identify the attack from the challenge
parameters:

| Observation | Attack | Day |
|---|---|---|
| `e` is small (3, 5, 17) and `m^e < n` | Cube/eth root of c | Day 567 |
| Same message, 3+ recipients, same `e` | Håstad broadcast (CRT + root) | Day 567 |
| `e1`, `e2` coprime, same `n`, same `m` | Common exponent (ext. Euclidean) | Day 567 |
| `e` is large, near `n^0.25`, d is small | Wiener's attack (continued fractions) | Today |
| Partial knowledge of factors (MSBs of p) | Coppersmith small roots | Today |
| Two moduli share a factor | GCD attack | Today |
| Ciphertext oracle (one bit leak) | Parity oracle | Day 578 |
| Decryption oracle (replay allowed) | Unpadded message recovery | Day 576 |
| PKCS#1 v1.5 conformance oracle | Bleichenbacher | Day 579 |

---

## Attack 1 — Wiener's Attack (Low Private Exponent)

If `d < n^0.25 / 3`, the private key `d` can be recovered from the public
key `(e, n)` using continued fraction expansion of `e/n`.

**Intuition:** RSA requires `e·d ≡ 1 mod φ(n)`, meaning `e·d = k·φ(n) + 1`
for some integer `k`. Rearranging: `e/n ≈ k/d` (since `φ(n) ≈ n`). The
fraction `k/d` appears as a convergent in the continued fraction expansion
of `e/n` — and convergents are computable from the public key.

```python
#!/usr/bin/env python3
"""
Wiener's attack on RSA with small private exponent.
Recovers d when d < n^(1/4) / 3.
"""
from __future__ import annotations

from math import isqrt
from sympy.ntheory.continued_fraction import continued_fraction_convergents, continued_fraction_iterator


def wiener_attack(e: int, n: int) -> int | None:
    """
    Recover d using Wiener's attack on RSA.
    Returns d if attack succeeds, None if d is not small enough.
    """
    # Convergents of e/n
    cf   = continued_fraction_iterator(e, n)
    for k, d in continued_fraction_convergents(cf):
        if k == 0:
            continue
        # Check if (e*d - 1) is divisible by k (gives phi(n))
        if (e * d - 1) % k != 0:
            continue
        phi_n = (e * d - 1) // k
        # phi(n) = (p-1)(q-1) = n - (p+q) + 1
        # So p+q = n - phi_n + 1
        b     = n - phi_n + 1
        # Check if b^2 - 4n is a perfect square (discriminant of p*q = n, p+q = b)
        disc  = b * b - 4 * n
        if disc < 0:
            continue
        sqrt_disc = isqrt(disc)
        if sqrt_disc * sqrt_disc != disc:
            continue
        # Found p and q
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        if p * q == n:
            return int(d)
    return None


# ── Demo: generate a vulnerable key ──────────────────────────────────────────

from Crypto.Util.number import getPrime, inverse

def gen_wiener_key(bits: int = 512) -> tuple[int, int, int, int]:
    """Generate an RSA key with d < n^0.25."""
    while True:
        p    = getPrime(bits // 2)
        q    = getPrime(bits // 2)
        n    = p * q
        phi  = (p - 1) * (q - 1)
        # Choose small d
        bound = isqrt(isqrt(n)) // 3
        d     = getPrime(bound.bit_length() - 1)   # d < n^0.25 / 3
        if d < 3:
            continue
        try:
            e = inverse(d, phi)
        except Exception:
            continue
        if e > n:   # e must be > n for continued fraction to work
            return e, n, d, phi


e, n, d_actual, _ = gen_wiener_key(512)
print(f"[*] e = {e}")
print(f"[*] n bits = {n.bit_length()}")
print(f"[*] d actual  = {d_actual}")

d_recovered = wiener_attack(e, n)
print(f"[*] d recovered = {d_recovered}")
assert d_recovered == d_actual, "Wiener attack failed"
print("[+] Wiener's attack succeeded")
```

---

## Attack 2 — Common Factor Attack (Batch GCD)

If two RSA moduli `n1 = p1 * q1` and `n2 = p1 * q2` share a prime factor
(weak RNG reuse), `gcd(n1, n2) = p1`, immediately factoring both.

```python
#!/usr/bin/env python3
"""
Batch GCD attack: find RSA keys that share a prime factor.
Efficient for large collections using pairwise GCDs.
"""
from __future__ import annotations

import math
from Crypto.Util.number import getPrime, inverse

def batch_gcd_attack(moduli: list[int]) -> dict[int, tuple[int, int]]:
    """
    For each pair (ni, nj), compute gcd. If gcd > 1, we have factored both.
    Naive O(n^2) — for large batches, use product-tree GCD.
    """
    factored: dict[int, tuple[int, int]] = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                p, q = g, moduli[i] // g
                factored[i] = (p, q)
            if 1 < g < moduli[j]:
                p, q = g, moduli[j] // g
                factored[j] = (p, q)
    return factored


# Generate 10 normal keys + 1 vulnerable pair sharing a prime
keys = []
shared_p = getPrime(512)

for i in range(10):
    p = getPrime(512)
    q = getPrime(512)
    keys.append(p * q)

# Insert two keys that share shared_p
q1 = getPrime(512)
q2 = getPrime(512)
keys.append(shared_p * q1)   # index 10
keys.append(shared_p * q2)   # index 11

factored = batch_gcd_attack(keys)
print(f"[+] Found {len(factored)} factored moduli:")
for idx, (p, q) in factored.items():
    print(f"  n[{idx:2d}] factored: p={p.bit_length()} bits, q={q.bit_length()} bits")
    assert keys[idx] == p * q

assert 10 in factored and 11 in factored, "Expected to factor shared-prime keys"
print("[+] Batch GCD attack succeeded")
```

---

## Attack 3 — Coppersmith Small Root (Known High Bits of Message)

If an attacker knows the upper `k` bits of the plaintext `m`, and
`k > b/e` (where `b` is the key size in bits), Coppersmith's theorem lets them
recover `m` in polynomial time.

**CTF scenario:** The plaintext is `"Order #XXXXXXXXX from customer ALICE"` where
the order number `XXXXXXXXX` is the secret. The attacker knows the template.

```python
#!/usr/bin/env python3
"""
Coppersmith small root: recover m when upper bits are known.
Uses sage (SageMath) — this is the canonical implementation.
"""

# ── SageMath version (requires: sage -python this_file.py) ────────────────────
SAGE_CODE = '''
from sage.all import *

# Parameters
e   = 3
n   = ...   # RSA modulus
c   = ...   # ciphertext
# Known: upper 2/3 of the message
m_known  = ...   # integer representing known bits (shifted left)
m_mask   = ...   # 0 for known bits, secret bits

# Coppersmith via FLATTER or lattice reduction
P.<x> = PolynomialRing(Zmod(n))
f = (m_known + x)^e - c
roots = f.small_roots(X=2^(n.nbits()//3), beta=1.0)
for r in roots:
    print(f"Secret bits: {r}")
    print(f"Full message: {m_known + r}")
'''

# ── Pure Python approximation for small keys (demo only) ──────────────────────
# For real Coppersmith, use SageMath. The pure-Python version below
# demonstrates the concept on a tiny key.

def coppersmith_demo(e: int, n: int, c: int, m_upper: int, unknown_bits: int) -> int | None:
    """
    Extremely simplified Coppersmith: brute-force the unknown bits.
    Only feasible for unknown_bits <= 24 (demo purposes).
    For real attacks, use SageMath's .small_roots().
    """
    for x in range(2**unknown_bits):
        m_candidate = m_upper | x
        if pow(m_candidate, e, n) == c:
            return m_candidate
    return None


print("[*] Coppersmith attack requires SageMath for practical use.")
print("[*] See SAGE_CODE above for the real implementation.")
print("[*] Demo: brute-force version for small unknown_bits:")

from Crypto.Util.number import getPrime
p, q     = getPrime(256), getPrime(256)
n_demo   = p * q
e_demo   = 3
# Message: known upper 400 bits, unknown lower 12 bits
secret   = 0xABC   # 12 bits
m_full   = (0xDEADBEEF << 12) | secret
c_demo   = pow(m_full, e_demo, n_demo)
result   = coppersmith_demo(e_demo, n_demo, c_demo, 0xDEADBEEF << 12, 12)
assert result == m_full, "Demo failed"
print(f"[+] Recovered secret bits: 0x{secret:x} (Coppersmith demo, 12 unknown bits)")
```

---

## CTF Problem Set: RSA Challenges

Each of the following is a realistic CTF challenge. Work through each one using
the appropriate attack from this session.

```
Challenge A — Wiener Warmup
  Given: n (2048-bit), e (nearly n in size), ciphertext c
  Goal: Recover plaintext
  Hint: Check if d < n^0.25 — if e is enormous, d is tiny.

Challenge B — Shared Prime
  Given: 100 RSA public keys (n1, e), ..., (n100, e)
  Goal: Decrypt a message encrypted under one of the keys
  Hint: Some pairs share a prime factor. One GCD and you have d.

Challenge C — Partial Key Recovery
  Given: n (1024-bit), e=3, c, and a hex string "flag = CTF{XXXXX_???????}"
         where the first 5 chars of the flag content are known
  Goal: Recover the full flag
  Hint: 5 known chars = 40 bits known at a fixed position. Coppersmith.

Challenge D — Low Private Exponent (CTF)
  Given: n (1024-bit), e (very large, > n^0.75)
  Goal: Factor n or decrypt c
  Hint: Wiener. Run the continued fraction attack. If d is small, it's there.

Challenge E — N = p^2 * q
  Given: n that is NOT semiprime — it factors as p^2 * q
  Goal: Decrypt ciphertext
  Hint: Use Fermat's factoring or Pollard's p-1 algorithm. The modulus is
        specially structured.
```

---

## Self-Assessment

```
[ ] 1. Wiener's attack works when d < n^0.25. NIST recommends d have the same
        bit-length as n. What does this tell you about the key generation
        parameter that was chosen poorly in vulnerable keys?

[ ] 2. The batch GCD attack found many weak RSA keys in the wild in 2012
        (Heninger et al., "Mining Your Ps and Qs"). What RNG failure caused
        so many keys to share prime factors?

[ ] 3. Coppersmith's theorem is about "small roots of polynomials modulo n."
        Explain in plain English what this means for RSA and why knowing
        1/3 of the message bits is theoretically sufficient to recover the rest.

[ ] 4. Given a CTF challenge with RSA where e = 65537 (standard) and n is
        2048 bits with no other information, what attacks are feasible? What
        additional information would you need to apply each attack?
```

---

## Key Takeaways

1. **Wiener's attack targets the mathematical relationship between e, d, and φ(n).**
   Choosing a small d for performance creates a weak key. The fix is simple:
   always generate d of full bit-length.
2. **Shared prime factors are catastrophic.** Two RSA keys sharing a prime can both
   be factored by a single GCD operation. The 2012 large-scale audit found that
   0.2% of RSA keys in the wild were vulnerable — millions of real keys.
3. **Coppersmith's theorem is powerful but requires SageMath.** For CTFs, always
   install SageMath and learn the `.small_roots()` API. It solves entire
   categories of RSA challenges that would otherwise require number theory PhD
   level implementation.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q583.1, Q583.2 …).

---

## Navigation

← Previous: [Day 582 — Cryptopals CTF Day 12](DAY-0582-Cryptopals-CTF-Day-12.md)
→ Next: [Day 584 — Crypto CTF Sprint Day 2](DAY-0584-Crypto-CTF-Sprint-Day-2.md)
