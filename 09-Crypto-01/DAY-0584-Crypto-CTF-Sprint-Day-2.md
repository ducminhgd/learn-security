---
title: "Crypto CTF Sprint — Day 2: DH / ECDH / ECDSA Challenges"
tags: [cryptography, CTF, DH, ECDH, ECDSA, discrete-logarithm,
  invalid-curve, small-subgroup, twist-attack, nonce-reuse,
  fault-attack, lattice-reduction, sprint]
module: 09-Crypto-01
day: 584
prerequisites:
  - Day 583 — Crypto CTF Sprint Day 1 (RSA)
  - Day 568 — Diffie-Hellman Attacks
  - Day 569 — ECDSA Nonce Reuse
related_topics:
  - Crypto CTF Sprint Day 3 (Day 585)
  - DH Attacks (Day 568)
  - ECDSA Nonce Reuse (Day 569)
---

# Day 584 — Crypto CTF Sprint: Day 2 (DH / ECDH / ECDSA)

> "Elliptic curve cryptography fails in exactly the same ways as finite-field
> DH when implementers cut corners. Invalid curve, small subgroup, reused nonce,
> biased nonce — each is a one-line mistake that collapses 256 bits of security
> to zero. Today you learn to spot all of them from a hex dump."
>
> — Ghost

---

## Goals

Sprint through DH, ECDH, and ECDSA CTF attack categories: discrete log over
small groups, invalid curve attacks, small subgroup confinement, ECDSA nonce
bias (lattice reduction), and fault attacks on scalar multiplication.

**Prerequisites:** Day 568 (DH attacks); Day 569 (ECDSA nonce reuse); Day 577
(DSA key recovery — same maths as ECDSA).
**Estimated lab time:** 5 hours.

---

## DH / ECDH / ECDSA CTF Vulnerability Fingerprint

| Observation | Attack | Difficulty |
|---|---|---|
| Small prime p (< 60-bit) | Baby-step giant-step discrete log | Easy |
| Smooth p-1 | Pohlig-Hellman (Day 568) | Medium |
| Server accepts arbitrary curve points | Invalid curve ECDH | Medium |
| Public key has small order | Small subgroup confinement | Medium |
| ECDSA with same r in two signatures | Nonce reuse → private key | Easy |
| ECDSA with many sigs, nonces partially known | Lattice attack (HNP) | Hard |
| Fault in scalar multiplication | Fault attack + invalid-curve CRT | Hard |
| secp256k1 with k from small range | Baby-step giant-step on k | Medium |

---

## Attack 1 — Baby-Step Giant-Step Discrete Log

For a group of order `n`, compute `g^x = h` in `O(√n)` time and space.

```python
#!/usr/bin/env python3
"""
Baby-step giant-step (BSGS) discrete logarithm.
Works for any group where n = group order is known and small.
"""
from __future__ import annotations

import math


def bsgs(g: int, h: int, p: int, n: int | None = None) -> int | None:
    """
    Solve g^x ≡ h (mod p) using baby-step giant-step.
    n: group order (defaults to p-1 for prime-order groups).
    Returns x if found, None otherwise.
    """
    if n is None:
        n = p - 1
    m     = math.isqrt(n) + 1
    table = {}

    # Baby steps: compute g^j mod p for j in [0, m)
    g_j = 1
    for j in range(m):
        table[g_j] = j
        g_j = (g_j * g) % p

    # Giant steps: compute h * g^(-m*i) for i in [0, m)
    g_inv_m = pow(g, (-m) % (p - 1), p)   # g^(-m) mod p
    h_curr  = h
    for i in range(m):
        if h_curr in table:
            x = i * m + table[h_curr]
            if pow(g, x, p) == h:
                return x
        h_curr = (h_curr * g_inv_m) % p
    return None


# ── Demo: small DH group ──────────────────────────────────────────────────────
p_small  = 0x00ffffffff00000001000000000000000000000001   # Small test prime
# Use a small 48-bit prime for speed
import secrets
p_demo   = 2**48 - 59   # A prime near 2^48
g_demo   = 2

# Secret x in [0, 2^24)  — small enough for BSGS
x_secret = secrets.randbelow(2**24)
h_demo   = pow(g_demo, x_secret, p_demo)

print(f"[*] p = {p_demo} ({p_demo.bit_length()} bits)")
print(f"[*] g = {g_demo}, secret x = {x_secret}")
x_recovered = bsgs(g_demo, h_demo, p_demo, 2**24)
print(f"[*] Recovered x = {x_recovered}")
assert x_recovered == x_secret
print("[+] BSGS discrete log succeeded")
```

---

## Attack 2 — Pohlig-Hellman Over Smooth Groups

If `p-1` is smooth (has only small prime factors), the discrete log problem
decomposes into small subgroup problems via the Chinese Remainder Theorem.

```python
#!/usr/bin/env python3
"""
Pohlig-Hellman discrete logarithm over a smooth-order group.
"""
from __future__ import annotations

from sympy.ntheory import factorint
from functools import reduce
from math import isqrt


def pohlig_hellman(g: int, h: int, p: int) -> int:
    """
    Solve g^x ≡ h (mod p) when p-1 is smooth.
    Uses Pohlig-Hellman with BSGS for each prime power subgroup.
    """
    order   = p - 1
    factors = factorint(order)   # {prime: exponent}
    residues, moduli = [], []

    for qi, ei in factors.items():
        qi_ei   = qi ** ei
        # Reduce to subgroup of order qi_ei
        g_sub   = pow(g, order // qi_ei, p)
        h_sub   = pow(h, order // qi_ei, p)
        # Solve discrete log in the qi_ei-order subgroup
        x_sub   = pohlig_subgroup(g_sub, h_sub, p, qi, ei)
        residues.append(x_sub)
        moduli.append(qi_ei)

    # CRT reconstruction
    return crt(residues, moduli)


def pohlig_subgroup(g: int, h: int, p: int, q: int, e: int) -> int:
    """Pohlig-Hellman in a q^e-order subgroup using DLP base q."""
    x   = 0
    g_k = pow(g, q ** (e - 1), p)
    for k in range(e):
        h_k = pow(pow(g, -x, p) * h % p, q ** (e - 1 - k), p)
        d_k = bsgs(g_k, h_k, p, q)
        if d_k is None:
            d_k = 0
        x += d_k * (q ** k)
    return x % (q ** e)


def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem reconstruction."""
    M   = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi  = M // m
        inv = pow(Mi, -1, m)
        x  += r * Mi * inv
    return x % M


# ── Demo: smooth p-1 ──────────────────────────────────────────────────────────
# Construct p = 2 * 3 * 5 * 7 * 11 * 13 * 17 + 1 (if prime)
import sympy
smooth_base = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23
p_smooth    = smooth_base + 1
while not sympy.isprime(p_smooth):
    smooth_base *= 2
    p_smooth     = smooth_base + 1

g_ph  = 2
x_ph  = 12345
h_ph  = pow(g_ph, x_ph, p_smooth)

x_rec = pohlig_hellman(g_ph, h_ph, p_smooth)
print(f"[+] Pohlig-Hellman: x = {x_ph}, recovered = {x_rec}")
assert x_rec % (p_smooth - 1) == x_ph % (p_smooth - 1)
print("[+] Pohlig-Hellman succeeded")
```

---

## Attack 3 — Invalid Curve ECDH

When a server performs ECDH but **does not validate that the peer's public key
lies on the specified curve**, the attacker can send points from a different
(twist) curve with small group order and extract the secret via Pohlig-Hellman.

```python
#!/usr/bin/env python3
"""
Invalid curve ECDH attack using SageMath.
(Pure Python sketch — use SageMath for real CTF work.)
"""

SAGE_SKETCH = '''
from sage.all import *

# Legitimate curve: secp256k1
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a  = 0
b  = 7
E  = EllipticCurve(GF(p), [a, b])
n  = E.order()   # Group order of secp256k1

# Twist: same p and a, different b — produces a curve with small subgroup
# Find b_twist such that E_twist has a smooth order
for b_twist in range(1, 1000):
    try:
        E_twist = EllipticCurve(GF(p), [a, b_twist])
        ord_twist = E_twist.order()
        from sympy import factorint
        factors = factorint(ord_twist)
        small_factors = [q for q in factors if q < 2**24]
        if small_factors:
            print(f"b_twist={b_twist}, small factors: {small_factors}")
            break
    except Exception:
        continue

# For each small-order subgroup, send a generator of that subgroup
# Server responds with scalar_multiple_of(secret, point)
# Use BSGS/Pohlig-Hellman to recover secret mod each small prime
# CRT combines residues to get full secret
'''

print("[*] Invalid curve attack requires SageMath for curve arithmetic.")
print("[*] Sketch:")
print(SAGE_SKETCH)
print()

# Pure-Python demo: small Weierstrass curve over tiny field
class ECPoint:
    """Minimal EC arithmetic over GF(p) for demo."""

    def __init__(self, x: int | None, y: int | None, a: int, p: int):
        self.x = x
        self.y = y
        self.a = a
        self.p = p

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __add__(self, other: "ECPoint") -> "ECPoint":
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        p = self.p
        if self.x == other.x:
            if self.y != other.y:
                return ECPoint(None, None, self.a, p)
            # Point doubling
            lam = (3 * self.x**2 + self.a) * pow(2 * self.y, -1, p) % p
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, -1, p) % p
        x3  = (lam**2 - self.x - other.x) % p
        y3  = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3, self.a, p)

    def __rmul__(self, n: int) -> "ECPoint":
        result = ECPoint(None, None, self.a, self.p)
        addend = self
        while n:
            if n & 1:
                result = result + addend
            addend = addend + addend
            n >>= 1
        return result


# Demo: small curve y^2 = x^3 + ax + b over GF(p_tiny)
p_tiny = 263
a_tiny = 1
b_tiny = 1   # Legitimate curve
# Generator
G_tiny = ECPoint(0, 1, a_tiny, p_tiny)   # Arbitrary point; may not be on curve
# In a real attack you'd use a point of known small order on the twist
print("[*] Invalid curve attack demo (concept only) — use SageMath for real work")
```

---

## Attack 4 — ECDSA Lattice Attack (Hidden Number Problem)

If ECDSA nonces have the same most-significant bits (leaked via timing or partial
key exposure), the private key can be recovered via lattice reduction (LLL).

```python
#!/usr/bin/env python3
"""
ECDSA lattice attack when the k MSBs of each nonce are known.
Uses the Hidden Number Problem (HNP) formulation.
"""
from __future__ import annotations


# The HNP formulation:
# Given m signatures (r_i, s_i) and message hashes h_i, with nonces k_i
# where the top t bits of k_i are known (= k_i_upper):
#
#   s_i = k_i^-1 * (h_i + x * r_i) mod n
#   k_i = s_i^-1 * (h_i + x * r_i) mod n
#   k_i - k_i_upper = s_i^-1 * h_i + s_i^-1 * r_i * x - k_i_upper  mod n
#
# Let u_i = s_i^-1 * h_i mod n
#     v_i = s_i^-1 * r_i mod n
#
# Then: k_i - k_i_upper ≡ u_i + v_i * x  (mod n)
# The left side is bounded by 2^(log_n - t).
# This gives a lattice problem: find x such that many bounded linear equations hold.
#
# Build a lattice L:
# [  n   0  0 ... 0    0  ]
# [  0   n  0 ... 0    0  ]
# ...
# [ v_0 v_1 ... v_{m-1} 1/K]
# [ u_0 u_1 ... u_{m-1} 0  ]
# where K = 2^(log_n - t)
#
# LLL reduces L; the short vector contains x (the private key).

SAGE_LATTICE = '''
from sage.all import *

# Curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Collected signatures (with known MSBs of nonce)
# sigs = [(r_i, s_i, h_i, k_upper_i), ...]

def ecdsa_lattice_attack(sigs, t, n):
    """t = number of known MSB bits in each nonce."""
    m  = len(sigs)
    K  = 2^(n.nbits() - t)
    
    # Build m x (m+2) matrix
    rows = []
    for (r, s, h, k_upper) in sigs:
        s_inv = inverse_mod(s, n)
        v = (s_inv * r) % n
        u = (s_inv * h) % n
        rows.append((v, u, k_upper))
    
    # Lattice construction
    M = matrix(QQ, m + 2, m + 2)
    for i in range(m):
        M[i, i] = n
        M[m,   i] = rows[i][0]   # v_i
        M[m+1, i] = rows[i][1]   # u_i - k_upper_i
    M[m,   m  ] = QQ(1) / K
    M[m+1, m+1] = QQ(0)
    
    # Subtract k_upper from u terms
    for i in range(m):
        M[m+1, i] = (rows[i][1] - rows[i][2]) % n
    
    L  = M.LLL()
    # Private key x is in the reduced vector
    for row in L.rows():
        x_candidate = int(row[m] * K)
        if 0 < x_candidate < n:
            # Verify against one known signature
            r0, s0, h0, _ = sigs[0]
            if pow(generator, x_candidate) * n == public_key:   # pseudocode
                return x_candidate
    return None
'''
print("[*] ECDSA lattice attack requires SageMath LLL.")
print("[*] See SAGE_LATTICE string for the implementation skeleton.")


# ── Conceptual demo: detect nonce bias and pivot to nonce reuse ──────────────
# If nonces share the top 1 byte (biased toward small values), this is detectable

def detect_nonce_bias(sigs: list[tuple[int, int]]) -> bool:
    """Detect if r values cluster in a small range (biased nonce k)."""
    rs = [r for r, s in sigs]
    # On secp256k1, r = (k*G).x mod n. If k < n/256, r < n/256
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    small_r_count = sum(1 for r in rs if r < n >> 8)
    # Expected by chance: 1/256 of signatures
    expected = len(sigs) / 256
    # If observed 5x higher, likely biased
    return small_r_count > 5 * expected


print("[+] Attack 4 (ECDSA lattice) — see SageMath code above for implementation")
```

---

## CTF Problem Set: DH / ECDH / ECDSA Challenges

```
Challenge A — Tiny DH
  Given: p (48-bit prime), g=2, public key h = g^x mod p
  Goal: Recover x and decrypt a message
  Tool: Baby-step giant-step. p is small enough for BSGS in seconds.

Challenge B — Pohlig Special
  Given: p = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 + 1, g=2, h = g^x mod p
  Goal: Recover x
  Tool: Pohlig-Hellman. Factorise p-1 first.

Challenge C — Invalid Curve Server
  Given: ECDH server using secp256k1 that accepts any x-coordinate
  Goal: Recover server's private key
  Tool: Send points from twist curves with small order; collect partial
        secrets; use Pohlig-Hellman + CRT.

Challenge D — Biased Nonce ECDSA
  Given: 40 ECDSA signatures where nonces have the same top byte
  Goal: Recover private key
  Tool: HNP lattice reduction (SageMath LLL on the lattice from above).

Challenge E — DH Parameter Injection
  Given: ECDH with server-selected curve parameters (not authenticated)
  Goal: Perform MITM and recover shared secret
  Tool: Same as Cryptopals Challenge 34 — inject g=1 or g=p-1; predict
        shared secret; decrypt traffic.
```

---

## Self-Assessment

```
[ ] 1. Baby-step giant-step has time and space complexity O(√n). For secp256k1
        (n ≈ 2^256), this is 2^128 operations — infeasible. Why is the same
        attack practical when the nonce k is chosen from a small range?

[ ] 2. Invalid curve ECDH requires the server to not validate the public key.
        Name the RFC/specification section that specifies this validation for
        TLS ECDH key exchange. What specific check is required?

[ ] 3. The HNP lattice attack on ECDSA requires t known MSBs of the nonce.
        How many signatures are typically needed when t=1 (one known bit)?
        When t=8 (one known byte)?

[ ] 4. In the Pohlig-Hellman demo, the discrete log was easy because p-1 was
        smooth. secp256k1's order n is a large prime. Why does Pohlig-Hellman
        NOT work against secp256k1's group order?
```

---

## Key Takeaways

1. **Group order determines attack feasibility.** A group with smooth order (many
   small prime factors) is vulnerable to Pohlig-Hellman. A group with prime
   order (like secp256k1) is not. Parameter selection is the first line of defence.
2. **Invalid curve attacks require one-line fixes.** Checking that a received
   point lies on the expected curve costs a single modular arithmetic operation.
   Omitting it gives attackers a tool to extract the private key with a few dozen
   queries.
3. **ECDSA nonce quality is everything.** Biased nonces (non-uniform, reused,
   predictable) all reduce to lattice problems. Use RFC 6979 deterministic nonce
   generation and you eliminate the entire class.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q584.1, Q584.2 …).

---

## Navigation

← Previous: [Day 583 — Crypto CTF Sprint Day 1](DAY-0583-Crypto-CTF-Sprint-Day-1.md)
→ Next: [Day 585 — Crypto CTF Sprint Day 3](DAY-0585-Crypto-CTF-Sprint-Day-3.md)
