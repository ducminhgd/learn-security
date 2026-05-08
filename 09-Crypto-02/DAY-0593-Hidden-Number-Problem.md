---
title: "Hidden Number Problem — Lattice Attacks on Biased ECDSA Nonces"
tags: [cryptography, lattice, HNP, ECDSA, nonce-bias, DSA, CVP, BDD,
  SageMath, LLL, BKZ, module-09-crypto-02]
module: 09-Crypto-02
day: 593
prerequisites:
  - Day 587 — LLL Algorithm
  - Day 569 — ECDSA Nonce Reuse (exact nonce reuse attack)
  - Day 577 — DSA Key Recovery from Known Nonce
related_topics:
  - HNP Lab (Day 594)
  - MT19937 State Recovery (Day 595)
---

# Day 593 — The Hidden Number Problem: Lattice Attacks on Biased ECDSA Nonces

> "The ECDSA nonce reuse attack from Day 569 is brute force: two signatures
> with the same k, you have the key. The Hidden Number Problem is surgical:
> you have a hundred signatures where each k is just slightly biased — maybe
> the top 4 bits are always zero. That 4-bit bias is enough. LLL sees it.
> You recover the private key from the lattice. This is how real Bitcoin wallet
> compromises happen."
>
> — Ghost

---

## Goals

Understand the Hidden Number Problem (HNP) formulation, how it arises from
biased ECDSA nonces, and how to reduce it to CVP/BDD on a lattice solvable
by LLL or BKZ.

**Prerequisites:** Days 569, 577 (ECDSA nonce attacks), Day 587 (LLL).
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Recon: The Hidden Number Problem

### Definition (Boneh–Venkatesan 1996)

Given:
- A prime `q` (group order)
- A hidden number `α ∈ Z_q` (the private key)
- `n` pairs `(t_i, u_i)` where `u_i = MSBs_k(α · t_i mod q)` — the `k`
  most significant bits of `α · t_i mod q`

**Goal:** Recover `α`.

**Reduction:** This reduces to **BDD** (Bounded Distance Decoding) on a
specific lattice. With `n ≥ 2k/log q` samples, LLL solves it in polynomial time.

---

## Stage 2 — ECDSA Nonce Bias → HNP

### ECDSA Signature Recap

Sign message `m` with private key `d`, nonce `k` (random, per-signature):

```
r = (k·G).x mod q
s = k^{-1} · (H(m) + d·r) mod q
```

From `(r, s)` and `H(m)`, derive:

```
k = s^{-1} · (H(m) + d·r) mod q
```

### Nonce Bias

Suppose the nonce generator is weak and the **top `l` bits of k are always 0**:
`k < q / 2^l` (the common "leading zero bits" bias).

Rearranging the ECDSA equation:

```
k = s^{-1} · H(m) + s^{-1} · r · d    (mod q)
```

Let `t_i = s_i^{-1} · r_i mod q` and `u_i = s_i^{-1} · H(m_i) mod q`.
Then:

```
k_i = t_i · d + u_i    (mod q)
```

Since `k_i < q / 2^l` (top `l` bits are zero), this says the fractional
part of `t_i · d / q` (scaled) is within `2^{-l}` of `-u_i / q`. This is
precisely the **Hidden Number Problem** with bias `l` bits.

### How Many Signatures Needed?

| Bias `l` bits | Signatures needed (approx) | Notes |
|---|---|---|
| 1 bit | ~400 | Very hard; requires BKZ-50+ |
| 2 bits | ~200 | Hard; BKZ-30 |
| 4 bits | ~100 | Practical with LLL |
| 8 bits | ~50 | Easy; LLL suffices |
| 16 bits | ~20 | Trivial |
| Full nonce (`l = 256`) | 1 | Day 569: exact nonce reuse |

---

## Stage 3 — The Lattice Construction

### Setup

Collect `n` signatures `(r_i, s_i)` on messages `m_i`. Compute:

```
t_i = r_i · s_i^{-1} mod q
u_i = H(m_i) · s_i^{-1} mod q
```

The bias gives: `t_i · d + u_i ≡ k_i (mod q)` where `|k_i| < B = q / 2^l`.

### The Lattice

Construct an `(n+2) × (n+2)` matrix:

```
M = | q   0   0  ...  0   0   0 |  ← row 0
    | 0   q   0  ...  0   0   0 |  ← row 1
    | .   .   .       .   .   . |
    | 0   0   0  ...  q   0   0 |  ← row n-1
    | t_0 t_1 t_2 ... t_{n-1} 1/q 0 |  ← row n (private key row)
    | u_0 u_1 u_2 ... u_{n-1} 0  B |  ← row n+1 (bias row)
```

The short vector `v` in this lattice encodes `(k_0, ..., k_{n-1}, d/q, 1)`.
Its norm is roughly `sqrt(n) · B`, much shorter than random lattice vectors
of norm ~sqrt(n) · q.

```python
#!/usr/bin/env python3
"""
Hidden Number Problem: lattice attack on ECDSA with biased nonces.
Uses SageMath LLL to recover the private key d.
"""
# SageMath
from sage.all import (ZZ, Integer, Matrix, vector, GF,
                      EllipticCurve, randint)


def hnp_ecdsa_attack(q: int, sigs: list[dict], bias_bits: int) -> int | None:
    """
    Recover ECDSA private key d from n signatures with l-bit nonce bias.

    sigs: list of dicts with keys: r, s, h (hash of message, as integer)
    bias_bits: l (number of MSBs of k that are zero, k < q/2^l)
    Returns: d (integer private key) or None
    """
    n = len(sigs)
    q_int = Integer(q)
    B     = Integer(q) >> bias_bits   # Bias bound: k_i < B

    # Compute t_i, u_i
    ts = [Integer(sig["r"]) * Integer(sig["s"]).inverse_mod(q_int) % q_int
          for sig in sigs]
    us = [Integer(sig["h"]) * Integer(sig["s"]).inverse_mod(q_int) % q_int
          for sig in sigs]

    # Build (n+2) × (n+2) lattice matrix
    # Scale factor for the last two entries
    # Using the Nguyen-Shparlinski formulation:
    M = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        M[i, i] = q_int          # q along diagonal (first n rows)
    for i in range(n):
        M[n, i] = ts[i]           # t_i in the (n+1)-th row
        M[n+1, i] = us[i]         # u_i in the (n+2)-th row
    M[n, n]     = Integer(1)      # scale: d row
    M[n+1, n+1] = B               # scale: bias row

    # LLL reduction
    L = M.LLL()

    # The short vector should be (k_0 - B, ..., k_{n-1} - B, d, B) or similar
    # The private key d is in position n of the short vector
    for row in L:
        # d candidate: row[n] (before the B scaling)
        d_candidate = int(row[n]) % int(q)
        if d_candidate == 0:
            d_candidate = int(-row[n]) % int(q)
        # Verify against first signature
        s0, r0, h0 = sigs[0]["s"], sigs[0]["r"], sigs[0]["h"]
        # k = (h + d*r) * s^{-1} mod q
        k_check = (h0 + d_candidate * r0) * pow(int(s0), -1, int(q)) % int(q)
        if k_check < (int(q) >> bias_bits):   # Verify bias holds
            return d_candidate
    return None


# ── Simulation ────────────────────────────────────────────────────────────────
# Use secp256k1 parameters (Bitcoin's curve) — simplified for demo
# Real secp256k1: q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# For demo, use a small prime-order group
p_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a_curve, b_curve = 0, 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
q_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Use smaller demo values to keep the simulation fast
import random
rng = random.SystemRandom()

# Demo with a small prime group instead of secp256k1 (for speed)
q_demo = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
# Use first 64 bits for demo
q_small = Integer(next(p for p in range(2**62, 2**63) if Integer(p).is_prime()))

d_true  = Integer(rng.randrange(1, int(q_small)))
bias    = 6   # top 6 bits of k are zero: k < q/64
n_sigs  = 80  # number of signatures

def sign_ecdsa_biased(d: int, q: int, h: int, bias: int) -> dict:
    """Sign with biased nonce (top `bias` bits are zero)."""
    k = rng.randrange(1, q >> bias)   # k < q/2^bias
    # In real ECDSA: r = (k·G).x mod q. For demo, simulate r:
    r = pow(k, 2, q) % q   # Fake r (not real EC multiplication — demo only)
    if r == 0:
        return sign_ecdsa_biased(d, q, h, bias)
    s = pow(k, -1, q) * (h + d * r) % q
    if s == 0:
        return sign_ecdsa_biased(d, q, h, bias)
    return {"r": int(r), "s": int(s), "h": int(h), "k": int(k)}

sigs = [sign_ecdsa_biased(int(d_true), int(q_small),
                          rng.randrange(1, int(q_small)), bias)
        for _ in range(n_sigs)]

print(f"[*] q = {int(q_small).bit_length()} bits")
print(f"[*] bias = {bias} bits (k < q/2^{bias}), {n_sigs} signatures")

d_recovered = hnp_ecdsa_attack(int(q_small), sigs, bias)
if d_recovered and d_recovered == int(d_true):
    print(f"[+] Private key d recovered!")
else:
    print(f"[!] Failed — need more signatures or stronger reduction (BKZ)")
    print(f"    Try increasing n_sigs or bias")
```

---

## Real-World Cases

### PS3 Private Key Recovery (2010)

Sony's PS3 used ECDSA with a **constant nonce** (k was the same for every
signature). This is nonce reuse (Day 569), a special case of HNP where bias
is infinite. Geohot recovered the private key and published the signing key.

### Bitcoin Wallet Compromises

Several Bitcoin wallets used flawed PRNG (Android SecureRandom bug, 2013)
that produced nonces with low entropy. The HNP lattice attack was applied to
Bitcoin transactions, recovering private keys and allowing theft of funds.

### NIST P-256 Side-Channel (Brumley & Tuveri 2011)

Timing leakage in OpenSSL's scalar multiplication for ECDSA signatures leaked
partial nonce bits. Approximately 200 signatures with a 3-bit leak sufficed
to recover the private key via HNP.

---

## Key Takeaways

1. **HNP generalises nonce reuse.** Exact nonce reuse (Day 569) is HNP with
   full bias. Partial bias (top k bits = 0) requires more signatures and a
   better reduction algorithm.
2. **The lattice encodes the bias as a distance.** The biased nonces `k_i`
   are much smaller than `q`. This translates to a lattice vector that is much
   shorter than random — LLL finds it.
3. **4-bit bias is practically exploitable.** With 100 ECDSA signatures and
   4 leading zero bits in each nonce, LLL recovers the private key. This means
   any weak PRNG that loses 4 bits per output is catastrophic for ECDSA.
4. **Detection:** monitor for repeated `r` values (exact reuse) or collect
   signatures and test nonce bias statistically before mounting HNP.

---

## Exercises

```
1. In the HNP lattice, why is the scaling factor B (the bias bound) placed
   at position (n+1, n+1)? What happens if you use q instead of B there?

2. As the bias decreases (fewer bits known), more signatures are needed.
   Estimate: with 2-bit bias and secp256k1 (256-bit q), approximately how
   many signatures does the literature say are needed for LLL to succeed?

3. The PS3 attack used constant k = k0 for ALL signatures.
   Show that with 2 signatures and constant k, you can recover d in O(1).
   (Hint: this is Day 569. Confirm HNP includes nonce-reuse as a special case.)

4. Research: what is the Nguyen-Shparlinski lattice variant for HNP?
   How does it differ from the formulation above?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q593.1, Q593.2 …).

---

## Navigation

← Previous: [Day 592 — RSA Lattice Attacks: Stereotyped Messages](DAY-0592-RSA-Lattice-Attacks-Stereotyped.md)
→ Next: [Day 594 — HNP Lab](DAY-0594-HNP-Lab.md)
