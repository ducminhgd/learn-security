---
title: "LWE and Kyber Internals — How Post-Quantum KEM Works"
tags: [cryptography, post-quantum, LWE, Module-LWE, Kyber, ML-KEM,
  polynomial-ring, NTT, CRYSTALS, key-encapsulation, module-09-crypto-02]
module: 09-Crypto-02
day: 607
prerequisites:
  - Day 606 — Post-Quantum Preview (Shor, NIST standards, LWE hardness)
  - Basic polynomial arithmetic (multiply, reduce)
  - Day 586 — Lattice Basics
related_topics:
  - Post-Quantum Preview (Day 606)
  - Crypto Catch-Up (Day 609)
---

# Day 607 — LWE and Kyber Internals: How a Post-Quantum KEM Works

> "You spent 45 days learning to break crypto. Today you learn to build it —
> the right way, from first principles. Kyber is the standard. Understanding
> how it works is not optional for a security engineer in 2026. And if you
> want to find implementation bugs in PQC libraries — which are coming — you
> need to know what the correct computation looks like."
>
> — Ghost

---

## Goals

Understand Module-LWE, polynomial rings over `Z_q`, how ML-KEM (Kyber)
performs key generation, encapsulation, and decapsulation, and identify
the implementation-level attack surfaces.

**Prerequisites:** Day 606 (LWE hardness, NIST context).
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Polynomial Rings Over Z_q

ML-KEM works in the polynomial ring:

```
R_q = Z_q[x] / (x^n + 1)

n = 256, q = 3329  (for ML-KEM-768)
```

Elements of `R_q` are polynomials of degree < 256 with coefficients in
`Z_3329 = {0, 1, ..., 3328}`. Multiplication is polynomial multiplication
followed by reduction mod `(x^256 + 1)` and coefficient reduction mod 3329.

```python
#!/usr/bin/env python3
"""
Polynomial ring R_q = Z_q[x] / (x^n + 1) arithmetic.
This is the building block of Kyber/ML-KEM.
"""
from __future__ import annotations

N = 256     # Polynomial degree
Q = 3329    # Prime modulus (Kyber's q)


def poly_add(a: list[int], b: list[int]) -> list[int]:
    """Pointwise addition mod q."""
    return [(ai + bi) % Q for ai, bi in zip(a, b)]


def poly_sub(a: list[int], b: list[int]) -> list[int]:
    """Pointwise subtraction mod q."""
    return [(ai - bi) % Q for ai, bi in zip(a, b)]


def poly_mul(a: list[int], b: list[int]) -> list[int]:
    """
    Polynomial multiplication mod (x^n + 1) and mod q.
    Uses schoolbook O(n^2) for clarity; production uses NTT.
    """
    result = [0] * N
    for i in range(N):
        for j in range(N):
            if i + j < N:
                result[i + j] = (result[i + j] + a[i] * b[j]) % Q
            else:
                # x^k where k >= N: x^(k) ≡ -x^(k-N) mod (x^N + 1)
                result[i + j - N] = (result[i + j - N] - a[i] * b[j]) % Q
    return result


def poly_compress(p: list[int], d: int) -> list[int]:
    """Compress polynomial: round each coefficient to d bits."""
    factor = (1 << d)
    return [round(x * factor / Q) % factor for x in p]


def poly_decompress(p: list[int], d: int) -> list[int]:
    """Decompress polynomial: scale d-bit values back to Z_q."""
    factor = (1 << d)
    return [round(x * Q / factor) % Q for x in p]


# Demo: verify x^256 ≡ -1 mod (x^256 + 1)
e256 = [0] * N
e256[255] = 1   # x^255
x   = [0] * N
x[1] = 1        # x
result = poly_mul(e256, x)   # x^256 mod (x^256 + 1)
print(f"[*] x^256 mod (x^256+1) = {result[:4]}...")   # Should be [Q-1, 0, 0, ...] ≡ -1

# Basic ring arithmetic
a = [1, 2, 3] + [0] * (N - 3)
b = [4, 5, 6] + [0] * (N - 3)
c = poly_mul(a, b)
print(f"[*] (1+2x+3x^2)(4+5x+6x^2) = {c[:8]}...")
```

---

## Stage 2 — Module-LWE

Kyber uses **Module-LWE**: instead of working in `Z_q^n`, it works in `R_q^k`
— vectors of polynomials. For ML-KEM-768, `k = 3`.

A Module-LWE sample is:

```
A ∈ R_q^{k×k}   (public matrix, uniformly random)
s ∈ R_q^k        (secret vector, small coefficients)
e ∈ R_q^k        (error vector, small coefficients)
b = A·s + e      (Module-LWE sample)
```

**Hard problem:** Given `(A, b)`, find `s` (or distinguish `(A, b)` from
a uniformly random pair).

---

## Stage 3 — ML-KEM Key Generation, Encapsulation, Decapsulation

### Key Generation

```python
#!/usr/bin/env python3
"""
Simplified ML-KEM-768 key generation (educational — not constant-time).
Real Kyber uses NTT for O(n log n) polynomial multiplication.
"""
from __future__ import annotations
import os
import hashlib

N, Q, K = 256, 3329, 3   # ML-KEM-768 parameters
ETA1, ETA2 = 2, 2         # Noise distribution parameters (CBD_eta)


def sample_uniform(seed: bytes, nonce: int, size: int) -> list[int]:
    """Sample a polynomial with uniform coefficients in Z_q using SHAKE-128."""
    import hashlib
    xof   = hashlib.shake_128()
    xof.update(seed + bytes([nonce]))
    out   = xof.digest(size * 3)   # Oversample, reject > q-1
    poly  = []
    i     = 0
    while len(poly) < size:
        d1 = out[i] + 256 * (out[i+1] & 0x0F)
        d2 = (out[i+1] >> 4) + 16 * out[i+2]
        if d1 < Q:
            poly.append(d1)
        if d2 < Q and len(poly) < size:
            poly.append(d2)
        i += 3
        if i + 2 >= len(out):
            out += xof.digest(size * 3)
    return poly[:size]


def cbd(seed: bytes, nonce: int, eta: int) -> list[int]:
    """Centered Binomial Distribution: small-coefficient polynomial."""
    import hashlib
    prf   = hashlib.shake_256()
    prf.update(seed + bytes([nonce]))
    buf   = prf.digest(64 * eta)   # 64*eta bytes needed
    poly  = []
    for i in range(N):
        a_ = sum(1 for bit in range(eta) if (buf[i * eta // 8] >> bit) & 1)
        b_ = sum(1 for bit in range(eta, 2 * eta) if (buf[i * eta // 8] >> bit) & 1)
        poly.append((a_ - b_) % Q)
    return poly


def keygen() -> tuple[dict, dict]:
    """
    ML-KEM key generation.
    Returns (public_key, private_key).
    """
    # 1. Sample seed d and expand to (ρ, σ)
    d    = os.urandom(32)
    rho  = hashlib.sha3_512(d).digest()[:32]   # For A
    sigma = hashlib.sha3_512(d).digest()[32:]   # For s, e

    # 2. Generate public matrix A ∈ R_q^{k×k} from rho
    A = [[sample_uniform(rho, i * K + j, N) for j in range(K)] for i in range(K)]

    # 3. Sample secret s and error e from CBD
    s = [cbd(sigma, i, ETA1)       for i in range(K)]
    e = [cbd(sigma, K + i, ETA1)   for i in range(K)]

    # 4. Compute b = A*s + e  (matrix-vector multiplication in R_q)
    b = []
    for i in range(K):
        row_sum = [0] * N
        for j in range(K):
            row_sum = poly_add(row_sum, poly_mul(A[i][j], s[j]))
        b.append(poly_add(row_sum, e[i]))

    # Public key: (A or ρ, b); Private key: s
    return ({"rho": rho, "b": b}, {"s": s, "rho": rho, "b": b})


# Demo (simplified — no NTT, slow for large inputs)
print("[*] ML-KEM-768 Key Generation (simplified, educational)")
pk, sk = keygen()
print(f"[*] Public key rho: {pk['rho'].hex()[:16]}...")
print(f"[*] Secret s[0][:5]: {sk['s'][0][:5]}")   # Small coefficients
print(f"[*] Secret coefficients range: [{min(sk['s'][0])}, {max(sk['s'][0])}]")
print("[+] Key generation complete")
```

### Encapsulation / Decapsulation (Conceptual)

```
Encapsulation (Alice → Bob, using Bob's public key pk = (ρ, t)):

  1. Sample random message m ∈ {0,1}^256
  2. Derive (r, K_bar, coins) = G(m || H(pk))
  3. Sample error polynomials r, e1, e2 from CBD using coins
  4. Compute:
       u = A^T · r + e1     (k polynomials)
       v = t^T · r + e2 + Decompress(m, 1)   (1 polynomial)
  5. Ciphertext c = (Compress(u, d_u), Compress(v, d_v))
  6. Shared secret K = KDF(K_bar || H(c))

Decapsulation (Bob, using sk = s):

  1. Decompress u, v from ciphertext c
  2. Compute: m' = Compress(v - s^T · u, 1)   ← recover message
     (because v - s^T·u = t^T·r + e2 + msg - s^T·(A^T·r + e1)
                        = (As)^T·r + ... + msg - s^T·A^T·r - s^T·e1
                        ≈ msg   since error terms are small)
  3. Re-encapsulate m' and check c == c'  → Reject if not (implicit rejection)
  4. Output shared secret K
```

---

## Stage 4 — Implementation Attack Surfaces

Post-quantum schemes introduce **new attack surfaces** that classical attackers
did not have to consider:

| Attack | Target | Description |
|---|---|---|
| Decryption failure oracle | Kyber | Malformed ciphertext → error leaks secret |
| Timing in CBD sampling | Dilithium | Branch on secret coefficient distribution |
| NTT timing side-channel | Kyber/Dilithium | Conditional reduction in butterfly step |
| Gaussian sampling (FALCON) | FALCON | Most sensitive: tree sampling leaks σ bits |
| Rejection sampling loop | Dilithium | Timing reveals secret polynomial s |
| Key reuse across schemes | Hybrid | Using same key for PQ + classical |

**Most dangerous:** FALCON's discrete Gaussian sampling is extremely sensitive
to timing. Any implementation that branches on the generated sample value
leaks private key bits. This is why hardware acceleration of FALCON is hard.

---

## Key Takeaways

1. **ML-KEM is built on polynomial ring arithmetic**, not integer arithmetic.
   The polynomial ring `Z_q[x]/(x^n+1)` with NTT multiplication is the
   computational engine — very different from modular exponentiation in RSA.
2. **The security parameter is the lattice dimension** (n·k for Module-LWE).
   ML-KEM-768 has effective dimension 768 — far beyond LLL's reach.
3. **Post-quantum schemes have new implementation bugs.** Gaussian sampling
   timing in FALCON, NTT timing in Kyber, and rejection sampling timing in
   Dilithium are active research areas. Security engineers must understand
   these to audit PQC implementations.
4. **You will see PQC in production within 2 years.** Learn the API
   (`liboqs`, `CIRCL`, `pqclean`) and understand what the parameters mean.

---

## Exercises

```
1. The polynomial ring Z_3329[x]/(x^256+1) has order 3329^256.
   Write a Python function that multiplies two random degree-10 polynomials
   in this ring and verify the result satisfies x^256 ≡ -1 mod (x^256+1).

2. In ML-KEM, why is the error e added? What would happen to security
   if e = 0 for all samples? Describe the resulting attack.

3. Research: what is the Number Theoretic Transform (NTT) and why does
   Kyber use it instead of schoolbook polynomial multiplication?
   What is the speedup for n=256?

4. FALCON uses discrete Gaussian sampling for its "trapdoor" signing.
   Research one published side-channel attack on FALCON's Gaussian sampler
   and describe: (a) what is leaked, (b) how many signatures are needed,
   (c) what is the mitigating countermeasure.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q607.1, Q607.2 …).

---

## Navigation

← Previous: [Day 606 — Post-Quantum Preview](DAY-0606-Post-Quantum-Preview.md)
→ Next: [Day 608 — PQC Attack Surface and Implementation Review](DAY-0608-PQC-Attack-Surface.md)
