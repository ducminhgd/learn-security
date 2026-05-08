---
title: "LLL Algorithm — Basis Reduction in Practice"
tags: [cryptography, lattice, LLL, Lenstra-Lovász, basis-reduction, Gram-Schmidt,
  SageMath, SVP, module-09-crypto-02]
module: 09-Crypto-02
day: 587
prerequisites:
  - Day 586 — Lattice Basics (SVP, CVP, Hadamard ratio)
related_topics:
  - LLL Lab (Day 588)
  - Coppersmith's Method (Day 589)
  - Hidden Number Problem (Day 593)
---

# Day 587 — The LLL Algorithm: Basis Reduction in Practice

> "LLL is 1982 technology that still breaks systems in 2026. Lenstra, Lenstra,
> and Lovász wanted to factor polynomials. They wrote an algorithm that happens
> to find short lattice vectors efficiently up to dimension ~200. Every lattice
> attack you will run in a CTF or a real engagement ultimately calls LLL. Know
> what it does. Know when it works. Know when it will not."
>
> — Ghost

---

## Goals

Understand the LLL algorithm — what it guarantees, how it works step by step,
and how to call it in SageMath. Verify the guarantee on a concrete lattice.

**Prerequisites:** Day 586 (lattice basics), Gram-Schmidt orthogonalization.
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Recon: What LLL Guarantees

The **Lenstra–Lenstra–Lovász (LLL) algorithm** (1982) takes a basis `B` of
rank `n` and returns a **reduced basis** `B*` such that the first vector `b_1*`
satisfies:

```
||b_1*|| ≤ 2^((n-1)/2) · λ_1(L)
```

where `λ_1(L)` is the true shortest vector length. The approximation factor
`2^((n-1)/2)` is exponential in `n`, but in practice (for n ≤ 200) the
returned vector is often exactly the shortest — or very close.

**Polynomial time:** LLL runs in `O(n^6 · log^3(max||b_i||))` — polynomial
in the dimension and the bit length of the basis vectors.

---

## Stage 2 — Algorithm: Gram-Schmidt + Lovász Condition

### Gram-Schmidt Review

Given basis `b_1, ..., b_n`, the **Gram-Schmidt orthogonalization** produces
orthogonal vectors `b_1*, ..., b_n*`:

```
b_1* = b_1
b_i* = b_i - sum_{j=1}^{i-1} μ_{ij} · b_j*

where  μ_{ij} = <b_i, b_j*> / <b_j*, b_j*>
```

The `μ_{ij}` are the Gram-Schmidt coefficients. Gram-Schmidt itself does not
stay integer — LLL works in the lattice (integer coefficients) while using
Gram-Schmidt for measurements.

### Two Conditions LLL Enforces

**Size reduction:** For all `i > j`:

```
|μ_{ij}| ≤ 1/2
```

If this fails, swap a multiple of `b_j` out of `b_i` to reduce the coefficient.

**Lovász condition:** For all consecutive pairs `(k-1, k)`:

```
||b_k*||^2 ≥ (δ - μ_{k,k-1}^2) · ||b_{k-1}*||^2
```

where `δ ∈ (1/4, 1)` is the **reduction parameter** (typically `3/4`).
If this fails, **swap** `b_{k-1}` and `b_k` and restart the check.

### The Algorithm

```
Input:  Basis B = [b_1, ..., b_n], parameter δ = 3/4
Output: LLL-reduced basis B*

1. Compute Gram-Schmidt B* and coefficients μ
2. k = 2
3. While k ≤ n:
   a. Size-reduce b_k against all b_j (j < k):
      For j = k-1 down to 1:
        if |μ_{kj}| > 1/2:
          b_k -= round(μ_{kj}) · b_j
          Recompute μ
   b. If Lovász condition holds for (k-1, k):
      k += 1
   Else:
      Swap(b_{k-1}, b_k)
      k = max(k-1, 2)
4. Return B
```

---

## Stage 3 — Implementation

### Python Implementation (Educational)

```python
#!/usr/bin/env python3
"""
LLL basis reduction algorithm — educational implementation.
For production use, prefer SageMath's built-in .LLL() method.
"""
from __future__ import annotations
import math
from fractions import Fraction


def gram_schmidt(B: list[list[Fraction]]) -> tuple[list[list[Fraction]],
                                                   list[list[Fraction]]]:
    """Return (B_star, mu) — GS orthogonalization and coefficients."""
    n   = len(B)
    dim = len(B[0])
    B_star = [[Fraction(0)] * dim for _ in range(n)]
    mu     = [[Fraction(0)] * n   for _ in range(n)]

    for i in range(n):
        B_star[i] = list(B[i])
        for j in range(i):
            dot_ij  = sum(B[i][k] * B_star[j][k] for k in range(dim))
            dot_jj  = sum(B_star[j][k] ** 2       for k in range(dim))
            mu[i][j] = dot_ij / dot_jj
            B_star[i] = [B_star[i][k] - mu[i][j] * B_star[j][k]
                         for k in range(dim)]
    return B_star, mu


def lll_reduce(B: list[list[int]], delta: float = 0.75) -> list[list[int]]:
    """
    LLL basis reduction.
    B: list of integer row vectors.
    Returns LLL-reduced basis as list of integer row vectors.
    """
    n = len(B)
    # Work with Fraction for exact arithmetic
    basis  = [[Fraction(x) for x in row] for row in B]
    delta_f = Fraction(delta).limit_denominator(1000)

    k = 1
    while k < n:
        B_star, mu = gram_schmidt(basis)

        # Size reduction: reduce basis[k] against all j < k
        for j in range(k - 1, -1, -1):
            m = round(float(mu[k][j]))
            if m != 0:
                basis[k] = [basis[k][i] - Fraction(m) * basis[j][i]
                            for i in range(len(basis[k]))]
                B_star, mu = gram_schmidt(basis)

        # Lovász condition
        dot_k   = sum(B_star[k][i] ** 2   for i in range(len(B_star[k])))
        dot_km1 = sum(B_star[k-1][i] ** 2 for i in range(len(B_star[k-1])))
        lhs = dot_k
        rhs = (delta_f - mu[k][k-1] ** 2) * dot_km1

        if lhs >= rhs:
            k += 1
        else:
            # Swap
            basis[k], basis[k-1] = basis[k-1], basis[k]
            k = max(k - 1, 1)

    # Convert back to integers
    return [[int(x) for x in row] for row in basis]


def vec_norm(v: list[int]) -> float:
    return math.sqrt(sum(x * x for x in v))


# ── Demo ──────────────────────────────────────────────────────────────────────
# A classic example: recover the hidden short vector (1, 0, 0, ...) embedded
# in a deliberately bad basis.

bad_basis = [
    [19, 2, 32, 46, 3, 33],
    [15, 42, 11, 0,  24, 14],
    [43, 15, 0,  24, 0,  16],
    [20, 44, 56, 40, 37, 29],
    [0,  48, 16, 38, 8,  14],
    [0,  2,  11, 16, 30, 42],
]

print("Original basis vectors (norms):")
for v in bad_basis:
    print(f"  {v}  ||v|| = {vec_norm(v):.2f}")

reduced = lll_reduce(bad_basis)
print("\nLLL-reduced basis vectors (norms):")
for v in reduced:
    print(f"  {v}  ||v|| = {vec_norm(v):.2f}")

shortest = min(reduced, key=vec_norm)
print(f"\nShortest vector found: {shortest}  ||v|| = {vec_norm(shortest):.4f}")
```

---

## Stage 4 — SageMath (Production Tool)

In CTF work and real research, you call SageMath's C library (fplll) directly:

```python
# ── SageMath / Python via subprocess demo ─────────────────────────────────────
# Run this in a SageMath session (sage -python or Jupyter with SageMath kernel)

from sage.all import Matrix, ZZ, vector

# Define a lattice basis as a matrix over ZZ
B = Matrix(ZZ, [
    [1, 0, 0, 0, 1337],
    [0, 1, 0, 0, 42],
    [0, 0, 1, 0, 99],
    [0, 0, 0, 1, 7],
    [0, 0, 0, 0, 10000],
])

# Run LLL with default delta=0.75
L = B.LLL()

print("LLL-reduced basis:")
print(L)
print(f"\nFirst (shortest) vector: {L[0]}")
print(f"Norm of first vector: {float(L[0].norm()):.4f}")

# For CVP (finding the lattice vector closest to a target):
# Use the embedding technique: build a new lattice that encodes CVP as SVP.
# (Covered in Day 588 lab.)
```

---

## Approximation Guarantees vs. Reality

The theoretical worst case is `2^((n-1)/2)`. In practice, LLL finds the actual
shortest vector (or something very close) for almost all random lattices in
dimensions up to roughly 200.

| Dimension n | Theoretical bound | Practical output |
|---|---|---|
| 10 | 32× longer than λ_1 | Usually exact λ_1 |
| 50 | ~10^7× longer | Usually within 2× |
| 100 | ~10^14× longer | Usually within 4× |
| 200 | ~10^29× longer | Within ~10× |
| 400 | huge | LLL fails; need BKZ-60 |

For dimensions > 200 where LLL is insufficient, **BKZ** (Block Korkine-Zolotarev)
is used at higher computational cost. Post-quantum crypto (Kyber, n=768) is safe
against any known lattice reduction algorithm at those dimensions.

---

## When LLL Wins vs. When It Fails

| Scenario | LLL outcome |
|---|---|
| SVP in dimension ≤ 100 with structured lattice | Finds exact shortest vector |
| Coppersmith (n ≤ 20, small bound) | Finds the root |
| HNP with 150 ECDSA signatures, 1-bit nonce bias | Finds key with BKZ-20 |
| LWE with n=256 (Kyber) | Fails — dimension too large |
| Merkle-Hellman knapsack (n=100) | Recovers private key |
| NTRU n=701 | Fails — post-quantum safe |

---

## Key Takeaways

1. **LLL produces a basis with short vectors in polynomial time.** The guarantee
   is an approximation, but in practice (n ≤ 200) it finds the actual SVP
   solution for lattices with special structure.
2. **Two conditions drive LLL:** size reduction (coefficients stay small) and
   the Lovász condition (swap to enforce Gaussian expected length decrease per
   level). Every step either advances `k` or brings the basis closer to reduced.
3. **SageMath wraps fplll**, the reference C++ implementation. For any CTF
   problem with a lattice, start with `Matrix(ZZ, ...).LLL()`.
4. **LLL is not magic.** It only finds short vectors if the lattice has a short
   vector that is significantly shorter than the rest. Post-quantum schemes
   deliberately ensure no such gap exists.

---

## Exercises

```
1. Run the Python LLL implementation above on the bad_basis. Verify that
   the output matches what SageMath gives. If they differ, why?

2. For the basis B = [[6, 5], [1, 2]]:
   a. Compute the Gram-Schmidt vectors b1*, b2* by hand.
   b. Compute μ_{21}.
   c. Check the Lovász condition with δ = 3/4.
   d. Apply one step of LLL and report the new basis.

3. In SageMath: generate a random 20×20 integer matrix with entries in
   [-100, 100]. Run LLL. How much shorter is the first vector of the
   reduced basis versus the first vector of the input?

4. (Research): What is BKZ? How does it differ from LLL? At what
   dimension does BKZ-20 outperform LLL significantly?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q587.1, Q587.2 …).

---

## Navigation

← Previous: [Day 586 — Lattice Basics](DAY-0586-Lattice-Basics.md)
→ Next: [Day 588 — LLL Lab](DAY-0588-LLL-Lab.md)
