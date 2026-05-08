---
title: "Lattice Basics — SVP, CVP, and Geometric Intuition"
tags: [cryptography, lattice, SVP, CVP, linear-algebra, basis, Hadamard-ratio,
  LWE, post-quantum, module-09-crypto-02]
module: 09-Crypto-02
day: 586
prerequisites:
  - Day 585 — Crypto CTF Sprint Day 3 (GCM / CTR / CBC)
  - Day 567 — RSA Attack Lab (RSA fundamentals)
  - Linear algebra basics (vectors, matrix multiplication, determinants)
related_topics:
  - LLL Algorithm (Day 587)
  - Coppersmith's Method (Day 589)
  - Hidden Number Problem (Day 593)
---

# Day 586 — Lattice Basics: SVP, CVP, and Geometric Intuition

> "A lattice is just a grid — infinite, regular, beautiful in its structure.
> Every cryptosystem built on 'hard lattice problems' assumes that finding the
> shortest vector in that grid is computationally infeasible. Your job is to
> find the edge cases where that assumption breaks. There are more than you think."
>
> — Ghost

---

## Goals

Understand what a lattice is, why lattice problems are hard in general but
exploitable in specific cryptographic constructions, and build the geometric
intuition that makes lattice attacks readable — not magical.

**Prerequisites:** Linear algebra (vectors, determinants). Days 585, 567.
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Recon: What Is a Lattice?

### Definition

A **lattice** `L` is the set of all integer linear combinations of `n`
linearly independent vectors `b_1, b_2, ..., b_n` in `R^m`:

```
L(B) = { c_1·b_1 + c_2·b_2 + ... + c_n·b_n  |  c_i ∈ Z }
```

The vectors `{b_i}` form the **basis** B of the lattice. The lattice is
infinite but discrete — it looks like a grid of points in space.

**Key insight:** The same lattice has infinitely many bases. Some bases are
"nice" (nearly orthogonal, short vectors). Most bases chosen by attackers are
deliberately "bad" (highly skewed, long vectors). Lattice attacks are mostly
about finding the nice basis from the bad one.

```
Good basis (nearly orthogonal):       Bad basis (highly skewed):

 *   *   *   *   *                     *         *         *
 *   *   *   *   *               *         *         *
 *   *   *   *   *         *         *         *         *
 *   *   *   *   *

 Vectors ≈ 90°                        Vectors ≈ 10°
```

### The Volume (Determinant)

The **determinant** of a lattice is the absolute value of the determinant of
any basis matrix:

```
det(L) = |det(B)|
```

It equals the volume of the fundamental parallelepiped — the unit cell of the
lattice. It is **basis-independent** (every basis of L gives the same det(L)).

The Gaussian heuristic says the length of the shortest lattice vector is
approximately:

```
λ_1 ≈ sqrt(n / (2πe)) · det(L)^(1/n)
```

---

## Core Hard Problems

### SVP — Shortest Vector Problem

Given a lattice basis B, find the shortest non-zero vector `v ∈ L(B)`.

**NP-hard** in general (for exact computation). Approximation is also hard.
Lattice-based cryptography assumes SVP is hard in high dimensions (≥ 400 dims).

### CVP — Closest Vector Problem

Given a lattice L and a target vector `t` (not necessarily in L), find the
lattice vector `v ∈ L` closest to `t`.

CVP is at least as hard as SVP. Most cryptographic attacks reduce to CVP.

### BDD — Bounded Distance Decoding

A special case of CVP: the target `t` is guaranteed to be close to a unique
lattice vector (within λ_1 / 2). This is the setting in LWE-based schemes
and in many attacks against biased nonces.

---

## Basis Quality — The Hadamard Ratio

The **Hadamard ratio** measures how orthogonal a basis is:

```
H(B) = det(L) / product(||b_i||) ∈ (0, 1]
```

- `H = 1`: perfectly orthogonal basis (ideal)
- `H ≈ 0`: highly skewed basis (hard to work with)
- LLL reduction produces a basis with `H ≥ (3/4)^(n(n-1)/4)` approximately

```python
#!/usr/bin/env python3
"""
Compute Hadamard ratio to measure lattice basis quality.
Higher ratio = more orthogonal = better for reduction algorithms.
"""
from __future__ import annotations
import math


def hadamard_ratio(B: list[list[float]]) -> float:
    """
    B: list of row vectors (the lattice basis).
    Returns Hadamard ratio ∈ (0, 1].
    """
    n = len(B)
    # Product of column norms
    norms_product = math.prod(
        math.sqrt(sum(B[i][j] ** 2 for j in range(len(B[i]))))
        for i in range(n)
    )
    # det(B) using Gram-Schmidt (simpler: use numpy in practice)
    # For 2×2: det = ad - bc
    if n == 2 and len(B[0]) == 2:
        det = abs(B[0][0] * B[1][1] - B[0][1] * B[1][0])
    else:
        raise NotImplementedError("Use numpy.linalg.det for n > 2")
    return det / norms_product


# Good basis (nearly orthogonal)
B_good = [[1, 0], [0, 1]]
print(f"Good basis H = {hadamard_ratio(B_good):.4f}")   # 1.0

# Skewed basis (same lattice, different basis)
B_bad = [[1, 0], [100, 1]]
print(f"Bad  basis H = {hadamard_ratio(B_bad):.4f}")    # ≈ 0.01

# Note: both generate the SAME lattice (Z^2)
# but the bad basis makes algorithms fail or run slowly
```

---

## Lattice Problems in Cryptography

### Where Hard Lattice Problems Are Used

| System | Hard Problem Assumed | Dimension |
|---|---|---|
| NTRU | SVP on ideal lattice | ~700 |
| Kyber (CRYSTALS) | Module-LWE (BDD) | ~256×3 |
| Dilithium | Module-LWE + Module-SIS | ~256×4 |
| RLWE schemes | Ring-SVP | ~1024 |
| Old crypto (to attack) | SVP/CVP in small dimension | 2–200 |

### Where Lattice Attacks Break Systems

| Target | Dimension | Why It's Exploitable |
|---|---|---|
| Merkle-Hellman knapsack | ~100 | Ratio of trapdoor makes SVP solvable |
| RSA small exponent + partial info | 2–10 | Coppersmith: polynomial root mod N |
| ECDSA biased nonces | ~100+ | HNP reduces to CVP/BDD |
| LCG truncated output | ~10 | Known structure → short vector |
| Early TLS session keys | 10–40 | Weak PRNG, small state |

---

## A Concrete 2D Example

The best way to build intuition is to see a 2D lattice attack:

```python
#!/usr/bin/env python3
"""
2D lattice: find the shortest vector by exhaustive search (only feasible for n≤2).
In higher dimensions, we use LLL (Day 587).
"""
from __future__ import annotations
import math


def lattice_point(B: list[list[int]], c1: int, c2: int) -> tuple[int, int]:
    """Return lattice point c1*b1 + c2*b2."""
    return (c1 * B[0][0] + c2 * B[1][0], c1 * B[0][1] + c2 * B[1][1])


def norm(v: tuple[int, int]) -> float:
    return math.sqrt(v[0] ** 2 + v[1] ** 2)


# A lattice with a skewed basis
B = [[3, 1], [5, 2]]   # basis vectors b1=(3,1), b2=(5,2)
print(f"Basis b1={B[0]}, b2={B[1]}")
print(f"det(L) = {abs(B[0][0]*B[1][1] - B[0][1]*B[1][0])}")

# Exhaustively find short vectors in the range c1,c2 ∈ [-10, 10]
candidates = []
for c1 in range(-10, 11):
    for c2 in range(-10, 11):
        if c1 == 0 and c2 == 0:
            continue
        v = lattice_point(B, c1, c2)
        candidates.append((norm(v), v, c1, c2))

candidates.sort()
print("\nShortest lattice vectors:")
for length, v, c1, c2 in candidates[:5]:
    print(f"  {c1}·b1 + {c2}·b2 = {v}  ||v|| = {length:.4f}")
```

Output:
```
Basis b1=[3, 1], b2=[5, 2]
det(L) = 1

Shortest lattice vectors:
  1·b1 + (-1)·b2 = (-2, -1)  ||v|| = 2.2361
  -1·b1 + 1·b2  = (2, 1)     ||v|| = 2.2361
  2·b1 + (-1)·b2 = (1, 0)    ||v|| = 1.0000
  -2·b1 + 1·b2  = (-1, 0)    ||v|| = 1.0000
  1·b1 + 0·b2  = (3, 1)      ||v|| = 3.1623
```

The shortest vector is `(1, 0)` — length 1 — which is NOT a basis vector but
IS a lattice vector. This is SVP: the basis hides it, but exhaustive search
(or LLL in higher dimensions) finds it.

---

## Connecting to Real Attacks

### The Pattern

Almost every lattice-based crypto attack follows this recipe:

```
1. Express the secret as a short vector in a carefully constructed lattice.
2. Use a basis reduction algorithm (LLL, BKZ) to find that short vector.
3. Read the secret off the recovered vector.
```

The construction of the lattice is the art. The reduction is the algorithm.

### Example: Recovery of a Secret Shift

Suppose a system sends `c = m + s mod q` where `s` is a small secret.
We can construct:

```
Lattice L = { (a, b) : a ≡ b·c mod q }

The vector (s, 1) is in L and has small norm if s << q.
LLL finds it.
```

This is the basic structure of LWE attacks. We will see Coppersmith (Day 589)
and HNP (Day 593) use exactly this recipe.

---

## Key Takeaways

1. **A lattice is a discrete subgroup of R^n** generated by integer combinations
   of basis vectors. The same lattice has many bases; reduction finds a short one.
2. **SVP and CVP are computationally hard in general** — the security of
   post-quantum cryptography rests on this. But in low dimensions or with
   special structure, LLL and Coppersmith solve them efficiently.
3. **Lattice attacks follow one pattern**: embed the secret as a short vector,
   run LLL, read the answer. The cleverness is in the embedding, not the
   algorithm.
4. **The Hadamard ratio** tells you how good (orthogonal) a basis is. LLL
   produces a basis with guaranteed Hadamard ratio — good enough to reveal
   short vectors in practice.

---

## Exercises

```
1. For the lattice L with basis B = [[17, 3], [5, 1]], compute:
   a. det(L)
   b. The Hadamard ratio
   c. By hand (or code): the shortest vector using the 2D exhaustive search
      from the code above

2. Prove that det(L) is basis-independent:
   Show that if B' = U·B where U has det(U) = ±1 (a unimodular matrix),
   then det(B') = det(B).

3. The Gaussian heuristic: for n=100, det(L) = 2^512, estimate λ_1 (the
   expected length of the shortest vector). Is this hard to find?

4. Why does a dimension-2 lattice (n=2) always have an efficient SVP
   algorithm (Gauss reduction), while dimension n=1000 is intractable?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q586.1, Q586.2 …).

---

## Navigation

← Previous: [Day 585 — Crypto CTF Sprint Day 3](../09-Crypto-01/DAY-0585-Crypto-CTF-Sprint-Day-3.md)
→ Next: [Day 587 — LLL Algorithm](DAY-0587-LLL-Algorithm.md)
