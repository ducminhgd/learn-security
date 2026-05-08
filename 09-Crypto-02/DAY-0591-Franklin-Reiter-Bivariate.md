---
title: "Franklin-Reiter Related Message Attack and Bivariate Coppersmith"
tags: [cryptography, RSA, Franklin-Reiter, bivariate-Coppersmith, lattice,
  related-message, polynomial-GCD, small-roots, SageMath, module-09-crypto-02]
module: 09-Crypto-02
day: 591
prerequisites:
  - Day 589 — Coppersmith's Method
  - Day 590 — Coppersmith Lab
  - Polynomial GCD (Euclidean algorithm for polynomials)
related_topics:
  - RSA Lattice Attacks Advanced (Day 592)
  - Coppersmith Lab (Day 590)
---

# Day 591 — Franklin-Reiter Related Message Attack and Bivariate Coppersmith

> "Franklin-Reiter is elegant in a way that should embarrass RSA designers.
> Two related messages under the same public key — not identical, just linearly
> related — leak both messages completely when e is small. The math is a
> polynomial GCD. No lattice needed. But pair it with Coppersmith and you
> recover both messages even when you only know they are 'close'. That is the
> combination that killed textbook RSA e=3 everywhere it was used."
>
> — Ghost

---

## Goals

Master the Franklin-Reiter related message attack (pure polynomial GCD), then
extend to bivariate Coppersmith (SageMath) for the harder case where the
relationship between messages is unknown. Apply both to a CTF-style challenge.

**Prerequisites:** Days 589–590 (Coppersmith), polynomial GCD.
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Franklin-Reiter: Related Messages

### Setup

Alice sends two messages `m1` and `m2` under the same RSA public key `(N, e)`
where `m2 = f(m1)` for a **known linear function** `f(x) = a·x + b`:

```
c1 = m1^e mod N
c2 = m2^e mod N = (a·m1 + b)^e mod N
```

The attacker knows `N, e, c1, c2, a, b` but not `m1` or `m2`.

### The Attack

Define two polynomials over `Z_N[x]`:

```
g1(x) = x^e - c1          (has root m1 mod N)
g2(x) = (a·x + b)^e - c2  (has root m1 mod N)
```

Both polynomials share the root `m1`. Therefore `(x - m1)` divides
`gcd(g1(x), g2(x))` in `Z_N[x]`.

If `gcd(g1, g2) = (x - m1)`, then m1 is recovered directly.

**Cost:** One polynomial GCD computation — O(e^2) operations. No LLL needed.

```python
#!/usr/bin/env python3
"""
Franklin-Reiter Related Message Attack.
Recovers m1 and m2 from c1, c2 when m2 = a*m1 + b (linear relation).
"""
# SageMath
from sage.all import (ZZ, Zmod, PolynomialRing, Integer,
                      random_prime, power_mod, gcd)


def franklin_reiter(N: int, e: int, c1: int, c2: int,
                    a: int, b: int) -> int | None:
    """
    Recover m1 from two related ciphertexts under RSA with small e.
    Returns m1 (integer) or None if gcd is not degree 1.
    """
    PR    = PolynomialRing(Zmod(Integer(N)), 'x')
    x     = PR.gen()
    g1    = x ** e - Integer(c1)
    g2    = (Integer(a) * x + Integer(b)) ** e - Integer(c2)
    g     = gcd(g1, g2)
    # g should be (x - m1) if the relation is correct
    if g.degree() == 1:
        # g = x - m1  →  m1 = -constant term / leading coeff
        m1 = Integer(-g[0]) * Integer(g[1]).inverse_mod(Integer(N))
        return int(m1) % N
    return None


# ── Demo ──────────────────────────────────────────────────────────────────────
p   = random_prime(2**256)
q   = random_prime(2**256)
N   = p * q
e   = 3

# Secret messages: m2 = 3*m1 + 7
m1  = Integer(ZZ.random_element(2**100, 2**200))
a, b = 3, 7
m2  = (a * m1 + b) % N
c1  = power_mod(int(m1), e, int(N))
c2  = power_mod(int(m2), e, int(N))

print(f"[*] N = {int(N).bit_length()} bits, e = {e}")
print(f"[*] Linear relation: m2 = {a}*m1 + {b}")

recovered_m1 = franklin_reiter(int(N), e, int(c1), int(c2), a, b)

if recovered_m1 is not None:
    recovered_m2 = (a * recovered_m1 + b) % int(N)
    print(f"[+] m1 recovered: {recovered_m1 == int(m1)}")
    print(f"[+] m2 recovered: {recovered_m2 == int(m2)}")
else:
    print("[!] GCD degree ≠ 1 — check parameters")
```

### Why It Works

The polynomial GCD over `Z_N[x]` behaves like GCD over a field when `N` is a
prime (or when all intermediate computations happen to avoid factors of N).
For composite `N`, occasional failures occur — retry with slightly different
parameters or use a different approach.

---

## Stage 2 — Short Pad Attack (Coppersmith + Franklin-Reiter)

The **short pad attack** applies when the same message `m` is sent twice with
different random pads: `m1 = m || r1`, `m2 = m || r2` where `r1, r2` are
small random values.

This reduces to Franklin-Reiter with an **unknown linear relation**:
`m2 ≈ m1 + (r2 - r1)` — but `r2 - r1` is small.

**Algorithm:**

1. Use Coppersmith (Day 589) to find the difference `Δ = r1 - r2`:
   - Define `f(x) = gcd((x + m1)^e - c1, (x + m2)^e - c2)` over Z_N[x]
   - For small `Δ`, `(m1 - m2)` is a root of `x^e - c1*(x+Δ)^{-e} ... ` (variants exist)
2. Once Δ is known, Franklin-Reiter recovers `m`.

```python
# SageMath: Short pad attack (simplified version)
from sage.all import ZZ, Zmod, PolynomialRing, Integer, random_prime, power_mod, gcd


def short_pad_attack(N: int, e: int, c1: int, c2: int, pad_bits: int):
    """
    Recover the base message m given two padded ciphertexts.
    m1 = m * 2^pad_bits + r1,  m2 = m * 2^pad_bits + r2
    c1 = m1^e mod N,  c2 = m2^e mod N.
    Assumes |r1 - r2| < 2^pad_bits << N^(1/e^2).
    """
    PR = PolynomialRing(Zmod(Integer(N)), 'x')
    x  = PR.gen()
    g1 = x ** e - Integer(c1)
    g2 = (x + Integer(2 ** pad_bits)) ** e - Integer(c2)  # Δ = 2^pad_bits

    # For the known-Δ case: GCD gives (x - m1)
    # In the unknown-Δ case, we search Δ in a small range or use Coppersmith.
    g  = gcd(g1, g2)
    if g.degree() == 1:
        m1_candidate = int(-g[0]) * int(Integer(g[1]).inverse_mod(Integer(N))) % N
        return m1_candidate
    return None


# Demo: same message, pads differ by exactly 1 (known Δ for illustration)
p   = random_prime(2**256)
q   = random_prime(2**256)
N   = p * q
e   = 3

m        = Integer(ZZ.random_element(2**100, 2**200))
pad_bits = 16
r1       = Integer(ZZ.random_element(0, 2**pad_bits))
r2       = Integer(ZZ.random_element(0, 2**pad_bits))
m1       = m * (2 ** pad_bits) + r1
m2       = m * (2 ** pad_bits) + r2
c1       = power_mod(int(m1), e, int(N))
c2       = power_mod(int(m2), e, int(N))

print(f"[*] Pad bits: {pad_bits}, Δ = {int(r1 - r2)}")
# Short pad attack requires searching Δ or using Coppersmith
# For teaching: we fix Δ = r2 - r1 and show Franklin-Reiter recovers m1
delta = int(r2 - r1) % int(N)
result = franklin_reiter(int(N), e, int(c1), int(c2), 1, delta)
if result:
    m_rec = int(result) >> pad_bits
    print(f"[+] Base message recovered: {m_rec == int(m)}")
```

---

## Stage 3 — Bivariate Coppersmith

When the relationship between messages is unknown (or nonlinear), we need
**bivariate small roots**: find `(x_0, y_0)` small such that
`f(x_0, y_0) ≡ 0 mod N`.

SageMath implements this via `small_roots()` on bivariate polynomials (slower,
less reliable than univariate). The Coppersmith–Herrmann–May variant is
implemented in some SageMath patches.

```python
# SageMath: Bivariate Coppersmith sketch
# Note: native SageMath small_roots() is univariate only.
# For bivariate, we use Groebner basis approach or Sage patches.

from sage.all import (ZZ, Zmod, PolynomialRing, Integer, matrix,
                      random_prime, power_mod)


def bivariate_coppersmith_demo(N: int, e: int, c1: int, c2: int,
                               Xbound: int, Ybound: int):
    """
    Bivariate Coppersmith: find small (x, y) such that
    (x)^e ≡ c1 mod N and (x + y)^e ≡ c2 mod N.
    i.e., m2 = m1 + y for small y.

    This is the research-level version. In practice, use the resultant trick:
    compute the resultant of g1(x) and g2(x+y) over y → univariate in x.
    """
    PR2 = PolynomialRing(Zmod(Integer(N)), ['x', 'y'])
    x, y = PR2.gens()
    g1 = x ** e - Integer(c1)
    g2 = (x + y) ** e - Integer(c2)
    # Resultant eliminates y → polynomial in x only
    Rx = PolynomialRing(Zmod(Integer(N)), 'x')
    xv = Rx.gen()
    g1r = Rx(g1.resultant(g2, y))
    # Now solve univariate: g1r has m1 as a root
    roots = g1r.small_roots(X=Integer(Xbound), beta=1.0, epsilon=0.04)
    return roots


# Demo setup
p    = random_prime(2**256)
q    = random_prime(2**256)
N    = p * q
e    = 3

m1   = Integer(ZZ.random_element(2**100, 2**150))
# Small unknown difference: m2 = m1 + y where y is small
y0   = Integer(ZZ.random_element(1, 2**30))
m2   = m1 + y0
c1   = power_mod(int(m1), e, int(N))
c2   = power_mod(int(m2), e, int(N))

print(f"[*] Bivariate Coppersmith: recover m1 given c1, c2 and |m2-m1| < 2^30")
roots = bivariate_coppersmith_demo(int(N), e, int(c1), int(c2),
                                   Xbound=int(2**150), Ybound=int(2**30))
if roots:
    for r in roots:
        if int(r) == int(m1):
            print(f"[+] m1 recovered via resultant + Coppersmith")
            break
```

---

## CTF Pattern Recognition

| Clue | Attack |
|---|---|
| Two ciphertexts, same `(N, e)`, known linear relation | Franklin-Reiter |
| Two ciphertexts, small random pad, same message | Short pad attack |
| One ciphertext, known partial plaintext structure | Coppersmith (univariate) |
| Two ciphertexts, same `N`, related keys | Coppersmith (bivariate / resultant) |
| e=3, three ciphertexts, same message, different N | Håstad broadcast (Day 567) |

---

## Key Takeaways

1. **Franklin-Reiter is zero-cost** relative to Coppersmith — it is just a
   polynomial GCD, which runs in O(e^2) operations. If you have two related
   ciphertexts under the same `(N, e)` with a known relation, Franklin-Reiter
   is the first tool to reach for.
2. **The short pad attack chains Coppersmith and Franklin-Reiter.** Coppersmith
   recovers the message difference Δ; Franklin-Reiter uses Δ to recover the
   full plaintext. Neither step alone suffices.
3. **Bivariate Coppersmith is more expensive and less reliable.** Use the
   resultant trick (eliminate one variable) to reduce to the univariate case
   whenever possible.
4. **RSA with e=3 and any structured plaintext is broken.** The combination
   of Coppersmith (partial knowledge) + Franklin-Reiter (related messages) +
   Håstad (broadcast) makes e=3 completely insecure in practice.

---

## Exercises

```
1. Implement Franklin-Reiter for e=5. How does the GCD computation change?
   Is the attack still practical?

2. In the short pad attack, we assumed Δ is known. Describe how Coppersmith
   (univariate) can be used to find Δ without prior knowledge.
   Construct the polynomial and the bound.

3. Run the bivariate demo above and vary y0 from 2^30 to 2^50.
   At what size does the attack fail? Why?

4. (CTF): You intercept two ciphertexts encrypted with RSA e=3, 1024-bit N.
   The plaintext format is "id:<uint64>,msg:<variable_text>".
   Both messages have the same 'id' field. Is Franklin-Reiter directly
   applicable? If not, what modification is needed?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q591.1, Q591.2 …).

---

## Navigation

← Previous: [Day 590 — Coppersmith Lab](DAY-0590-Coppersmith-Lab.md)
→ Next: [Day 592 — RSA Lattice Attacks: Stereotyped Messages](DAY-0592-RSA-Lattice-Attacks-Stereotyped.md)
