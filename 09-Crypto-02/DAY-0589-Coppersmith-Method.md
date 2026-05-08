---
title: "Coppersmith's Method — Small Roots of Polynomials mod N"
tags: [cryptography, lattice, Coppersmith, RSA, small-roots, Howgrave-Graham,
  SageMath, polynomial, module-09-crypto-02]
module: 09-Crypto-02
day: 589
prerequisites:
  - Day 587 — LLL Algorithm
  - Day 567 — RSA Attack Lab (RSA basics)
  - Basic polynomial algebra (roots, modular arithmetic)
related_topics:
  - Coppersmith Lab (Day 590)
  - Bivariate Coppersmith / Franklin-Reiter (Day 591)
  - Hidden Number Problem (Day 593)
---

# Day 589 — Coppersmith's Method: Small Roots of Polynomials mod N

> "In 1996, Don Coppersmith published a result that made every RSA system with
> partial plaintext knowledge or small exponent vulnerable. The idea is elegant:
> if you know a root of a polynomial mod N is small, LLL can find it. The bound
> on 'small' depends on the polynomial degree and N. In practice: if you know
> half the bits of the RSA plaintext, Coppersmith recovers the rest. That is
> devastating."
>
> — Ghost

---

## Goals

Understand Coppersmith's theorem for univariate polynomials, the
Howgrave-Graham formulation, and how SageMath's `small_roots()` implements it.
Map the technique to concrete RSA attack scenarios.

**Prerequisites:** Day 587 (LLL), Day 567 (RSA), polynomial modular arithmetic.
**Estimated study time:** 3–4 hours.

---

## Stage 1 — Recon: The Core Theorem

### Howgrave-Graham Theorem (1997)

Let `f(x)` be a monic polynomial of degree `d` in `Z[x]`, and let `N` be a
positive integer. Define `X = N^(1/d - ε)` for some small `ε > 0`.

If `|x_0| < X` and `f(x_0) ≡ 0 (mod N)`, and the polynomial is "small"
(i.e., `||f(xX)||_2 < N / sqrt(d)`), then `f(x_0) = 0` over the integers.

**In plain English:**

> If a polynomial `f(x)` has a small root `x_0` modulo `N`, and `|x_0|` is
> small relative to `N^(1/d)`, then LLL can find `x_0`.

### The Bound

For a polynomial of degree `d`:

```
|x_0| < N^(1/d)   ← the theoretical bound
|x_0| < N^(1/d - ε)   ← the practical bound (LLL approximation)
```

Typical CTF usage:
- **d=1** (linear): trivial — no need for Coppersmith
- **d=2** (quadratic): `|x_0| < N^(1/2)` — very powerful
- **d=3** (cubic): `|x_0| < N^(1/3)` — useful for RSA e=3
- **d=5 or more**: bounds become restrictive; combine with structure

---

## The Algorithm

### Step 1 — Construct Helper Polynomials

Given `f(x)` with root `x_0 mod N`, generate `m` helper polynomials that
also have `x_0` as a root mod `N^m`:

```
g_{i,j}(x) = x^j · N^(m-i) · f(x)^i    for i = 0..m, j = 0..d-1
```

These form a collection of polynomials that all vanish mod `N^m` at `x_0`.

### Step 2 — Build a Lattice from Coefficients

Evaluate each `g_{i,j}(xX)` (substitute `x → xX` to normalize the root
to `|x_0/X| < 1`). The coefficients of these polynomials become the rows of
a lattice matrix.

### Step 3 — LLL on the Lattice

LLL finds a short vector in this lattice, which corresponds to a linear
combination `h(x)` of the helper polynomials. Because `h(xX)` has small
coefficients and `h(x_0)` vanishes mod `N^m`, by the Howgrave-Graham theorem
`h(x_0) = 0` over the integers.

### Step 4 — Root over Z

Solve `h(x) = 0` as an integer polynomial (using Newton's method or factoring).
This gives `x_0` exactly.

---

## Stage 2 — Attack Scenarios

### Scenario A: RSA with Small Partial Plaintext (Stereotyped Messages)

**Setup:** Attacker knows the high-order bits of plaintext `m`:

```
m = m_known · 2^k + m_unknown
c = m^e mod N
```

Define `f(x) = (m_known · 2^k + x)^e - c mod N`. Then `x_0 = m_unknown`
is a root of `f` mod `N`, and `|x_0| < 2^k`.

**Condition for success:** `2^k < N^(1/e)`.
For `e = 3`: `2^k < N^(1/3)`. If N is 2048-bit and e=3, k can be up to 683 bits.

```python
# SageMath: Coppersmith partial plaintext recovery
from sage.all import ZZ, Zmod, PolynomialRing, Integer

def coppersmith_partial_plaintext(N, e, c, m_known, k):
    """
    Recover the unknown lower k bits of RSA plaintext.
    m = m_known * 2^k + m_unknown
    c = m^e mod N
    """
    P = PolynomialRing(Zmod(N), 'x')
    x = P.gen()
    f = (Integer(m_known) * (2 ** k) + x) ** e - c

    # small_roots: bound X = 2^k, beta=1.0 (full modulus N)
    roots = f.small_roots(X=2**k, beta=1.0, epsilon=0.05)
    return roots

# --- Demo ---
from sage.all import random_prime, power_mod

bits = 512   # Smaller N for demo speed
p    = random_prime(2 ** bits)
q    = random_prime(2 ** bits)
N    = p * q
e    = 3
phi  = (p - 1) * (q - 1)
d    = Integer(e).inverse_mod(phi)

# Plaintext: known high bits + unknown low 100 bits
m_full    = Integer(ZZ.random_element(2 ** (bits - 50), 2 ** bits))
k         = 100   # We know all bits except the bottom 100
m_known   = int(m_full) >> k
m_unknown = int(m_full) & ((1 << k) - 1)
c         = power_mod(int(m_full), e, int(N))

print(f"[*] N = {int(N).bit_length()} bits")
print(f"[*] e = {e}")
print(f"[*] Unknown lower {k} bits of plaintext")

roots = coppersmith_partial_plaintext(int(N), e, int(c), m_known, k)
if roots:
    m_rec = (m_known << k) + int(roots[0])
    print(f"[+] Recovered plaintext matches: {m_rec == int(m_full)}")
else:
    print("[!] No roots found — bound may be too large for e=3")
```

### Scenario B: RSA with Small e and Known High Plaintext Bits

Common CTF pattern: `e = 3`, N is 1024-bit, and the top 342 bits of m are known
(padded with a known prefix). Coppersmith recovers the remaining ~341 bits.

### Scenario C: Factoring N with Partial Key

If you know the high `d/4` bits of the RSA private key `d`, Coppersmith
(via a bivariate variant) can factor N. This is Boneh-Durfee's attack.

### Scenario D: Short Pad Attack on RSA

If the same message `m` is padded with a small random `r` and sent as
`m1 = m + r1`, `m2 = m + r2` under the same `(N, e)`:

```
f1(x) = (m + x)^e - c1 mod N     has root r1
f2(x) = (m + x)^e - c2 mod N     has root r2
```

Combined with Franklin-Reiter (Day 591), this recovers `m` exactly.

---

## Stage 3 — The `small_roots()` Interface

SageMath's `small_roots()` implements the Howgrave-Graham version of
Coppersmith. The key parameters:

| Parameter | Meaning | Default |
|---|---|---|
| `X` | Bound on the root: `|x_0| < X` | Required |
| `beta` | Root is a root mod `N^beta` (usually 1.0 = root mod N) | 1.0 |
| `epsilon` | Approximation slack (smaller = slower but stronger) | 0.05 |

```python
# SageMath: general small_roots usage
from sage.all import ZZ, Zmod, PolynomialRing, Integer, random_prime

N = random_prime(2**256) * random_prime(2**256)
P = PolynomialRing(Zmod(N), 'x')
x = P.gen()

# Secret small value: x_0 is 50 bits
x0 = Integer(ZZ.random_element(2**49, 2**50))

# f(x_0) ≡ 0 mod N
# f(x) = x^2 + 17*x - (x0^2 + 17*x0)   [constructed to have x0 as root]
c = Integer(x0) ** 2 + 17 * Integer(x0)
f = x**2 + 17 * x - c

roots = f.small_roots(X=2**50, beta=1.0)
print(f"x_0       = {x0}")
print(f"Recovered = {roots}")
assert int(roots[0]) == int(x0)
print("[+] small_roots succeeded")
```

---

## Why This Works: Intuition

The key insight is that "polynomial has a small root mod N" implies the root
is also small in absolute value (integers). This allows us to convert a modular
problem into an integer problem solvable with LLL:

```
Step 1: Polynomial equation mod N (hard in general)
Step 2: Build a lattice encoding the polynomial structure
Step 3: LLL finds a short vector = polynomial with small integer root
Step 4: Factor over Z (easy for degree ≤ 4)
```

The **Howgrave-Graham bound** tells you when this works: when the root is
smaller than `N^(1/d)`, the short vector in the LLL-reduced basis
corresponds to a polynomial that shares the root with `f` over the integers.

---

## Common CTF Mistakes

| Mistake | Result | Fix |
|---|---|---|
| Using a monic form that changes the root | Wrong root | Verify f(x_0) mod N == 0 before attacking |
| Setting X too large | LLL returns wrong short vector | Tighten X to actual bound |
| Forgetting to scale x → xX | LLL lattice is ill-conditioned | Let small_roots() handle scaling |
| Wrong epsilon | No roots or wrong roots | Try 0.01 to 0.1; smaller is slower |
| Polynomial not reduced mod N | small_roots() fails | Ensure f is in Zmod(N)[x] |

---

## Key Takeaways

1. **Coppersmith = LLL on a lattice of polynomial coefficients.** The algorithm
   finds integer solutions to modular polynomial equations when the solution is
   "small" (< N^(1/d) for degree d).
2. **The practical bound is tight for e=3:** If you know N^(1/3) bits of the
   plaintext in any position (high, low, or spread), Coppersmith recovers the
   rest. For 2048-bit N with e=3, that's 683 bits you can not know.
3. **`small_roots()` in SageMath is your primary weapon.** Understand what
   parameters it takes. Always verify: `int(f(root)) % N == 0`.
4. **Coppersmith is most powerful combined with other attacks.** It is the core
   primitive behind Franklin-Reiter (Day 591), Boneh-Durfee, and lattice-based
   ECDSA attacks (Day 594).

---

## Exercises

```
1. Implement a simplified version of Coppersmith (degree 1) that recovers
   the root of x + a ≡ 0 mod N without using small_roots() — just compute
   x_0 = -a mod N. Verify this is the "trivial" case.

2. In SageMath: generate a 512-bit N, e=3, and a random 512-bit plaintext m.
   Compute c = m^3 mod N. Then use small_roots() to recover m given the top
   171 bits. Verify success.

3. Why does the bound scale as N^(1/d)? Trace through the Howgrave-Graham
   argument: what happens to the polynomial norm if |x_0| > N^(1/d)?

4. Read the abstract of Coppersmith's original 1996 paper "Finding a Small
   Root of a Univariate Modular Equation." List the three main results.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q589.1, Q589.2 …).

---

## Navigation

← Previous: [Day 588 — LLL Lab](DAY-0588-LLL-Lab.md)
→ Next: [Day 590 — Coppersmith Lab](DAY-0590-Coppersmith-Lab.md)
