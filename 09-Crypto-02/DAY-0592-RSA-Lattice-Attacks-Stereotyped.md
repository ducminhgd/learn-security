---
title: "RSA Lattice Attacks — Stereotyped Messages and Wiener's Attack"
tags: [cryptography, RSA, Wiener, continued-fractions, small-d, stereotyped,
  lattice, SageMath, module-09-crypto-02]
module: 09-Crypto-02
day: 592
prerequisites:
  - Day 591 — Franklin-Reiter and Bivariate Coppersmith
  - Day 583 — Crypto CTF Sprint Day 1 (Wiener basics)
related_topics:
  - Coppersmith Method (Day 589)
  - Hidden Number Problem (Day 593)
---

# Day 592 — RSA Lattice Attacks: Stereotyped Messages and Wiener's Attack

> "Wiener's attack is a gift from 1990 that keeps on giving. Small private
> exponent? Factor the public key in milliseconds. No lattice, no Coppersmith —
> just continued fractions. And yet people still deploy RSA with d < N^0.25.
> Today you learn both Wiener (fast, elegant) and the stereotyped message attack
> (Coppersmith in another costume). Together they cover the two most common
> RSA mistakes in CTF and in production."
>
> — Ghost

---

## Goals

Master Wiener's continued-fraction attack for small RSA private exponents,
implement the stereotyped message attack (Coppersmith variant), and connect
both to the broader landscape of RSA vulnerabilities.

**Prerequisites:** Day 591, Day 583. Continued fractions (brief intro below).
**Estimated study time:** 3–4 hours.

---

## Part 1 — Wiener's Attack: Small Private Exponent

### The Vulnerability

If the RSA private exponent `d < N^0.25 / 3`, the **public exponent** `e`
reveals `d` via continued fraction expansion of `e/N`.

**Why it happens:** e·d ≡ 1 (mod φ(N)) implies `e·d = 1 + k·φ(N)` for
some small integer `k`. This means `e/N ≈ k/d` — a rational approximation
of `e/N` with small numerator and denominator.

The **continued fraction algorithm** finds all best rational approximations of
a rational number. One of them is `k/d`.

### Continued Fractions: Quick Reference

The continued fraction expansion of `e/N` is:

```
e/N = a_0 + 1/(a_1 + 1/(a_2 + 1/(a_3 + ...)))
```

Each convergent `p_i/q_i` of this expansion is a candidate for `k/d`.
We test each: if `e·q_i - 1` is divisible by `p_i`, and the result gives
a valid φ(N), then `q_i = d`.

```python
#!/usr/bin/env python3
"""
Wiener's attack: recover RSA private key d when d < N^0.25 / 3.
Uses continued fraction expansion of e/N.
"""
from __future__ import annotations
import math


def continued_fraction(num: int, den: int):
    """Generate coefficients of the continued fraction expansion of num/den."""
    while den:
        q    = num // den
        num, den = den, num - q * den
        yield q


def convergents(cf):
    """Yield (numerator, denominator) convergents from continued fraction coefficients."""
    p_prev, p_curr = 1, 0
    q_prev, q_curr = 0, 1
    for a in cf:
        p_prev, p_curr = p_curr, a * p_curr + p_prev
        q_prev, q_curr = q_curr, a * q_curr + q_prev
        yield p_curr, q_curr


def integer_sqrt(n: int) -> int:
    """Integer square root via Newton's method."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def wiener_attack(N: int, e: int) -> int | None:
    """
    Wiener's attack: find d given N and e.
    Returns d if successful, None otherwise.
    """
    cf   = continued_fraction(e, N)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # φ(N) candidate: e*d = 1 + k*φ(N) → φ(N) = (e*d - 1) / k
        if (e * d - 1) % k != 0:
            continue
        phi_candidate = (e * d - 1) // k
        # φ(N) = (p-1)(q-1) = N - p - q + 1
        # So p + q = N - φ_candidate + 1
        # p, q are roots of x^2 - (p+q)x + N = 0
        b = N - phi_candidate + 1
        discriminant = b * b - 4 * N
        if discriminant < 0:
            continue
        sqrt_disc = integer_sqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue  # Not a perfect square → not valid
        # p, q = (b ± sqrt_disc) / 2
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        if p * q == N:
            return d   # Found!
    return None


# ── Demo ──────────────────────────────────────────────────────────────────────
import random

def generate_rsa_small_d(bits: int = 512) -> dict:
    """Generate RSA keypair with intentionally small d."""
    from sympy import isprime, nextprime
    rng = random.SystemRandom()

    while True:
        # Generate p, q ~ 2^(bits/2)
        p = rng.randrange(2 ** (bits // 2 - 1), 2 ** (bits // 2))
        while not isprime(p):
            p += 1
        q = rng.randrange(2 ** (bits // 2 - 1), 2 ** (bits // 2))
        while not isprime(q):
            q += 1
        N   = p * q
        phi = (p - 1) * (q - 1)
        # Pick small d: d < N^0.25 / 3
        d_bound = int(N ** 0.25) // 3
        d = rng.randrange(2, d_bound)
        while math.gcd(d, phi) != 1:
            d = rng.randrange(2, d_bound)
        e = pow(d, -1, phi)
        return {"N": N, "e": e, "d": d, "p": p, "q": q}


keys   = generate_rsa_small_d(256)   # 256-bit for demo speed
N, e, d_actual = keys["N"], keys["e"], keys["d"]

print(f"[*] N = {N.bit_length()} bits")
print(f"[*] d = {d_actual.bit_length()} bits (threshold: N^0.25/3 ≈ "
      f"{int(N**0.25 // 3).bit_length()} bits)")

d_recovered = wiener_attack(N, e)
if d_recovered:
    print(f"[+] Wiener's attack succeeded: d_recovered == d: "
          f"{d_recovered == d_actual}")
else:
    print("[!] Attack failed — d may not be small enough")
```

---

## Part 2 — Stereotyped Messages (Coppersmith with Known Structure)

A **stereotyped message** has a known prefix and/or suffix with a small unknown
middle section. Coppersmith's method applies directly:

```
m = known_prefix || unknown_middle || known_suffix
m = A + x·B + C  where A, C are known, B = 2^(suffix_bits), |x| < X
```

The polynomial is: `f(x) = (A + x·B + C)^e - c mod N`.

This is a CTF staple: challenge provides `(N, e, c)` and tells you the message
format. You construct the polynomial and call `small_roots()`.

```python
# SageMath: Stereotyped message attack — general template
from sage.all import ZZ, Zmod, PolynomialRing, Integer, power_mod, random_prime


def stereotyped_message_attack(N: int, e: int, c: int,
                               known_high: int, known_low: int,
                               unknown_bits: int) -> int | None:
    """
    Recover the unknown middle bits of an RSA plaintext.

    m = known_high * 2^(unknown_bits + low_bits) + unknown * 2^low_bits + known_low
    where low_bits = bit_length(known_low).
    """
    low_bits = known_low.bit_length() if known_low > 0 else 0
    # Shift amounts
    shift_low  = Integer(2 ** low_bits)
    shift_high = Integer(2 ** (unknown_bits + low_bits))

    PR = PolynomialRing(Zmod(Integer(N)), 'x')
    xv = PR.gen()
    f  = (Integer(known_high) * shift_high +
          xv * shift_low + Integer(known_low)) ** e - Integer(c)

    X     = Integer(2 ** unknown_bits)
    roots = f.small_roots(X=X, beta=1.0, epsilon=0.04)
    return int(roots[0]) if roots else None


# Demo
p   = random_prime(2**256)
q   = random_prime(2**256)
N   = p * q
e   = 3

# Plaintext: "MSG:" (32 bits known) + 80 unknown bits + "\x00\x01" (16 bits known)
prefix_val   = int.from_bytes(b"MSG:", "big")
suffix_val   = int.from_bytes(b"\x00\x01", "big")
unknown      = Integer(ZZ.random_element(2**79, 2**80))
suffix_bits  = 16
prefix_bits  = 32

m = (prefix_val << (80 + suffix_bits)) + (int(unknown) << suffix_bits) + suffix_val
c = power_mod(m, e, int(N))

result = stereotyped_message_attack(
    int(N), e, int(c),
    known_high=prefix_val, known_low=suffix_val, unknown_bits=80
)

if result is not None:
    print(f"[+] Unknown recovered: {result == int(unknown)}")
else:
    print("[!] Attack failed")
```

---

## Part 3 — Combining Attacks: Decision Tree

When you see an RSA challenge, use this decision tree:

```
                           RSA Challenge
                               │
             ┌─────────────────┴──────────────────┐
             │                                    │
          Small e?                             Large e?
          (e ≤ 65537)                         (e > N^0.75)
             │                                    │
     ┌───────┴────────┐                    Wiener's attack
     │                │                    (check d < N^0.25)
  e = 3?        e = 65537
     │                │
     ├─ 3 ciphertexts → Håstad (Day 567)
     ├─ 2 ciphertexts, known relation → Franklin-Reiter (Day 591)
     ├─ Known partial plaintext → Coppersmith / Stereotyped (Day 589-592)
     └─ None of above → look for p, q relation (common factor, etc.)
```

---

## Real-World Cases

| Attack | CVE / Case | Impact |
|---|---|---|
| Wiener's attack | ROCA (CVE-2017-15361, Infineon TPMs) | Related — small d structure |
| Stereotyped message | RSA e=3 in TLS 1.0/1.1 with known padding | BEAST/Lucky13 variants |
| Franklin-Reiter | SSH host key fingerprint in old SSH-1 | Protocol-level message relation |
| Short pad (Coppersmith) | OpenSSL RSA PKCS#1 v1.5 padding | CVE-1998-0510 (Bleichenbacher) |

---

## Key Takeaways

1. **Wiener's attack is a 4-line algorithm that factors RSA.** The only
   requirement: d < N^0.25 / 3. It uses continued fractions, not LLL. If you
   see a CTF with a very large e (close to N), compute d = inverse(e, phi)
   and notice d is tiny — then run Wiener.
2. **Stereotyped messages are Coppersmith in a protocol costume.** Know the
   message format → know where the unknown bits are → construct the polynomial
   → `small_roots()`. The construction is mechanical once you see the pattern.
3. **The RSA attack decision tree is a flowchart, not a list.** Practice applying
   it to new challenges until the choice of attack is reflexive.

---

## Exercises

```
1. Generate an RSA keypair with d exactly at the Wiener bound (d = N^0.25 / 3).
   Does Wiener's attack succeed? What about d = N^0.25 / 2?

2. In the stereotyped message demo, increase the unknown bits to 120.
   Does the attack still work for e=3 and 512-bit N? Explain using the
   Coppersmith bound N^(1/3).

3. Implement the Wiener attack check as a function that returns:
   - "safe": d > N^0.292
   - "vulnerable to Wiener": d < N^0.25 / 3
   - "gray zone — use Boneh-Durfee": N^0.25/3 < d < N^0.292

4. Read the ROCA vulnerability (CVE-2017-15361) summary. It affected Infineon
   TPM chips used in millions of laptops and smart cards. What property of the
   generated primes made them vulnerable? Is it Wiener's attack directly?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q592.1, Q592.2 …).

---

## Navigation

← Previous: [Day 591 — Franklin-Reiter and Bivariate Coppersmith](DAY-0591-Franklin-Reiter-Bivariate.md)
→ Next: [Day 593 — Hidden Number Problem](DAY-0593-Hidden-Number-Problem.md)
