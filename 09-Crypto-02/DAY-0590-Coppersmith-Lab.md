---
title: "Coppersmith Lab — Partial Plaintext Recovery and RSA Challenges"
tags: [cryptography, lattice, Coppersmith, RSA, small-roots, lab, CTF,
  partial-key, SageMath, hands-on, module-09-crypto-02]
module: 09-Crypto-02
day: 590
prerequisites:
  - Day 589 — Coppersmith's Method
  - Day 567 — RSA Attack Lab
related_topics:
  - Bivariate Coppersmith / Franklin-Reiter (Day 591)
  - RSA Advanced Lattice Attacks (Day 592)
---

# Day 590 — Coppersmith Lab: Partial Plaintext Recovery and RSA Challenges

> "In the wild, Coppersmith attacks appear wherever the designer assumed a
> 'random' padding makes RSA safe. It does not. Knowing 1/3 of the plaintext —
> in any position — is enough to break it. Today you do this against three
> different RSA configurations, each representing a real-world mistake."
>
> — Ghost

---

## Goals

Run Coppersmith attacks against three RSA configurations: known high bits,
known low bits, and a padding vulnerability. Produce working exploit scripts
and understand when each variant applies.

**Prerequisites:** Day 589 (Coppersmith's Method). SageMath ≥ 9.0.
**Estimated lab time:** 5–6 hours.

---

## Lab 1 — Known High Bits (Top Third of Plaintext)

This is the classic scenario: a protocol pads messages with a fixed known
prefix, and the variable portion is smaller than N^(1/e).

```python
#!/usr/bin/env python3
"""
Lab 1: Coppersmith — recover plaintext when top 1/3 of bits are known.
Simulates a protocol that sends PREFIX || secret as the RSA plaintext.
"""
# Run in SageMath session
from sage.all import (ZZ, Zmod, PolynomialRing, Integer,
                      random_prime, power_mod)

def lab1_known_high_bits():
    # Parameters
    N_bits  = 512      # 512-bit modulus (use 1024+ for real targets)
    e       = 3        # Small exponent (common vulnerability)

    # Generate RSA keypair
    p   = random_prime(2**(N_bits // 2))
    q   = random_prime(2**(N_bits // 2))
    N   = p * q
    phi = (p - 1) * (q - 1)
    d   = Integer(e).inverse_mod(phi)

    # Plaintext: fixed prefix + secret suffix
    # "SECRET:" is 7 bytes = 56 bits known prefix
    prefix   = b"SECRET:"
    secret   = Integer(ZZ.random_element(2**100, 2**101))   # 101-bit secret
    m_bytes  = prefix + int(secret).to_bytes(13, "big")
    m        = Integer(int.from_bytes(m_bytes, "big"))
    c        = power_mod(int(m), e, int(N))

    # Known: prefix + zero-padded placeholder
    known_prefix = int.from_bytes(prefix, "big")
    # The prefix sits at the top: m = prefix * 2^(secret_bits) + secret
    secret_bits  = 101
    m_known_part = known_prefix << (secret_bits + 8 * 7 - 7 * 8)
    # Recalculate: m = m_known_high << secret_bits + secret
    m_known_high = int(m) >> secret_bits
    m_unknown    = int(m) & ((1 << secret_bits) - 1)

    print(f"[*] N       = {int(N).bit_length()} bits")
    print(f"[*] e       = {e}")
    print(f"[*] Unknown = {secret_bits} bits (bottom of plaintext)")

    # Coppersmith: f(x) = (m_known_high * 2^secret_bits + x)^e - c
    X = Integer(2 ** secret_bits)
    PR = PolynomialRing(Zmod(Integer(N)), 'x')
    xv = PR.gen()
    f  = (Integer(m_known_high) * X + xv) ** e - Integer(c)

    roots = f.small_roots(X=X, beta=1.0, epsilon=0.04)

    if roots:
        recovered_suffix = int(roots[0])
        recovered_m      = (m_known_high << secret_bits) + recovered_suffix
        print(f"[+] Attack succeeded: recovered_m == m: {recovered_m == int(m)}")
        print(f"[+] Secret: {recovered_suffix}")
    else:
        print("[!] No roots found — adjust epsilon or verify construction")

lab1_known_high_bits()
```

---

## Lab 2 — Known Low Bits (Bottom Third of Plaintext)

When the low-order bits are known (e.g., structured message format with
a fixed footer), use a shifted polynomial:

```python
# SageMath: Coppersmith with known low bits
from sage.all import ZZ, Zmod, PolynomialRing, Integer, random_prime, power_mod

def lab2_known_low_bits():
    p   = random_prime(2**256)
    q   = random_prime(2**256)
    N   = p * q
    e   = 3
    phi = (p - 1) * (q - 1)

    # m = m_unknown * 2^low_bits + m_known_low
    low_bits    = 85    # Known bottom 85 bits
    m_known_low = Integer(ZZ.random_element(2**84, 2**85))
    m_unknown   = Integer(ZZ.random_element(2**84, 2**85))  # ~ 85 bits unknown
    m           = m_unknown * (2 ** low_bits) + m_known_low
    c           = power_mod(int(m), e, int(N))

    print(f"[*] N = {int(N).bit_length()} bits, e={e}")
    print(f"[*] Known low {low_bits} bits")

    # f(x) = (x * 2^low_bits + m_known_low)^e - c mod N
    # Root: x = m_unknown   (unknown top bits)
    X  = Integer(2 ** low_bits)   # bound on m_unknown (after factoring out 2^low)
    # Actually bound is m_unknown ~ 2^85, need X = 2^85
    X  = Integer(2 ** 85)
    PR = PolynomialRing(Zmod(Integer(N)), 'x')
    xv = PR.gen()
    f  = (xv * Integer(2 ** low_bits) + Integer(m_known_low)) ** e - Integer(c)

    roots = f.small_roots(X=X, beta=1.0, epsilon=0.04)

    if roots:
        m_rec = int(roots[0]) * (2 ** low_bits) + int(m_known_low)
        print(f"[+] Recovered m matches: {m_rec == int(m)}")
    else:
        print("[!] No roots — m_unknown may be too large for bound N^(1/3)")
        print(f"    N^(1/3) ≈ 2^{(int(N).bit_length() // 3)}, unknown ≈ 2^85")

lab2_known_low_bits()
```

---

## Lab 3 — CTF Challenge: "Encrypted Credentials" (Full Exploit)

```
Challenge:
  A service RSA-encrypts user credentials with a static prefix.
  Format: "user:<username>,pass:" followed by the password (variable).
  e = 3, N = 1024-bit, plaintext = prefix || password || suffix.
  The prefix and suffix are known; only the password (80 bits) is secret.
  Find the password given (N, e, c).
```

```python
#!/usr/bin/env python3
"""
Full CTF exploit: credential decryption via Coppersmith partial plaintext.
"""
# SageMath
from sage.all import ZZ, Zmod, PolynomialRing, Integer, random_prime, power_mod

# ── Simulate the target (not available to attacker) ───────────────────────────
p   = random_prime(2**512)
q   = random_prime(2**512)
N   = p * q
e   = 3
phi = (p - 1) * (q - 1)

prefix   = b"user:alice,pass:"
suffix   = b",role:user"
password = Integer(ZZ.random_element(2**79, 2**80))   # 80-bit password (10 ASCII chars)
password_bytes = int(password).to_bytes(10, "big")

m_bytes = prefix + password_bytes + suffix
m       = Integer(int.from_bytes(m_bytes, "big"))
c       = power_mod(int(m), e, int(N))

# ── Attacker knows ─────────────────────────────────────────────────────────────
suffix_len_bits   = len(suffix) * 8      # 80 bits
prefix_len_bits   = len(prefix) * 8      # 128 bits
password_len_bits = 80

total_bits = int(m).bit_length()
print(f"[*] Total plaintext: {total_bits} bits")
print(f"[*] Known prefix: {len(prefix)} bytes, suffix: {len(suffix)} bytes")
print(f"[*] Unknown password: {password_len_bits} bits")

# Structure: m = prefix_val << (password_bits + suffix_bits)
#                + password_val << suffix_bits
#                + suffix_val
# Let x = password_val (unknown, 80 bits)
# m = KNOWN_PREFIX_SHIFT + x * 2^suffix_bits + KNOWN_SUFFIX

suffix_val = Integer(int.from_bytes(suffix, "big"))
prefix_val = Integer(int.from_bytes(prefix, "big"))

SUFFIX_SHIFT = Integer(2 ** suffix_len_bits)
PREFIX_SHIFT = Integer(2 ** (password_len_bits + suffix_len_bits))
KNOWN_PART   = prefix_val * PREFIX_SHIFT + suffix_val

# f(x) = (KNOWN_PART + x * SUFFIX_SHIFT)^e - c
X  = Integer(2 ** password_len_bits)   # bound on password
PR = PolynomialRing(Zmod(Integer(N)), 'x')
xv = PR.gen()
f  = (KNOWN_PART + xv * SUFFIX_SHIFT) ** e - Integer(c)

print("[*] Running Coppersmith small_roots...")
roots = f.small_roots(X=X, beta=1.0, epsilon=0.03)

if roots:
    pw_int  = int(roots[0])
    pw_bytes = pw_int.to_bytes(10, "big")
    print(f"[+] Password recovered: {pw_bytes}")
    print(f"[+] Match: {pw_bytes == password_bytes}")
    print(f"\nFLAG: FLAG{{coppersmith_partial_plaintext_rtfm}}")
else:
    print("[!] Coppersmith failed — check bounds and polynomial construction")
    # Debugging: verify polynomial construction
    print(f"    f(password) mod N = {int(f(password)) % int(N)}")
```

---

## Lab 4 — Boneh-Durfee: Small Private Exponent Attack

When the RSA private exponent `d` is small (d < N^0.292), Coppersmith (via
Boneh-Durfee 1999) factors N:

```python
# SageMath: Boneh-Durfee — small private exponent attack
# This requires finding small roots of a BIVARIATE polynomial.
# The technique is covered more fully in Day 591 (bivariate Coppersmith).
# Here we preview the setup.

from sage.all import ZZ, Integer

def boneh_durfee_check(N: int, e: int) -> str:
    """
    Quick check: is d likely small enough for Boneh-Durfee?
    If d < N^0.292, the attack works.
    """
    bits_N  = Integer(N).bit_length()
    bound   = bits_N * 0.292
    # In practice: if e > N^0.75, d is likely small (since e*d ≡ 1 mod φ(N))
    bits_e  = Integer(e).bit_length()
    if bits_e > bits_N * 0.75:
        return f"d is likely < N^0.292 — Boneh-Durfee applies (N={bits_N}b, e={bits_e}b)"
    return f"d may not be small enough — Boneh-Durfee may not apply"

# Example: vulnerable keypair with small d
p        = Integer(17389) * Integer(100003)   # tiny demo
q        = Integer(23399) * Integer(100019)
N_small  = Integer(17389 * 23399 * 100003 * 100019)   # not actually RSA-correct
# Real use: generate p, q with specific d constraint — see Day 583 (Wiener)
print(boneh_durfee_check(int(N_small), 65537))
print("Full Boneh-Durfee implementation: see Day 591 (bivariate Coppersmith)")
```

---

## Self-Assessment

```
[ ] 1. In Lab 3 (encrypted credentials), change the password size to 120 bits.
        Does Coppersmith still succeed? At what bit size does it fail for e=3?
        (Hint: the bound is N^(1/3) ≈ 341 bits for 1024-bit N.)

[ ] 2. Lab 1 and Lab 2 attack known-high and known-low bits respectively.
        Can you attack known-MIDDLE bits (e.g., you know the middle 1/3 of m)?
        Sketch the polynomial you would construct.

[ ] 3. In all three labs, what happens if you use e=65537 instead of e=3?
        Recalculate the bound and explain why Coppersmith becomes impractical.

[ ] 4. Write a function that, given (N, e, c) and a known prefix, automatically
        constructs the polynomial and calls small_roots(). Make it generic
        enough to handle both prefix-only and prefix+suffix scenarios.
```

---

## Key Takeaways

1. **Coppersmith is a precision tool**: it requires knowing where the unknown
   bits are (high, low, or embedded). The polynomial construction must exactly
   reflect the structure of the plaintext.
2. **The bound is N^(1/e)**: for e=3 and 1024-bit N, you can recover up to
   ~341 unknown bits. Knowing MORE than 683 bits of a 1024-bit plaintext
   gives you the rest.
3. **`small_roots()` can fail silently**: always verify `f(root) % N == 0`
   after recovery. If it fails, debug the polynomial construction first.
4. **Real-world impact**: RSA-PKCS#1 v1.5 padding, fixed-format protocol
   messages, and certificate signing requests with known structure are all
   vulnerable to this class of attack under small e.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q590.1, Q590.2 …).

---

## Navigation

← Previous: [Day 589 — Coppersmith's Method](DAY-0589-Coppersmith-Method.md)
→ Next: [Day 591 — Franklin-Reiter and Bivariate Coppersmith](DAY-0591-Franklin-Reiter-Bivariate.md)
