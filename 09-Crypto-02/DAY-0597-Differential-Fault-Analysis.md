---
title: "Differential Fault Analysis — DFA on AES and RSA-CRT"
tags: [cryptography, DFA, differential-fault-analysis, AES, RSA-CRT, Bellcore,
  fault-injection, side-channel, smart-card, embedded, CWE-1247, module-09-crypto-02]
module: 09-Crypto-02
day: 597
prerequisites:
  - Day 566 — ECB Cut-and-Paste (AES block structure)
  - Day 567 — RSA Attack Lab (RSA-CRT)
  - Basic AES internals: S-Box, MixColumns, ShiftRows
related_topics:
  - Cache Timing Attacks (Day 598)
  - PRNG Attack Lab (Day 596)
---

# Day 597 — Differential Fault Analysis: DFA on AES and RSA-CRT

> "Differential Fault Analysis is not a mathematical attack — it is a physical
> one. You introduce a fault in the computation: zap the chip with a voltage
> glitch, point a laser at the cache line, heat the substrate. Get a corrupted
> ciphertext. Compare it with the correct one. The difference leaks the key.
> This broke smart cards. This broke RSA on embedded chips. This is why your
> bank card changed three times in the last decade."
>
> — Ghost

---

## Goals

Understand Differential Fault Analysis (DFA) at the conceptual and mathematical
level, learn the Bellcore attack on RSA-CRT (one fault = factor N), and study
the AES DFA attack model (fault in round 8).

**Prerequisites:** AES internals, RSA-CRT basics (Day 567).
**Estimated study time:** 3–4 hours (theory heavy; lab is simulated).

---

## Stage 1 — What Is DFA?

### Definition

**Differential Fault Analysis (DFA)** injects a fault into a cryptographic
computation and exploits the *difference* between the correct and faulty output
to recover secret key material.

```
Correct computation:  C  = f_k(M)
Faulty computation:   C' = f_k'(M)   where k' ≠ k (fault in round r)
Difference:           ΔC = C ⊕ C'    leaks information about round key k_r
```

By collecting enough (C, C') pairs with carefully induced faults, the attacker
recovers the round key `k_r`, then back-propagates to the master key.

### Physical Fault Injection Methods

| Method | Technique | Precision | Cost |
|---|---|---|---|
| Clock glitch | Momentary under/over-voltage on clock | Medium | $50–$500 |
| Power glitch | Spike on VCC pin | Low | $50–$500 |
| Laser injection | Focused UV/IR laser on die | High | $50k–$200k |
| EM fault | Electromagnetic pulse near chip | Medium | $500–$5k |
| Temperature | Extreme heat/cold | Low | $10 |

### Threat Model

DFA requires **physical access** to the device and the ability to inject a
fault at a precise moment in the computation. The target output must be
observable. Typical targets:

- Smart cards (payment, SIM, passports)
- HSMs (Hardware Security Modules) with weak physical protection
- Microcontrollers in IoT devices
- FPGAs without fault-detection logic

---

## Stage 2 — Bellcore Attack: One Fault Factors RSA

### RSA-CRT Background

RSA private key decryption using the Chinese Remainder Theorem:

```
d_p = d mod (p-1)
d_q = d mod (q-1)

m_p = c^{d_p} mod p      ← computation on p side
m_q = c^{d_q} mod q      ← computation on q side

m = CRT(m_p, m_q, p, q)  ← combine via CRT
```

This is 4× faster than standard `c^d mod N`. Most RSA hardware implementations
use RSA-CRT.

### The Attack (Boneh, DeMillo, Lipton 1997)

Inject a fault during the `m_q` computation. The result `m_q'` is wrong:

```
Correct signature:  s  = CRT(m_p, m_q, p, q)
Faulty signature:   s' = CRT(m_p, m_q', p, q)   where m_q' ≠ m_q
```

Now compute:

```
gcd(s - s', N) = p   (with high probability)
```

**Why?** The correct `s` satisfies `s ≡ m_p (mod p)` and `s ≡ m_q (mod q)`.
The faulty `s'` satisfies `s' ≡ m_p (mod p)` but `s' ≡ m_q' (mod q)` where
`m_q' ≠ m_q`. So:

```
(s - s') ≡ 0 (mod p)   but   (s - s') ≢ 0 (mod q)
→ gcd(s - s', N) = p
```

One faulty signature + one correct signature = the factors of N.

```python
#!/usr/bin/env python3
"""
Simulated Bellcore attack on RSA-CRT.
One induced fault in the q-side computation reveals p.
"""
from __future__ import annotations
import math
import random


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean: returns (gcd, x, y) where a*x + b*y = gcd."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def crt_combine(m_p: int, m_q: int, p: int, q: int) -> int:
    """Chinese Remainder Theorem combination."""
    q_inv_p = pow(q, -1, p)
    h = (q_inv_p * (m_p - m_q)) % p
    return m_q + h * q


def rsa_crt_sign_correct(c: int, d_p: int, d_q: int, p: int, q: int) -> int:
    """Correct RSA-CRT signature."""
    m_p = pow(c, d_p, p)
    m_q = pow(c, d_q, q)
    return crt_combine(m_p, m_q, p, q)


def rsa_crt_sign_faulty(c: int, d_p: int, d_q: int, p: int, q: int) -> int:
    """RSA-CRT signature with a simulated fault in the q-side computation."""
    m_p = pow(c, d_p, p)
    m_q = pow(c, d_q, q)
    # Inject a 1-bit fault in m_q (flip a random bit)
    fault_bit = 1 << random.randint(0, m_q.bit_length() - 1)
    m_q_faulty = m_q ^ fault_bit
    return crt_combine(m_p, m_q_faulty, p, q)


def bellcore_attack(s_correct: int, s_faulty: int, N: int) -> tuple[int, int] | None:
    """
    Recover p and q from one correct + one faulty RSA-CRT signature.
    """
    p = math.gcd(s_correct - s_faulty, N)
    if 1 < p < N:
        q = N // p
        assert p * q == N
        return p, q
    return None


# ── Demo ──────────────────────────────────────────────────────────────────────
from sympy import nextprime

# Generate small RSA keypair for demo
bits   = 256
p      = nextprime(random.getrandbits(bits // 2))
q      = nextprime(random.getrandbits(bits // 2))
N      = p * q
e      = 65537
phi    = (p - 1) * (q - 1)
d      = pow(e, -1, phi)
d_p    = d % (p - 1)
d_q    = d % (q - 1)

# Message to sign
c = random.randint(2, N - 1)

s_correct = rsa_crt_sign_correct(c, d_p, d_q, p, q)
s_faulty  = rsa_crt_sign_faulty(c, d_p, d_q, p, q)

print(f"[*] N = {N.bit_length()} bits")
print(f"[*] Correct signature:  s  = {str(s_correct)[:20]}...")
print(f"[*] Faulty  signature:  s' = {str(s_faulty)[:20]}...")

factors = bellcore_attack(s_correct, s_faulty, N)
if factors:
    p_rec, q_rec = factors
    print(f"[+] p recovered: {p_rec == p}")
    print(f"[+] q recovered: {q_rec == q}")
    d_rec = pow(e, -1, (p_rec - 1) * (q_rec - 1))
    print(f"[+] d recovered: {d_rec == d}")
    print(f"\n[+] Bellcore attack succeeded with 1 faulty signature!")
else:
    print("[!] GCD = 1 or N — try again (may need to re-run with new fault)")
```

---

## Stage 3 — DFA on AES (Round 8 Fault)

### AES Structure Review

AES-128 has 10 rounds. Each round performs:
1. **SubBytes** — non-linear S-Box substitution
2. **ShiftRows** — cyclic row shifts
3. **MixColumns** — linear mixing over GF(2^8)
4. **AddRoundKey** — XOR with round key

Round 10 skips MixColumns. The last round key `k10` is directly related to
the master key.

### The Attack Model

Inject a fault at the **start of round 9** (after round 8 MixColumns).
The fault flips one byte of the state. This single-byte fault propagates
through round 9 and round 10 (without MixColumns) to produce 4 incorrect
bytes in the final ciphertext (due to ShiftRows).

By collecting multiple faulty ciphertexts and testing all 256 possible values
of each round-10 key byte, the attacker identifies the consistent key byte
that explains all faults.

```python
#!/usr/bin/env python3
"""
Simulated DFA on AES-128: one byte fault injected before round 9.
Demonstrates the differential analysis approach.

Full DFA requires ~50 (correct, faulty) pairs and ~2^32 work per byte.
This is a simplified educational simulation.
"""
from __future__ import annotations
from Crypto.Cipher import AES


KEY = bytes.fromhex("deadbeef01234567cafebabe89abcdef")
CORRECT_PLAINTEXT = b"Hello Ghost!!!!!"   # 16 bytes


def aes_encrypt_with_fault(key: bytes, plaintext: bytes,
                           fault_byte_pos: int, fault_value: int) -> bytes:
    """
    Encrypt with a simulated single-byte fault injected before round 9.
    (Conceptual simulation — real DFA requires AES internals.)
    """
    # In reality: fault is injected mid-computation.
    # For simulation: XOR a byte in the middle of the computation.
    # We approximate by encrypting with a slightly modified state.
    cipher       = AES.new(key, AES.MODE_ECB)
    correct_ct   = cipher.encrypt(plaintext)

    # Simulate: the fault causes a known differential in the final round
    # Real DFA: fault_byte at position fault_byte_pos propagates to 4 positions
    faulty_ct = bytearray(correct_ct)
    faulty_ct[fault_byte_pos] ^= fault_value   # Simplified fault propagation
    return bytes(faulty_ct)


def dfa_key_byte_recovery(correct_ct: bytes,
                           faulty_cts: list[bytes],
                           byte_pos: int) -> list[int]:
    """
    Test all 256 candidates for a key byte.
    Return candidates consistent with all (correct, faulty) pairs.
    """
    candidates = list(range(256))
    for faulty_ct in faulty_cts:
        delta = correct_ct[byte_pos] ^ faulty_ct[byte_pos]
        # Consistency check: in real DFA, we verify through the inverse S-Box
        # Here: simple delta filter (educational approximation)
        candidates = [k for k in candidates
                      if (k ^ correct_ct[byte_pos]) != 0 and delta != 0]
    return candidates


# Demo
cipher_correct = AES.new(KEY, AES.MODE_ECB)
ct_correct     = cipher_correct.encrypt(CORRECT_PLAINTEXT)

# Generate 10 faulty ciphertexts (different faults, same position)
faulty_cts = [
    aes_encrypt_with_fault(KEY, CORRECT_PLAINTEXT,
                           fault_byte_pos=0,
                           fault_value=i + 1)
    for i in range(10)
]

print(f"[*] Correct CT:  {ct_correct.hex()}")
print(f"[*] Faulty CT 1: {faulty_cts[0].hex()}")
print(f"[*] Differential: "
      f"{bytes(a^b for a,b in zip(ct_correct, faulty_cts[0])).hex()}")

candidates = dfa_key_byte_recovery(ct_correct, faulty_cts, byte_pos=0)
print(f"[*] Key byte candidates after {len(faulty_cts)} faults: "
      f"{len(candidates)} remaining")
print(f"[*] Actual key byte 0: {KEY[0]:#04x} = {KEY[0]}")
print("\n[!] Full DFA requires AES internals — see Piret & Quisquater 2003")
```

---

## Countermeasures

| Countermeasure | Protects Against | Implementation |
|---|---|---|
| Computation verification | DFA (detect fault) | Compute twice, compare |
| Infective computation | DFA (make output useless) | Fault changes output randomly |
| Temporal randomisation | Timing-based fault injection | Add random delays |
| Sensor detection | Physical tampering | Voltage/light/temp sensors |
| Dual-rail logic | Power analysis + DFA | Hardware design |
| Error-correcting codes | Single-bit faults | SEC-DED codes on state |

For RSA-CRT specifically: always verify `s^e ≡ c (mod N)` before returning.
One modular exponentiation prevents Bellcore.

---

## Key Takeaways

1. **One faulty RSA-CRT signature factors N.** The Bellcore attack requires
   physical access and one fault injection — achievable with $50 of electronics.
   The fix (verify `s^e mod N` before output) is equally cheap.
2. **DFA on AES requires ~50 faults** for full 128-bit key recovery. It is
   practical against unprotected implementations on smart cards and MCUs.
3. **DFA is a side-channel attack on the computation, not the algorithm.**
   AES and RSA are mathematically secure. DFA exploits the physical
   implementation.
4. **Real-world impact:** EMV payment chips were vulnerable to DFA (Teuwen
   et al. 2010). Countermeasures were added after public disclosure.

---

## Exercises

```
1. In the Bellcore demo, change the fault to affect the p-side (m_p) instead
   of q-side. Does gcd(s - s', N) still factor N? Why or why not?

2. What happens if two different faults are injected in the same RSA-CRT
   signature (both p-side and q-side)? Does the attack still work?

3. Describe a software countermeasure against Bellcore that adds O(1) time
   overhead. Implement it in the demo code.

4. Research: the Piret-Quisquater DFA on AES requires a fault in round 8
   at a specific byte. How many (correct, faulty) pairs are needed to uniquely
   determine one byte of the last round key?
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q597.1, Q597.2 …).

---

## Navigation

← Previous: [Day 596 — PRNG Attack Lab](DAY-0596-PRNG-Attack-Lab.md)
→ Next: [Day 598 — Cache Timing Attacks](DAY-0598-Cache-Timing-Attacks.md)
