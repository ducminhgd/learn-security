---
title: "LCG and LFSR Attacks — Cracking Linear PRNGs"
tags: [cryptography, LCG, LFSR, Berlekamp-Massey, linear-congruential,
  seed-recovery, lattice, truncated-output, PRNG, CWE-338, module-09-crypto-02]
module: 09-Crypto-02
day: 599
prerequisites:
  - Day 596 — PRNG Attack Lab (LCG intro)
  - Day 587 — LLL Algorithm (for truncated LCG lattice attack)
  - Basic linear algebra over GF(2) (for LFSR)
related_topics:
  - MT19937 State Recovery (Day 595)
  - Cache Timing Attacks (Day 598)
  - Milestone Day 600 (Day 600)
---

# Day 599 — LCG and LFSR Attacks: Cracking Linear PRNGs

> "Every programming language shipped with a broken random number generator
> for decades. C's rand(), Java's Random, PHP's mt_rand() — all predictable
> from a handful of outputs. The Linear Feedback Shift Register is the hardware
> version: one of its outputs, and the Berlekamp-Massey algorithm reconstructs
> the entire state in O(n^2) operations. Today you learn both. Tomorrow,
> when you see a challenge with 'random tokens', this is where you start."
>
> — Ghost

---

## Goals

Attack the Linear Congruential Generator (LCG) with unknown modulus via
lattice methods, then implement the Berlekamp-Massey algorithm to recover
LFSR structure from output bits. Connect both to real-world token prediction.

**Prerequisites:** Day 596 (LCG basics), Day 587 (LLL), GF(2) arithmetic.
**Estimated study time:** 3–4 hours.

---

## Part 1 — LCG: Full and Truncated Output Recovery

### LCG Recap

A Linear Congruential Generator with **known parameters** (m, a, b):

```
x_{n+1} = (a * x_n + b) mod m
output_n = x_n   (full output)
```

**Known parameters, unknown seed:** With two outputs, solve `x_1 = (a*x_0 + b) mod m`
for x_0 trivially.

### Attack 1: Unknown Modulus

If `a, b` are known but `m` is unknown, recover `m` from several outputs:

```python
#!/usr/bin/env python3
"""
LCG attack: recover unknown modulus m from 6+ consecutive full outputs.

Key insight: t_n = x_{n+2} - 2*x_{n+1} + x_n ≡ 0 (mod m)
So m divides gcd(t_0, t_1, t_2, ...).
"""
from __future__ import annotations
import math
import random


def lcg_next(x: int, a: int, b: int, m: int) -> int:
    return (a * x + b) % m


def recover_unknown_modulus(outputs: list[int]) -> int:
    """
    Given 6+ consecutive LCG outputs with known a, b but unknown m,
    recover m using gcd of second differences.
    """
    # Second differences: t_n = x_{n+2} - 2*x_{n+1} + x_n
    # These are all ≡ 0 (mod m), so m divides gcd of all |t_n|
    diffs = []
    for i in range(len(outputs) - 2):
        t = abs(outputs[i+2] - 2*outputs[i+1] + outputs[i])
        if t > 0:
            diffs.append(t)

    if not diffs:
        return -1

    m_candidate = diffs[0]
    for d in diffs[1:]:
        m_candidate = math.gcd(m_candidate, d)

    return m_candidate


# Demo: LCG with unknown modulus
true_m = random.randint(2**30, 2**32)
a      = random.randint(1, true_m - 1)
b      = random.randint(0, true_m - 1)
seed   = random.randint(0, true_m - 1)

# Generate 10 outputs
x = seed
outputs = []
for _ in range(10):
    x = lcg_next(x, a, b, true_m)
    outputs.append(x)

m_recovered = recover_unknown_modulus(outputs)
print(f"[*] True m:      {true_m}")
print(f"[*] Recovered m: {m_recovered}")
print(f"[+] Match: {m_recovered == true_m}")
```

### Attack 2: Truncated LCG via Lattice (The Hard Case)

When only the **top k bits** of each output are visible (truncated), a lattice
attack recovers the full state.

This is the attack on `rand()` in many languages when only partial output
is observable (e.g., generating a random float between 0 and 1):

```python
# SageMath: Truncated LCG lattice attack
from sage.all import Matrix, ZZ, Integer, vector

def truncated_lcg_attack(trunc_outputs: list[int], a: int, b: int, m: int,
                         trunc_bits: int, n_out: int) -> int | None:
    """
    Recover LCG seed from n_out truncated outputs (top trunc_bits each).
    Uses the lattice method (Frieze, Håstad, Kannan, Lagarias, Shamir 1988).

    Constructs lattice where short vector encodes (x_0, x_1, ..., x_{n-1}).
    """
    # Build the lattice
    # Row i: (0, ..., 0, m, 0, ..., 0) for i < n_out (modular rows)
    # Row n_out: (1, a, a^2, ..., a^{n-1}) (recurrence row)
    n   = n_out
    M   = Matrix(ZZ, n + 1, n + 1)
    # Fill modular rows
    for i in range(n):
        M[i, i] = Integer(m)
    # Recurrence row: encode a^0, a^1, ..., a^{n-1} mod m
    for i in range(n):
        M[n, i] = pow(int(a), i, int(m))
    M[n, n] = Integer(1)

    # Target vector: approximate the truncated outputs
    shift = Integer(m) >> trunc_bits    # Scale: each output ≈ trunc_val * shift
    target = vector(ZZ, [Integer(t) * shift for t in trunc_outputs] + [0])

    # Run LLL and find the closest lattice vector (CVP via embedding)
    L = M.LLL()

    # The short vector should be close to target
    for row in L:
        candidate_x0 = int(row[0]) % int(m)
        # Verify: does this seed generate the observed truncated outputs?
        x = candidate_x0
        valid = True
        for t_obs in trunc_outputs:
            t_full = (x >> (x.bit_length() - trunc_bits)) if x > 0 else 0
            # Loose check (truncation can vary)
            valid = valid and (abs(t_full - t_obs) < 2)
            x = (int(a) * x + int(b)) % int(m)
        if valid:
            return candidate_x0
    return None


# Demo
m_trunc = Integer(2**32)
a_trunc = Integer(1664525)
b_trunc = Integer(1013904223)
seed_t  = Integer(0xDEADBEEF)

trunc_bits = 16   # Observe only top 16 bits of each 32-bit output
x_state    = seed_t
trunc_outs = []
for _ in range(8):
    x_state = (a_trunc * x_state + b_trunc) % m_trunc
    trunc_outs.append(int(x_state) >> 16)   # Top 16 bits

print(f"[*] Truncated outputs (top {trunc_bits} bits): {trunc_outs}")
recovered = truncated_lcg_attack(trunc_outs, int(a_trunc), int(b_trunc),
                                 int(m_trunc), trunc_bits, len(trunc_outs))
print(f"[*] Seed recovered: {recovered}")
```

---

## Part 2 — LFSR: Berlekamp-Massey

### What Is an LFSR?

A **Linear Feedback Shift Register (LFSR)** of length `L` generates bits:

```
s_n = c_1 * s_{n-1} XOR c_2 * s_{n-2} XOR ... XOR c_L * s_{n-L}   (over GF(2))
```

The connection polynomial `C(x) = 1 + c_1*x + c_2*x^2 + ... + c_L*x^L`
determines the recurrence. With a maximal-length polynomial, an L-bit LFSR
produces a sequence of period `2^L - 1`.

**Security problem:** Given `2L` consecutive output bits, the **Berlekamp-Massey
algorithm** recovers both `L` and `C(x)` in `O(L^2)` operations. The entire
future output is then predictable.

### Berlekamp-Massey Algorithm

```python
#!/usr/bin/env python3
"""
Berlekamp-Massey algorithm: recover LFSR connection polynomial from output bits.
Given 2L bits, find the minimum-length LFSR that generates them.
"""
from __future__ import annotations


def berlekamp_massey(bits: list[int]) -> list[int]:
    """
    Berlekamp-Massey algorithm over GF(2).
    Returns the connection polynomial C as a list of coefficients
    [c_1, c_2, ..., c_L] such that:
    s_n = c_1*s_{n-1} XOR c_2*s_{n-2} XOR ... XOR c_L*s_{n-L}
    """
    n   = len(bits)
    C   = [1]       # Current connection polynomial
    B   = [1]       # Previous polynomial
    L   = 0         # Current LFSR length
    m   = 1         # Number of steps since last update
    b   = 1         # Discrepancy at last update

    for i in range(n):
        # Compute discrepancy d = s_i XOR sum(C_j * s_{i-j})
        d = bits[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] * bits[i - j]
        d &= 1   # GF(2)

        if d == 0:
            m += 1
        elif 2 * L <= i:
            # Update C: C = C - (d / b) * x^m * B  over GF(2): d/b = d*b = d (b=1)
            T   = C[:]
            tmp = [0] * (m + len(B))
            for j, bj in enumerate(B):
                tmp[m + j] ^= bj   # x^m * B, no division needed (GF(2))
            C = [c ^ t for c, t in zip(C + [0]*max(0, len(tmp)-len(C)),
                                         tmp + [0]*max(0, len(C)-len(tmp)))]
            L = i + 1 - L
            B = T
            b = d
            m = 1
        else:
            tmp = [0] * (m + len(B))
            for j, bj in enumerate(B):
                tmp[m + j] ^= bj
            C = [c ^ t for c, t in zip(C + [0]*max(0, len(tmp)-len(C)),
                                         tmp + [0]*max(0, len(C)-len(tmp)))]
            m += 1

    # Return [c_1, ..., c_L]
    return C[1:L+1]


def lfsr_predict(seed_bits: list[int], C: list[int], n_predict: int) -> list[int]:
    """Given initial L bits and connection polynomial, predict n_predict more bits."""
    L    = len(C)
    buf  = list(seed_bits[-L:])
    pred = []
    for _ in range(n_predict):
        nxt = 0
        for j, cj in enumerate(C):
            nxt ^= cj * buf[-(j + 1)]
        nxt &= 1
        pred.append(nxt)
        buf.append(nxt)
        buf = buf[-L:]
    return pred


# ── Demo ──────────────────────────────────────────────────────────────────────
import random

# Generate a secret LFSR (attacker does not know L or C)
L_true   = 32   # 32-bit LFSR
# Primitive polynomial over GF(2) — determines period 2^32 - 1
# Using x^32 + x^22 + x^2 + x + 1 (a known primitive polynomial)
C_true   = [0] * L_true
for tap in [22, 2, 1, 0]:    # Feedback taps (0-indexed)
    C_true[tap] = 1

# Generate initial state
state    = [random.randint(0, 1) for _ in range(L_true)]
all_bits = state[:]

for _ in range(200):   # Generate 200 bits
    nxt = 0
    for j, cj in enumerate(C_true):
        nxt ^= cj * all_bits[-(j + 1)]
    nxt &= 1
    all_bits.append(nxt)

observed = all_bits[:2 * L_true]   # Attacker sees first 2L bits
future   = all_bits[2 * L_true:]   # These should be predicted

# Attack
C_recovered = berlekamp_massey(observed)
L_recovered = len(C_recovered)
print(f"[*] Observed 2L = {len(observed)} bits")
print(f"[+] LFSR length L recovered: {L_recovered} (true: {L_true})")
print(f"[+] Connection poly match:   {C_recovered == C_true}")

# Predict next 20 bits
predicted = lfsr_predict(observed, C_recovered, 20)
print(f"\n[*] Next 20 bits (actual):    {future[:20]}")
print(f"[*] Next 20 bits (predicted): {predicted}")
print(f"[+] Prediction correct: {predicted == future[:20]}")
```

---

## Real-World Cases

| PRNG | Used In | Attack |
|---|---|---|
| LCG (glibc rand) | C standard library | Seed brute-force or lattice |
| LCG (Java Random) | Java, Android | 2 outputs = full seed |
| LFSR (A5/1) | GSM voice encryption | Correlation attack + B-M |
| RC4 | SSL/WEP, old TLS | Distinguishing attacks, bias |
| Wichmann-Hill LCG | Early Python random | Period too short |
| Dual_EC_DRBG | NSA backdoor PRNG | Trapdoor via ECDLP |

---

## Key Takeaways

1. **The LCG with unknown modulus is recoverable from 6+ outputs.** The modulus
   divides the GCD of second differences — an algebraic fact that requires no
   expensive computation.
2. **Truncated LCG requires lattice methods** but is still broken. Even if you
   see only the top 16 bits of 32-bit outputs, a lattice attack with 8+ samples
   recovers the full state.
3. **Berlekamp-Massey is the definitive LFSR attack.** Given 2L bits, it
   recovers the connection polynomial and predicts all future output. A5/1
   (GSM encryption) was broken using correlation attacks + B-M.
4. **No linear PRNG is safe for cryptography.** The defining property of all
   these generators is *linearity* — which makes them mathematically weak to
   algebraic attacks, regardless of how complex they look.

---

## Exercises

```
1. Run the LCG modulus recovery demo with only 5 outputs instead of 10.
   Does it still succeed? At what minimum number of outputs does the GCD
   approach converge to the true m?

2. Implement the Berlekamp-Massey algorithm over GF(3) (ternary LFSR).
   How does the algorithm change?

3. GSM's A5/1 LFSR uses three LFSRs (L=19, 22, 23) with a majority
   clocking rule. With 64 bits of keystream (known plaintext), how many
   bits does B-M need to recover each individual LFSR's polynomial?

4. Find one open-source project on GitHub that uses Python's random module
   for cryptographic purposes (session tokens, API keys, password resets).
   Write a 3-sentence disclosure explaining the vulnerability and fix.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q599.1, Q599.2 …).

---

## Navigation

← Previous: [Day 598 — Cache Timing Attacks](DAY-0598-Cache-Timing-Attacks.md)
→ Next: [Day 600 — Milestone: 600 Days](DAY-0600-Milestone-600.md)
