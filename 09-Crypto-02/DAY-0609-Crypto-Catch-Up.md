---
title: "Crypto Catch-Up — Review, Gaps, and Competency Check Preparation"
tags: [cryptography, catch-up, review, gap-analysis, competency-prep,
  SageMath, practice, module-09-crypto-02]
module: 09-Crypto-02
day: 609
prerequisites:
  - Days 561–608 — Complete Module 09
related_topics:
  - Crypto Competency Check (Day 610)
  - Malware Analysis Setup (Day 611)
---

# Day 609 — Crypto Catch-Up: Review, Gaps, and Competency Check Preparation

> "Tomorrow is the competency check for Module 09. Not a test I wrote to trip
> you up — a check I wrote to confirm you are ready to move forward. If you
> are not ready, you tell me now. We use today to fix the gaps. If you are
> ready, today is the last chance to sharpen the things that are mostly right
> but not automatic yet. Know the difference."
>
> — Ghost

---

## Goals

Use this day to address any remaining gaps in Module 09, drill the most
commonly missed techniques from the CTF sprints, and run a final preparation
checklist before the Day 610 competency check.

**Prerequisites:** Days 561–608.
**Time budget:** Full day — invest where your score is weakest.

---

## Step 1 — Self-Diagnosis (30 minutes)

Without opening any notes, write down (from memory):

```
1. The four stages of a CBC padding oracle attack:
   _______________________________________________
   _______________________________________________

2. The Coppersmith bound for a degree-e polynomial:
   x_0 must be smaller than _____________________

3. The number of ECDSA signatures needed for HNP with 8-bit bias:
   Approximately __________________________________

4. How many MT19937 outputs are needed to clone the state:
   _______________________________________________

5. What gcd(s_correct - s_faulty, N) returns in the Bellcore attack:
   _______________________________________________

6. Name two NIST PQC standards and their hard problems:
   a. _____________ — hard problem: _____________
   b. _____________ — hard problem: _____________
```

Score yourself (≥ 5/6 correct → move to Step 3). If < 5/6 → Step 2.

---

## Step 2 — Targeted Drilling (1–3 hours)

### If you missed Coppersmith

Re-read Day 589. Then run this exercise from memory:

```python
# SageMath: Coppersmith from scratch (no notes)
# Given N (512-bit), e=3, c, and the top 160 bits of m:
# Construct f(x) and call small_roots()

from sage.all import ZZ, Zmod, PolynomialRing, Integer, random_prime, power_mod

p = random_prime(2**256); q = random_prime(2**256)
N = p * q; e = 3
m_full = Integer(ZZ.random_element(2**400, 2**512))
c = power_mod(int(m_full), e, int(N))
m_known = int(m_full) >> 160   # Top bits known
unknown_bits = 160

# Write the attack without looking at Day 589:
PR = PolynomialRing(Zmod(Integer(N)), 'x')
x  = PR.gen()
f  = (Integer(m_known) * Integer(2**unknown_bits) + x)**e - Integer(c)
roots = f.small_roots(X=Integer(2**unknown_bits), beta=1.0, epsilon=0.04)
print(f"[+] Root found: {roots[0] == int(m_full) % (2**unknown_bits)}" if roots else "[!] Failed")
```

### If you missed HNP

Re-read Days 593–594. Then build the lattice from memory for 40 signatures
with 8-bit nonce bias. Do not look at Day 593 until after you try.

```python
# SageMath: Build HNP lattice from memory
# q = group order, sigs = list of (r, s, h), bias = 8
# ts = [r*inv(s) mod q for r,s,h in sigs]
# us = [h*inv(s) mod q for r,s,h in sigs]
# n = len(sigs), B = q >> 8
# Build (n+2)×(n+2) matrix: q on diagonal for first n rows,
# ts and 1 in row n, us and B in row n+1
# Run LLL, find d in position n of short row
print("Build the HNP lattice from memory. Then compare to Day 593.")
```

### If you missed MT19937

Re-read Day 595. Implement untemper from memory for the hardest step
(the 7-bit left-shift XOR AND):

```python
# The hardest untemper step: reverse y ^= (y << 7) & 0x9D2C5680
# Write this from memory:
def undo_left_shift_7(y: int) -> int:
    """Reverse: y ^= (y << 7) & 0x9D2C5680"""
    b   = 0x9D2C5680
    tmp = y
    for _ in range(4):   # 4 iterations cover 32 bits given 7-bit shift
        tmp = y ^ ((tmp << 7) & b)
    return tmp & 0xFFFFFFFF

# Verify
def temper_step_7(y: int) -> int:
    return (y ^ ((y << 7) & 0x9D2C5680)) & 0xFFFFFFFF

for test in [0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678]:
    assert undo_left_shift_7(temper_step_7(test)) == test
print("[+] untemper step 7 correct")
```

### If you missed Wiener's Attack

Re-read Day 592. Implement continued fraction convergents from memory:

```python
def wiener(N: int, e: int) -> int | None:
    """Wiener's attack: recover d from (N, e) using continued fractions."""
    import math
    def cf(num, den):
        while den: q = num//den; num,den = den,num-q*den; yield q
    p, pp, q, qp = 1, 0, 0, 1
    for a in cf(e, N):
        p, pp = a*p + pp, p
        q, qp = a*q + qp, q
        k, d  = p, q
        if k == 0: continue
        if (e*d - 1) % k != 0: continue
        phi = (e*d - 1) // k
        b = N - phi + 1; disc = b*b - 4*N
        if disc < 0: continue
        sq = int(disc**0.5)
        for s2 in [sq-1, sq, sq+1]:
            if s2*s2 == disc:
                p_f = (b+s2)//2; q_f = N//p_f
                if p_f*q_f == N: return d
    return None

# Test
from sympy import nextprime; import random; rng = random.SystemRandom()
p_t = nextprime(rng.getrandbits(128)); q_t = nextprime(rng.getrandbits(128))
N_t = p_t*q_t; phi_t = (p_t-1)*(q_t-1)
d_t = rng.randrange(2, int(N_t**0.25)//3)
while __import__("math").gcd(d_t, phi_t) != 1: d_t -= 1
e_t = pow(d_t, -1, phi_t)
assert wiener(N_t, e_t) == d_t
print("[+] Wiener from memory: correct")
```

---

## Step 3 — Final Preparation Checklist

Work through these in the 2 hours before the competency check:

```
SageMath readiness:
[ ] Open SageMath. Type: Matrix(ZZ, [[1,0],[0,1]]).LLL()  → should return matrix
[ ] Type: PolynomialRing(Zmod(101), 'x').gen()^2 - 5     → polynomial f
[ ] Call f.small_roots(X=10, beta=1.0)                   → should return [x_0]

Key commands to have memorised:
[ ] Build ZZ matrix for LLL
[ ] Define polynomial ring over Zmod(N)
[ ] Call small_roots() with correct parameters
[ ] Compute modular inverse: Integer(a).inverse_mod(Integer(b))
[ ] Generate random prime: random_prime(2**256)

Attack identification:
[ ] RSA, e=3, single ciphertext, partial plaintext → Coppersmith
[ ] RSA, e=3, two ciphertexts, m2 = a*m1+b       → Franklin-Reiter
[ ] RSA, large e                                  → Wiener
[ ] ECDSA, many signatures, k biased              → HNP lattice
[ ] AES-CBC, server returns 400/403               → Padding oracle
[ ] AES-GCM, nonce reuse                          → Forbidden attack
[ ] 624 PRNG outputs                              → MT19937 clone
[ ] LCG, 2 outputs                                → Seed recovery
```

---

## Step 4 — Pre-Competency Check Drill (1 hour)

Solve this mini-problem without notes:

```
N = random 512-bit RSA modulus (generate one in SageMath)
e = 3
m = random 300-bit message

Part A: Encrypt m → c.
Part B: Give yourself only the top 100 bits of m.
         Recover m completely using Coppersmith.
Part C: Create m2 = 7*m + 13 mod N.
         Encrypt m2 → c2.
         Recover both m and m2 from (c, c2) using Franklin-Reiter.
Part D: Generate 100 ECDSA signatures with 8-bit nonce bias.
         Run HNP lattice. Recover d. Forge one signature.
         (Use the secp256k1 simulation from Day 594.)
```

Document your times:

```
Part A completed in: ___________
Part B completed in: ___________
Part C completed in: ___________
Part D completed in: ___________
```

**Target:** All four parts in under 90 minutes total. If you cannot finish
Part B in 20 minutes, spend the remaining time on Coppersmith drills.

---

## What the Competency Check Will Test (Day 610)

The Day 610 check has three parts:

1. **Written explanation** (20 min): Given three attack names, explain in
   plain language what each attack does, when it applies, and what the
   defender should do.

2. **Live lab** (90 min): Two fresh crypto challenges — no category hints.
   You have SageMath, Python, and your toolkit. Solve and document.

3. **Self-assessment review** (20 min): Review your Module 09 checklist
   from Day 605. Identify and record any items still below score 3.

**Pass criteria:**
- Written: ≥ 70% accuracy
- Lab: ≥ 1 of 2 challenges fully solved; second at least partially solved
- Self-assessment: honest, specific, no items scored 5 that you could not
  demonstrate in the lab

---

## Key Takeaways

1. **Identify the attack class before writing a single line of code.**
   Mis-identifying the attack wastes 90% of your lab time. The 2-minute
   analysis step is the most important.
2. **SageMath is your power tool.** Anything you cannot implement in SageMath
   in under 5 minutes is not your real toolkit — it is a memorised script.
   Know the API.
3. **Gaps at Day 609 are fixable in 4–6 hours of targeted drilling.** Gaps at
   Day 610 cost you a module repeat. Today is the last cheap day to fix them.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q609.1, Q609.2 …).

---

## Navigation

← Previous: [Day 608 — PQC Attack Surface](DAY-0608-PQC-Attack-Surface.md)
→ Next: [Day 610 — Crypto Competency Check](DAY-0610-Crypto-Competency-Check.md)
