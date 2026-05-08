---
title: "Crypto CTF Sprint — Day 7: Timed Exam"
tags: [cryptography, CTF, timed-exam, RSA, ECDSA, symmetric, lattice,
  Coppersmith, padding-oracle, sprint, self-assessment, module-09-crypto-02]
module: 09-Crypto-02
day: 604
prerequisites:
  - Days 561–603 — Full crypto module
  - Day 600 — Milestone 600 (gap analysis complete)
related_topics:
  - Crypto CTF Sprint Day 8 (Day 605)
  - Crypto Competency Check (Day 610)
---

# Day 604 — Crypto CTF Sprint: Day 7 (Timed Exam)

> "No hints today. No categories. No technique labels. Five problems. Three
> hours. Everything you have learned since Day 561 is tested. Do not guess —
> analyse. Do not code first — think first. An hour of thought saves two
> hours of wrong implementation. Go."
>
> — Ghost

---

## Rules

- **3 hours hard stop** from the moment you begin.
- **No looking at previous day notes during the attempt.** Write your approach
  from memory, then implement.
- **Log your time** for each problem.
- After the 3 hours: open your notes, check answers, score yourself.
- Problems are presented without technique hints or category labels.

---

## Start Timer → Begin

### Problem 1

```
Given:
  N = 83479261934810273401298374918237461928374612983746192837461928374619283
      74619283746192837461928374619283746192837461928374619283746192837461934
  e = 3
  c = 29173948176234917823649817234698172364981723649817236498172364981723649
      81723649817236498172364981723649817236498172364981723649817236498172364

The plaintext m is known to start with the bytes b"CTF_FLAG:" (9 bytes = 72 bits).
Recover m.

Constraints:
  - N is 256-bit
  - m is at most 256 bits
  - The top 72 bits of m are known

Output: m as hex
```

*(Note: These are synthetic numbers for the exercise format — replace with
actual CTF-style numbers when running. The technique and approach are what matter.)*

```
Time started:  ___________
Approach identified: ___________
Code written:  ___________
Answer:        ___________
Time ended:    ___________
```

---

### Problem 2

```
A signing oracle signs arbitrary messages with secp256k1 ECDSA.
You may request 300 signatures.
The nonces are generated as: k = (secret || random_32bit) where secret is
a fixed 224-bit value and random_32bit is freshly sampled each time.
Total k size: 256 bits.

Top 224 bits of k are FIXED across all 300 signatures.
Bottom 32 bits vary randomly per signature.

Public key Q is given. Recover private key d.

Hint count remaining: 0
```

```
Time started:   ___________
Approach:
_____________________________________________________________________________
_____________________________________________________________________________

Implementation:
_____________________________________________________________________________

Private key d: ___________
Verification:  sign("PROOF") with d, verify with Q → ___________
Time ended:    ___________
```

**Analysis guide (do NOT read until after attempt):**

```
Top 224 bits fixed → k = K_top * 2^32 + r_i where K_top is unknown constant.
k_i - k_j = r_i - r_j (difference of 32-bit randoms — very small!)

ECDSA: s_i = k_i^{-1} * (h_i + d*r_i) mod q
        s_j = k_j^{-1} * (h_j + d*r_j) mod q

Eliminating K_top:
  k_i = K_top * 2^32 + r_i
  k_j = K_top * 2^32 + r_j
  k_i - k_j = r_i - r_j = Δr (at most 32 bits — very small)

From ECDSA equations:
  s_i * k_i - s_j * k_j = h_i - h_j + d*(s_i*r_i - s_j*r_j) ... (work it out)

This reduces to HNP on the differences. Collect ~100 pairs, build lattice,
run LLL. The bound is 2^32 — very small. Should work with ~30 pairs.
```

---

### Problem 3

```
AES-128-GCM encrypted file. You have access to a decryption oracle that
tells you if the tag is valid (200) or not (403). The oracle uses a fixed
key and a nonce that INCREMENTS by 1 for each request.

You have captured:
  Nonce N1 = 0x000000000000000000000001
  Ciphertext C1 + Tag T1

Make 65535 oracle queries (the nonce will wrap from 0xFFFF to 0x0001).
Then capture nonce N1 again with a different plaintext:
  Nonce N1' = N1   (same nonce! wrapped around)
  Ciphertext C2 + Tag T2

Using (N1, C1, T1) and (N1', C2, T2):
  a. Recover the GHASH key H.
  b. Forge a valid (C3, T3) for the admin access payload.

Admin payload: b"GRANT_ACCESS:admin:9999"
```

```
Time started:     ___________
GHASH key H:      ___________
Keystream S:      ___________
Forged C3 (hex):  ___________
Forged T3 (hex):  ___________
Time ended:       ___________
```

---

### Problem 4

```
You have 624 outputs from an unknown PRNG. The outputs are given as
32-bit unsigned integers. Predict the next 5 outputs.

Outputs (hex, 624 values):
[Load from: challenge_data/problem4_outputs.hex]
(For exam purposes: generate these using Python's random.getrandbits(32)
with a random seed, then attempt recovery.)

Next 5 predictions:
  #625: ___________
  #626: ___________
  #627: ___________
  #628: ___________
  #629: ___________
```

```python
# Self-generate the challenge for practice
import random
rng = random.Random()   # Random system seed
outputs = [rng.getrandbits(32) for _ in range(624)]
future  = [rng.getrandbits(32) for _ in range(5)]

# Save outputs
with open("problem4_outputs.hex", "w") as f:
    for o in outputs:
        f.write(f"{o:08x}\n")

# Your attack here (MT19937 state recovery — Day 595):
# ...
# Verify predictions match future
```

---

### Problem 5

```
LCG with UNKNOWN parameters (a, b, m). You have 10 consecutive outputs:
  x = [2847391028, 1029384756, 3847291029, 2948173654, 1928374650,
       3748291065, 2938471029, 1847362938, 3947281736, 2018374659]

Find: a, b, m, and the seed x_0.
Predict x_10 (the 11th output).
```

```
Time started:   ___________
m:              ___________
a:              ___________
b:              ___________
seed x_0:       ___________
x_10:           ___________
Time ended:     ___________
```

---

## Scoring

| Problem | Points | Notes |
|---|---|---|
| 1 — RSA Coppersmith | 20 | Full points for correct m |
| 2 — HNP (fixed top bits) | 25 | Correct d + valid signature |
| 3 — GCM Nonce Wrap | 25 | Correct H, S, and forged tag |
| 4 — MT19937 | 15 | All 5 predictions correct |
| 5 — Unknown LCG | 15 | All parameters + x_10 correct |
| **Total** | **100** | |

**Pass criterion:** ≥ 70 points within 3 hours.

```
Total time:    ___________
Total score:   ___________
Problems solved in time: ___________
```

---

## Post-Exam Analysis

After scoring, complete this analysis:

```
Problems I solved first attempt:    ___________
Problems I needed to look up:       ___________
Problems I did not attempt:         ___________

Bottleneck (where time was spent):
  [ ] Problem identification (not recognising the attack type)
  [ ] SageMath / library usage (syntax issues)
  [ ] Maths (forgot how the algorithm works)
  [ ] Debugging (code ran but produced wrong answer)
  [ ] Time management (spent too long on one problem)

Top skill to improve before Day 610: ___________
```

---

## Key Takeaways

1. **Timed exams reveal your actual skill level.** Open-book labs show your
   maximum; timed closed-book tests show your reliable performance. Both matter
   for real engagements.
2. **Problem identification is the most important skill.** Once you correctly
   identify "this is HNP with fixed high bits", implementation is mechanical.
   If you spent more than 10 minutes identifying the attack type, that is the
   gap to address.
3. **Every problem here appeared in a real CTF** (CTFtime, picoCTF, DEFCON,
   PlaidCTF). After solving these, you are ready for crypto challenges at any
   CTF that is not specifically researching new post-quantum techniques.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q604.1, Q604.2 …).

---

## Navigation

← Previous: [Day 603 — Crypto CTF Sprint Day 6](DAY-0603-Crypto-CTF-Sprint-Day-6.md)
→ Next: [Day 605 — Crypto CTF Sprint Day 8: Review and Module Wrap-Up](DAY-0605-Crypto-CTF-Sprint-Day-8.md)
