---
title: "Crypto CTF Sprint — Day 4: Lattice Challenges"
tags: [cryptography, CTF, lattice, LLL, Coppersmith, HNP, knapsack, SVP,
  sprint, SageMath, module-09-crypto-02]
module: 09-Crypto-02
day: 601
prerequisites:
  - Day 600 — Milestone 600
  - Days 586–594 — Lattice basics, LLL, Coppersmith, HNP
related_topics:
  - Crypto CTF Sprint Day 5 (Day 602)
  - LLL Algorithm (Day 587)
  - Coppersmith's Method (Day 589)
---

# Day 601 — Crypto CTF Sprint: Day 4 (Lattice Challenges)

> "CTF lattice challenges have a signature. You see a big matrix, some modular
> arithmetic, a 'random' vector. You see partial information about a secret.
> You see a polynomial with a known form. You know what to do. Build the lattice.
> Run LLL. Read the short vector. Today you prove you can do this under time
> pressure, across four different problem shapes."
>
> — Ghost

---

## Goals

Solve four CTF-style lattice challenges under timed conditions. Each problem
tests a distinct lattice attack pattern from Days 586–594.

**Prerequisites:** Days 586–600 (lattice theory + all labs).
**Estimated time:** 5–6 hours (aim for 4).

---

## Problem A — "Broken Knapsack" (LLL / Merkle-Hellman)

**Difficulty:** Intermediate | **Estimated:** 60 min

**Prompt:**
```
A legacy system sends you an encrypted message. The encryption scheme is:
  - Public key: a = [a_0, ..., a_24] (25 integers, each ~15 bits)
  - Ciphertext: c = sum(m_i * a_i for i in range(25))  where m_i ∈ {0,1}

a = [
  14843, 19031, 28432, 37519, 62018, 100451, 190234, 369821,
  720019, 1430028, 2840012, 5680091, 11360193, 22720481, 45440912,
  90881891, 181763801, 363527482, 727054912, 1454109825,
  2908219648, 5816439297, 11632878594, 23265757188, 46531514376
]
c = 49832719451

Recover the binary message m.
```

**Solve template:**

```python
# SageMath
from sage.all import Matrix, ZZ, Integer

a = [
    14843, 19031, 28432, 37519, 62018, 100451, 190234, 369821,
    720019, 1430028, 2840012, 5680091, 11360193, 22720481, 45440912,
    90881891, 181763801, 363527482, 727054912, 1454109825,
    2908219648, 5816439297, 11632878594, 23265757188, 46531514376
]
c = 49832719451
n = len(a)

# ── Your LLL construction here ────────────────────────────────────────────────
# Hint: The standard Merkle-Hellman embedding (Day 588):
# Build (n+1) × (n+1) matrix, embed 2*a_i in the last column,
# set last row to -(2*c - 1), run LLL, find row with all entries ∈ {-1, +1}

# ── Solution ──────────────────────────────────────────────────────────────────
N_scale = 1 << (n.bit_length())
M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 1
    M[i, n] = 2 * a[i]
M[n, n] = -(2 * c - 1)

L = M.LLL()
for row in L:
    bits = [int(row[i]) for i in range(n)]
    if all(b in (1, -1) for b in bits):
        message = [1 if b == 1 else 0 for b in bits]
        # Verify
        if sum(m * ai for m, ai in zip(message, a)) == c:
            print(f"[+] Message: {''.join(map(str, message))}")
            break
```

**Flag format:** `FLAG{binary_string_as_hex}`

---

## Problem B — "Partial Exponent" (Coppersmith / Known High Bits)

**Difficulty:** Intermediate | **Estimated:** 75 min

**Prompt:**
```
RSA parameters (e=3):
  N = 117731086835239760993093895538698039890024695804285088808720
      73827249601041329082093960174617919948697024937478543009341
      (512-bit modulus)
  e = 3
  c = <computed from unknown m>

You know the top 160 bits of m:
  m_high = 0xDEADBEEF_CAFEBABE_12345678_90ABCDEF_FEDCBA98

Recover m completely and find the hidden flag in the decrypted plaintext.
The plaintext format is: <m_high_bits><FLAG_IN_ASCII><padding>
```

```python
# SageMath solve template
from sage.all import ZZ, Zmod, PolynomialRing, Integer, power_mod

N = Integer("117731086835239760993093895538698039890024695804285088808720"
            "73827249601041329082093960174617919948697024937478543009341")
e = 3
# c is given in the challenge (omitted here — add actual c when running)
c = Integer("CHALLENGE_CIPHERTEXT_GOES_HERE")

m_high_bits = Integer(0xDEADBEEFC AFEBABE1234567890ABCDEFFEDCBA98)
unknown_bits = 512 - 160   # Bottom 352 bits unknown

PR = PolynomialRing(Zmod(N), 'x')
x  = PR.gen()

f = (m_high_bits * Integer(2 ** unknown_bits) + x) ** e - c
# Bound: unknown is 352 bits, need < N^(1/3) ≈ 171 bits for e=3
# This may FAIL: 352 > 171. Adjust m_high to know more bits.
# Solution: This is intentionally challenging — if bound too large,
# use structural constraints (padding format) to narrow the unknown.
roots = f.small_roots(X=Integer(2 ** unknown_bits), beta=1.0, epsilon=0.03)
if roots:
    m_rec = int(m_high_bits) * (2 ** unknown_bits) + int(roots[0])
    print(f"[+] m = {m_rec}")
    print(f"[+] As text: {m_rec.to_bytes(64, 'big')}")
```

**Note:** The bound exceeds N^(1/3) — a deliberate difficulty. To solve:
look at the plaintext format. If there is padding structure (e.g., fixed
suffix bytes), embed it to reduce the unknown to < 171 bits.

---

## Problem C — "Nonce Hunter" (HNP / ECDSA)

**Difficulty:** Advanced | **Estimated:** 90 min

**Prompt:**
```
A signing service uses secp256k1. The implementation has a bug:
all nonces k have their top 6 bits set to 0b000000.
You can request up to 200 signatures.
Public key Q is provided.
Recover the private key d and sign the target message:
  target = "authorize:transfer:9999999"
```

```python
# Solve template
# 1. Collect signatures (simulated — use the oracle from Day 594)
# 2. Build HNP lattice (Day 593-594)
# 3. Run LLL
# 4. Verify d, forge signature

from sage.all import Matrix, ZZ, Integer
import hashlib, ecdsa

Q_GROUP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BIAS    = 6

# ── Load your collected signatures here ──────────────────────────────────────
# sigs = [(r1, s1, h1), (r2, s2, h2), ...]
# (Collect from the oracle service: GET /sign?msg=... returns {r, s})

# ── HNP Lattice ───────────────────────────────────────────────────────────────
def run_hnp_attack(sigs, q, bias):
    n   = len(sigs)
    q_i = Integer(q)
    B   = q_i >> bias
    ts  = [Integer(r) * Integer(s).inverse_mod(q_i) % q_i for r, s, h in sigs]
    us  = [Integer(h) * Integer(s).inverse_mod(q_i) % q_i for r, s, h in sigs]
    M   = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        M[i, i] = q_i
    for i in range(n):
        M[n, i]   = ts[i]
        M[n+1, i] = us[i]
    M[n, n]     = Integer(1)
    M[n+1, n+1] = B
    L = M.LLL()
    for row in L:
        for sign in [1, -1]:
            d_cand = int(sign * row[n]) % int(q_i)
            if d_cand == 0:
                continue
            # Verify against first sig
            r0, s0, h0 = sigs[0]
            k0 = (h0 + d_cand * r0) * pow(int(s0), -1, int(q_i)) % int(q_i)
            if k0 < int(B):
                return d_cand
    return None

# d_recovered = run_hnp_attack(sigs, Q_GROUP, BIAS)
# if d_recovered:
#     sk = ecdsa.SigningKey.from_secret_exponent(d_recovered, curve=ecdsa.SECP256k1)
#     sig = sk.sign(b"authorize:transfer:9999999", hashfunc=hashlib.sha256)
#     print(f"[+] Forged sig: {sig.hex()}")
print("Collect signatures from oracle → fill sigs → run run_hnp_attack()")
```

---

## Problem D — "Small Roots" (Coppersmith CTF Standard)

**Difficulty:** Intermediate | **Estimated:** 45 min

**Prompt:**
```
The flag was encrypted as: c = flag^65537 mod N
  N = 2^512 random prime product
  e = 65537

BUT: the flag was padded as flag = 0xDEAD_BEEF_<36_unknown_bytes>_FEED
Top 4 bytes and bottom 2 bytes are known.
N is 512-bit. Flag is 512-bit.
Unknown middle: 36 bytes = 288 bits.

N^(1/e) for e=65537 is tiny. Can Coppersmith work here?

Hint: It can't directly for e=65537. But the unknown is 288 bits,
which is much less than N^(1/2) = 256 bits... wait. Is there another approach?

Think: if the flag is in a known format, maybe you don't need Coppersmith.
Maybe the flag space is small enough to brute-force — or there's a structural
shortcut. Describe your approach.
```

**Teaching note:** This problem deliberately tests whether the student
reaches for the right tool. Coppersmith requires unknown < N^(1/e). For
e=65537, unknown must be < 512/65537 ≈ 0.008 bits — impossible. The correct
approach: notice that 36 unknown bytes = 2^288 search space — too large.
But if the flag has more structure (it's printable ASCII), the search
space is ~95^36 ≈ 2^236 — still too large. The real solution: look for
a smarter reduction (e.g., the flag follows a CTF pattern like
`FLAG{...}` where the braces are at known positions, reducing the
unknown to the flag content only).

```python
# Meta-solve: structural analysis
known_prefix = b"\xDE\xAD\xBE\xEF"
known_suffix = b"\xFE\xED"
# Flag format: FLAG{...} → ASCII printable, 36 bytes inner
# If flag = "FLAG{" + 31 char + "}", padding is deterministic
flag_prefix = b"FLAG{"
flag_suffix = b"}"
# Total unknown: 31 ASCII chars = 31 * 7 bits ≈ 217 bits (still large)
# Further: CTF flags use hexadecimal or lowercase letters → 36 choices per byte
# 36^31 ≈ 2^160 — approaching feasibility with targeted search
# Or: use meet-in-the-middle on the 31 chars split as 15+16
print("This problem tests problem-space analysis, not LLL.")
print("Coppersmith fails for e=65537. Consider: what IS the actual unknown?")
```

---

## Sprint Scoring

| Problem | Points | Time Limit | Bonus |
|---|---|---|---|
| A — Merkle-Hellman | 20 | 60 min | +5 if under 30 min |
| B — Coppersmith | 30 | 75 min | +10 if flag found |
| C — HNP | 35 | 90 min | +5 if forged sig verified |
| D — Structural Analysis | 15 | 45 min | +5 if approach is correct |
| **Total** | **100** | **4h 30m** | **+25** |

**Pass criterion:** ≥ 60 points. If below 60, identify which lattice concept
needs reinforcement and revisit the corresponding theory day.

```
Your score:
  A: _____ / 25    Time: _____
  B: _____ / 40    Time: _____
  C: _____ / 40    Time: _____
  D: _____ / 20    Time: _____
  Total: _____ / 125
```

---

## Key Takeaways

1. **Problem A** (Merkle-Hellman): The embedding trick is mechanical. If you
   took more than 30 minutes, the block was the lattice construction, not the
   concept. Drill the embedding until it is reflexive.
2. **Problem B** (Coppersmith): Knowing the bound is the skill. Coppersmith
   fails when the unknown exceeds N^(1/e). Recognising this and pivoting to
   structural analysis is what separates a cryptographer from a tool user.
3. **Problem C** (HNP): This is the real-world attack. If you scored here,
   you are ready to work on actual ECDSA implementations in production systems.
4. **Problem D**: The lesson is meta. Not every crypto challenge needs a
   lattice. Some need careful problem decomposition.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q601.1, Q601.2 …).

---

## Navigation

← Previous: [Day 600 — Milestone 600](DAY-0600-Milestone-600.md)
→ Next: [Day 602 — Crypto CTF Sprint Day 5](DAY-0602-Crypto-CTF-Sprint-Day-5.md)
