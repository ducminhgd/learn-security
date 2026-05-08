---
title: "MT19937 State Recovery — Cloning the Mersenne Twister"
tags: [cryptography, PRNG, MT19937, Mersenne-Twister, state-recovery,
  untemper, session-tokens, prediction, CWE-338, module-09-crypto-02]
module: 09-Crypto-02
day: 595
prerequisites:
  - Day 573 — Cryptopals CTF Day 3 (MT19937 clone challenge basics)
  - Basic understanding of bitwise operations (XOR, shift, AND)
related_topics:
  - PRNG Attack Lab (Day 596)
  - HNP Lab (Day 594)
  - LCG and LFSR Attacks (Day 599)
---

# Day 595 — MT19937 State Recovery: Cloning the Mersenne Twister

> "MT19937 is the gold standard PRNG for statistical simulation. It has a
> 19937-bit state, a 2^19937 period, and passes every Diehard statistical test.
> It is cryptographically worthless. Given 624 consecutive outputs, you clone
> the state completely and predict every future output with 100% accuracy.
> Every language runtime uses it as the default random() call. Every web
> framework that ever seeded a session token with random() is broken."
>
> — Ghost

---

## Goals

Understand the MT19937 internal state structure and the temper/untemper
transform, implement a state recovery attack from 624 consecutive outputs,
and clone the RNG to predict future values.

**Prerequisites:** Day 573 (MT19937 Cryptopals clone challenge).
**Estimated study time:** 3–4 hours.

---

## Stage 1 — MT19937 Internals

### State

MT19937 maintains a state array of **624 32-bit integers** plus a position index.
The full state space is 624 × 32 = 19968 bits (slightly more than the 19937-bit
period, hence the name).

### The Twist

Every 624 outputs, the state is "twisted" — all 624 words are mixed:

```python
def twist(state: list[int]) -> list[int]:
    """Apply the twist recurrence to regenerate the state."""
    N, M  = 624, 397
    UPPER = 0x80000000   # Most significant bit
    LOWER = 0x7FFFFFFF   # Lower 31 bits
    MATRIX_A = 0x9908B0DF

    new_state = state[:]
    for i in range(N):
        x  = (state[i] & UPPER) | (state[(i + 1) % N] & LOWER)
        xA = x >> 1
        if x & 1:
            xA ^= MATRIX_A
        new_state[i] = state[(i + M) % N] ^ xA
    return new_state
```

### The Temper Transform

Each output `y` is the state word `s[index]` passed through a **temper
transform** — a series of XOR-shift-AND operations that improve statistical
quality:

```python
def temper(s: int) -> int:
    """Apply the MT19937 temper transform to state word s."""
    y  = s
    y ^= (y >> 11)
    y ^= (y << 7)  & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF
```

Each of these four operations is **invertible** — this is the key to the attack.

---

## Stage 2 — The Untemper Transform

To recover the state word `s` from an output `y = temper(s)`, we reverse
each step in the opposite order:

```python
def untemper(y: int) -> int:
    """
    Invert the MT19937 temper transform.
    Given output y, return the original state word s.
    """
    # Step 4 inverse: y ^= (y >> 18)
    # y18 = y ^ (y >> 18)   — only top 18 bits of y matter for the XOR
    y ^= (y >> 18)

    # Step 3 inverse: y ^= (y << 15) & 0xEFC60000
    # << 15 means only the top 17 bits of the shifted value matter
    y ^= (y << 15) & 0xEFC60000

    # Step 2 inverse: y ^= (y << 7) & 0x9D2C5680
    # Requires iterative recovery (each 7 bits computed from previous)
    b = 0x9D2C5680
    tmp = y
    for _ in range(4):   # 4 iterations cover all 32 bits
        tmp = y ^ ((tmp << 7) & b)
    y = tmp & 0xFFFFFFFF

    # Step 1 inverse: y ^= (y >> 11)
    # Similar iterative recovery
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    y = tmp & 0xFFFFFFFF

    return y


# Verify untemper is the inverse of temper
import random
rng = random.Random(42)
for _ in range(1000):
    s = rng.getrandbits(32)
    assert untemper(temper(s)) == s, f"untemper(temper({s})) != {s}"
print("[+] untemper verified for 1000 random values")
```

---

## Stage 3 — State Recovery Attack

Given 624 consecutive 32-bit outputs, recover the full MT19937 state:

```python
#!/usr/bin/env python3
"""
MT19937 state recovery attack.
Observe 624 outputs → clone the RNG → predict all future outputs.
"""
from __future__ import annotations
import random


def untemper(y: int) -> int:
    """Inverse of MT19937 temper transform (from Stage 2)."""
    y ^= (y >> 18)
    y ^= (y << 15) & 0xEFC60000
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp & 0xFFFFFFFF
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    return tmp & 0xFFFFFFFF


def clone_mt19937(outputs: list[int]) -> random.Random:
    """
    Clone MT19937 state from 624 consecutive 32-bit outputs.
    Returns a cloned Random object that will produce identical future values.
    """
    if len(outputs) < 624:
        raise ValueError(f"Need 624 outputs, got {len(outputs)}")
    # Recover state array by untemper-ing each output
    state = [untemper(y) for y in outputs[:624]]
    # Reconstruct the Random object internals
    # Python's random.Random state format: (version, state_tuple, None)
    # state_tuple = (mt_state_words..., index)
    cloned = random.Random()
    cloned.setstate((3, tuple(state) + (624,), None))
    return cloned


# ── Demo ──────────────────────────────────────────────────────────────────────

# Target RNG (unknown seed — attacker cannot see this)
target_rng = random.Random()
target_rng.seed()   # Random system seed

# Attacker observes 624 consecutive 32-bit outputs
observed = [target_rng.getrandbits(32) for _ in range(624)]
print(f"[*] Observed 624 outputs: {observed[:4]}... (first 4 shown)")

# Clone
cloned_rng = clone_mt19937(observed)

# Predict the next 10 outputs
print("\n[*] Comparing next 10 outputs:")
all_match = True
for i in range(10):
    actual    = target_rng.getrandbits(32)
    predicted = cloned_rng.getrandbits(32)
    match     = actual == predicted
    all_match = all_match and match
    print(f"  Output {i+625}: actual={actual:10d}, predicted={predicted:10d} "
          f"{'✓' if match else '✗'}")

print(f"\n[+] All predictions correct: {all_match}")
print("[+] MT19937 cloned successfully — RNG is fully compromised")
```

---

## Stage 4 — Real-World Impact

### Session Token Prediction

```python
#!/usr/bin/env python3
"""
Simulate a web app that generates session tokens using MT19937.
Attack: observe 624 tokens → predict the next one.
"""
import random
import hashlib

# Web app's token generator (vulnerable)
class VulnerableSessionManager:
    def __init__(self):
        self._rng = random.Random()   # Uses MT19937 with system seed

    def new_session_token(self, user_id: int) -> str:
        """Generate a session token. DO NOT use in production."""
        rand_bits = self._rng.getrandbits(32)
        token_raw = f"{user_id}:{rand_bits}"
        return hashlib.md5(token_raw.encode()).hexdigest()

    def get_random_bits(self) -> int:
        """Internal — exposed for demo to simulate observation."""
        return self._rng.getrandbits(32)


# Attacker observes 624 token-generation calls (perhaps via /forgot-password
# or /csrf-token endpoints that use the same PRNG)
app    = VulnerableSessionManager()
# Observe 624 raw PRNG outputs (attacker needs raw bits, not MD5)
# In practice: PRNG output exposed via predictable anti-CSRF tokens,
# password reset tokens, or other weakly seeded random values.
observed = [app.get_random_bits() for _ in range(624)]

# Clone the RNG
cloned = clone_mt19937(observed)

# Predict the next session token for user 42
next_rand_actual    = app.get_random_bits()
next_rand_predicted = cloned.getrandbits(32)

actual_token    = hashlib.md5(f"42:{next_rand_actual}".encode()).hexdigest()
predicted_token = hashlib.md5(f"42:{next_rand_predicted}".encode()).hexdigest()

print(f"[*] Actual next token:    {actual_token}")
print(f"[*] Predicted next token: {predicted_token}")
print(f"[+] Prediction correct: {actual_token == predicted_token}")
print("\nImpact: Attacker hijacks any session created after observation window.")
```

### Real CVEs and Incidents

| Case | PRNG | Impact |
|---|---|---|
| PHP `rand()` / `mt_rand()` (pre-8.3) | MT19937 | Session token prediction |
| Python `random` module in Flask secret | MT19937 | Flask session forgery |
| Ruby `rand` (pre-1.9) | MT19937 | Session ID prediction |
| Node.js `Math.random()` (V8) | Modified MT | Predictable in some versions |
| Java `java.util.Random` | LCG, not MT | See Day 596 |

---

## Key Takeaways

1. **MT19937 is NOT cryptographically secure.** 624 outputs fully reveal the
   state. Python's `random`, PHP's `mt_rand()`, and Ruby's `rand` all use it.
   Never use these for security-sensitive values.
2. **The untemper transform is mechanical.** Each XOR-shift operation has a
   straightforward inverse. Once you understand the pattern, untemper is
   a 20-line function.
3. **The attack requires exactly 624 consecutive outputs.** In practice, you
   may see partial or non-consecutive outputs. The harder variant
   (partial-state recovery) requires more samples and statistical analysis.
4. **Use `secrets` module or `os.urandom()`.** These call the OS CSPRNG
   (e.g., /dev/urandom backed by ChaCha20 on modern Linux). They are not
   predictable from outputs.

---

## Exercises

```
1. Implement the untemper function without using loops — using only
   bitwise operations. Verify it is equivalent.

2. What happens if you only observe 620 outputs (not 624)?
   Can you still recover the state? What additional information would help?

3. PHP's mt_rand() uses a modified MT19937 with a different temper function.
   Research the differences. Can the same untemper approach be adapted?

4. Flask uses a "secret key" to sign session cookies. If a developer
   generates the secret key with `random.random()` or `random.getrandbits(128)`,
   demonstrate how observing the session cookie values could let an attacker
   forge admin sessions.
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q595.1, Q595.2 …).

---

## Navigation

← Previous: [Day 594 — HNP Lab](DAY-0594-HNP-Lab.md)
→ Next: [Day 596 — PRNG Attack Lab](DAY-0596-PRNG-Attack-Lab.md)
