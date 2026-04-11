---
title: "Randomness and PRNG Attacks"
tags: [foundation, cryptography, PRNG, CSPRNG, randomness, seed-guessing,
       session-token, predictable-token, math-rand, crypto-rand]
module: 01-Foundation-04
day: 35
related_topics:
  - Password Hashing and Cracking (Day 034)
  - Session Management and Broken Session Lab (Day 040)
  - Password Reset Flaws (Day 046)
---

# Day 035 — Randomness and PRNG Attacks

## Goals

By the end of this lesson you will be able to:

1. Explain the difference between a PRNG and a CSPRNG.
2. Identify code patterns that use insecure random number generators for
   security-sensitive values (tokens, IDs, nonces).
3. Predict the output of a seeded linear congruential generator (LCG).
4. Demonstrate a seed-guessing attack against a time-seeded token generator.
5. Explain the entropy sources used by OS-level CSPRNGs.
6. List the correct random generation function for each major language.

---

## Prerequisites

- [Day 034 — Password Hashing and Cracking](DAY-0034-Password-Hashing-and-Cracking.md)

---

## Main Content — Part 1: PRNG vs CSPRNG

### 1. Definitions

**PRNG (Pseudo-Random Number Generator):**
- Deterministic algorithm that produces a sequence from a seed.
- Given the seed, the full sequence is reproducible.
- Examples: Mersenne Twister (Python `random`, Java `java.util.Random`),
  LCG (C `rand()`), Xorshift.
- **Not suitable for security.** Fast, uniform distribution, but predictable
  if the seed is known or guessable.

**CSPRNG (Cryptographically Secure PRNG):**
- Uses entropy from the OS: hardware timing jitter, interrupt sources,
  thermal noise.
- Output is computationally indistinguishable from random.
- Even with knowledge of previous outputs, the next output is unpredictable.
- Examples: `/dev/urandom` (Linux), `CryptGenRandom` (Windows),
  `os.urandom()` (Python), `crypto.randomBytes()` (Node.js).

---

### 2. The Linear Congruential Generator (LCG)

The simplest PRNG — used in many standard libraries:

```
X_{n+1} = (a × X_n + c) mod m

Where:
  a = multiplier
  c = increment
  m = modulus
  X_0 = seed
```

**Predicting an LCG:**

```python
# Simulated C library rand() (simplified LCG)
a, c, m = 1103515245, 12345, 2**31

def lcg(seed):
    state = seed
    while True:
        state = (a * state + c) % m
        yield state

# If attacker knows one output:
known_output = next(lcg(time.time_ns()))
# Recover next output given a (the state IS the output in this case):
# next_output = (a * known_output + c) % m
```

**Real-world impact:** PHP's `rand()` (before PHP 7) used a similar LCG.
Password reset tokens generated with `rand()` were predictable from the
server's time and any observed output.

---

### 3. Mersenne Twister — Python's `random`

Python's `random` module uses Mersenne Twister (MT19937):

```python
import random
random.seed(42)
print(random.random())   # Always 0.6394... when seeded with 42
```

**State recovery attack:**
After observing 624 consecutive 32-bit outputs, the full internal state
of MT19937 can be recovered using the "untemper" operation. Every
subsequent output can be predicted.

**The `randcrack` library:**

```python
from randcrack import RandCrack

rc = RandCrack()

# Observe 624 × 32-bit outputs:
for _ in range(624):
    rc.submit(random.getrandbits(32))

# Now predict future values:
predicted = rc.predict_getrandbits(32)
actual = random.getrandbits(32)
print(predicted == actual)   # True
```

---

## Main Content — Part 2: Attack Scenarios

### 4. Seed-Guessing Attack — Time-Seeded Tokens

A common vulnerability pattern:

```python
import random, time

def generate_reset_token():
    random.seed(int(time.time()))   # Seeded with Unix timestamp
    return random.randint(0, 999999)

token = generate_reset_token()
# Token: 6-digit number, seeded with the current second
```

**Attack:**

```python
import random, time

target_time = int(time.time())  # We know approximately when the token was generated
# Try ±60 seconds around our estimate:
for t in range(target_time - 60, target_time + 60):
    random.seed(t)
    candidate = random.randint(0, 999999)
    if candidate == 372841:  # The token we received
        print(f"Seed found: {t}")
        # Now generate next tokens for this victim
```

**Variant — sequential ID as seed:**

```javascript
// Node.js (insecure)
function generateSessionToken(userId) {
    // Seeds with userId — predictable!
    Math.seedrandom(userId);
    return Math.random().toString(36).slice(2);
}
```

---

### 5. Real-World Vulnerable Pattern Recognition

**Language-specific danger zones:**

```python
# INSECURE — Python
import random
token = random.token_hex(16)              # random module = PRNG
session_id = str(random.randint(1, 2**64))
reset_token = "".join(random.choices("abcdef0123456789", k=32))

# SECURE — Python
import secrets
token = secrets.token_hex(16)             # CSPRNG
session_id = secrets.token_urlsafe(32)
```

```javascript
// INSECURE — Node.js
const token = Math.random().toString(36).slice(2);

// SECURE — Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

```go
// INSECURE — Go
import "math/rand"
token := rand.Int63()          // Seeded, predictable

// SECURE — Go
import "crypto/rand"
import "math/big"
n, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil))
```

```php
// INSECURE — PHP
$token = md5(rand());               // LCG rand() + MD5
$token = md5(uniqid());             // time-based

// SECURE — PHP
$token = bin2hex(random_bytes(32)); // CSPRNG
```

---

### 6. Entropy Sources and `/dev/urandom`

**Linux entropy sources:**
- Hardware events: keystrokes, mouse movement, disk I/O timing.
- Interrupt timing jitter.
- Hardware RNG (e.g. Intel RDRAND via `rdseed`).
- Clock skew.

**`/dev/random` vs `/dev/urandom`:**
- `/dev/random` (old behaviour): Blocks when entropy pool is "empty."
  Caused performance issues on headless servers.
- `/dev/urandom`: Never blocks; uses a CSPRNG seeded from the pool.
  On Linux 4.8+, `/dev/urandom` and `/dev/random` use the same CSPRNG.
- **Use `/dev/urandom`** (or `getrandom(2)` syscall directly).

**Early-boot entropy issue:** VMs that start from a snapshot or containers
with no hardware entropy sources can have low entropy at startup. The first
TLS key generated in this state may be weaker. Solutions: `haveged` daemon,
hardware RNG (`--device /dev/hwrng`), or `virtio-rng` in VMs.

---

## Key Takeaways

1. **`math.random()`, `rand()`, Python's `random` = PRNG = predictable.**
   Never use them for tokens, session IDs, nonces, salts, or any
   security-sensitive value.
2. **A 6-digit PIN with time-based seeding can be predicted in 120 tries.**
   The attacker just needs to know approximately when the token was generated
   (the email header timestamp is enough).
3. **Mersenne Twister state can be recovered in 624 outputs.** If an app
   generates 624+ values from `random` and any of them are observable,
   all future values are predictable.
4. **Use OS-level CSPRNG:** `secrets` (Python), `crypto.randomBytes()`
   (Node.js), `crypto/rand` (Go), `random_bytes()` (PHP). One simple rule.
5. **Minimum token entropy: 128 bits.** A 32-byte hex token = 256 bits
   of CSPRNG output → computationally infeasible to brute-force.

---

## Exercises

### Exercise 1 — Identify the Vulnerability

For each code snippet, state: SECURE or INSECURE, and why.

```python
# A
import os, binascii
token = binascii.hexlify(os.urandom(16)).decode()

# B
import random, time
random.seed(time.time())
token = ''.join([str(random.randint(0, 9)) for _ in range(8)])

# C
import secrets
otp = secrets.randbelow(10**6)  # 6-digit OTP

# D
import hashlib, time
token = hashlib.sha256(str(time.time()).encode()).hexdigest()

# E
import uuid
session_id = str(uuid.uuid4())  # UUID4 uses os.urandom internally in Python
```

### Exercise 2 — Seed-Guessing Attack

Set up the vulnerable token generator from this lesson and build the
brute-force script. How long does it take to find the correct seed?
What if the attacker has a 5-minute window instead of 120 seconds?

### Exercise 3 — Fix the Code

Rewrite exercise B and D from Exercise 1 using `secrets`. Verify that
the outputs are not predictable by running them 1000 times and checking
for duplicates.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 034 — Password Hashing and Cracking](DAY-0034-Password-Hashing-and-Cracking.md)*
*Next: [Day 036 — Breaking Weak Cipher Lab](DAY-0036-Breaking-Weak-Cipher-Lab.md)*
