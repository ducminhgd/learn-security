---
title: "LLL Lab — Breaking Merkle-Hellman and Solving SVP CTF Challenges"
tags: [cryptography, lattice, LLL, Merkle-Hellman, knapsack, CTF, SageMath,
  SVP, lab, hands-on, module-09-crypto-02]
module: 09-Crypto-02
day: 588
prerequisites:
  - Day 587 — LLL Algorithm
  - SageMath installed (or available via Docker)
related_topics:
  - Coppersmith's Method (Day 589)
  - Hidden Number Problem (Day 593)
---

# Day 588 — LLL Lab: Breaking Merkle-Hellman and SVP Challenges

> "Theory without a target is philosophy. Today you run LLL against something
> real: the Merkle-Hellman knapsack cryptosystem — once considered 'provably
> secure', broken in 1982 by Shamir using exactly this algorithm. Then you solve
> two CTF problems that show you the pattern. After today, every lattice CTF
> challenge will look the same to you."
>
> — Ghost

---

## Goals

Apply LLL to break the Merkle-Hellman knapsack cryptosystem, solve two
CTF-style SVP challenges, and build the muscle memory for constructing
lattices from cryptographic problems.

**Prerequisites:** Day 587 (LLL Algorithm). SageMath ≥ 9.0.
**Estimated lab time:** 4–5 hours.

---

## Lab Setup

```bash
# Option 1: SageMath via Docker (recommended for isolation)
docker run -it --rm sagemath/sagemath:latest sage

# Option 2: Install SageMath natively (Ubuntu/Debian)
sudo apt install sagemath

# Option 3: Use CoCalc (cloud, no install needed) — cocalc.com
# Create a new Sage worksheet and paste code blocks below.

# Verify LLL is available
sage: Matrix(ZZ, [[3, 1], [5, 2]]).LLL()
```

---

## Lab 1 — Breaking Merkle-Hellman Knapsack

### Background

The Merkle-Hellman knapsack cryptosystem (1978) encrypts a binary message
`m = (m_1, ..., m_n)` using a public key `a = (a_1, ..., a_n)`:

```
Ciphertext: c = sum(m_i * a_i for i in range(n))
```

The private key is a "superincreasing" sequence `w = (w_1, ..., w_n)` and
modular parameters `(q, r)` where `a_i = r * w_i mod q`. A superincreasing
sequence satisfies `w_k > sum(w_j for j < k)`, making decryption trivial.

**Shamir's attack (1982):** Construct a lattice from the public key and
ciphertext, find the short vector corresponding to `m`, read off the bits.

### The Attack

```python
#!/usr/bin/env python3
"""
Merkle-Hellman knapsack attack via LLL (Shamir 1982).

The attack constructs an (n+1) × (n+1) lattice whose shortest vector
encodes the binary plaintext bits.
"""
# Run this in a SageMath session
from sage.all import Matrix, ZZ, vector, Integer


def generate_mh_keypair(n: int):
    """Generate Merkle-Hellman keypair of size n."""
    import random
    rng = random.SystemRandom()

    # Superincreasing private key
    w = []
    total = 0
    for _ in range(n):
        wi = rng.randint(total + 1, total + 100)
        w.append(wi)
        total += wi

    # q > sum(w), r coprime to q
    q = rng.randint(total + 1, total + 1000)
    r = rng.randint(2, q - 1)
    while gcd(r, q) != 1:
        r = rng.randint(2, q - 1)

    r_inv = Integer(r).inverse_mod(q)

    # Public key
    a = [(r * wi) % q for wi in w]

    return {"w": w, "q": q, "r": r, "r_inv": r_inv, "a": a}


def mh_encrypt(a: list[int], message_bits: list[int]) -> int:
    """Encrypt binary message using public key a."""
    return sum(b * ai for b, ai in zip(message_bits, a))


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def attack_merkle_hellman(a: list[int], c: int) -> list[int] | None:
    """
    LLL attack on Merkle-Hellman.

    Construct the lattice:
      L = | I_n    a |
          | 0   c-N/2|

    where I_n is the n×n identity and the last column is the public key.
    A short vector in this lattice encodes (m - 1/2) where m ∈ {0,1}^n.

    Reference: Lagarias & Odlyzko (1985), Shamir's original 1982 attack.
    """
    n = len(a)
    N = 1 << (n.bit_length())   # A power of 2 > n as weighting factor

    # Build the lattice matrix (n+1) × (n+1)
    # Rows 0..n-1: [e_i | a_i] where e_i is the i-th unit vector scaled by N
    # Row n:       [0..0 | c]
    # We embed c in the last column to create the target distance
    M = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        M[i][i] = 1          # Identity block
        M[i][n] = a[i]       # Public key column
    M[n][n] = -c             # Ciphertext negated in last entry

    # Add 1/2 trick: multiply last column by 2 and treat as Z lattice
    for i in range(n + 1):
        M[i][n] *= 2
    M[n][n] += 1             # 2c - 1, so the short vector maps to {-1, +1}^n

    mat = Matrix(ZZ, M)
    reduced = mat.LLL()

    # The shortest vector should be (±1, ..., ±1, 0) or similar
    # Convert ±1 → bit (1→1, -1→0)
    for row in reduced:
        row_list = list(row)
        if row_list[-1] == 0:   # Last entry should be 0
            bits = [(1 if x == 1 else 0) for x in row_list[:-1]]
            if all(b in (0, 1) for b in bits):
                return bits
        if row_list[-1] == 0:
            bits = [(1 if x == -1 else 0) for x in row_list[:-1]]
            if all(b in (0, 1) for b in bits):
                return bits
    return None


# ── Run the attack ─────────────────────────────────────────────────────────────
import random
rng = random.SystemRandom()

N_BITS = 20   # Start with 20 bits; increase to test LLL limits
message = [rng.randint(0, 1) for _ in range(N_BITS)]
keys    = generate_mh_keypair(N_BITS)
c       = mh_encrypt(keys["a"], message)

print(f"[*] n = {N_BITS} bits")
print(f"[*] Message  : {''.join(map(str, message))}")
print(f"[*] Ciphertext: {c}")

recovered = attack_merkle_hellman(keys["a"], c)
if recovered and recovered == message:
    print(f"[+] Recovered: {''.join(map(str, recovered))}")
    print("[+] Attack succeeded!")
else:
    print(f"[!] Recovered: {recovered}")
    print("[!] Attack failed — try again or increase LLL quality")
```

### Notes on the Construction

The key insight is the **embedding trick**: we build a lattice where the
target vector `(m_1 - 1/2, ..., m_n - 1/2, 0)` is short precisely because
all `m_i ∈ {0, 1}`, so each component is ±1/2 — much shorter than random
lattice vectors which have components of order `||a||`.

---

## Lab 2 — SVP CTF Challenge: "Find the Hidden Combination"

This is a standard CTF pattern. A server gives you a set of "hints" that are
linear combinations of a secret vector with small coefficients:

```
hint_i = sum(secret_j * c_{ij}) + small_noise
```

Your job: construct a lattice, run LLL, read the secret.

```python
# SageMath: solve a hidden combination problem
from sage.all import Matrix, ZZ, vector

# Secret vector (what we want): small integers in [-5, 5]
SECRET = vector(ZZ, [3, -2, 4, 1, -3, 2, -4, 1, 3, -1])
n = len(SECRET)

# "Public" matrix A — large random coefficients (this is what the server gives)
import random
rng = random.SystemRandom()
A = Matrix(ZZ, [[rng.randint(1, 10**6) for _ in range(n)]
                for _ in range(n)])

# Hints: A * SECRET (in a real CTF, the server gives you these, not A directly)
hints = A * SECRET

print(f"Secret:  {list(SECRET)}")
print(f"Hints:   {list(hints)[:3]}... (server gives you these)")

# ── Attack ────────────────────────────────────────────────────────────────────
# Build lattice: rows = columns of A, last row = -hints, scaled
# The vector (SECRET | 1) maps to (A*SECRET - hints | 1) = (0 | 1)
# which is short if SECRET is short.

# Embed A as columns, add -hints as extra column
M = A.augment(Matrix(ZZ, n, 1, list(-hints)))
# Add a row for the scaling weight
bottom = Matrix(ZZ, 1, n + 1, [0] * n + [10**7])
M = M.stack(bottom)

L = M.LLL()
print(f"\nLLL first rows (looking for the secret):")
for row in L[:3]:
    print(f"  {list(row)}")

# The short row encodes the secret (possibly scaled)
# Check each row
for row in L:
    if row[-1] != 0:
        candidate = vector(ZZ, list(row[:-1]))
        scale = row[-1]
        if abs(scale) == 10**7:
            s = candidate * (1 if scale > 0 else -1) // (10**7 // 10**7)
            # normalize
        else:
            continue
        # Try direct match
        if candidate == SECRET or candidate == -SECRET:
            print(f"\n[+] Recovered secret: {list(candidate)}")
            break
```

---

## Lab 3 — CTF Challenge: "Broken Knapsack" (Full Problem)

```
Challenge card:
  Category: Crypto
  Difficulty: Intermediate
  Scenario: A legacy authentication system encodes user roles as a bitmask
  and encrypts it using a "provably secure" Merkle-Hellman scheme.
  Given the public key and your encrypted role token, forge an admin token.

  Flag: FLAG{lll_breaks_superincreasing_knapsack_every_time}
```

**Setup** (Docker Compose):

```yaml
version: "3.9"
services:
  challenge:
    image: python:3.12-alpine
    volumes:
      - ./server.py:/app/server.py
    command: python /app/server.py
    ports:
      - "4000:4000"
    networks:
      - lab
networks:
  lab:
    driver: bridge
```

**server.py** (the challenge target — do not look at this as the student):

```python
#!/usr/bin/env python3
"""
Merkle-Hellman Auth Server — challenge target.
Exposes: GET /pubkey, POST /verify?token=<hex>
Returns 'Welcome admin!' if the decrypted role bitmask has bit 0 set.
"""
import http.server
import json
import random

rng = random.SystemRandom()
N   = 25

def _superincreasing(n: int) -> list[int]:
    w, total = [], 0
    for _ in range(n):
        wi = rng.randint(total + 1, total + 50)
        w.append(wi); total += wi
    return w

w   = _superincreasing(N)
q   = sum(w) + rng.randint(100, 500)
r   = rng.randint(2, q - 1)
while __import__("math").gcd(r, q) != 1:
    r = rng.randint(2, q - 1)
a   = [(r * wi) % q for wi in w]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/pubkey":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"a": a, "n": N}).encode())
    def do_POST(self):
        if self.path.startswith("/verify"):
            qs     = self.path.split("token=")[-1]
            c      = int(qs, 16)
            r_inv  = pow(r, -1, q)
            c_prime = (c * r_inv) % q
            bits, total = [], 0
            for wi in reversed(w):
                if total + wi <= c_prime:
                    bits.insert(0, 1); total += wi
                else:
                    bits.insert(0, 0)
            self.send_response(200)
            self.end_headers()
            msg = b"Welcome admin!" if bits[0] == 1 else b"Access denied."
            self.wfile.write(msg)

http.server.HTTPServer(("0.0.0.0", 4000), Handler).serve_forever()
```

**Solve script skeleton** (fill in the LLL attack):

```python
#!/usr/bin/env python3
"""Exploit: forge admin token for the Merkle-Hellman server."""
import requests
from sage.all import Matrix, ZZ

BASE = "http://localhost:4000"

# 1. Fetch public key
resp = requests.get(f"{BASE}/pubkey")
data = resp.json()
a, n = data["a"], data["n"]
print(f"[*] Public key ({n} elements): {a[:5]}...")

# 2. Target: message with bit 0 = 1 (admin role)
#    We want m = (1, 0, 0, ..., 0)
target_c = a[0]   # m_0 = 1, all others 0: c = a[0] * 1 = a[0]
print(f"[*] Forged ciphertext (just a[0]): {target_c}")

# 3. Verify admin access
token = hex(target_c)[2:]
resp  = requests.post(f"{BASE}/verify?token={token}")
print(f"[+] Server response: {resp.text}")

# ── Alternative: use LLL to verify the forged ciphertext decrypts correctly ──
# (As a sanity check — in real CTF you wouldn't have the private key)
# ... attack code here (from Lab 1 above) ...
print("\nFLAG: FLAG{lll_breaks_superincreasing_knapsack_every_time}")
```

---

## Self-Assessment

```
[ ] 1. In Lab 1, change N_BITS to 50. Does the attack still succeed?
        At what dimension does your implementation begin to fail?
        (Hint: standard LLL breaks around n=100 for random knapsacks;
        the embedding quality is critical.)

[ ] 2. The embedding trick used 2×a_i columns and the -2c+1 trick.
        Why is the factor of 2 needed? What happens to the short vector
        without it?

[ ] 3. In the CTF challenge above, the forged ciphertext was just a[0].
        This works because m=(1,0,...,0) is valid. Describe the general
        approach: given the LLL output for a specific c, how do you forge
        a c for an arbitrary target m?

[ ] 4. What does it mean for a knapsack to be "superincreasing"?
        Why does superincreasing make decryption easy but also make
        LLL attacks feasible? (Hint: the ratio between consecutive elements.)
```

---

## Key Takeaways

1. **Merkle-Hellman was considered "provably secure" in 1978.** Shamir broke it
   in 1982 using LLL. This is a pattern: "proven security" in cryptography is
   only as strong as the hardness assumption it relies on.
2. **The embedding trick is the core skill.** Every lattice attack on a crypto
   system involves embedding the secret into a lattice where it becomes the
   short vector. The algorithm (LLL) is fixed; the embedding is the art.
3. **LLL is fast enough for n ≤ 150 in seconds on a laptop.** For larger n,
   use BKZ or stronger algorithms. SageMath's `.LLL()` is fast fplll underneath.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q588.1, Q588.2 …).

---

## Navigation

← Previous: [Day 587 — LLL Algorithm](DAY-0587-LLL-Algorithm.md)
→ Next: [Day 589 — Coppersmith's Method](DAY-0589-Coppersmith-Method.md)
