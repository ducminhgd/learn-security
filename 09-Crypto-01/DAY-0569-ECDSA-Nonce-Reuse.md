---
title: "ECDSA Nonce Reuse — Private Key Recovery from Repeated k"
tags: [cryptography, ECDSA, nonce-reuse, private-key-recovery, PS3, bitcoin,
  CWE-338, T1600, lattice, nonce, signature-scheme]
module: 09-Crypto-01
day: 569
prerequisites:
  - Day 032 — Asymmetric Encryption and RSA Attacks
  - Day 568 — Diffie-Hellman Attacks (ECC foundations)
related_topics:
  - ECDSA Lab (Day 570)
  - Diffie-Hellman Attacks (Day 568)
  - Randomness and PRNG Attacks (Day 035)
---

# Day 569 — ECDSA Nonce Reuse

> "The PlayStation 3 was a fortress. Billions of dollars in hardware, a custom
> CPU, cryptographic signing on every piece of code that ran on it. Then someone
> realised the nonce was constant. Not broken — constant. The private key fell
> out of two signatures and a pencil."
>
> — Ghost

---

## Goals

- Understand the ECDSA signing algorithm and the role of the nonce `k`.
- Derive the private key recovery equation when `k` is reused.
- Implement the attack in Python and verify it against real signatures.
- Connect the attack to the PS3 hack (2010) and Bitcoin wallet thefts.

**Prerequisites:** Day 032 (ECC basics, key pairs), Day 035 (PRNG weaknesses).
**Estimated study time:** 3 hours.

---

## 1. Recon — How ECDSA Works

### ECDSA Signing

Given:
- Curve parameters: `(p, a, b, G, n)` — base point `G` of order `n`
- Private key: `d` (integer in `[1, n-1]`)
- Public key: `Q = d × G`
- Message: `m`

To sign:

```
1. Compute message hash: z = hash(m) truncated to n-bit length
2. Choose a random nonce:  k ∈ [1, n-1]  (must be unique per signature!)
3. Compute point:          R = k × G
4. Compute r = R.x mod n  (x-coordinate of R, modulo n)
   If r = 0, choose a new k
5. Compute s = k⁻¹ × (z + r×d) mod n
   If s = 0, choose a new k
6. Signature = (r, s)
```

### ECDSA Verification

Given signature `(r, s)`, public key `Q`, message `m`:

```
1. z = hash(m) (same truncation)
2. u₁ = z × s⁻¹ mod n
3. u₂ = r × s⁻¹ mod n
4. P  = u₁ × G + u₂ × Q
5. Valid iff P.x mod n == r
```

---

## 2. Exploit — The Nonce Reuse Equation

### The Vulnerability

If the same `k` is used for two different signatures `(r₁, s₁)` and `(r₂, s₂)`
on messages `m₁` and `m₂`:

Since `k` is the same:
```
r₁ = r₂ = R.x mod n  (same point R = k × G)
```

The two signature equations are:
```
s₁ = k⁻¹ × (z₁ + r × d) mod n
s₂ = k⁻¹ × (z₂ + r × d) mod n
```

Subtracting:
```
s₁ - s₂ = k⁻¹ × (z₁ - z₂) mod n
k = (z₁ - z₂) × (s₁ - s₂)⁻¹ mod n
```

Once `k` is known, recover `d` from either signature:
```
d = (s₁ × k - z₁) × r⁻¹ mod n
```

**Result:** Two signatures with the same `k` → full private key in two arithmetic operations.

---

## 3. Minimal Exploit

```python
#!/usr/bin/env python3
"""
ecdsa_nonce_reuse.py — recover ECDSA private key from two signatures sharing k
Uses the secp256k1 curve (Bitcoin's curve)
"""
from __future__ import annotations

import hashlib
from ecdsa import SigningKey, SECP256k1, NIST384p
from ecdsa.numbertheory import inverse_mod

# ── Setup: generate a key pair ────────────────────────────────────────────
CURVE = SECP256k1
sk    = SigningKey.generate(curve=CURVE)
vk    = sk.get_verifying_key()

d = sk.privkey.secret_multiplier   # Private key (integer) — attacker does NOT have this
n = CURVE.order                     # Curve order

# ── Sign two messages using the SAME nonce k (the bug) ───────────────────
import secrets
k_reused = secrets.randbelow(n - 1) + 1   # One nonce — should never be reused!

def sign_with_fixed_k(message: bytes, private_key_int: int,
                       k: int, curve) -> tuple[int, int]:
    """Sign deterministically with a fixed k (vulnerable)."""
    G = curve.generator
    n = curve.order
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big') % n
    R = k * G
    r = R.x() % n
    assert r != 0
    s = (inverse_mod(k, n) * (z + r * private_key_int)) % n
    assert s != 0
    return r, s

msg1 = b"Transfer 1 BTC to Alice"
msg2 = b"Transfer 10 BTC to Bob"

z1 = int.from_bytes(hashlib.sha256(msg1).digest(), 'big') % n
z2 = int.from_bytes(hashlib.sha256(msg2).digest(), 'big') % n

r1, s1 = sign_with_fixed_k(msg1, d, k_reused, CURVE)
r2, s2 = sign_with_fixed_k(msg2, d, k_reused, CURVE)

print(f"[*] Public key (hex): {vk.to_string().hex()[:32]}...")
print(f"[*] Signature 1: r={r1}, s={s1}")
print(f"[*] Signature 2: r={r2}, s={s2}")
print(f"[*] r1 == r2: {r1 == r2}")   # True — same k means same R

# ── Attack: recover k, then recover d ────────────────────────────────────
# k = (z1 - z2) / (s1 - s2) mod n

k_recovered = ((z1 - z2) * inverse_mod(s1 - s2, n)) % n

# Recover private key d from signature 1
d_recovered = ((s1 * k_recovered - z1) * inverse_mod(r1, n)) % n

print(f"\n[+] k recovered:         {k_recovered}")
print(f"[+] k actual:            {k_reused}")
print(f"[+] k match:             {k_recovered == k_reused}")
print(f"\n[+] Private key recovered: {d_recovered}")
print(f"[+] Private key actual:    {d}")
print(f"[+] Key match:             {d_recovered == d}")
# → Private key match: True
```

---

## 4. The PlayStation 3 Hack (2010)

Sony's PS3 implemented ECDSA signing for code authentication — every binary
that ran on the PS3 had to be signed by Sony's private key. The console
verified signatures against Sony's public key before execution.

Fail0verflow discovered that Sony's implementation generated the same `k` for
every signature — `k` was a hardcoded constant rather than a random value.

```
Observation: every Sony-signed binary had r values that were all equal
→ Same R = k × G → same k for every signature

Attack:
  k = (z₁ - z₂) / (s₁ - s₂) mod n   [two Sony signatures]
  d = (s₁k - z₁) / r₁ mod n

Sony's private key recovered.
Attackers could now sign arbitrary code.
PS3 jailbreaking became trivial — run anything.
```

Sony released a firmware update changing their signing key. The attackers had
backups. The signed bootloader could not be revoked without bricking the console.

---

## 5. Bitcoin Wallet Thefts

In 2013, a batch of Bitcoin transactions was identified where two signatures
from the same address shared the same `r` value (and thus the same `k`).

```
Blockchain analysis: scan all transactions for (address, r) pairs
If address A signs tx1 and tx2 with the same r → nonce reuse
→ k recovery → d recovery → private key of wallet
→ funds stolen
```

Affected wallets: an estimated 158 BTC drained via automated nonce-reuse
scanners operated by researchers and, separately, by thieves.

Root cause: poorly seeded PRNG in an Android Bitcoin wallet library (`SecureRandom`
not properly seeded on some Android versions).

---

## 6. Detect

### Signature Scanning

```python
#!/usr/bin/env python3
"""
scan_nonce_reuse.py — detect ECDSA nonce reuse by scanning for repeated r values
"""
from __future__ import annotations

def find_reused_nonces(
    signatures: list[tuple[bytes, int, int]],  # (message, r, s)
) -> list[tuple[int, int]]:
    """Return indices of signature pairs that share an r value."""
    r_to_index: dict[int, int] = {}
    reused: list[tuple[int, int]] = []
    for idx, (_, r, _) in enumerate(signatures):
        if r in r_to_index:
            reused.append((r_to_index[r], idx))
        else:
            r_to_index[r] = idx
    return reused

# In Bitcoin blockchain analysis:
# Parse every transaction; extract (txid, r, s) for each signature
# → any two txids with equal r from same address → nonce reuse → key recovery
```

---

## 7. Harden — Fix

```python
# BAD: random k — depends on PRNG quality
import random
k = random.randint(1, n - 1)   # random.random is NOT cryptographically secure

# BAD: fixed k — catastrophic
k = 42   # Sony's mistake

# GOOD 1: RFC 6979 — deterministic k from private key + message hash
# Deterministic ≠ reused: k = HMAC-DRBG(d, z) is unique per (d, z) pair
from ecdsa import SigningKey, SECP256k1
import hashlib
sk = SigningKey.generate(curve=SECP256k1)
# ecdsa library uses RFC 6979 by default
sig = sk.sign(b"message", hashfunc=hashlib.sha256)
# k is deterministically derived from (d, message) — never the same for
# different messages, never random, no PRNG dependency

# GOOD 2: Ed25519 — uses deterministic nonce by design, not DSA construction
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
private_key = Ed25519PrivateKey.generate()
signature   = private_key.sign(b"message")
# Ed25519 is immune to nonce reuse by construction — no k to misuse
```

**Rule:** Use RFC 6979 deterministic nonce generation (standardised, widely
implemented) or switch to Ed25519. Never use a random `k` from a
general-purpose PRNG, and never hardcode `k`.

---

## Key Takeaways

1. The nonce `k` in ECDSA must be unique, unpredictable, and securely random
   per signature. Reusing `k` for any two signatures with the same key leaks
   the private key in two arithmetic steps.
2. RFC 6979 eliminates PRNG-based nonce generation entirely by deriving `k`
   deterministically from the private key and the message. This means two
   different messages always produce different `k` values without relying on
   randomness quality.
3. Ed25519 is the modern alternative to ECDSA. Its signing algorithm does not
   use a separate random nonce — the "nonce" is derived deterministically from
   the private key and message in a way that is provably secure even if the
   same key signs the same message twice.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q569.1, Q569.2 …).

---

## Navigation

← Previous: [Day 568 — Diffie-Hellman Attacks](DAY-0568-Diffie-Hellman-Attacks.md)
→ Next: [Day 570 — ECDSA Lab](DAY-0570-ECDSA-Lab.md)
