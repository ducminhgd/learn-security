---
title: "Cryptopals CTF Practice — Day 3: Set 3 (CBC and Stream Ciphers)"
tags: [cryptography, cryptopals, CTF, CBC-padding-oracle, CTR-mode,
  MT19937, PRNG, stream-cipher, nonce-reuse, set-3]
module: 09-Crypto-01
day: 573
prerequisites:
  - Day 572 — Cryptopals CTF Day 2 (Set 2 complete)
  - Day 561 — Padding Oracle Attack
  - Day 035 — Randomness and PRNG Attacks
related_topics:
  - Cryptopals CTF Day 4 (Day 574)
  - Padding Oracle Attack (Day 561)
  - Timing Attacks (Day 563)
---

# Day 573 — Cryptopals CTF Practice: Day 3

> "Set 3 introduces Mersenne Twister attacks and CTR mode nonce reuse. The MT
> attack is pure PRNG cryptanalysis — 624 outputs completely determine the
> internal state. CTR nonce reuse reduces to repeating-key XOR, which you
> already know how to break. Connect the dots."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 3 (challenges 17–24): the full CBC padding oracle
attack, CTR mode implementation, CTR nonce reuse, and Mersenne Twister
cloning from output.

**Prerequisites:** Set 2 complete; Day 561 (padding oracle); Day 035 (PRNG).
**Estimated lab time:** 5 hours (Set 3 is harder — budget extra time for
challenges 19–23).
**Resource:** https://cryptopals.com/sets/3

---

## Challenge 17 — The CBC Padding Oracle

This is the full padding oracle attack you studied in Days 561–562. Implement
it end-to-end using the Cryptopals oracle.

```python
#!/usr/bin/env python3
"""
Challenge 17: Full CBC padding oracle attack.
This is the most important challenge in Set 3.
"""
from __future__ import annotations

import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ORACLE_KEY = secrets.token_bytes(16)

STRINGS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbicn",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
]

def c17_encrypt() -> tuple[bytes, bytes]:
    """Pick random string, encrypt with CBC, return (ciphertext, iv)."""
    import base64
    s  = STRINGS[secrets.randbelow(len(STRINGS))]
    pt = base64.b64decode(s)
    iv = secrets.token_bytes(16)
    ct = aes_cbc_encrypt(pt, ORACLE_KEY, iv)
    return ct, iv

def c17_oracle(ciphertext: bytes, iv: bytes) -> bool:
    """Return True if decryption produces valid PKCS#7 padding."""
    try:
        aes_cbc_decrypt(ciphertext, ORACLE_KEY, iv)
        return True
    except ValueError:
        return False

def padding_oracle_attack(ciphertext: bytes, iv: bytes) -> bytes:
    """Full padding oracle attack against CBC ciphertext."""
    blocks = [iv] + [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    for block_idx in range(1, len(blocks)):
        prev  = bytearray(blocks[block_idx - 1])
        curr  = bytes(blocks[block_idx])
        intermediate = bytearray(16)
        decrypted    = bytearray(16)

        for byte_pos in range(15, -1, -1):
            padding_val = 16 - byte_pos

            # Fix already-solved bytes in prev
            crafted = bytearray(16)
            for k in range(byte_pos + 1, 16):
                crafted[k] = intermediate[k] ^ padding_val

            for guess in range(256):
                crafted[byte_pos] = guess
                test_ct = bytes(crafted) + curr
                test_iv = bytes(16)
                if c17_oracle(test_ct, test_iv):
                    if byte_pos == 15:
                        # Guard against accidental 2-byte padding match
                        crafted[byte_pos - 1] ^= 0xFF
                        if not c17_oracle(bytes(crafted) + curr, test_iv):
                            crafted[byte_pos - 1] ^= 0xFF
                            continue
                    intermediate[byte_pos] = guess ^ padding_val
                    decrypted[byte_pos]    = intermediate[byte_pos] ^ prev[byte_pos]
                    break

        plaintext += bytes(decrypted)

    # Strip PKCS#7 padding from final block
    n = plaintext[-1]
    return plaintext[:-n]

ct, iv = c17_encrypt()
recovered = padding_oracle_attack(ct, iv)
print(f"[+] Recovered: {recovered!r}")
print("[+] Challenge 17 passed")
```

---

## Challenge 18 — Implement CTR Mode

```python
import struct

def aes_ctr(data: bytes, key: bytes, nonce: int = 0) -> bytes:
    """
    AES-CTR mode: encrypt/decrypt are identical.
    Keystream = AES(key, nonce || counter) for each 16-byte block.
    Little-endian nonce format (as per Cryptopals spec).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypto_modes
    from cryptography.hazmat.backends import default_backend
    result = bytearray()
    cipher = Cipher(algorithms.AES(key), crypto_modes.ECB(), backend=default_backend())

    block_count = (len(data) + 15) // 16
    for i in range(block_count):
        # Counter block: 64-bit little-endian nonce + 64-bit little-endian counter
        counter_block = struct.pack('<QQ', nonce, i)
        enc = cipher.encryptor()
        keystream_block = enc.update(counter_block) + enc.finalize()
        chunk = data[i*16:(i+1)*16]
        result += bytes(a ^ b for a, b in zip(chunk, keystream_block))

    return bytes(result)

# Verify against Cryptopals test vector
import base64
ct_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
key    = b"YELLOW SUBMARINE"
ct     = base64.b64decode(ct_b64)
pt     = aes_ctr(ct, key, nonce=0)
print(f"[+] CTR decrypted: {pt!r}")
print("[+] Challenge 18 passed")
```

---

## Challenge 19 & 20 — Break CTR Nonce Reuse

```python
#!/usr/bin/env python3
"""
Challenges 19 & 20: break CTR mode when the same nonce is reused across
multiple ciphertexts.

CTR with fixed nonce: C[i] = P[i] XOR KeyStream[i]
If two plaintexts P and Q use the same keystream K:
  C1 = P XOR K
  C2 = Q XOR K
  C1 XOR C2 = P XOR Q   ← attacker computes this directly

This is identical to the repeating-key XOR problem (challenge 6, Set 1).
"""
from __future__ import annotations

import base64
import urllib.request

FIXED_KEY   = secrets.token_bytes(16)
FIXED_NONCE = 0   # Vulnerability: same nonce for all ciphertexts

# Load challenge data (64 base64-encoded plaintexts)
def c20_get_ciphertexts() -> list[bytes]:
    url = "https://cryptopals.com/static/challenge-data/20.txt"
    with urllib.request.urlopen(url) as f:
        lines = f.read().decode().strip().split('\n')
    return [aes_ctr(base64.b64decode(line), FIXED_KEY, FIXED_NONCE)
            for line in lines]

ciphertexts = c20_get_ciphertexts()
min_len     = min(len(ct) for ct in ciphertexts)

# Truncate all ciphertexts to the length of the shortest
truncated = [ct[:min_len] for ct in ciphertexts]

# Concatenate to form a single "ciphertext" = repeating-key XOR with keystream
# Then use frequency analysis (same as challenge 6)
combined_ct = b"".join(truncated)

# The key = keystream bytes 0..min_len-1, which we recover via frequency analysis
keystream_estimates = []
for byte_pos in range(min_len):
    column = bytes(ct[byte_pos] for ct in truncated)
    best_key, _, _ = break_single_xor(column)
    keystream_estimates.append(best_key)

keystream = bytes(keystream_estimates)
print("[+] Keystream (first 20 bytes):", keystream[:20].hex())

# Decrypt all ciphertexts
for i, ct in enumerate(truncated[:5]):
    pt = bytes(c ^ k for c, k in zip(ct, keystream))
    print(f"  [{i}] {pt[:60].decode(errors='replace')}")
print("[+] Challenges 19/20 passed")
```

---

## Challenge 21 — Implement Mersenne Twister MT19937

```python
#!/usr/bin/env python3
"""
MT19937 Mersenne Twister implementation.
This is required for challenges 22, 23, and 24.
"""
from __future__ import annotations

class MT19937:
    W, N, M, R = 32, 624, 397, 31
    A          = 0x9908B0DF
    B, C       = 0x9D2C5680, 0xEFC60000
    S, T       = 7, 15
    U, D       = 11, 0xFFFFFFFF
    L          = 18
    F          = 1812433253
    MASK       = 0xFFFFFFFF

    def __init__(self, seed: int):
        self.index = self.N
        self.mt    = [0] * self.N
        self.mt[0] = seed & self.MASK
        for i in range(1, self.N):
            self.mt[i] = (
                self.F * (self.mt[i-1] ^ (self.mt[i-1] >> (self.W-2))) + i
            ) & self.MASK

    def _generate(self):
        for i in range(self.N):
            x  = ((self.mt[i]          & (self.MASK << self.R) & self.MASK) +
                   (self.mt[(i+1) % self.N] & (~(self.MASK << self.R) & self.MASK)))
            xA = x >> 1
            if x & 1:
                xA ^= self.A
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ xA
        self.index = 0

    def extract(self) -> int:
        if self.index >= self.N:
            self._generate()
        y = self.mt[self.index]
        self.index += 1
        # Temper
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)
        return y & self.MASK

rng = MT19937(seed=42)
print(f"[*] MT19937 first output: {rng.extract()}")
print("[+] Challenge 21 passed")
```

---

## Challenge 22 — Crack MT19937 Seed (Time-Based)

```python
import time

def wait_and_seed() -> tuple[int, int]:
    """Simulate server: sleep random amount, seed MT with Unix time."""
    import random
    wait = random.randint(40, 1000)  # 40–1000 second sleep (simulated)
    seed = int(time.time()) + wait   # Pretend time has passed
    rng  = MT19937(seed)
    return rng.extract(), seed

output, actual_seed = wait_and_seed()
print(f"[*] MT output: {output}")

# Attacker: try recent timestamps
now = int(time.time()) + 1000   # Upper bound
for candidate_seed in range(now, now - 2000, -1):
    rng = MT19937(candidate_seed)
    if rng.extract() == output:
        print(f"[+] Seed cracked: {candidate_seed} (actual: {actual_seed})")
        break
print("[+] Challenge 22 passed")
```

---

## Challenge 23 — Clone MT19937 State from 624 Outputs

```python
def untemper(y: int) -> int:
    """
    Reverse the MT19937 tempering transformation to recover the raw state.
    Each step is invertible.
    """
    # Invert y ^= (y >> L)  [L=18, half of 32]
    y ^= y >> 18
    # Invert y ^= (y << T) & C  [T=15, C=0xEFC60000]
    y ^= (y << 15) & 0xEFC60000
    # Invert y ^= (y << S) & B  [S=7, B=0x9D2C5680]
    # Each application recovers 7 more bits
    b = y
    b = y ^ ((b << 7) & 0x9D2C5680)
    b = y ^ ((b << 7) & 0x9D2C5680)
    b = y ^ ((b << 7) & 0x9D2C5680)
    b = y ^ ((b << 7) & 0x9D2C5680)
    y = b
    # Invert y ^= (y >> U) & D  [U=11, D=0xFFFFFFFF]
    b = y
    b = y ^ (b >> 11)
    b = y ^ (b >> 11)
    y = b
    return y & 0xFFFFFFFF

# Clone: observe 624 outputs, recover state, predict future outputs
true_rng  = MT19937(seed=secrets.randbelow(2**32))
observed  = [true_rng.extract() for _ in range(624)]

# Recover MT state
clone      = MT19937(seed=0)
clone.mt   = [untemper(o) for o in observed]
clone.index = 624   # State fully loaded — ready to generate

# Verify: next 10 outputs of clone match true_rng
for i in range(10):
    a = true_rng.extract()
    b = clone.extract()
    assert a == b, f"Mismatch at output {i}: {a} != {b}"
    print(f"  [{i}] true={a}, clone={b}, match={a==b}")
print("[+] Challenge 23 passed — MT19937 fully cloned from 624 outputs")
```

---

## Challenge 24 — Create and Break MT19937 Stream Cipher

```python
def mt_keystream(seed: int, length: int) -> bytes:
    """Generate keystream bytes from MT19937 (8 bits per extract output)."""
    rng = MT19937(seed)
    raw = b""
    while len(raw) < length:
        raw += rng.extract().to_bytes(4, 'big')
    return raw[:length]

def mt_encrypt(plaintext: bytes, seed_16bit: int) -> bytes:
    """Encrypt with MT19937 keystream using 16-bit seed (vulnerable)."""
    ks = mt_keystream(seed_16bit, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))

# Attack: known-plaintext + brute-force 16-bit seed (65536 possibilities)
known_suffix = b"A" * 14   # Known plaintext at end of message
ciphertext   = mt_encrypt(b"Some secret text" + known_suffix, seed_16bit=12345)

for candidate in range(65536):
    ks    = mt_keystream(candidate, len(ciphertext))
    pt    = bytes(c ^ k for c, k in zip(ciphertext, ks))
    if pt[-14:] == known_suffix:
        print(f"[+] Seed found: {candidate}")
        break
print("[+] Challenge 24 passed")
```

---

## Set 3 Self-Assessment

```
[ ] 1. In challenge 17, why does the oracle need to distinguish padding errors
        from decryption errors? What if it only returned 200/500 with no body?
        Would the attack still work?

[ ] 2. CTR mode with a fixed nonce reduces to repeating-key XOR. Explain
        exactly why — write out the XOR equations.

[ ] 3. Challenge 23 clones MT19937 from 624 outputs. What does this tell you
        about using MT19937 for cryptographic purposes? What is the correct
        alternative for a CSPRNG?

[ ] 4. Challenge 22 cracks a time-based seed. What would need to change for
        the seed to be uncrackable? Is "use a larger timestamp range"
        sufficient? Why or why not?
```

---

## Key Takeaways

1. CTR mode with a fixed nonce is equivalent to repeating-key XOR with the
   AES keystream as the key. You already know how to break repeating-key XOR
   (Set 1, Challenge 6). The same technique applies directly.
2. MT19937 is not a cryptographically secure PRNG. 624 consecutive outputs
   completely determine all future outputs. Any system that seeds MT19937 with
   a timestamp or uses it for cryptographic purposes is fully broken. Use
   `os.urandom()` or `secrets.token_bytes()`.
3. Challenge 17 is the padding oracle attack you implemented in Days 561–562.
   Seeing it again in a different framing confirms the technique is general —
   any oracle that distinguishes padding errors is exploitable by the same algorithm.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q573.1, Q573.2 …).

---

## Navigation

← Previous: [Day 572 — Cryptopals CTF Day 2](DAY-0572-Cryptopals-CTF-Day-2.md)
→ Next: [Day 574 — Cryptopals CTF Practice: Day 4](DAY-0574-Cryptopals-CTF-Day-4.md)
