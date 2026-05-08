---
title: "Cryptopals CTF Practice — Day 2: Set 2 (Block Ciphers)"
tags: [cryptography, cryptopals, CTF, CBC, PKCS7, CBC-bitflipping,
  ECB-byte-at-a-time, cut-and-paste, set-2, block-cipher-attacks]
module: 09-Crypto-01
day: 572
prerequisites:
  - Day 571 — Cryptopals CTF Day 1 (Set 1 complete)
  - Day 561 — Padding Oracle Attack
  - Day 566 — ECB Cut-and-Paste
related_topics:
  - Cryptopals CTF Day 3 (Day 573)
  - Padding Oracle Lab (Day 562)
---

# Day 572 — Cryptopals CTF Practice: Day 2

> "Set 2 is where casual students stop and serious students begin. The
> ECB oracle, the CBC bit-flipping attack, the padding oracle — these are
> the attacks that appear in real vulnerability reports. Build each one.
> Debug each one. Own each one."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 2 (challenges 9–16): PKCS#7 padding, CBC mode,
ECB byte-at-a-time oracle, CBC bit-flipping, and the padding oracle attack.
Challenges 12, 13, and 16 are the most important — spend extra time on them.

**Prerequisites:** Set 1 complete; Day 561 (padding oracle theory); Day 566
(ECB cut-and-paste).
**Estimated lab time:** 5 hours (this set is harder than Set 1).
**Resource:** https://cryptopals.com/sets/2

---

## Challenge 9 — Implement PKCS#7 Padding

```python
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n] * n)

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("Empty input")
    n = data[-1]
    if n < 1 or n > block_size:
        raise ValueError(f"Invalid padding byte: {n}")
    if data[-n:] != bytes([n] * n):
        raise ValueError("Inconsistent padding")
    return data[:-n]

# Test
assert pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
assert pkcs7_pad(b"YELLOW SUBMARINE", 16) == b"YELLOW SUBMARINE\x10" * 0 + b"YELLOW SUBMARINE" + bytes([16]*16)
print("[+] Challenge 9 passed")
```

---

## Challenge 10 — Implement CBC Mode

```python
from __future__ import annotations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc    = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec    = cipher.decryptor()
    raw    = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(raw)

# Decrypt the challenge file
import base64, urllib.request
with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/10.txt") as f:
    ct = base64.b64decode(f.read())
KEY = b"YELLOW SUBMARINE"
IV  = bytes(16)   # All-zero IV
pt  = aes_cbc_decrypt(ct, KEY, IV)
print(pt[:100].decode())
# → "I'm back and I'm ringin' the bell..."
print("[+] Challenge 10 passed")
```

---

## Challenge 11 — ECB/CBC Detection Oracle

```python
def encryption_oracle(plaintext: bytes) -> tuple[bytes, str]:
    """Randomly encrypt with ECB or CBC — returns (ciphertext, actual_mode)."""
    import secrets
    key  = secrets.token_bytes(16)
    iv   = secrets.token_bytes(16)
    # Prepend/append 5–10 random bytes to plaintext
    prepend = secrets.token_bytes(secrets.randbelow(6) + 5)
    append  = secrets.token_bytes(secrets.randbelow(6) + 5)
    pt      = prepend + plaintext + append

    if secrets.randbelow(2) == 0:
        ct = aes_cbc_encrypt(pt, key, iv)
        return ct, "CBC"
    else:
        ct_raw = pkcs7_pad(pt)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc    = cipher.encryptor()
        ct     = enc.update(ct_raw) + enc.finalize()
        return ct, "ECB"

def detect_mode(ciphertext: bytes) -> str:
    """Detect ECB by checking for repeated 16-byte blocks."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    return "ECB" if len(blocks) != len(set(blocks)) else "CBC"

# Test: force ECB detection by using a long repeated plaintext
from collections import Counter
correct = 0
for _ in range(100):
    ct, actual = encryption_oracle(b"A" * 48)  # 3 identical blocks → detectable in ECB
    detected   = detect_mode(ct)
    if detected == actual:
        correct += 1
print(f"[+] Challenge 11: {correct}/100 correct detections")
```

---

## Challenge 12 — ECB Byte-at-a-Time (Simple)

**This is the most important challenge in Set 2.**

```python
#!/usr/bin/env python3
"""
ECB byte-at-a-time oracle: recover an unknown suffix appended by the oracle.
"""
from __future__ import annotations

import base64
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Secret suffix — the attacker does not know this
SECRET_SUFFIX = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3AgTm8gSSBqdXN0IGRyb3ZlIGJ5"
)
ORACLE_KEY = secrets.token_bytes(16)

def oracle_12(attacker_input: bytes) -> bytes:
    """ECB oracle: encrypt(attacker_input + secret_suffix, fixed_key)."""
    plaintext = attacker_input + SECRET_SUFFIX
    padded    = pkcs7_pad(plaintext)
    cipher    = Cipher(algorithms.AES(ORACLE_KEY), modes.ECB(),
                       backend=default_backend())
    enc       = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def byte_at_a_time_attack(oracle) -> bytes:
    """Recover the secret suffix one byte at a time."""

    # Step 1: Discover block size
    initial_len = len(oracle(b""))
    block_size  = None
    for i in range(1, 64):
        ct_len = len(oracle(b"A" * i))
        if ct_len != initial_len:
            block_size = ct_len - initial_len
            break
    assert block_size is not None, "Could not detect block size"
    print(f"[*] Block size: {block_size}")

    # Step 2: Confirm ECB mode
    ct_test = oracle(b"A" * (block_size * 2))
    assert ct_test[:block_size] == ct_test[block_size:block_size*2], "Not ECB"
    print("[*] Mode: ECB confirmed")

    # Step 3: Recover suffix one byte at a time
    suffix_len = len(oracle(b""))
    recovered  = b""

    for byte_num in range(suffix_len):
        block_num    = byte_num // block_size
        byte_in_block = byte_num % block_size

        # Craft input: (block_size - 1 - byte_in_block) 'A' bytes
        # This pushes the next unknown byte to the end of the target block
        padding_len = block_size - 1 - byte_in_block
        prefix      = b"A" * padding_len

        # Get the target block (what the oracle returns for this padding)
        target_block = oracle(prefix)[block_num*block_size:(block_num+1)*block_size]

        # Bruteforce the byte: try all 256 values
        found = False
        for candidate in range(256):
            # Build a block: padding + recovered so far + candidate byte
            test_input = prefix + recovered + bytes([candidate])
            test_block = oracle(test_input)[block_num*block_size:(block_num+1)*block_size]
            if test_block == target_block:
                recovered += bytes([candidate])
                found = True
                break

        if not found:
            # Reached padding bytes — done
            break

    return pkcs7_unpad(recovered) if recovered else recovered

recovered = byte_at_a_time_attack(oracle_12)
print(f"\n[+] Recovered suffix:\n{recovered.decode()}")
print("[+] Challenge 12 passed")
```

---

## Challenge 13 — ECB Cut-and-Paste

This is what you built in Day 566 — implement it fully here.

```python
# Refer to Day 566 for the complete implementation.
# Challenge 13 asks you to forge an admin profile via ECB block manipulation.
# Your oracle:
#   encrypt_profile("alice@corp.com") → token
#   decrypt_profile(token)            → {"email":"alice","uid":"10","role":"user"}
# Goal: forge a token with role=admin

# ── Quick solution reference (do not copy without understanding) ──────────
# 1. Request token for email = "AAAAAAAAAA" + "admin\x0b"*11 + "@x.com"
#    → block 1 = E(admin\x0b×11) = C_admin
# 2. Request token for email = "AAAA@corp.com" (aligns role= to block boundary)
#    → blocks 0-1 contain everything up to "role="
# 3. Concatenate blocks 0-1 from step 2 + C_admin from step 1
# See Day 566 for full walkthrough.
print("[+] Challenge 13: see Day 566 for implementation")
```

---

## Challenge 14 — ECB Byte-at-a-Time (Harder)

The oracle now prepends a random-length random prefix before your input. The
byte-at-a-time attack still works — you just need to align past the random prefix.

```python
import secrets

RANDOM_PREFIX = secrets.token_bytes(secrets.randbelow(48) + 1)

def oracle_14(attacker_input: bytes) -> bytes:
    """Same as oracle_12 but with a random prefix."""
    plaintext = RANDOM_PREFIX + attacker_input + SECRET_SUFFIX
    padded    = pkcs7_pad(plaintext)
    cipher    = Cipher(algorithms.AES(ORACLE_KEY), modes.ECB(),
                       backend=default_backend())
    enc       = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def find_prefix_length(oracle) -> int:
    """
    Find the random prefix length by sending identical blocks and
    looking for the first block that stops changing.
    """
    # Send 2 identical blocks — they will align once we add enough padding
    for extra in range(16):
        ct = oracle(b"A" * extra + b"B" * 32)
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                # Found two identical consecutive blocks
                prefix_len = i * 16 - extra
                return prefix_len
    raise ValueError("Could not find prefix length")

prefix_len = find_prefix_length(oracle_14)
print(f"[*] Prefix length: {prefix_len} (actual: {len(RANDOM_PREFIX)})")
# Now pad to align past the prefix, then run byte-at-a-time as before
print("[+] Challenge 14: prefix detected and aligned")
```

---

## Challenge 15 — PKCS#7 Padding Validation

```python
def validate_pkcs7(data: bytes) -> bytes:
    """Strict PKCS#7 unpadding that raises on malformed padding."""
    if not data:
        raise ValueError("Empty data")
    n = data[-1]
    if n == 0 or n > 16:
        raise ValueError(f"Invalid padding length: {n}")
    if data[-n:] != bytes([n] * n):
        raise ValueError("Inconsistent padding bytes")
    return data[:-n]

# Test valid and invalid cases
assert validate_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
try:
    validate_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    assert False
except ValueError:
    pass
try:
    validate_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")
    assert False
except ValueError:
    pass
print("[+] Challenge 15 passed")
```

---

## Challenge 16 — CBC Bit-Flipping

**The CBC bit-flip attack — one of the most important attacks you will learn
in this set.**

```python
#!/usr/bin/env python3
"""
CBC bit-flipping: flip bits in ciphertext block i to corrupt plaintext block i+1
in a controlled way, injecting arbitrary bytes.
"""
from __future__ import annotations

import secrets

FLIP_KEY = secrets.token_bytes(16)
FLIP_IV  = secrets.token_bytes(16)

def c16_encrypt(user_input: str) -> bytes:
    """
    Prepend and append fixed strings. Strip metacharacters from input.
    Encrypt with AES-CBC.
    """
    sanitised = user_input.replace(';', '%3B').replace('=', '%3D')
    prefix    = b"comment1=cooking%20MCs;userdata="
    suffix    = b";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix + sanitised.encode() + suffix
    return aes_cbc_encrypt(plaintext, FLIP_KEY, FLIP_IV)

def c16_decrypt_is_admin(ciphertext: bytes) -> bool:
    """Return True if decrypted token contains ';admin=true;'."""
    try:
        plaintext = aes_cbc_decrypt(ciphertext, FLIP_KEY, FLIP_IV)
        return b";admin=true;" in plaintext
    except Exception:
        return False

def cbc_bitflip_attack() -> bytes:
    """
    Flip bits in ciphertext block 1 to inject ';admin=true;' into block 2.

    How CBC decryption works:
        P[n] = Decrypt(C[n]) XOR C[n-1]

    If we flip a bit in C[n-1], the same bit flips in P[n].
    This corrupts P[n-1] (since C[n-1] is now changed), but P[n] gets our
    controlled flip.

    prefix = "comment1=cooking%20MCs;userdata=" = 32 bytes (exactly 2 blocks)
    Our input starts at block 2 (bytes 32+).

    We send ":admin<true:" (using : and < instead of ; and =)
    → These land in block 2 (bytes 32-47)

    We flip bits in block 1 ciphertext (bytes 16-31) at the exact offsets:
      offset 0 in block 1 → flips byte 0 of block 2 ('prefix[32]' = ':' → ';')
      offset 6 in block 1 → flips byte 6 of block 2 ('<' → '=')
      etc.
    """
    # Craft input so ":admin<true:" starts at beginning of a plaintext block
    # prefix is 32 bytes (2 full blocks) → our input starts at plaintext block 2
    user_input = ":admin<true:"
    ct = bytearray(c16_encrypt(user_input))

    # We want to flip in the ciphertext of block 1 (bytes 16-31)
    # to affect plaintext block 2 (bytes 32-47)
    # ':' (0x3a) XOR '?' = ';' (0x3b) → XOR with 0x01
    # '<' (0x3c) XOR '?' = '=' (0x3d) → XOR with 0x01
    ct[16 + 0] ^= 0x01   # ':' → ';' (first character of user_input at block 2)
    ct[16 + 6] ^= 0x01   # '<' → '=' (7th character, 'admin<' = 6 chars)

    return bytes(ct)

forged_ct  = cbc_bitflip_attack()
is_admin   = c16_decrypt_is_admin(forged_ct)
print(f"[+] Is admin: {is_admin}")
assert is_admin, "Bit-flip attack failed"
print("[+] Challenge 16 passed — CBC bit-flip attack successful")
```

---

## Set 2 Self-Assessment

```
[ ] 1. In challenge 12, why does the block size detection work? What causes the
        output length to jump?

[ ] 2. In challenge 16, we corrupt plaintext block n-1 while injecting into
        block n. What is in block n-1 after the attack? Why does the server
        not reject the corrupted prefix?

[ ] 3. Challenge 16 requires knowing where in the plaintext our input lands.
        What if we did not know the prefix length? How would the attack change?

[ ] 4. The oracle in challenge 12 uses a fixed key. If the key changed on
        every request, would the byte-at-a-time attack still work? Why/why not?
```

---

## Key Takeaways

1. Challenge 12 (ECB byte-at-a-time) is the foundational ECB oracle attack.
   Any system that encrypts attacker-controlled input alongside a secret suffix
   using ECB leaks the suffix byte by byte, requiring at most `256 × len(suffix)`
   oracle queries.
2. Challenge 16 (CBC bit-flip) demonstrates that CBC without authentication is
   malleable. You can flip any bit in plaintext block `n` by flipping the
   corresponding bit in ciphertext block `n-1`. Authentication (HMAC or GCM)
   is required to prevent this.
3. Both attacks in this set were used in real vulnerabilities. ECB oracle
   attacks appeared in early session token implementations; CBC bit-flipping
   appeared in early SSL/TLS session manipulation research.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q572.1, Q572.2 …).

---

## Navigation

← Previous: [Day 571 — Cryptopals CTF Day 1](DAY-0571-Cryptopals-CTF-Day-1.md)
→ Next: [Day 573 — Cryptopals CTF Practice: Day 3](DAY-0573-Cryptopals-CTF-Day-3.md)
