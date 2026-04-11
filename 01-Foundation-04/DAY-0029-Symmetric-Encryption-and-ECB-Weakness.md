---
title: "Symmetric Encryption and ECB Weakness"
tags: [foundation, cryptography, AES, ECB, CBC, CTR, GCM, block-cipher,
       symmetric, ECB-penguin, padding, attacker-mindset]
module: 01-Foundation-04
day: 29
related_topics:
  - TLS Handshake PKI and Cert Chains (Day 033)
  - Crypto in the Wild CVE Review (Day 037)
  - Padding Oracle Attacks (Day 574)
---

# Day 029 — Symmetric Encryption and ECB Weakness

## Goals

By the end of this lesson you will be able to:

1. Explain symmetric encryption: one key, encrypt and decrypt.
2. Describe block cipher operation: block size, padding, modes of operation.
3. Explain ECB mode and demonstrate why it leaks patterns.
4. Explain CBC mode — how IV chaining fixes ECB's weakness.
5. Explain CTR and GCM modes and when to use each.
6. Identify which mode is in use from ciphertext length patterns.
7. Describe the ECB "cut-and-paste" attack on block boundaries.

---

## Prerequisites

- [Day 005 — HTTP Cookies, Sessions and TLS](../01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)

---

## Main Content — Part 1: Block Ciphers

### 1. Symmetric Encryption Fundamentals

In symmetric encryption, the same key encrypts and decrypts:

```
Plaintext + Key → [Cipher] → Ciphertext
Ciphertext + Key → [Cipher] → Plaintext
```

**AES (Advanced Encryption Standard)** is the standard block cipher.
- Block size: always 128 bits (16 bytes).
- Key sizes: 128, 192, or 256 bits (AES-128, AES-192, AES-256).
- AES-256 is the default choice for new systems.

**Block cipher**: operates on fixed-size blocks. A message longer than
one block needs a **mode of operation** that chains or parallelises blocks.

---

### 2. Padding

AES requires input in exact 16-byte blocks. If the last block is short,
it must be padded.

**PKCS#7 padding:**

```
If block is 13 bytes, pad with 3 bytes of value 0x03:
[...13 bytes...][03][03][03]

If block is 16 bytes (full), add a full padding block:
[...16 bytes...][10][10][10][10][10][10][10][10]
[10][10][10][10][10][10][10][10]
# 16 bytes of value 0x10 (= decimal 16)
```

**Why full-block padding?** The decryptor must always be able to strip
padding. A padding byte of `0x10` means "remove 16 bytes." If the last
byte is `0x01`, remove 1 byte. The extra block ensures this is unambiguous.

**Security implication:** Incorrect padding validation is the root cause of
the CBC padding oracle attack (covered in Advanced Track). Padding error
messages reveal bits of the plaintext.

---

## Main Content — Part 2: Modes of Operation

### 3. ECB Mode — The Penguin Problem

**Electronic Code Book (ECB):** Each block is encrypted independently.
Same plaintext block → same ciphertext block.

```
Plaintext:   [Block 1][Block 2][Block 3]
ECB encrypt: [C1 = E(Block1)][C2 = E(Block2)][C3 = E(Block3)]

If Block 1 == Block 3 then C1 == C3
```

**The ECB Penguin:** If you encrypt a bitmap image with ECB, regions of
identical colour (same pixel value repeated) produce identical ciphertext
blocks. The image structure remains clearly visible in the ciphertext — a
famous demonstration that ECB "encrypts" without obscuring patterns.

**Attack consequence for applications:**

If an application encrypts user data in ECB mode with a fixed key:

```
Plaintext:  [username: adm][in; role: us][er; extra: XX]
            [Block 1        ][Block 2        ][Block 3        ]
```

An attacker who can choose their username to align block boundaries can
swap ciphertext blocks to forge plaintext:

```python
# ECB cut-and-paste attack example
# The registration endpoint takes a username and returns an encrypted token
# Blocks are 16 bytes

# Step 1: Register with username that produces 'admin' as the second block:
#   email=AAAAAAAAAAadmin@foo.com
#   Block 1: "email=AAAAAAAAAA"  (16 bytes)
#   Block 2: "admin@foo.com..." (16 bytes — contains 'admin' at start)

# Step 2: Register normally with your real email to get a normal token
#   Block 1: "email=normal@foo" (16 bytes)
#   Block 2: ".com&role=user&." (16 bytes)
#   Block 3: "..."

# Step 3: Replace block 2 of the normal token with block 2 from step 1
# Result: forged token where role=admin appears in the decrypted plaintext
```

---

### 4. CBC Mode — Chained Blocks

**Cipher Block Chaining (CBC):** Each plaintext block is XORed with the
previous ciphertext block before encryption. The first block uses a random
**Initialisation Vector (IV)**.

```
C0 = IV (random, 16 bytes)
C1 = E(P1 XOR C0)
C2 = E(P2 XOR C1)
C3 = E(P3 XOR C2)
```

**Why this fixes ECB:** Identical plaintext blocks produce different
ciphertext blocks because the XOR with different preceding ciphertext
makes each block context-dependent.

**Security requirement:** The IV must be:
1. **Random** — not predictable.
2. **Unique per message** — never reused with the same key.
3. **Transmitted with the ciphertext** — the IV is not secret.

**Common misconfiguration:** Using a fixed IV (often all-zeros). This
makes CBC identical to ECB for the first block and enables chosen-plaintext
attacks.

---

### 5. CTR Mode — Stream Cipher from Block Cipher

**Counter (CTR) mode:** Encrypts a counter value to produce a keystream,
then XORs the keystream with plaintext. The block cipher is used to generate
pseudorandom bytes, not to encrypt blocks directly.

```
Keystream_n = E(Nonce || Counter_n)
Ciphertext_n = Plaintext_n XOR Keystream_n
```

**Advantages:**
- No padding required (stream, not block).
- Parallelisable (each counter value is independent).
- Random access: decrypt any byte without decrypting preceding bytes.

**Critical requirement:** Never reuse (Nonce, Key) pair. If two messages
are encrypted with the same nonce and key:

```
C1 = P1 XOR Keystream
C2 = P2 XOR Keystream
C1 XOR C2 = P1 XOR P2  ← Keystream cancels out → two-time pad attack
```

Knowing one plaintext gives you the other. **One nonce reuse = break.**

---

### 6. GCM Mode — Authenticated Encryption

**Galois/Counter Mode (GCM):** CTR mode + a Galois field MAC (GHASH).
Provides both **confidentiality** (CTR) and **integrity/authentication**
(the authentication tag).

```
AES-256-GCM output: Ciphertext + 128-bit Authentication Tag
```

**Why GCM is the standard choice today:**
- Detects ciphertext tampering (the authentication tag fails to verify).
- No padding oracle possible (auth tag check prevents decryption of
  invalid ciphertext).
- Hardware acceleration in modern CPUs (AES-NI + PCLMULQDQ).

**The nonce problem:** Same as CTR — never reuse (nonce, key). Nonce reuse
in GCM is catastrophic: it reveals the GHASH key, allowing the attacker to
forge authentication tags.

---

### 7. Mode Selection Guide

| Mode | Authenticated | Parallel | Padding needed | Use when |
|---|---|---|---|---|
| **ECB** | No | Yes | Yes | Never — patterns leak |
| **CBC** | No | Decrypt only | Yes | Legacy; must add HMAC |
| **CTR** | No | Yes | No | Streaming, add separate MAC |
| **GCM** | Yes | Yes | No | All new systems |
| **ChaCha20-Poly1305** | Yes | Yes | No | Mobile / no AES-NI |

---

## Key Takeaways

1. **Never use ECB.** Identical plaintext blocks → identical ciphertext
   blocks. Any structured data (images, JSON, user records) leaks patterns.
2. **CBC requires a random IV per message.** Fixed IV makes the first block
   ECB-equivalent and enables chosen-plaintext attacks.
3. **CTR and CBC require separate integrity protection (HMAC).** Encryption
   without authentication allows ciphertext manipulation → padding oracle,
   bit-flipping attacks.
4. **GCM = confidentiality + integrity in one pass.** It is the correct
   default for any new symmetric encryption. The only exception is when
   AES-NI is unavailable — then ChaCha20-Poly1305.
5. **Nonce reuse in CTR/GCM is catastrophic.** If nonces are sequential
   integers and an attacker can restart the counter (e.g. network device
   reboot), they can decrypt traffic. Use random 96-bit nonces with GCM.

---

## Exercises

### Exercise 1 — Visualise ECB Pattern Leakage

```python
from Crypto.Cipher import AES
from PIL import Image
import struct

# Read a bitmap image (any 24-bit BMP, or create one with red squares):
img = Image.open("test.bmp").convert("RGB")
pixel_data = img.tobytes()

# Pad to AES block size
while len(pixel_data) % 16 != 0:
    pixel_data += b'\x00'

# Encrypt with ECB (same fixed key — demonstrating the flaw)
key = b'0123456789ABCDEF'  # 16-byte AES-128 key
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(pixel_data)

# Save encrypted as image (same dimensions, raw pixel data)
enc_img = Image.frombytes("RGB", img.size, encrypted[:len(img.tobytes())])
enc_img.save("ecb_encrypted.bmp")
```

Open `ecb_encrypted.bmp`. Can you recognise the original image's shapes?
Now encrypt with AES-CBC with a random IV and repeat. Compare.

### Exercise 2 — Nonce Reuse Attack

```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)
nonce = b'\x00' * 12   # Fixed nonce — the vulnerability

def encrypt_ctr(plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    return cipher.encrypt(plaintext)

# Two plaintexts encrypted with same key+nonce:
p1 = b"Attack at dawn!!"
p2 = b"Retreat at noon!"
c1 = encrypt_ctr(p1)
c2 = encrypt_ctr(p2)

# Given c1 and knowing p1, recover p2:
keystream = bytes(a ^ b for a, b in zip(c1, p1))
recovered_p2 = bytes(a ^ b for a, b in zip(c2, keystream))
print(recovered_p2)   # Should print: b"Retreat at noon!"
```

Run this. Understand why it works. What does it mean for session tokens
generated with a fixed IV?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 028 — Web Architecture Competency Check](../01-Foundation-03/DAY-0028-Web-Architecture-Competency-Check.md)*
*Next: [Day 030 — Hashing, Collisions and Length Extension](DAY-0030-Hashing-Collisions-and-Length-Extension.md)*
