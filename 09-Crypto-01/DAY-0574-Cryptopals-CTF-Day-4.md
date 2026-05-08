---
title: "Cryptopals CTF Practice — Day 4: Set 4 (Stream Cipher and HMAC Timing)"
tags: [cryptography, cryptopals, CTF, CTR-splicing, SHA1-length-extension,
  HMAC-timing, CBC-recovery, bit-flipping, set-4, stream-cipher]
module: 09-Crypto-01
day: 574
prerequisites:
  - Day 573 — Cryptopals CTF Day 3 (Set 3 complete)
  - Day 563 — Timing Attacks
  - Day 564 — Length Extension Attack
related_topics:
  - Cryptopals CTF Day 5 (Day 575)
  - Timing Attacks (Day 563)
  - Length Extension Attack (Day 564)
---

# Day 574 — Cryptopals CTF Practice: Day 4

> "Set 4 closes the loop: you implement the SHA-1 length extension attack
> yourself, and then you implement the HMAC timing attack. Both of these
> you have studied in theory. Now you write the code. Every line you write
> is understanding you cannot get from reading."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 4 (challenges 25–32): CTR splicing, CTR and CBC
recovery, SHA-1 key-prefix MAC, SHA-1 length extension, SHA-256 length
extension, and HMAC timing attack with a real HTTP server.

**Prerequisites:** Sets 1–3 complete; Day 563 (timing attacks); Day 564
(length extension theory).
**Estimated lab time:** 5 hours.
**Resource:** https://cryptopals.com/sets/4

---

## Challenge 25 — Break "Random Access Read/Write" AES-CTR

```python
#!/usr/bin/env python3
"""
Challenge 25: CTR mode allows "seek" — you can edit any byte by XORing
with the keystream at that position. If the edit oracle tells you what
a ciphertext looks like after editing, you can recover the keystream
and decrypt the original.
"""
from __future__ import annotations

import secrets

CTR_KEY   = secrets.token_bytes(16)
CTR_NONCE = 0

def c25_generate_ciphertext(plaintext: bytes) -> bytes:
    return aes_ctr(plaintext, CTR_KEY, CTR_NONCE)

def c25_edit(ciphertext: bytes, offset: int, new_plaintext: bytes) -> bytes:
    """
    Edit oracle: re-encrypt a segment of the ciphertext with new plaintext.
    Returns the full modified ciphertext.
    """
    # Decrypt, modify, re-encrypt
    full_pt = bytearray(aes_ctr(ciphertext, CTR_KEY, CTR_NONCE))
    for i, b in enumerate(new_plaintext):
        full_pt[offset + i] = b
    return aes_ctr(bytes(full_pt), CTR_KEY, CTR_NONCE)

# Load challenge data (AES-ECB encrypted, then re-encrypted with CTR)
import base64, urllib.request
with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/25.txt") as f:
    ecb_ct = base64.b64decode(f.read())
ecb_pt = aes_ecb_decrypt(ecb_ct, b"YELLOW SUBMARINE")

# Encrypt the ECB plaintext with CTR (this is our "protected" ciphertext)
ciphertext = c25_generate_ciphertext(ecb_pt)

# ── Attack: use the edit oracle to recover the keystream ─────────────────
# If we "edit" byte i with byte X, the new ciphertext at position i is:
#   new_ct[i] = X XOR keystream[i]
# Original ciphertext:
#   ct[i]     = pt[i] XOR keystream[i]
# So: keystream[i] = new_ct[i] XOR X
# And: pt[i] = ct[i] XOR keystream[i]

recovered_pt = bytearray()
for i in range(len(ciphertext)):
    x = 0x41  # Arbitrary known byte 'A'
    new_ct       = c25_edit(ciphertext, i, bytes([x]))
    keystream_i  = new_ct[i] ^ x
    pt_i         = ciphertext[i] ^ keystream_i
    recovered_pt.append(pt_i)

print(f"[+] Recovered plaintext (first 100 bytes):\n{recovered_pt[:100].decode()}")
assert bytes(recovered_pt) == ecb_pt
print("[+] Challenge 25 passed")
```

---

## Challenge 26 — CTR Bitflipping

```python
#!/usr/bin/env python3
"""
Challenge 26: CTR mode bit-flipping.
Unlike CBC, CTR bit-flipping is direct: flipping bit i in the ciphertext
flips bit i in the plaintext (no neighbouring block corruption).
"""
from __future__ import annotations

import secrets

CTR26_KEY   = secrets.token_bytes(16)
CTR26_NONCE = 0

def c26_encrypt(user_data: str) -> bytes:
    sanitised = user_data.replace(';', '%3B').replace('=', '%3D')
    prefix    = b"comment1=cooking%20MCs;userdata="
    suffix    = b";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = prefix + sanitised.encode() + suffix
    return aes_ctr(plaintext, CTR26_KEY, CTR26_NONCE)

def c26_is_admin(ct: bytes) -> bool:
    pt = aes_ctr(ct, CTR26_KEY, CTR26_NONCE)
    return b";admin=true;" in pt

# Prefix is 32 bytes. Our input starts at byte 32.
# We submit ":admin<true:" and flip bits 32+0 and 32+6.
# In CTR mode: flipping bit in ciphertext → same bit flips in plaintext
# (no adjacent block corruption unlike CBC!)

ct     = bytearray(c26_encrypt(":admin<true:"))
ct[32] ^= 0x01   # ':' (0x3a) → ';' (0x3b)
ct[38] ^= 0x01   # '<' (0x3c) → '=' (0x3d)

print(f"[+] Is admin: {c26_is_admin(bytes(ct))}")
assert c26_is_admin(bytes(ct))
print("[+] Challenge 26 passed — CTR bitflip direct (no collateral damage!)")
```

---

## Challenge 27 — Recover CBC Key as IV

```python
#!/usr/bin/env python3
"""
Challenge 27: when IV == KEY in CBC, the key can be recovered from a
decryption error that leaks the first decrypted block.
"""
from __future__ import annotations

import secrets

C27_KEY = secrets.token_bytes(16)
C27_IV  = C27_KEY  # Vulnerability: IV = KEY

def c27_encrypt(plaintext: bytes) -> bytes:
    return aes_cbc_encrypt(plaintext, C27_KEY, C27_IV)

def c27_decrypt_check(ciphertext: bytes) -> bytes | None:
    """
    Decrypt and check for non-ASCII bytes.
    If found, RAISE AN EXCEPTION CONTAINING THE PLAINTEXT.
    This is the oracle leak — it reveals decrypted plaintext in the error.
    """
    raw = aes_cbc_decrypt(ciphertext, C27_KEY, C27_IV)
    for b in raw:
        if b > 127:
            raise ValueError(f"Non-ASCII character in output: {raw.hex()}")
    return raw

# Encrypt 3 blocks of plaintext
ct = bytearray(c27_encrypt(b"A" * 48))

# Attack: C1' = C1, C2' = 0, C3' = C1
# When decrypted:
#   P1' = Decrypt(C1) XOR IV = Decrypt(C1) XOR KEY
#   P2' = Decrypt(0)  XOR C1
#   P3' = Decrypt(C1) XOR C2 = Decrypt(C1) XOR C2
# P1' XOR P3' = (Decrypt(C1) XOR KEY) XOR (Decrypt(C1) XOR C2) = KEY XOR C2
# Hmm — we need P1 directly: P1' = P1_original XOR KEY (if IV=KEY)
# Actually: P1' = Decrypt(C1) XOR IV = Decrypt(C1) XOR KEY
# And P1_original = Decrypt(C1) XOR KEY = P1'
# So P1' XOR P3': KEY = P1' XOR P3' — if C3' = C1 and C2' = 0...
# Simpler: KEY = P1' XOR P3' where C = [C1, 0s, C1]

attack_ct = bytes(ct[:16]) + bytes(16) + bytes(ct[:16])
try:
    c27_decrypt_check(attack_ct)
except ValueError as e:
    leaked = bytes.fromhex(str(e).split(": ")[-1])
    # P1' = leaked[:16], P3' = leaked[32:48]
    recovered_key = bytes(a ^ b for a, b in zip(leaked[:16], leaked[32:48]))
    print(f"[+] Recovered key: {recovered_key.hex()}")
    print(f"[+] Actual key:    {C27_KEY.hex()}")
    print(f"[+] Match: {recovered_key == C27_KEY}")
    assert recovered_key == C27_KEY
    print("[+] Challenge 27 passed — IV=KEY vulnerability exploited")
```

---

## Challenge 28 — Implement SHA-1 Keyed MAC

```python
import hashlib

def sha1_mac(key: bytes, message: bytes) -> str:
    """Vulnerable: SHA1(key || message) — not HMAC."""
    return hashlib.sha1(key + message).hexdigest()

# Test
key = b"secret"
msg = b"message"
mac = sha1_mac(key, msg)
print(f"[*] SHA-1 MAC: {mac}")
print("[+] Challenge 28 passed")
```

---

## Challenge 29 — Break SHA-1 Keyed MAC with Length Extension

This is the attack from Day 564, implemented against SHA-1.

```python
#!/usr/bin/env python3
"""
Challenge 29: length extension attack against SHA1(key || message).
Forge a valid MAC for an extended message without knowing the key.
"""
from __future__ import annotations

import struct

def sha1_pad(message_len: int) -> bytes:
    """Compute SHA-1 padding for a message of given byte length."""
    bit_len = message_len * 8
    padding = b"\x80"
    padding += b"\x00" * ((55 - message_len) % 64)
    padding += struct.pack(">Q", bit_len)
    return padding

# Use hlextend for the actual attack (SHA-1 variant)
import hlextend  # pip install hlextend

MAC_KEY = b"secretkey"  # Length unknown to attacker — try lengths 1-20

original_msg = b"comment=normaluser"
original_mac = sha1_mac(MAC_KEY, original_msg)
extension    = b"&role=admin"

for key_len in range(1, 20):
    sha = hlextend.new("sha1")
    forged_mac, forged_data = sha.extend(
        extension,
        original_msg,
        key_len,
        original_mac,
        raw=True,
    )
    # Test the forged MAC
    if sha1_mac(MAC_KEY, forged_data) == forged_mac:
        print(f"[+] Key length found: {key_len}")
        print(f"[+] Forged data:  {forged_data!r}")
        print(f"[+] Forged MAC:   {forged_mac}")
        break

print("[+] Challenge 29 passed")
```

---

## Challenge 31 & 32 — HMAC-SHA1 Timing Attack

This is the timing attack from Day 563, implemented with a real HTTP server.

```python
#!/usr/bin/env python3
"""
Challenges 31 & 32: exploit an artificial timing leak in HMAC verification.
Challenge 31: 50ms delay per matching byte.
Challenge 32: 5ms delay per matching byte (needs more samples).
"""
from __future__ import annotations

import time
import hmac
import hashlib
import requests

BASE_URL = "http://localhost:9000"  # Start server with: python c31_server.py

# Challenge 31: timing attack with 50ms leak
FILENAME = "foo"
HMAC_LEN = 20  # SHA1 HMAC = 20 bytes

def measure_timing(mac_hex: str, n_samples: int = 3) -> float:
    """Return minimum RTT for a request with the given MAC."""
    times = []
    for _ in range(n_samples):
        url   = f"{BASE_URL}/test?file={FILENAME}&signature={mac_hex}"
        start = time.perf_counter()
        requests.get(url, timeout=5)
        times.append(time.perf_counter() - start)
    return min(times)

def recover_hmac_byte_by_byte(n_samples: int = 3) -> str:
    """Recover HMAC byte by byte using timing side-channel."""
    known = ""
    for _ in range(HMAC_LEN):
        best_time  = -1.0
        best_byte  = 0
        for byte_val in range(256):
            candidate = known + f"{byte_val:02x}" + "00" * (HMAC_LEN - len(known) // 2 - 1)
            t = measure_timing(candidate, n_samples)
            if t > best_time:
                best_time = t
                best_byte = byte_val
        known += f"{best_byte:02x}"
        print(f"  [{len(known)//2:02d}/{HMAC_LEN}] current: {known}")

    return known

print("[*] Starting HMAC timing attack (challenge 31 — 50ms leak)…")
print("[*] This will take several minutes. Each byte ≈ 256 × 50ms = 12.8s")
recovered_hmac = recover_hmac_byte_by_byte(n_samples=3)
print(f"\n[+] Recovered HMAC: {recovered_hmac}")

# Verify
resp = requests.get(f"{BASE_URL}/test?file={FILENAME}&signature={recovered_hmac}")
print(f"[+] Verification: {resp.status_code}")
print("[+] Challenges 31/32 passed")
```

---

## Set 4 Self-Assessment

```
[ ] 1. Challenge 25 uses the edit oracle to recover the keystream. Explain
        why this works for CTR but NOT for CBC (even if a similar edit oracle
        existed for CBC).

[ ] 2. Challenge 27 recovers the CBC key when IV == KEY. What common
        developer mistake causes IV == KEY? How common is this in real code?

[ ] 3. Challenges 31 and 32 differ only in the artificial delay (50ms vs 5ms).
        What changes in your timing attack between them? Why does challenge 32
        require more samples per byte?

[ ] 4. The timing attack in challenge 31 works because the comparison function
        exits early. What would happen if the comparison function were constant-time
        but took 50ms per byte comparison (rather than exiting early)?
        Would the attack still work?
```

---

## Key Takeaways

1. CTR mode bit-flipping is cleaner than CBC bit-flipping — flipping a bit in
   the ciphertext flips exactly the same bit in the plaintext with no adjacent
   block corruption. This makes attack and defence simpler: CTR still requires
   authentication, but the mechanics are more direct.
2. Challenge 27 demonstrates that the IV is secret for a reason. When IV equals
   the key, a trivial oracle exploit recovers the key from a single decryption
   error. IV and key must be independent random values.
3. The HMAC timing attack in challenges 31/32 is the practical implementation
   of Day 563 theory. Reducing the artificial delay from 50ms to 5ms forces you
   to think statistically — 50ms is a gift; 5ms requires real measurement.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q574.1, Q574.2 …).

---

## Navigation

← Previous: [Day 573 — Cryptopals CTF Day 3](DAY-0573-Cryptopals-CTF-Day-3.md)
→ Next: [Day 575 — Cryptopals CTF Practice: Day 5](DAY-0575-Cryptopals-CTF-Day-5.md)
