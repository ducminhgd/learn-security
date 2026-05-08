---
title: "ECB Cut-and-Paste — Block Boundary Manipulation"
tags: [cryptography, ECB, block-cipher, cut-and-paste, block-oracle,
  AES-ECB, CWE-327, T1600, deterministic-encryption, role-escalation]
module: 09-Crypto-01
day: 566
prerequisites:
  - Day 029 — Symmetric Encryption and ECB Weakness
  - Day 562 — Padding Oracle Lab (block cipher mindset)
related_topics:
  - Padding Oracle Attack (Day 561)
  - RSA Attack Lab (Day 567)
  - Cryptopals Set 2 (Day 572)
---

# Day 566 — ECB Cut-and-Paste

> "ECB mode encrypts each block independently. That is not a feature — it is
> a confession that the designer did not think about what an attacker can do
> with two ciphertexts from the same key. Cut, paste, submit. Three steps to
> privilege escalation."
>
> — Ghost

---

## Goals

- Understand why ECB's determinism makes block boundaries a manipulation surface.
- Implement the ECB cut-and-paste attack to forge an admin role token.
- Extend the concept to the ECB byte-at-a-time decryption technique.
- Confirm that CBC (with proper IV) eliminates this class of attack.

**Prerequisites:** Day 029 (ECB mode, the penguin problem), Day 562 (block
cipher lab mindset).
**Estimated study time:** 3 hours.

---

## 1. Recon — Why ECB Is Malleable

### ECB in One Sentence

ECB (Electronic Codebook) encrypts every 16-byte block independently using
the same key:

```
C₁ = AES_Encrypt(key, P₁)
C₂ = AES_Encrypt(key, P₂)
C₃ = AES_Encrypt(key, P₃)
```

**Critical property:** identical plaintext blocks always produce identical
ciphertext blocks. No chaining. No IV. No context.

### What This Means for an Attacker

1. **Rearrange:** swap C₂ and C₃ to swap plaintext blocks P₂ and P₃.
2. **Replace:** replace C₂ from message A with C₂ from message B — the server
   decrypts the combined ciphertext and sees a mix of both plaintexts.
3. **Detect structure:** identical ciphertext blocks reveal identical plaintext
   blocks, leaking data patterns even without the key.

---

## 2. Exploit — The Cut-and-Paste Attack

### Scenario

A web application issues profile tokens using AES-ECB:

```
profile = "email=alice@corp.com&uid=10&role=user"
token   = AES_ECB_Encrypt(key, profile)
```

The attacker controls their email address. They want to forge a token that
decrypts to `role=admin`.

### Block Layout Analysis

AES operates on 16-byte blocks. Map the token format to blocks:

```
Byte position:  0         16        32        48
Plaintext:     |email=alice@corp|.com&uid=10&rol|e=user          |
Block:         |    Block 0     |    Block 1     |    Block 2     |
```

Block 2 contains `e=user` followed by PKCS#7 padding. If we can replace
block 2 with a block that decrypts to `e=admin\x09\x09\x09\x09\x09\x09\x09\x09\x09`
(PKCS#7-padded "e=admin"), we forge the admin role.

### Attack Steps

**Step 1:** Craft an email that places `admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b`
exactly at a block boundary.

```
email=         ← 6 bytes
AAAAAAAAAAadmin\x0b...\x0b  ← 10 bytes of 'A' padding + "admin" + PKCS7 fill
@corp.com      ← rest
```

Layout:
```
|email=AAAAAAAAAA|admin\x0b\x0b\x0b\x0b|...|
|    Block 0     |    Block 1 (target)  |...|
```

Block 1 encrypts to `C_admin` — the ciphertext of a properly-padded "admin" block.

**Step 2:** Craft an email that pushes `role=` to the start of the final block.

```
email=alice@corp.com&uid=10&role=
```
Must align so `role=` falls at byte 32 (start of block 2).

Test alignment:
```
|email=alice@corp|.com&uid=10&role|=user + padding |
```
`role=` starts at byte 32 → block 2 begins with `role=`. If we can make block 2
start with `role=admin\x09...` we win.

Actually simpler: we just need to position things so the last block is purely `role=user`.
Then we replace that last block with our crafted `C_admin`.

### Minimal Exploit

```python
#!/usr/bin/env python3
"""
ecb_cut_paste.py — ECB cut-and-paste attack to forge an admin role token
"""
from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY = os.urandom(16)   # Server secret — attacker does not know this

# ── Server-side functions ─────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - len(data) % block
    return data + bytes([n] * n)

def pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    return data[:-n]

def profile_for(email: str) -> str:
    """Create a profile string, stripping metacharacters."""
    email = email.replace('&', '').replace('=', '')
    return f"email={email}&uid=10&role=user"

def encrypt_profile(email: str) -> bytes:
    profile = profile_for(email).encode()
    padded  = pkcs7_pad(profile)
    cipher  = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())
    enc     = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def decrypt_profile(token: bytes) -> dict:
    cipher = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())
    dec    = cipher.decryptor()
    raw    = dec.update(token) + dec.finalize()
    plain  = pkcs7_unpad(raw).decode()
    # Parse key=value pairs
    return dict(kv.split('=') for kv in plain.split('&'))

# ── Attacker-side exploit ─────────────────────────────────────────────────

def ecb_cut_paste_attack() -> bytes:
    """Return a forged token that decrypts to role=admin."""

    # ── Step 1: Harvest C_admin ──────────────────────────────────────────
    # We need a block that decrypts to "admin" + PKCS#7(11)
    # "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" = 16 bytes exactly
    # Place it at block boundary: email= (6 bytes) + 10 'A's padding = 16 bytes
    # → block 1 = "admin\x0b×11"

    crafted_email_1 = "AAAAAAAAAA" + "admin" + "\x0b" * 11 + "@x.com"
    token_1  = encrypt_profile(crafted_email_1)
    c_admin  = token_1[16:32]   # block 1 = the admin block

    # Verify what block 1 decrypts to
    # (for debugging only — attacker cannot do this without the key)
    print(f"[*] C_admin (hex): {c_admin.hex()}")

    # ── Step 2: Align real email so last block is purely "role=user" padding
    # "email=" = 6 bytes.  We want the profile to end with:
    # ... &role= | user + padding
    # Profile: email=<email>&uid=10&role=user
    # Lengths:  6 + len(email) + 14 = total
    # We need total ≡ 0 (mod 16) BEFORE "user" so that "user" starts at a
    # block boundary by itself — actually we want "&role=" to end at a block
    # boundary, i.e. (6 + len(email) + "&uid=10&role=".len()) ≡ 0 mod 16
    # "&uid=10&role=" = 13 bytes
    # 6 + len(email) + 13 ≡ 0 mod 16  →  len(email) ≡ -19 ≡ 13 (mod 16)
    # Simplest: email with 13 chars, e.g. "AAAA@corp.com" (13 chars)

    crafted_email_2 = "AAAA@corp.com"   # 13 characters
    token_2 = encrypt_profile(crafted_email_2)

    # token_2 layout:
    # Block 0: "email=AAAA@corp"  (15 chars of profile start)
    # Block 1: ".com&uid=10&role"  ← ends with "role"
    # Block 2: "=user\x0c×12"     ← "=user" + padding = 16 bytes

    # ── Step 3: Swap last block ──────────────────────────────────────────
    # Replace block 2 ("=user" + padding) with c_admin ("admin" + \x0b×11)
    # But wait — we need "role=admin", not "role" + "admin" in separate blocks.
    # Let me re-think the alignment.

    # Correct target:
    # We want the last two blocks to be:
    #   "...&role=" at end of one block
    #   "admin\x0b×11" as the next (and last) block
    # So we need "&role=" to land at a block boundary.
    # Profile structure: "email=" + email + "&uid=10&role=user"
    # "&uid=10&role=" = 13 bytes
    # We need "email=" + email_bytes to be a multiple of 16 minus 0
    # AND "email=" + email_bytes + "&uid=10&role=" to be a multiple of 16.
    # 6 + len(email) + 13 ≡ 0 mod 16
    # len(email) ≡ -19 mod 16 = -3 mod 16 = 13 mod 16
    # Minimal: len = 13 chars → "AAAA@corp.com"

    # With "AAAA@corp.com" (13 chars):
    # Block 0 (bytes 0-15):  "email=AAAA@corp"
    # Block 1 (bytes 16-31): ".com&uid=10&role"
    # Block 2 (bytes 32-47): "=user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"

    # Hmm — block boundary cuts "role=" across blocks 1 and 2 as "role" | "=user".
    # We want "=user" block replaced with "=admin\x09×9".
    # Our c_admin block was built as "admin\x0b×11". We need "=admin\x09×9" instead.

    # Re-harvest C_eq_admin:
    # "=" + "admin" = 6 bytes. Pad to 16: "=admin" + "\x09"*9 + 1 byte... wait
    # "=admin" = 6 bytes, \x0a*10 = 10 bytes → total 16 bytes
    c_eq_admin_plain = b"=admin" + b"\x0a" * 10

    # Place "=admin\x0a×10" at block boundary:
    # "email=" + 10 'A's = 16 bytes → block 0 ends exactly
    # block 1 = "=admin\x0a×10" (our target)
    crafted_email_3 = "A" * 10 + "=admin" + "\x0a" * 10 + "@x.com"
    token_3  = encrypt_profile(crafted_email_3)
    c_eq_admin = token_3[16:32]   # block 1

    # Final forged token: token_2 blocks 0-1 + c_eq_admin
    forged = token_2[:32] + c_eq_admin
    return forged

# ── Run the attack ────────────────────────────────────────────────────────
forged_token = ecb_cut_paste_attack()
profile = decrypt_profile(forged_token)
print(f"\n[+] Forged profile: {profile}")
assert profile.get('role') == 'admin', "Attack failed — role is not admin"
print("[+] Role escalation successful: role = admin")
```

---

## 3. ECB Byte-at-a-Time Decryption

A second ECB attack: if the server appends a secret suffix to your input before
encrypting, you can decrypt the suffix one byte at a time.

```
encrypt("A" × 15 + ?)  → block 0 = AES("A"×15 + secret[0])
```

Bruteforce the unknown byte: try all 256 values of `?`, compare with the oracle.
When they match, you have `secret[0]`. Repeat for each subsequent byte by
adjusting the prefix length.

This is the **Cryptopals Set 2 Challenge 12** — you will implement it fully in
the CTF practice days (Day 572).

---

## 4. Detect

```
# Detection signal: identical ciphertext blocks in different tokens

# If the application uses ECB and user-controlled input is embedded before
# secret data, tokens from different users may share block patterns.

# Example: two users with email = "alice@corp.co" and "alice@corp.co"
# → blocks 0 and 1 are identical across their tokens

# Defender detection: scan session tokens for repeated 16-byte blocks
# → presence of identical 16-byte blocks in a token ≈ ECB mode in use
# → alert: migrate to AES-GCM or AES-CBC-HMAC

# WAF rule: block submission of tokens that contain binary % 16 == 0 aligned
# repeated byte sequences — extremely low false-positive rate
```

---

## 5. Harden — Fix

```python
# BAD: AES-ECB — deterministic, malleable, never appropriate for tokens
cipher = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())

# GOOD 1: AES-CBC with random IV — eliminates block reuse attacks
IV = os.urandom(16)
cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
# Still needs MAC (add HMAC or use GCM)

# GOOD 2: AES-GCM — authenticated + non-deterministic + no block boundaries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)
aesgcm = AESGCM(KEY)
token = nonce + aesgcm.encrypt(nonce, profile.encode(), associated_data=None)
# Any block-level manipulation invalidates the authentication tag
```

**Rule:** ECB mode must never be used for anything that an attacker can observe
or influence. The only legitimate use of ECB is as a primitive building block
inside higher constructions — and even then, use a purpose-built mode instead.

---

## Real-World Cases

| Context | ECB misuse | Impact |
|---|---|---|
| Zoom (2020) | Meeting encryption used ECB for some key derivation paths | Pattern leakage in video streams; fixed in later versions |
| PHP session serialisation | Some PHP session handlers serialised ECB-encrypted blobs | Token forgery in affected configurations |
| Cryptopals challenges | Sets 1 and 2 teach this exact attack | Education — designed to be broken |
| WEP (802.11) | RC4 with static IV (functionally similar to ECB for repeating frames) | Complete key recovery with enough traffic |

---

## Key Takeaways

1. ECB mode is deterministic. Determinism is the enemy of security for
   encryption. If the same input ever produces the same output, an attacker
   can build a codebook and rearrange blocks without the key.
2. The cut-and-paste attack requires only the ability to request tokens for
   crafted inputs and concatenate ciphertext blocks. No key, no cryptanalysis —
   just careful block alignment.
3. The byte-at-a-time attack requires only an encryption oracle for
   attacker-controlled prefixes. Again, no key needed. ECB's lack of chaining
   makes every block independently attackable.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q566.1, Q566.2 …).

---

## Navigation

← Previous: [Day 565 — Length Extension Lab](DAY-0565-Length-Extension-Lab.md)
→ Next: [Day 567 — RSA Attack Lab](DAY-0567-RSA-Attack-Lab.md)
