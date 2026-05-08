---
title: "Crypto CTF Sprint — Day 3: CBC / CTR / GCM Challenges"
tags: [cryptography, CTF, CBC, CTR, GCM, padding-oracle, bit-flip,
  nonce-reuse, GCM-forgery, authentication-bypass, GHASH, forbidden-attack,
  AES, sprint, CWE-326]
module: 09-Crypto-01
day: 585
prerequisites:
  - Day 584 — Crypto CTF Sprint Day 2 (DH/ECDH/ECDSA)
  - Day 561 — CBC Padding Oracle
  - Day 572 — Cryptopals CTF Day 2 (CBC bit-flip, CTR basics)
related_topics:
  - Cryptopals CTF Day 1-12 (Days 571-582)
  - Padding Oracle (Day 561)
---

# Day 585 — Crypto CTF Sprint: Day 3 (CBC / CTR / GCM)

> "Symmetric cipher vulnerabilities in CTF almost always reduce to one of three
> root causes: the IV is predictable, the nonce is reused, or the authentication
> is missing. GCM nonce reuse is the modern version: a single repeated nonce
> hands you the authentication key H and lets you forge any ciphertext. That is
> not a theoretical attack — it killed real TLS sessions."
>
> — Ghost

---

## Goals

Sprint through the most common AES CTF attack patterns: CBC padding oracle
(review and edge cases), CTR nonce reuse, GCM nonce reuse (forbidden attack),
and GCM authentication tag forgery. Build the complete attacker toolkit for
symmetric cipher challenges.

**Prerequisites:** Days 561, 572, and the Cryptopals CTF series (571–582).
**Estimated lab time:** 5 hours.

---

## AES Mode Vulnerability Fingerprint

| Mode | Vulnerability | Attack | Key Tell |
|---|---|---|---|
| CBC | Padding oracle | Byte-by-byte decryption | Server returns 200/403 pattern |
| CBC | Predictable IV (ECB-like) | BEAST attack / IV prediction | IV = last ciphertext block |
| CBC | IV=0, attacker controls input | Bit-flip to forge | Attacker data in known position |
| CTR | Nonce reuse | XOR keystreams, freq analysis | Two ciphertexts of known length |
| CTR | Bit-flip | Direct 1-bit = 1-bit flip | Direct, no block corruption |
| GCM | Nonce reuse | Forbidden attack — recover H | Same (key, nonce) pair seen twice |
| GCM | Weak H (H=0) | Universal forgery | Edge case: key generates H=0 |
| GCM | No nonce randomness | Predictable nonce → reuse | Counter starts at 1, resets |

---

## Attack 1 — CBC Padding Oracle (Advanced Variants)

The basic padding oracle was covered in Day 561. CTF variants include:

**Variant A: Non-standard error codes.** The oracle might return a timing difference
instead of a HTTP status code. Use statistical timing from Day 563.

**Variant B: Last-block stripping.** The server only returns an error if the LAST
block has bad padding. You still attack all blocks by rearranging the ciphertext.

**Variant C: CBC-R (decryption oracle in reverse).** Given only a decryption oracle
(no encryption), use the padding oracle backward to encrypt arbitrary plaintext.

```python
#!/usr/bin/env python3
"""
CBC-R: encrypt arbitrary plaintext using only a padding oracle (decryption service).
"""
from __future__ import annotations

import os
from Crypto.Cipher import AES


BLOCK = 16
KEY   = os.urandom(BLOCK)


def cbc_decrypt_oracle(ciphertext: bytes, iv: bytes) -> bytes:
    """Server: decrypt and return plaintext (simulated)."""
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(ciphertext)


def cbc_padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    """Server: returns True iff padding is valid."""
    pt = cbc_decrypt_oracle(ciphertext, iv)
    n  = pt[-1]
    if n < 1 or n > BLOCK:
        return False
    return pt[-n:] == bytes([n] * n)


def oracle_decrypt_block(ct_block: bytes, prev_block: bytes) -> bytes:
    """
    Decrypt a single 16-byte block using the padding oracle.
    Returns the 16-byte plaintext.
    """
    # We need to find I[] such that AES_k_decrypt(ct_block) == I
    # Then pt = I XOR prev_block
    I  = bytearray(BLOCK)
    for byte_pos in range(BLOCK - 1, -1, -1):
        pad_byte = BLOCK - byte_pos
        # Set known intermediate bytes to produce pad_byte
        crafted_prev = bytearray(BLOCK)
        for k in range(byte_pos + 1, BLOCK):
            crafted_prev[k] = I[k] ^ pad_byte
        # Brute-force byte at byte_pos
        for guess in range(256):
            crafted_prev[byte_pos] = guess
            if cbc_padding_oracle(ct_block, bytes(crafted_prev)):
                # Check for false positive at last byte (pad could be \x02\x02 etc.)
                if byte_pos == BLOCK - 1:
                    crafted_prev[byte_pos - 1] ^= 1
                    if not cbc_padding_oracle(ct_block, bytes(crafted_prev)):
                        continue
                    crafted_prev[byte_pos - 1] ^= 1
                I[byte_pos] = guess ^ pad_byte
                break
    return bytes(I[k] ^ prev_block[k] for k in range(BLOCK))


def cbcr_encrypt(target_plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt arbitrary plaintext using only a padding oracle.
    Works backward: solve for each ciphertext block such that
    decryption produces the desired plaintext.
    """
    from Crypto.Util.Padding import pad
    padded = pad(target_plaintext, BLOCK)
    n_blocks = len(padded) // BLOCK

    # Start with a random final "ciphertext" block C_n
    c_blocks = [os.urandom(BLOCK)]   # C_n (random, will be "prev" for decryption)

    for i in range(n_blocks - 1, -1, -1):
        target_pt_block = padded[i * BLOCK : (i + 1) * BLOCK]
        c_prev          = c_blocks[0]   # Current "next" block

        # Find I = AES_k_decrypt(c_prev) using the oracle
        # We construct a fake-prev such that decryption of c_prev produces valid padding
        I = bytearray(BLOCK)
        for byte_pos in range(BLOCK - 1, -1, -1):
            pad_byte = BLOCK - byte_pos
            crafted  = bytearray(BLOCK)
            for k in range(byte_pos + 1, BLOCK):
                crafted[k] = I[k] ^ pad_byte
            for guess in range(256):
                crafted[byte_pos] = guess
                if cbc_padding_oracle(c_prev, bytes(crafted)):
                    if byte_pos == BLOCK - 1:
                        crafted[byte_pos - 1] ^= 1
                        if not cbc_padding_oracle(c_prev, bytes(crafted)):
                            continue
                        crafted[byte_pos - 1] ^= 1
                    I[byte_pos] = guess ^ pad_byte
                    break

        # New ciphertext block: c_new = I XOR target_pt_block
        c_new = bytes(I[k] ^ target_pt_block[k] for k in range(BLOCK))
        c_blocks.insert(0, c_new)

    iv = c_blocks[0]
    ct = b"".join(c_blocks[1:])
    return iv, ct


# Demo
target = b"admin=true;role=superuser"
iv_enc, ct_enc = cbcr_encrypt(target)
recovered      = cbc_decrypt_oracle(ct_enc, iv_enc)
print(f"[+] CBC-R encrypted:  {target!r}")
print(f"[+] CBC-R decrypted:  {recovered.rstrip(bytes([recovered[-1]]))}") # strip pad
assert recovered.rstrip(bytes([recovered[-1]])) == target
print("[+] CBC-R attack succeeded — encrypted without AES key!")
```

---

## Attack 2 — GCM Nonce Reuse (Forbidden Attack)

AES-GCM produces ciphertext `C` and authentication tag `T` from plaintext `P`,
nonce `N`, and additional authenticated data `A`:

```
Keystream K = AES_k(N || 0...) ⊕ counter_blocks
C = P XOR K
H = AES_k(0^128)                       ← GHASH key (depends only on k)
T = GHASH(H, A, C) XOR AES_k(N || 1)  ← authentication tag
```

If the **same nonce is used twice** with different plaintexts (P1, P2), the
keystreams are identical: `K1 = K2`. Therefore:

```
C1 XOR C2 = P1 XOR P2   ← same as CTR nonce reuse!
T1 XOR T2 = GHASH(H, A1, C1) XOR GHASH(H, A2, C2)
```

From two (ciphertext, tag) pairs with the same nonce, you can recover `H`
(the GHASH key) and then forge arbitrary tags — breaking authentication entirely.

```python
#!/usr/bin/env python3
"""
GCM Forbidden Attack: recover H and forge tags when nonce is reused.

Reference: 'Nonce Disrespecting Adversaries' (Joux 2006; Bock et al. 2016).
"""
from __future__ import annotations

import os
from Crypto.Cipher import AES


# ── GCM primitives ────────────────────────────────────────────────────────────

GF2_128_MOD = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1   # GF(2^128) irreducible poly


def gf2_128_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^128) with the GCM irreducible polynomial."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a >> 128:
            a ^= GF2_128_MOD
        b >>= 1
    return result


def ghash(H: int, A: bytes, C: bytes) -> int:
    """Compute GHASH(H, A, C)."""
    def pad16(b: bytes) -> bytes:
        return b + b"\x00" * ((-len(b)) % 16)

    data = pad16(A) + pad16(C)
    data += len(A).to_bytes(8, "big") + len(C).to_bytes(8, "big")
    x = 0
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16], "big")
        x     = gf2_128_mul(x ^ block, H)
    return x


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                aad: bytes = b"") -> tuple[bytes, bytes]:
    """AES-GCM encryption. Returns (ciphertext, tag)."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


# ── Forbidden attack: recover H from two (nonce, C, T) pairs ──────────────────

KEY   = os.urandom(16)
NONCE = os.urandom(12)   # Same nonce used twice — the vulnerability

P1  = b"Transfer $1000 to Alice."
P2  = b"Transfer $9000 to Mallory"
A1  = b"AccountID: 1001"
A2  = b"AccountID: 2002"

C1, T1 = gcm_encrypt(KEY, NONCE, P1, A1)
C2, T2 = gcm_encrypt(KEY, NONCE, P2, A2)

# H satisfies the polynomial equation:
# T1 = GHASH(H, A1, C1) XOR S   (where S = AES_k(nonce || 1))
# T2 = GHASH(H, A2, C2) XOR S
# T1 XOR T2 = GHASH(H, A1, C1) XOR GHASH(H, A2, C2)
# This is a polynomial equation in H over GF(2^128).
# Solving for H requires finding roots of this polynomial — use SageMath.

# For the demo: we know KEY so we can compute H directly.
H_actual = int.from_bytes(AES.new(KEY, AES.MODE_ECB).encrypt(b"\x00" * 16), "big")
print(f"[*] H (GHASH key) = {H_actual:#x}")

# Verify: GHASH equation holds
S         = int.from_bytes(AES.new(KEY, AES.MODE_ECB).encrypt(NONCE + b"\x00\x00\x00\x01"), "big")
T1_int    = int.from_bytes(T1, "big")
T2_int    = int.from_bytes(T2, "big")
T1_check  = ghash(H_actual, A1, C1) ^ S
T2_check  = ghash(H_actual, A2, C2) ^ S

assert T1_check == T1_int, "GHASH computation mismatch for T1"
assert T2_check == T2_int, "GHASH computation mismatch for T2"
print("[+] GHASH equations verified")

# ── Forgery: once H and S are known, forge tag for any (A_forged, C_forged) ──
# S is recoverable once H is known: S = T1 XOR GHASH(H, A1, C1)

S_recovered = T1_int ^ ghash(H_actual, A1, C1)
assert S_recovered == S, "S recovery failed"
print(f"[+] S (E_k(nonce||1)) recovered: {S_recovered:#x}")

# Forge: change A2/C2 to arbitrary content
A_forged = b"AccountID: 9999"
C_forged = C2   # Keep same ciphertext (different plaintext meaning via A field)
T_forged = (ghash(H_actual, A_forged, C_forged) ^ S_recovered).to_bytes(16, "big")

# Verify forged tag with actual AES-GCM
cipher_verify = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
cipher_verify.update(A_forged)
try:
    cipher_verify.decrypt_and_verify(C_forged, T_forged)
    print("[+] Forged tag accepted! GCM authentication bypassed.")
except Exception as exc:
    print(f"[!] Verification failed: {exc}")

print("[+] GCM Forbidden Attack demonstrated")
```

---

## Attack 3 — CTR Nonce Reuse (Multi-Message)

When multiple messages share the same (key, nonce) in CTR mode:

```
K = AES_k(nonce || 0) || AES_k(nonce || 1) || ...
C1 = P1 XOR K
C2 = P2 XOR K

C1 XOR C2 = P1 XOR P2
```

Knowing any partial plaintext from one message lets you recover the keystream
and decrypt all others. Against English text: use frequency analysis.

```python
#!/usr/bin/env python3
"""
CTR nonce reuse: recover keystream from many messages sharing (key, nonce).
Uses repeated-key XOR analysis with frequency scoring.
"""
from __future__ import annotations

import os
from Crypto.Cipher import AES
from collections import Counter


KEY   = os.urandom(16)
NONCE = os.urandom(8)   # Same nonce for ALL messages — the bug

PLAINTEXTS = [
    b"I am the very model of a modern major general",
    b"I've information vegetable, animal, and mineral",
    b"I know the kings of England, and I quote the fights",
    b"historical, from Marathon to Waterloo, in order categorical",
    b"I'm very well acquainted, too, with matters mathematical",
    b"I understand equations, both the simple and quadratical",
    b"About binomial theorem I am teeming with a lot o' news",
    b"With many cheerful facts about the square of the hypotenuse",
]

min_len    = min(len(p) for p in PLAINTEXTS)
ciphertexts = []
for pt in PLAINTEXTS:
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    ciphertexts.append(cipher.encrypt(pt))

# Truncate to min length for analysis
trunc = [c[:min_len] for c in ciphertexts]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def score_english(text: bytes) -> float:
    """Score a byte string for English frequency."""
    freq = " etaoinshrdlucmfwypvbgkjqxz"
    score = 0.0
    for b in text:
        c = chr(b).lower()
        if c in freq:
            score += len(freq) - freq.index(c)
    return score


def recover_keystream_byte(col: bytes) -> int:
    """
    Given one column of XOR'd ciphertexts (each byte = keystream[i] XOR p[i]),
    find the keystream byte that produces the most English-like column.
    """
    best_score = -1
    best_k     = 0
    for k in range(256):
        col_dec = bytes(b ^ k for b in col)
        s = score_english(col_dec)
        if s > best_score:
            best_score = s
            best_k     = k
    return best_k


# Stack the ciphertexts column-by-column and recover keystream
keystream = bytes(
    recover_keystream_byte(bytes(ct[i] for ct in trunc))
    for i in range(min_len)
)

# Decrypt all plaintexts with recovered keystream
print("[*] Recovered plaintexts (first 50 bytes):")
for ct in ciphertexts:
    recovered = xor_bytes(ct[:min_len], keystream)
    print(f"  {recovered[:50]}")

# Verify first plaintext
assert xor_bytes(ciphertexts[0][:min_len], keystream) == PLAINTEXTS[0][:min_len]
print("[+] CTR nonce reuse attack succeeded")
```

---

## CTF Problem Set: CBC / CTR / GCM Challenges

```
Challenge A — Classic Padding Oracle
  Given: AES-CBC encrypted cookie, server returns 200/500
  Goal: Decrypt the cookie, find the admin flag inside
  Tool: Day 561 padding oracle. Standard attack.

Challenge B — IV Leak
  Given: AES-CBC, but IV is the MD5 hash of the key
  Goal: If you can trigger an error that leaks the IV, recover the key
  Tool: Challenge 27 from Cryptopals (Day 574). IV=MD5(key) → same
        attack as IV=key with a one-way function in between.

Challenge C — CTR Seek
  Given: 10 ciphertexts under the same CTR nonce
  Goal: Decrypt the second message given you know the first
  Approach: C1 XOR C2 = P1 XOR P2 → if P1 known, P2 = C2 XOR C1 XOR P1

Challenge D — GCM Nonce Counter Reset
  Given: AES-GCM server that resets its nonce counter every 2^16 requests
  Goal: After 65536 requests, nonces repeat. Apply the forbidden attack.
  Tool: Collect two ciphertext/tag pairs under the same nonce. Recover H.

Challenge E — GCM Weak Key (H=0)
  Given: AES-GCM with a specific key that produces H=0
  Goal: Forge the authentication tag for any ciphertext
  Analysis: GHASH(0, A, C) = 0 for all inputs. Tag = AES_k(nonce||1).
            If you can observe any valid tag, it IS AES_k(nonce||1).
            Forge by submitting any C with that tag.

Challenge F — Streaming CTR + Partial Plaintext Known
  Given: CTR encrypted network traffic, 20 bytes of known plaintext
         at offset 100
  Goal: Recover plaintext at offsets 0–100 and 120–200
  Tool: Known plaintext at offset → recover keystream bytes at that offset
        → CTR keystream is contiguous → no help outside the known window.
        Use frequency analysis for the unknown portions.
```

---

## Self-Assessment

```
[ ] 1. In CBC-R, you encrypted arbitrary plaintext using only a decryption oracle.
        This means any CBC padding oracle is ALSO an encryption oracle for the
        attacker. What does this imply for web applications that expose a
        CBC decryption error side-channel?

[ ] 2. The GCM Forbidden Attack recovers H from two (nonce, C, T) pairs.
        If the attacker has only ONE pair, can they still forge tags?
        What additional information would they need?

[ ] 3. AES-GCM is widely recommended over AES-CBC. List three properties
        of GCM that make it superior to CBC for authenticated encryption.
        Then describe the one condition under which GCM is WORSE than
        standard CBC+HMAC.

[ ] 4. GCM nonce reuse is catastrophic (breaks both confidentiality and
        integrity). CTR nonce reuse only breaks confidentiality. Explain
        why the authentication tag in GCM makes nonce reuse MORE dangerous,
        not less.
```

---

## Module 09 Crypto Attacks — Progress Checklist

Complete this checklist before advancing to Module 10:

```
Symmetric attacks:
[  ] CBC Padding Oracle (Days 561-562)
[  ] CTR Bit-Flip / Nonce Reuse (Day 572-573)
[  ] GCM Nonce Reuse / Forbidden Attack (Day 585)
[  ] CBC-MAC Forgery (Day 580)
[  ] CRIME Compression Oracle (Day 581)

Hash attacks:
[  ] SHA-2 Length Extension (Days 564-565)
[  ] Joux Multicollision (Day 582)
[  ] Timing attack on HMAC (Day 563)

Asymmetric attacks:
[  ] RSA cube root / broadcast / common modulus (Day 567)
[  ] RSA Parity Oracle (Day 578)
[  ] Bleichenbacher e=3 forgery (Day 576)
[  ] Bleichenbacher PKCS#1 v1.5 oracle (Day 579)
[  ] RSA Unpadded Oracle (Day 576)
[  ] Wiener's attack (Day 583)
[  ] Common factor GCD (Day 583)

Signature attacks:
[  ] ECDSA Nonce Reuse (Days 569-570)
[  ] DSA Nonce Recovery from k / repeated r (Days 577)
[  ] DSA Parameter Tampering (Day 578)
[  ] Bleichenbacher e=3 forgery (Day 576)

Key exchange attacks:
[  ] DH Parameter Injection MITM (Day 575)
[  ] DH Pohlig-Hellman (Day 568)
[  ] ECDH Invalid Curve (Day 568)
[  ] Baby-Step Giant-Step DLP (Day 584)
```

---

## Key Takeaways

1. **GCM nonce reuse is catastrophic and irreversible.** A single nonce reuse
   hands the attacker both the keystream AND the GHASH authentication key.
   Once H is known, every past and future ciphertext encrypted with that nonce
   can be forged. Use hardware counters or 96-bit random nonces.
2. **CBC-R demonstrates the power of decryption oracles.** Any CBC padding oracle
   is not just a decryption primitive — it is an encryption primitive. An
   attacker who can observe padding errors can encrypt arbitrary data without
   the AES key.
3. **Mode selection determines the attack surface.** CTR mode and GCM mode have
   fundamentally different failure modes. CTR without authentication is weak.
   GCM with nonce reuse is catastrophic. Authenticated encryption with unique
   nonces (AES-GCM with hardware counter, or XChaCha20-Poly1305 with random
   nonce) is the correct choice for new code.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q585.1, Q585.2 …).

---

## Navigation

← Previous: [Day 584 — Crypto CTF Sprint Day 2](DAY-0584-Crypto-CTF-Sprint-Day-2.md)
→ Next: Day 586 — Module 10 (upcoming)
