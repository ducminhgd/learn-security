---
title: "Cryptopals CTF Practice — Day 6: Set 6 Part 1 (RSA Unpadded Oracle + e=3 Forgery)"
tags: [cryptography, cryptopals, CTF, RSA, unpadded-oracle, bleichenbacher-e3,
  signature-forgery, cube-root, PKCS1, set-6]
module: 09-Crypto-01
day: 576
prerequisites:
  - Day 575 — Cryptopals CTF Day 5 (Set 5 complete)
  - Day 567 — RSA Attack Lab (small exponent, CRT)
related_topics:
  - Cryptopals CTF Day 7 (Day 577)
  - RSA Attack Lab (Day 567)
  - Bleichenbacher PKCS#1 v1.5 (Day 579)
---

# Day 576 — Cryptopals CTF Practice: Day 6

> "Textbook RSA is not RSA. The moment you strip the padding you transform a public-key
> cryptosystem into a malleable toy. Challenge 41 proves it in fifteen lines. Challenge 42
> proves that even adding padding is not enough if the verifier is sloppy."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 6 Challenges 41 and 42: RSA unpadded message recovery
via a multiplicative oracle, and Bleichenbacher's e=3 RSA signature forgery
exploiting a buggy PKCS#1 v1.5 verifier.

**Prerequisites:** Sets 1–5 complete; Day 567 (RSA small exponent, cube root).
**Estimated lab time:** 3 hours.
**Resource:** https://cryptopals.com/sets/6

---

## Challenge 41 — Implement Unpadded Message Recovery Oracle

Without padding, RSA is multiplicatively homomorphic: `enc(m1) * enc(m2) = enc(m1 * m2)`.
That single property is enough to decrypt any ciphertext — even one the oracle refuses to
give you directly — using one extra query.

```python
#!/usr/bin/env python3
"""
Challenge 41: Unpadded RSA oracle attack.

The oracle decrypts any ciphertext it has not seen before. Because RSA is
multiplicatively homomorphic, we blind the ciphertext, query the oracle for
the blinded version, then unblind the result to recover the original plaintext.
"""
from __future__ import annotations

import hashlib
import random
from typing import NamedTuple

import gmpy2  # pip install gmpy2


# ── Minimal RSA key generation ────────────────────────────────────────────────

def gen_rsa_keypair(bits: int = 1024) -> tuple[tuple[int, int], tuple[int, int]]:
    """Return ((e, n), (d, n)) — public and private keys."""
    from Crypto.Util.number import getPrime  # pip install pycryptodome
    e = 3
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p == q:
            continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) == 1:
            d = int(gmpy2.invert(e, phi))
            return (e, n), (d, n)


def rsa_encrypt(m: int, pub: tuple[int, int]) -> int:
    e, n = pub
    return pow(m, e, n)


def rsa_decrypt(c: int, priv: tuple[int, int]) -> int:
    d, n = priv
    return pow(c, d, n)


# ── Oracle: refuses to decrypt a ciphertext it has already seen ──────────────

_seen: set[int] = set()

def c41_oracle(ciphertext: int, priv: tuple[int, int]) -> int | None:
    if ciphertext in _seen:
        return None          # Refuse replay
    _seen.add(ciphertext)
    return rsa_decrypt(ciphertext, priv)


# ── Attack ────────────────────────────────────────────────────────────────────

pub, priv = gen_rsa_keypair(1024)
e, n = pub

# Simulate: attacker intercepts this ciphertext
secret_msg = int.from_bytes(b"ATTACK AT DAWN", "big")
ciphertext = rsa_encrypt(secret_msg, pub)

# Oracle decrypts once (e.g. legitimate recipient reads it)
_ = c41_oracle(ciphertext, priv)

# Attacker now tries direct decryption — oracle refuses
assert c41_oracle(ciphertext, priv) is None, "Oracle should refuse replay"

# Attack: multiply ciphertext by s^e mod n (blinding)
#   c'  = s^e * c mod n
#   m'  = decrypt(c') = s * m mod n
#   m   = m' * modinv(s, n) mod n
s     = random.randint(2, n - 1)
c_blind   = (pow(s, e, n) * ciphertext) % n
m_blind   = c41_oracle(c_blind, priv)   # Different ciphertext — oracle accepts

assert m_blind is not None
s_inv     = int(gmpy2.invert(s, n))
recovered = (m_blind * s_inv) % n

print(f"[+] Original message : {secret_msg}")
print(f"[+] Recovered message: {recovered}")
assert recovered == secret_msg, "Recovery failed!"
print("[+] Challenge 41 passed — unpadded RSA is trivially malleable")
```

**Why it works:** RSA without padding is multiplicatively homomorphic.
Multiplying the ciphertext by `s^e mod n` multiplies the plaintext by `s mod n`.
The oracle sees a different ciphertext and decrypts it. We remove the blinding
factor `s` with its modular inverse.

**Fix:** OAEP padding (or any randomised padding). Padded schemes are not
homomorphic because the padding randomises the relationship between ciphertext
and plaintext.

---

## Challenge 42 — Bleichenbacher's e=3 RSA Attack (Signature Forgery)

PKCS#1 v1.5 RSA signatures pad the message digest as:

```
0x 00 01 FF FF ... FF 00 [DigestInfo ASN.1] [hash bytes]
```

A buggy verifier checks only the prefix and suffix — it does not verify that the
`0xFF` padding bytes extend all the way to the key length. With `e=3`, an attacker
can cube-root a carefully crafted block and produce a forged signature without
the private key.

```python
#!/usr/bin/env python3
"""
Challenge 42: Bleichenbacher's e=3 RSA signature forgery.

Exploit: verifier checks start (00 01 ff...) and end ([DigestInfo][hash])
but ignores whether the padding fills the full space.
With e=3 we can cube-root a forged block directly.
"""
from __future__ import annotations

import hashlib
from gmpy2 import iroot, mpz


# ── SHA-1 DigestInfo ASN.1 DER prefix ────────────────────────────────────────
# This is the standardised OID for SHA-1 inside an RSA signature structure.
SHA1_ASN1_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")


def pkcs1_v15_sign(msg: bytes, priv: tuple[int, int], key_bytes: int) -> bytes:
    """Correct PKCS#1 v1.5 SHA-1 signature."""
    d, n = priv
    h    = hashlib.sha1(msg).digest()
    # Build fully padded block
    data    = SHA1_ASN1_PREFIX + h
    pad_len = key_bytes - len(data) - 3
    block   = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + data
    m       = int.from_bytes(block, "big")
    s       = pow(m, d, n)
    return s.to_bytes(key_bytes, "big")


def pkcs1_v15_verify_buggy(msg: bytes, sig: bytes, pub: tuple[int, int],
                            key_bytes: int) -> bool:
    """
    Buggy verifier: checks prefix 00 01 ff+ 00 and suffix [DigestInfo][hash],
    but does NOT check that the padding extends to key_bytes.
    """
    e, n = pub
    s    = int.from_bytes(sig, "big")
    m    = pow(s, e, n)
    block = m.to_bytes(key_bytes, "big")  # right-pad to key size

    # Only check: starts with 00 01, has at least one ff, then 00
    if block[0:2] != b"\x00\x01":
        return False
    i = 2
    if block[i] != 0xff:
        return False
    while i < key_bytes and block[i] == 0xff:
        i += 1
    if block[i] != 0x00:
        return False
    i += 1
    # Check DigestInfo + hash suffix — starting at i, ignoring garbage after
    expected_suffix = SHA1_ASN1_PREFIX + hashlib.sha1(msg).digest()
    return block[i : i + len(expected_suffix)] == expected_suffix


def forge_signature(msg: bytes, key_bytes: int) -> bytes:
    """
    Forge a signature that passes the buggy verifier.
    With e=3, find S such that S^3 has the right prefix.
    """
    h    = hashlib.sha1(msg).digest()
    # Build the desired plaintext prefix:  00 01 ff 00 [ASN1][hash]
    # We use MINIMAL padding (one 0xff byte), since verifier doesn't count them
    desired = b"\x00\x01\xff\x00" + SHA1_ASN1_PREFIX + h
    # Pad the rest with zeros to key_bytes
    desired = desired + b"\x00" * (key_bytes - len(desired))

    # Treat as integer and take cube root (ceiling)
    target      = int.from_bytes(desired, "big")
    sig_int, _  = iroot(mpz(target), 3)
    if sig_int ** 3 < target:
        sig_int += 1

    return int(sig_int).to_bytes(key_bytes, "big")


# ── Demonstration ─────────────────────────────────────────────────────────────

pub, priv   = gen_rsa_keypair(3072)   # 3072-bit key, e=3
KEY_BYTES   = 3072 // 8
target_msg  = b"hi mom"

# Forge without the private key
forged_sig = forge_signature(target_msg, KEY_BYTES)

# Verify against the buggy verifier
result = pkcs1_v15_verify_buggy(target_msg, forged_sig, pub, KEY_BYTES)
print(f"[+] Buggy verifier accepts forged sig: {result}")
assert result is True

# Confirm legitimate signature also passes (sanity check)
legit_sig = pkcs1_v15_sign(target_msg, priv, KEY_BYTES)
assert pkcs1_v15_verify_buggy(target_msg, legit_sig, pub, KEY_BYTES)
print("[+] Challenge 42 passed — Bleichenbacher e=3 forgery works")
```

**Why it works:** With `e=3`, `m = s³ mod n`. If `s < n^(1/3)`, then `s³ < n`
and there is no modular reduction — so we can freely choose `s = ⌈cbrt(target)⌉`.
The cube of this `s` starts with the correct prefix. The buggy verifier never
checks that the padding fills the remaining space, so the garbage trailing bytes
go unnoticed.

**The real-world impact:** This exact bug (CVE-2006-4339) affected OpenSSL 0.9.7a,
Mozilla NSS, and GnuTLS simultaneously. Any TLS 1.0 server using RSA-with-SHA1
and a key of 1024–4096 bits was vulnerable to forged certificate signatures.

**Fix:** After verifying the prefix and suffix, assert that `i + len(suffix) == key_bytes`
— the suffix must end exactly at the block boundary, leaving no room for garbage.

---

## Set 6 / Challenges 41–42 Self-Assessment

```
[ ] 1. In the unpadded oracle attack, you multiply the ciphertext by s^e mod n.
        If you instead divided by s^e mod n (multiplied by modinv(s^e, n)), what
        would you recover?

[ ] 2. The buggy verifier in challenge 42 is "right-justified" by the verifier
        code: it checks block[i:i+len(suffix)] rather than block[-len(suffix):].
        Explain why checking from the right (the constant-time fix) would defeat
        this forgery completely.

[ ] 3. Why does the forge_signature function use a 3072-bit key in the demo
        rather than a 1024-bit key? Hint: what happens to the garbage bytes as
        key size increases?

[ ] 4. Challenge 41's oracle restriction (refuse replay) is meant to prevent
        the unpadded recovery attack. Why does it still fail? What additional
        property would a secure scheme need to prevent this class of attack?
```

---

## Key Takeaways

1. **Textbook RSA is not secure.** The multiplicative homomorphism is not an edge
   case — it is the core arithmetic of RSA. Every scheme that omits padding
   leaks plaintexts trivially.
2. **Bleichenbacher's e=3 forgery** shows that padding alone is not enough.
   The verifier must check the entire structure, not just the prefix and suffix.
   The `i + len(suffix) == key_bytes` check is a single comparison, costs nothing,
   and closes the vulnerability completely.
3. **The attacker only needs the public key.** Both of these attacks use only
   `(e, n)`. Private key material is never needed. This makes forgery feasible
   for any attacker who can interact with the target system.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q576.1, Q576.2 …).

---

## Navigation

← Previous: [Day 575 — Cryptopals CTF Day 5](DAY-0575-Cryptopals-CTF-Day-5.md)
→ Next: [Day 577 — Cryptopals CTF Day 7](DAY-0577-Cryptopals-CTF-Day-7.md)
