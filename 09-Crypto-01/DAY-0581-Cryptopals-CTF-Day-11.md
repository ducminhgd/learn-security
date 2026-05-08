---
title: "Cryptopals CTF Practice — Day 11: Set 7 Part 2 (CRIME Compression Oracle)"
tags: [cryptography, cryptopals, CTF, CRIME, compression-oracle, TLS,
  DEFLATE, chosen-plaintext, secret-recovery, side-channel, set-7,
  challenge-51, CVE-2012-4929]
module: 09-Crypto-01
day: 581
prerequisites:
  - Day 580 — Cryptopals CTF Day 10 (CBC-MAC forgery)
  - Day 563 — Timing Attacks (oracle-based recovery pattern)
related_topics:
  - Cryptopals CTF Day 12 (Day 582)
  - CRIME Attack CVE-2012-4929
---

# Day 581 — Cryptopals CTF Practice: Day 11

> "CRIME is one of the most elegant attacks in modern cryptography. The cipher
> keeps the data secret, but the compressor leaks how redundant the plaintext
> is. One bit of information — 'did the length increase or not?' — is enough
> to recover a session token character by character. This is what happens when
> two systems talk to each other without knowing about each other's side effects."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 7 Challenge 51: implement the CRIME compression
oracle attack. Compress a request body containing a secret session token,
observe the ciphertext length, and recover the token byte by byte.

**Prerequisites:** Sets 1–6 complete; Day 563 (oracle-based secret recovery).
**Estimated lab time:** 3 hours.
**Resource:** https://cryptopals.com/sets/7

---

## How CRIME Works

CRIME (Compression Ratio Info-leak Made Easy, CVE-2012-4929) exploited
TLS+DEFLATE compression that was active by default in TLS 1.0/1.1. The attack:

1. The attacker controls part of the plaintext (e.g., cookie header injection).
2. The victim's browser sends a request compressed with DEFLATE inside TLS.
3. The attacker observes the **length** of the TLS record (ciphertext length
   leaks compressed length because stream ciphers and CTR preserve length).
4. DEFLATE backreferences duplicated strings. If the attacker's injected string
   matches the secret cookie, the compressed output is **shorter**.
5. By appending one candidate byte at a time to their injected string, the
   attacker finds the byte that produces the shortest ciphertext — that byte
   is in the secret cookie.

```
Example:
  Template: POST / HTTP/1.1\r\nCookie: secret=ABC...\r\n\r\n[attacker_prefix]
  If attacker_prefix = "secret=A" → DEFLATE finds "secret=A" in cookie → shorter
  If attacker_prefix = "secret=B" → no match → longer
```

---

## Challenge 51 — Implement the Compression Oracle

```python
#!/usr/bin/env python3
"""
Challenge 51: CRIME compression oracle.
Recover a secret session token embedded in an HTTP-like request
by observing the compressed+encrypted length.
"""
from __future__ import annotations

import os
import zlib
from Crypto.Cipher import AES


# ── Secret token ──────────────────────────────────────────────────────────────
SESSION_TOKEN = b"TmV2ZXIgcmV2ZWFsIHRoZSBXdQ=="   # base64-ish, 28 bytes


def build_request(payload: bytes) -> bytes:
    """
    Construct a simulated HTTP request body that includes:
    - A static header with the secret session token
    - The attacker-controlled payload
    """
    return (
        b"POST / HTTP/1.1\r\n"
        b"Host: hapless.com\r\n"
        b"Cookie: sessionid=" + SESSION_TOKEN + b"\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"\r\n"
        + payload
    )


def compress_encrypt_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Compress with DEFLATE, then encrypt with AES-CTR. Length is observable."""
    compressed = zlib.compress(data, level=9)
    cipher     = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(compressed)


def compression_oracle(payload: bytes) -> int:
    """
    Oracle: compress-then-encrypt the full request including our payload.
    Returns the ciphertext length (observable to attacker in CRIME scenario).
    """
    key   = b"YELLOW SUBMARINE"
    nonce = os.urandom(8)   # Random nonce each call — does not matter for length
    req   = build_request(payload)
    ct    = compress_encrypt_ctr(req, key, nonce)
    return len(ct)


# ── Attack: recover SESSION_TOKEN byte by byte ────────────────────────────────

# The token alphabet: base64 chars + '='
ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# Known prefix in the request that precedes the token
COOKIE_PREFIX = b"Cookie: sessionid="

# ── Phase 1: determine token length by finding when lengths stop decreasing ──

def recover_token_length() -> int:
    """
    Increase padding until compressed length stops growing.
    The point where length jumps marks the natural block boundary.
    """
    base = compression_oracle(b"")
    for pad in range(1, 100):
        if compression_oracle(b"A" * pad) > base:
            return pad - 1
    return -1


# ── Phase 2: byte-by-byte recovery ───────────────────────────────────────────

def recover_next_byte(known: bytes) -> int | None:
    """
    For each candidate byte, prepend COOKIE_PREFIX + known + candidate to the payload.
    The candidate that produces the shortest ciphertext matches the next secret byte.
    """
    # Align: add padding so that our prefix + known_token + candidate
    # is exactly block-aligned before the match region
    # (padding ensures the candidate comparison is isolated)
    candidates = {}
    for byte_val in ALPHABET:
        payload = COOKIE_PREFIX + known + bytes([byte_val])
        candidates[byte_val] = compression_oracle(payload)

    min_len = min(candidates.values())
    # Collect all bytes that produced the minimum length
    best = [b for b, l in candidates.items() if l == min_len]
    if len(best) == 1:
        return best[0]
    # Tie-break: add extra padding to distinguish
    for byte_val in best:
        # Repeat the candidate — if it's the right byte, the repeated string
        # compresses even better (DEFLATE finds a longer backreference)
        payload = COOKIE_PREFIX + known + bytes([byte_val]) * 3
        candidates[byte_val] = compression_oracle(payload)
    min_len = min(candidates.values())
    best    = [b for b, l in candidates.items() if l == min_len]
    return best[0] if len(best) == 1 else None


def attack() -> bytes:
    """Recover the full session token using the compression oracle."""
    known = b""
    print(f"[*] Recovering token (known prefix: {COOKIE_PREFIX!r})")
    for pos in range(60):   # Upper bound on token length
        next_byte = recover_next_byte(known)
        if next_byte is None:
            print(f"  [!] Ambiguous at position {pos} — trying brute-force fallback")
            break
        known += bytes([next_byte])
        print(f"  [{pos+1:2d}] byte = 0x{next_byte:02x} ({chr(next_byte)!r})  known: {known!r}")
        # Stop when we've recovered the full token (known length from oracle)
        if known == SESSION_TOKEN:
            break
    return known


recovered = attack()
print(f"\n[+] Recovered token: {recovered!r}")
print(f"[+] Expected token:  {SESSION_TOKEN!r}")
assert recovered == SESSION_TOKEN
print("[+] Challenge 51 passed")
```

---

## Why CTR Mode Does Not Help

In CBC mode, ciphertext length is padded to the nearest block boundary —
the oracle would round up to 16 bytes. An attacker would need to inject enough
data to cross a block boundary and get a step-change.

In CTR mode (and RC4, which TLS used historically), the ciphertext is exactly
the same length as the compressed plaintext. The oracle leaks one byte of
precision per query instead of 16, making recovery faster.

Cryptopals challenge 51 asks you to implement both variants:
- **CTR variant:** every byte counts — straightforward character-by-character
  recovery.
- **CBC variant:** you need to align your injection so that adding the correct
  byte keeps the ciphertext in the shorter block-count, while an incorrect byte
  pushes it over a boundary.

```python
def compression_oracle_cbc(payload: bytes) -> int:
    """CBC variant: ciphertext length is padded to 16-byte boundary."""
    from Crypto.Util.Padding import pad as aes_pad
    key  = b"YELLOW SUBMARINE"
    iv   = os.urandom(16)
    req  = build_request(payload)
    comp = zlib.compress(req, level=9)
    ct   = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(aes_pad(comp, 16))
    return len(ct)


def recover_byte_cbc(known: bytes, block_len: int = 16) -> int | None:
    """
    CBC variant: find the padding size P such that:
      len(compress(prefix + known + '?')) + P == len(compress(prefix + known))
    The correct byte keeps total within the current block; wrong bytes push it over.
    """
    # Find current length with padding to reach block boundary
    base_len = None
    for pad_size in range(block_len):
        pad    = b"A" * pad_size
        length = compression_oracle_cbc(COOKIE_PREFIX + known + pad)
        if base_len is None:
            base_len = length
        elif length > base_len:
            # We just crossed a block boundary; pad_size is the slack
            slack = pad_size - 1
            break

    candidates = {}
    for byte_val in ALPHABET:
        # With the correct byte, the compressed output fits in the current block
        payload = COOKIE_PREFIX + known + bytes([byte_val]) + b"A" * slack
        candidates[byte_val] = compression_oracle_cbc(payload)

    min_len = min(candidates.values())
    best    = [b for b, l in candidates.items() if l == min_len]
    return best[0] if len(best) == 1 else None
```

---

## Real-World Impact

| CVE | Description | Fix |
|---|---|---|
| CVE-2012-4929 (CRIME) | TLS compression leaks HTTPS cookies | Disable TLS compression (RFC 7525) |
| CVE-2013-3587 (BREACH) | HTTP response body compression leaks CSRF tokens | Add per-request randomness to secrets |
| CVE-2015-2808 (RC4 NOMORE) | RC4 keystream biases leak compressed data | Disable RC4 in TLS (RFC 7465) |

BREACH is the HTTP-level version: even without TLS compression, if the server
compresses its HTTP response body (gzip) and includes an attacker-influenced
value (CSRF token reflection) alongside a secret, the same length oracle applies.

---

## Self-Assessment

```
[ ] 1. In the CTR variant, why does using AES-CTR instead of AES-CBC make the
        oracle more precise (byte-level vs block-level resolution)?

[ ] 2. BREACH works against HTTPS even without TLS compression. What specific
        server behaviour is required for BREACH to apply? (Hint: think about
        what is in the response body.)

[ ] 3. A common BREACH mitigation is "add random padding to the response body."
        Why does random padding defeat the oracle? What statistical assumption
        does the attack rely on?

[ ] 4. TLS 1.3 removed support for record-layer compression. Does this make
        CRIME/BREACH impossible on TLS 1.3 connections? Explain.
```

---

## Key Takeaways

1. **Compression leaks information about data redundancy.** DEFLATE backreferences
   cause the compressed output to be shorter when attacker-controlled data
   matches secret data. Shorter output → observable length difference → oracle.
2. **Encryption hides content, not length.** CTR mode and stream ciphers preserve
   the compressed length exactly. Even block ciphers leak coarse length
   information. Never assume encryption hides all observable properties of the
   plaintext.
3. **The fix is architectural, not cryptographic.** Disabling compression breaks
   the oracle. Adding per-response randomness (BREACH mitigation) raises the
   noise floor. The cleanest fix is never compressing data that contains both
   a secret and attacker-controlled content in the same context.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q581.1, Q581.2 …).

---

## Navigation

← Previous: [Day 580 — Cryptopals CTF Day 10](DAY-0580-Cryptopals-CTF-Day-10.md)
→ Next: [Day 582 — Cryptopals CTF Day 12](DAY-0582-Cryptopals-CTF-Day-12.md)
