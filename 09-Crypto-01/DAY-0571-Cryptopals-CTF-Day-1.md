---
title: "Cryptopals CTF Practice — Day 1: Set 1 (Basics)"
tags: [cryptography, cryptopals, CTF, XOR, base64, hex-encoding,
  single-byte-XOR, repeating-key-XOR, frequency-analysis, set-1]
module: 09-Crypto-01
day: 571
prerequisites:
  - Day 029 — Symmetric Encryption and ECB Weakness
  - Day 036 — Breaking Weak Cipher Lab
related_topics:
  - Cryptopals CTF Day 2 (Day 572)
  - ECB Cut-and-Paste (Day 566)
---

# Day 571 — Cryptopals CTF Practice: Day 1

> "The Cryptopals challenges are the best crypto training material ever written.
> They are not reading exercises — they are programming exercises. If you cannot
> implement the attack, you do not understand it. Start with Set 1. It looks
> easy. It is not."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 1 (challenges 1–8): encoding, XOR cryptanalysis, ECB
detection. Every challenge must be solved with code you wrote — no `solution`
repositories, no copy-paste. Understand every operation.

**Prerequisites:** Day 029 (ECB), Day 036 (breaking weak ciphers, frequency
analysis).
**Estimated lab time:** 4 hours.
**Resource:** https://cryptopals.com/sets/1

---

## Challenge Overview — Set 1

| # | Name | Concept |
|---|---|---|
| 1 | Convert hex to base64 | Encoding mechanics |
| 2 | Fixed XOR | Bitwise XOR on byte arrays |
| 3 | Single-byte XOR cipher | Frequency analysis |
| 4 | Detect single-character XOR | Apply #3 at scale |
| 5 | Implement repeating-key XOR | Vigenère-like cipher |
| 6 | Break repeating-key XOR | Hamming distance + frequency analysis |
| 7 | AES in ECB mode | Decrypt with a known key |
| 8 | Detect AES in ECB mode | Identical block detection |

---

## Challenge 1 — Convert Hex to Base64

```python
# Challenge 1: hex string → bytes → base64
# Always work in bytes. String encoding is not cryptography.

import base64

hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
raw     = bytes.fromhex(hex_str)
b64     = base64.b64encode(raw).decode()
print(b64)
# → SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

**Key insight:** Hex and base64 are encodings, not encryption. Any attacker who
sees either knows the underlying bytes.

---

## Challenge 2 — Fixed XOR

```python
# XOR two equal-length byte strings
def fixed_xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
b = bytes.fromhex("686974207468652062756c6c277320657965")
print(fixed_xor(a, b).hex())
# → 746865206b696420646f6e277420706c6179
```

---

## Challenge 3 — Single-Byte XOR Cipher

```python
#!/usr/bin/env python3
"""
Break a single-byte XOR cipher using English letter frequency analysis.
"""
from __future__ import annotations

import string

ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2,
    'q': 0.1, 'z': 0.1, ' ': 13.0,  # Space is most common character
}

def score_english(text: bytes) -> float:
    """Score a byte string by English letter frequency."""
    score = 0.0
    for b in text:
        c = chr(b).lower()
        score += ENGLISH_FREQ.get(c, 0.0)
    return score

def break_single_xor(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Return (key_byte, plaintext, score) for best single-byte XOR key."""
    best = (0, b'', -1.0)
    for key in range(256):
        candidate = bytes(b ^ key for b in ciphertext)
        s = score_english(candidate)
        if s > best[2]:
            best = (key, candidate, s)
    return best

ct = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
key, plaintext, score = break_single_xor(ct)
print(f"Key: {key} (0x{key:02x}) → '{chr(key)}'")
print(f"Plaintext: {plaintext.decode(errors='replace')}")
# → "Cooking MC's like a pound of bacon"
```

---

## Challenge 4 — Detect Single-Character XOR

```python
# Download https://cryptopals.com/static/challenge-data/4.txt
# One line was encrypted with single-byte XOR — find it.

import urllib.request

def detect_single_xor(lines: list[bytes]) -> tuple[int, int, bytes]:
    """Return (line_number, key, plaintext) for the encrypted line."""
    best = (0, 0, b'', -1.0)
    for i, line in enumerate(lines):
        key, plaintext, score = break_single_xor(line)
        if score > best[3]:
            best = (i, key, plaintext, score)
    return best[0], best[1], best[2]

with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/4.txt") as f:
    lines = [bytes.fromhex(line.strip().decode()) for line in f]

line_num, key, plaintext = detect_single_xor(lines)
print(f"Line {line_num}: key=0x{key:02x}")
print(f"Plaintext: {plaintext.decode(errors='replace').strip()}")
# → "Now that the party is jumping\n"
```

---

## Challenge 5 — Repeating-Key XOR

```python
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt/decrypt with a repeating-key XOR (Vigenère-like)."""
    return bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))

# Test
plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key   = b"ICE"
expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
result = repeating_key_xor(plain, key)
assert result.hex() == expected
print("[+] Challenge 5 passed")
```

---

## Challenge 6 — Break Repeating-Key XOR

```python
#!/usr/bin/env python3
"""
Break repeating-key XOR (Vigenère cipher) using Hamming distance + frequency analysis.
This is the most important challenge in Set 1 — it is the core of all classical
stream cipher cryptanalysis.
"""
from __future__ import annotations

import base64
import urllib.request
from itertools import combinations

def hamming_distance(a: bytes, b: bytes) -> int:
    """Count differing bits between two byte strings."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def find_key_size(ciphertext: bytes, min_ks: int = 2, max_ks: int = 40) -> int:
    """
    Find the most likely key size using normalised Hamming distance.
    The correct key size produces the lowest normalised distance
    because same-key-position bytes XOR'd with the same key byte
    maintain English letter frequency patterns.
    """
    scores: list[tuple[float, int]] = []
    for ks in range(min_ks, max_ks + 1):
        # Use first 4 blocks for stability
        blocks = [ciphertext[i*ks:(i+1)*ks] for i in range(4)]
        distances = [hamming_distance(a, b) / ks
                     for a, b in combinations(blocks, 2)]
        scores.append((sum(distances) / len(distances), ks))
    scores.sort()
    return scores[0][1]

def break_repeating_xor(ciphertext: bytes) -> bytes:
    """Full attack: find key size, then break each byte position as single-byte XOR."""
    key_size = find_key_size(ciphertext)
    print(f"[*] Most likely key size: {key_size}")

    # Transpose blocks: byte at position i of each ks-block forms one array
    transposed = [
        bytes(ciphertext[j] for j in range(i, len(ciphertext), key_size))
        for i in range(key_size)
    ]

    key = bytes(break_single_xor(block)[0] for block in transposed)
    return key

# Load the challenge data
with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/6.txt") as f:
    raw = base64.b64decode(f.read())

key = break_repeating_xor(raw)
print(f"[+] Key: {key!r}")

plaintext = repeating_key_xor(raw, key)
print(f"\n[+] First 200 chars of plaintext:\n{plaintext[:200].decode()}")
# → "I'm back and I'm ringin' the bell..."
# Key → b"Terminator X: Bring the noise"
```

---

## Challenge 7 — AES in ECB Mode

```python
import base64
import urllib.request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/7.txt") as f:
    ct = base64.b64decode(f.read())

KEY = b"YELLOW SUBMARINE"
plaintext = aes_ecb_decrypt(ct, KEY)
print(plaintext[:200].decode())
# → "I'm back and I'm ringin' the bell..."
```

---

## Challenge 8 — Detect AES in ECB Mode

```python
#!/usr/bin/env python3
"""
Detect which line in the challenge data was encrypted with AES-ECB.
ECB encrypts identical plaintext blocks to identical ciphertext blocks.
Find the ciphertext with repeated 16-byte blocks.
"""
import urllib.request
import hashlib
from collections import Counter

def has_repeated_blocks(data: bytes, block_size: int = 16) -> bool:
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    return len(blocks) != len(set(blocks))

with urllib.request.urlopen("https://cryptopals.com/static/challenge-data/8.txt") as f:
    lines = [bytes.fromhex(line.strip().decode()) for line in f]

for i, line in enumerate(lines):
    if has_repeated_blocks(line):
        # Count how many times each block appears
        blocks  = [line[j:j+16] for j in range(0, len(line), 16)]
        counter = Counter(blocks)
        repeated = {k: v for k, v in counter.items() if v > 1}
        print(f"[+] Line {i}: {len(repeated)} repeated blocks → ECB detected")
        print(f"    {line.hex()[:40]}...")
# → Line 132 has repeated blocks
```

---

## Self-Assessment

After completing all 8 challenges, answer these without looking at your code:

```
[ ] 1. What is the normalised Hamming distance trick for finding Vigenère key length?
        Explain it in one paragraph.

[ ] 2. Challenge 8 detects ECB because identical plaintext → identical ciphertext.
        Why does this not work for CBC mode with a random IV?

[ ] 3. Challenge 6 transposes the ciphertext before frequency analysis.
        Why? What would happen if you did NOT transpose?

[ ] 4. What property of English text makes frequency analysis work?
        Would it work against compressed or base64-encoded plaintext?
```

If you cannot answer all four confidently, redo the challenge it tests.

---

## Key Takeaways

1. Cryptopals challenges are not CTF tricks — they are the fundamental attacks
   underlying TLS, SSH, and every cryptographic protocol. Challenge 6 (break
   repeating-key XOR) is the exact technique used to break Vigenère ciphers
   and early stream cipher misuse.
2. Frequency analysis works because natural language has predictable byte
   distribution. Any cipher that produces output correlated to its input
   (including ECB) is vulnerable to statistical attack.
3. Implementing these attacks matters. You can read about Hamming distance as
   a key-size estimator in ten minutes. Building it and watching it produce
   the correct key size on real data takes an hour — and produces understanding
   that reading never will.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q571.1, Q571.2 …).

---

## Navigation

← Previous: [Day 570 — ECDSA Lab](DAY-0570-ECDSA-Lab.md)
→ Next: [Day 572 — Cryptopals CTF Practice: Day 2](DAY-0572-Cryptopals-CTF-Day-2.md)
