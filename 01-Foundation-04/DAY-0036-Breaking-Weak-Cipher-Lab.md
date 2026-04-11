---
title: "Breaking Weak Cipher Lab"
tags: [foundation, cryptography, lab, Vigenere, XOR, frequency-analysis,
       classical-ciphers, cryptanalysis, index-of-coincidence]
module: 01-Foundation-04
day: 36
related_topics:
  - Symmetric Encryption and ECB Weakness (Day 029)
  - Randomness and PRNG Attacks (Day 035)
  - Crypto in the Wild CVE Review (Day 037)
  - Cryptographic Attacks Advanced (Day 574)
---

# Day 036 — Breaking Weak Cipher Lab

## Goals

This is a **lab day**. By the end you will have:

1. Broken a single-byte XOR cipher using frequency analysis.
2. Detected repeating-key XOR using the Hamming distance / index of
   coincidence technique.
3. Broken a Vigenère cipher by determining the key length and applying
   single-byte XOR analysis to each column.
4. Explained why these classical ciphers are not "encryption" in any
   meaningful security sense.

> "Break it yourself. Reading about frequency analysis produces a reader.
> Writing the code produces a cryptanalyst."
> — Ghost

---

## Prerequisites

- [Day 029 — Symmetric Encryption and ECB Weakness](DAY-0029-Symmetric-Encryption-and-ECB-Weakness.md)
- [Day 035 — Randomness and PRNG Attacks](DAY-0035-Randomness-and-PRNG-Attacks.md)

---

## Background

### Classical Ciphers in CTFs and Real Systems

Classical ciphers (Caesar, Vigenère, XOR) still appear in:
- CTF crypto challenges (foundational knowledge required).
- Poorly-designed "encryption" in old software (custom XOR routines).
- Malware obfuscation (single-byte XOR is extremely common).
- Protocol buffers with "scrambling" layers on embedded devices.

**The Cryptopals Challenges** (cryptopals.com) are the standard reference.
Today's lab covers Sets 1–2 core concepts.

---

## Lab Part 1 — Single-Byte XOR

### The Cipher

```
Ciphertext = Plaintext XOR key (repeated single byte)
```

Example: key = `0x2F`

```
P: 48 65 6c 6c 6f  ("Hello")
K: 2f 2f 2f 2f 2f
C: 67 4a 43 43 40
```

### The Attack — Frequency Analysis

English text has a known character frequency distribution:
`e, t, a, o, i, n, s, h, r` are the most common letters (~70% of text).

**Algorithm:**
1. For each possible key byte (0–255):
   - XOR the ciphertext with that byte.
   - Score the result by how closely the character frequencies match English.
2. The key byte with the highest score is the correct key.

```python
from collections import Counter

# English letter frequencies (approximate)
ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
    'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
    'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10,
    'z': 0.07
}

def score_text(text: bytes) -> float:
    """Score bytes as English text. Higher = more English-like."""
    score = 0.0
    for byte in text:
        char = chr(byte).lower()
        score += ENGLISH_FREQ.get(char, 0)
    return score

def break_single_byte_xor(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Returns (key_byte, plaintext, score)."""
    best = (0, b'', 0.0)
    for key_byte in range(256):
        candidate = bytes(b ^ key_byte for b in ciphertext)
        s = score_text(candidate)
        if s > best[2]:
            best = (key_byte, candidate, s)
    return best

# Test it:
import base64
# This is a base64-encoded, single-byte XOR'd ciphertext:
ct_b64 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
ct = bytes.fromhex(ct_b64)
key, plaintext, score = break_single_byte_xor(ct)
print(f"Key:  {key} (0x{key:02x})")
print(f"Text: {plaintext}")
```

---

## Lab Part 2 — Repeating-Key XOR (Vigenère)

### Finding the Key Length — Hamming Distance

**Hamming distance:** The number of bit positions where two byte strings
differ.

```python
def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))
```

**Key insight:** If we guess the key length is `k`, take any two k-byte
blocks of ciphertext. If `k` is correct, both blocks were XOR'd with the
same key — their XOR gives `(P1 XOR K) XOR (P2 XOR K) = P1 XOR P2`.
The XOR of two English text blocks has a lower Hamming distance than two
random blocks.

**Algorithm to find key length:**

```python
def normalised_hamming(ct: bytes, keysize: int) -> float:
    """Average normalised Hamming distance for a guessed key length."""
    blocks = [ct[i:i+keysize] for i in range(0, len(ct), keysize) if len(ct[i:i+keysize]) == keysize]
    distances = []
    for i in range(min(len(blocks)-1, 4)):
        d = hamming_distance(blocks[i], blocks[i+1]) / keysize
        distances.append(d)
    return sum(distances) / len(distances) if distances else float('inf')

# Try key lengths 2–40:
for keysize in range(2, 41):
    dist = normalised_hamming(ciphertext, keysize)
    print(f"Keysize {keysize:2d}: {dist:.4f}")

# The keysize with the LOWEST normalised Hamming distance is likely correct
```

### Breaking the Cipher Column-by-Column

Once you have the key length `k`:
1. Take every k-th byte: bytes 0, k, 2k, 3k, ... → all XOR'd with key[0].
2. Take bytes 1, k+1, 2k+1, ... → all XOR'd with key[1].
3. Each "column" is a single-byte XOR cipher → apply the frequency analysis
   from Part 1 to each column.

```python
def break_repeating_key_xor(ct: bytes, keysize: int) -> tuple[bytes, bytes]:
    """Returns (key, plaintext)."""
    # Split into columns
    columns = [bytes(ct[i] for i in range(j, len(ct), keysize))
               for j in range(keysize)]

    key = bytes(break_single_byte_xor(col)[0] for col in columns)

    # Decrypt
    plaintext = bytes(
        ct[i] ^ key[i % keysize]
        for i in range(len(ct))
    )
    return key, plaintext

# Full solution:
import base64

# Cryptopals Set 1, Challenge 6 (the classic example):
# Download from: https://cryptopals.com/static/challenge-data/6.txt
with open("6.txt") as f:
    ct = base64.b64decode(f.read())

# Find the best key length:
best_keysize = min(range(2, 41), key=lambda k: normalised_hamming(ct, k))
print(f"Best key length: {best_keysize}")

key, plaintext = break_repeating_key_xor(ct, best_keysize)
print(f"Key: {key}")
print(f"Plaintext (first 100 chars): {plaintext[:100]}")
```

---

## Lab Part 3 — Index of Coincidence (Alternative Key Length Detection)

The **Index of Coincidence (IC)** measures how likely it is that two randomly
selected characters from a text are the same. For English: IC ≈ 0.065.
For random data: IC ≈ 0.038.

```python
def index_of_coincidence(text: bytes) -> float:
    n = len(text)
    if n < 2:
        return 0
    freq = Counter(text)
    numerator = sum(c * (c - 1) for c in freq.values())
    return numerator / (n * (n - 1))

# For a correct key length, each column's IC should be close to 0.065:
for keysize in range(2, 41):
    columns = [bytes(ct[i] for i in range(j, len(ct), keysize))
               for j in range(keysize)]
    avg_ic = sum(index_of_coincidence(col) for col in columns) / keysize
    print(f"Keysize {keysize:2d}: IC = {avg_ic:.4f}")

# The keysize where IC is closest to 0.065 = the correct key length
```

---

## Key Takeaways

1. **Frequency analysis breaks any single-byte XOR or Caesar cipher.**
   The statistics of English text are deterministic enough to make this
   mechanical.
2. **Hamming distance / IC detects repeating-key XOR key lengths.**
   This is the foundation of breaking historical ciphers and any modern
   stream cipher that reuses a keystream.
3. **These classical cipher attacks appear in CTF cryptography challenges.**
   Master them before Day 050. The Cryptopals challenges (Set 1) are
   essential practice.
4. **Custom XOR obfuscation in malware is broken the same way.**
   If malware authors use single-byte XOR to hide strings, you recover
   the key by scoring all 256 possible keys against English frequency.
5. **The reason AES won:** None of these attacks work. AES introduces
   non-linear substitutions (S-boxes) and diffusion (MixColumns) that
   destroy the frequency structure in every encryption round.

---

## Exercises

### Full Lab Sequence

Work through the Cryptopals Challenges Set 1:
https://cryptopals.com/sets/1

| Challenge | What you build |
|---|---|
| 1 | Hex to Base64 |
| 2 | Fixed-length XOR |
| 3 | **Single-byte XOR cipher** (this lesson) |
| 4 | Detect single-byte XOR in a file of 60 ciphertexts |
| 5 | Implement repeating-key XOR |
| 6 | **Break repeating-key XOR** (this lesson) |
| 7 | Decrypt AES-128 ECB |
| 8 | **Detect AES ECB ciphertext** (Day 029 concept) |

Complete all 8 challenges. Post your results in your exercises folder.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 035 — Randomness and PRNG Attacks](DAY-0035-Randomness-and-PRNG-Attacks.md)*
*Next: [Day 037 — Crypto in the Wild — CVE Review](DAY-0037-Crypto-in-the-Wild-CVE-Review.md)*
