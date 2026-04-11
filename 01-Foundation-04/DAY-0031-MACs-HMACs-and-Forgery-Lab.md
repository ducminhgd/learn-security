---
title: "MACs, HMACs, and Forgery Lab"
tags: [foundation, cryptography, MAC, HMAC, forgery, MAC-then-encrypt,
       timing-attack, constant-time-comparison, integrity]
module: 01-Foundation-04
day: 31
related_topics:
  - Hashing Collisions and Length Extension (Day 030)
  - Asymmetric Encryption and RSA Attacks (Day 032)
  - JWT Structure and JWT Attack Lab (Day 042)
  - Crypto Attacks — Timing and Padding Oracle (Day 574)
---

# Day 031 — MACs, HMACs, and Forgery Lab

## Goals

By the end of this lesson you will be able to:

1. Define MAC (Message Authentication Code) and distinguish it from a hash.
2. Explain HMAC construction and why it resists length extension.
3. Describe the "MAC-then-Encrypt" vs "Encrypt-then-MAC" ordering and
   which is correct (and why the order matters enormously).
4. Implement a timing attack against an insecure MAC comparison function.
5. Implement a constant-time comparison function and explain why it defeats
   timing attacks.
6. Explain the role of HMAC in real-world protocols (JWT, AWS SigV4,
   cookie signing, API authentication).

---

## Prerequisites

- [Day 030 — Hashing, Collisions and Length Extension](DAY-0030-Hashing-Collisions-and-Length-Extension.md)

---

## Main Content — Part 1: Message Authentication Codes

### 1. Hash vs MAC

| Property | Hash (H) | MAC |
|---|---|---|
| Requires secret key | No | Yes |
| Provides integrity | No (anyone can compute) | Yes (only with the key) |
| Provides authenticity | No | Yes |
| Can be computed by attacker | Yes | No (without the key) |

A hash tells you the data hasn't changed (if you store the hash securely
separately). A MAC tells you the data came from someone who knows the key.

---

### 2. HMAC Construction

HMAC-SHA256 is:

```
HMAC(key, message) = H( (key XOR opad) || H( (key XOR ipad) || message ) )

Where:
- opad = 0x5c repeated to block size (outer padding)
- ipad = 0x36 repeated to block size (inner padding)
- || = concatenation
```

**Why two nested calls?**

1. The inner hash: `H( (key XOR ipad) || message )` binds the key to the
   message. The key material is mixed in before the message.
2. The outer hash: `H( (key XOR opad) || inner )` adds a second layer of
   key mixing. Even if the inner hash's internal state were exposed, the
   outer hash with a different key mask prevents length extension.

**In code:**

```python
import hmac, hashlib

key = b"secret_key"
message = b"order=confirm&amount=100"

# Correct way:
mac = hmac.new(key, message, hashlib.sha256).digest()
print(mac.hex())

# Verify:
def verify(key, message, received_mac):
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, received_mac)
    # compare_digest: constant-time comparison — prevents timing attacks
```

---

## Main Content — Part 2: Encryption and Authentication Ordering

### 3. MAC-then-Encrypt vs Encrypt-then-MAC

This ordering debate has real security consequences.

**Encrypt-then-MAC (EtM) — Correct:**

```
Ciphertext = Encrypt(Plaintext)
Tag = MAC(Ciphertext)
Send: (Ciphertext, Tag)

On receive:
1. Verify Tag == MAC(Ciphertext) — REJECT if invalid, immediately
2. Decrypt Ciphertext
```

**Why it is correct:**
- The MAC is computed over the ciphertext. Any tampering with the
  ciphertext changes the MAC → detected before decryption.
- The decryption function is never called on attacker-controlled data
  unless the MAC is valid.
- **Prevents padding oracle attacks** — the decryptor is never called.

**MAC-then-Encrypt (MtE) — Vulnerable:**

```
Tag = MAC(Plaintext)
Ciphertext = Encrypt(Plaintext || Tag)
Send: Ciphertext

On receive:
1. Decrypt Ciphertext → get Plaintext + Tag
2. Verify Tag == MAC(Plaintext)
```

**Why it is dangerous:**
- You must decrypt first, then verify.
- An attacker can submit a tampered ciphertext and observe the decryption
  error — this leaks information through error oracles.
- **TLS 1.0 and 1.1 used CBC-then-MAC** → Lucky13 attack (2013) exploited
  the timing difference between "padding incorrect" and "MAC incorrect" in
  the decryption path.

**TLS 1.3** uses AEAD ciphers (AES-GCM, ChaCha20-Poly1305) which are
inherently Encrypt-and-MAC simultaneously. This eliminates the ordering
problem entirely.

---

## Main Content — Part 3: Timing Attacks

### 4. The Timing Attack on String Comparison

Python's `==` operator compares strings byte by byte and returns early
on the first mismatch. This means:

- Comparing `"abc"` to `"xyz"` is fast (fails on byte 1).
- Comparing `"abcXXXX"` to `"abcYYYY"` is slower (matches on bytes 1–3).

An attacker who can measure HTTP response time can exploit this to recover
a MAC byte by byte.

**Demonstration:**

```python
import time

SECRET_MAC = b"correct_hmac_hexdigest_here_256bit"

def insecure_verify(user_mac: bytes) -> bool:
    return SECRET_MAC == user_mac  # Python's == exits early on mismatch

# Timing attack to recover the first byte:
import os
results = {}
for candidate_byte in range(256):
    times = []
    for _ in range(100):
        test_mac = bytes([candidate_byte]) + os.urandom(len(SECRET_MAC) - 1)
        start = time.perf_counter_ns()
        insecure_verify(test_mac)
        elapsed = time.perf_counter_ns() - start
        times.append(elapsed)
    results[candidate_byte] = sum(times) / len(times)

# The byte with the highest average time matched the first byte longest
best_byte = max(results, key=results.get)
print(f"First byte is likely: {best_byte:02x}")
print(f"Actual first byte:    {SECRET_MAC[0]:02x}")
```

**Real-world impact:** This works better over a local network where
latency is stable and noise is low. Remote timing attacks require more
samples (thousands) to overcome network jitter. Flask/Rails cookie signing
bugs have been exploited with timing attacks.

---

### 5. Constant-Time Comparison

```python
import hmac

def constant_time_verify(user_mac: bytes, expected_mac: bytes) -> bool:
    """
    hmac.compare_digest performs XOR comparison across all bytes.
    Returns False without short-circuiting.
    Time is constant regardless of how many bytes match.
    """
    return hmac.compare_digest(expected_mac, user_mac)
```

**Why XOR:**

```python
def xor_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y   # XOR accumulates differences; OR prevents early exit
    return result == 0    # True only if result is 0 (all bytes matched)
```

Every byte is XORed. `result` is `0` only if all pairs matched. No early
return. Always O(n) time.

---

### 6. HMAC in Real-World Systems

**JWT (JSON Web Token):** HMAC-SHA256 is the most common JWT signing
algorithm (`alg: "HS256"`). The header + payload are signed with HMAC.
Covered in depth on Day 042.

**AWS Signature Version 4:** All AWS API calls use HMAC-SHA256 to sign:
`HMAC(HMAC(HMAC(HMAC("AWS4" + key, date), region), service), "aws4_request")`

**Django cookie signing:**

```python
# Django signs session cookies with:
# base64(cookie_value) + ":" + HMAC(secret_key, cookie_value)
# Using constant-time comparison in verification
```

**Flask-Login / itsdangerous:**

```python
from itsdangerous import TimestampSigner
s = TimestampSigner(app.secret_key)
token = s.sign(b"user:1234")   # HMAC-signed, timestamped
# Attack: altering the token → signature verification fails
```

---

## Key Takeaways

1. **MAC ≠ Hash.** A MAC requires a shared key. Hashes are public; anyone
   can compute them. Use MAC when you need to verify that data came from
   an authorised party.
2. **HMAC is not H(key || message).** The double-nested construction
   is intentional and prevents both length extension and related-key attacks.
3. **Encrypt-then-MAC is the correct ordering.** Authentication must be
   verified before decryption. Doing it the other way enables oracles.
4. **Never compare MACs with `==` or `strcmp`.** Always use
   `hmac.compare_digest()` or equivalent constant-time comparison.
   Timing attacks against naive comparison are real and have been exploited.
5. **AEAD modes (GCM, ChaCha20-Poly1305) solve the ordering problem.**
   They encrypt and authenticate in one pass, in the correct order. For
   new systems, use AEAD and avoid the MAC-then-Encrypt decision entirely.

---

## Exercises

### Exercise 1 — Timing Attack Lab

Build a web server with a timing-vulnerable MAC check:

```python
from flask import Flask, request
import hmac, hashlib, time

app = Flask(__name__)
SECRET = b"mysecretkey"

@app.route('/verify')
def verify():
    user_mac = request.args.get('mac', '').encode()
    expected = hmac.new(SECRET, b"admin=true", hashlib.sha256).hexdigest().encode()

    # Insecure comparison — timing oracle
    if user_mac == expected:
        return "Access granted"
    return "Access denied", 403
```

Write a script that measures response time for different first bytes of
the MAC. Can you recover the first byte with 1000 samples per candidate?
Then fix it with `hmac.compare_digest`.

### Exercise 2 — HMAC vs H(key||message) Forgery

Using `hashpumpy` from Day 030:

1. Confirm that `H(secret + message)` is forgeable via length extension.
2. Confirm that `HMAC(secret, message)` is NOT forgeable (the forged MAC
   from hashpumpy does not verify against the HMAC check).
3. Explain the structural difference that prevents the attack.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 030 — Hashing, Collisions and Length Extension](DAY-0030-Hashing-Collisions-and-Length-Extension.md)*
*Next: [Day 032 — Asymmetric Encryption and RSA Attacks](DAY-0032-Asymmetric-Encryption-and-RSA-Attacks.md)*
