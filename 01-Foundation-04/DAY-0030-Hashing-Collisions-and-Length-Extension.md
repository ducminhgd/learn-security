---
title: "Hashing, Collisions, and Length Extension"
tags: [foundation, cryptography, hashing, SHA, MD5, collision,
       length-extension, preimage, birthday-attack, integrity]
module: 01-Foundation-04
day: 30
related_topics:
  - Symmetric Encryption and ECB Weakness (Day 029)
  - MACs HMACs and Forgery Lab (Day 031)
  - Password Hashing and Cracking (Day 034)
  - Crypto in the Wild CVE Review (Day 037)
---

# Day 030 — Hashing, Collisions, and Length Extension

## Goals

By the end of this lesson you will be able to:

1. Explain the three security properties of a cryptographic hash function:
   pre-image resistance, second pre-image resistance, collision resistance.
2. Name the current status of MD5, SHA-1, and SHA-256.
3. Explain the birthday attack and calculate its complexity for a given
   output size.
4. Describe the Merkle–Damgård construction and why it enables length
   extension.
5. Execute a SHA-256 length extension attack against a vulnerable MAC
   implementation using `hashpumpy`.
6. Identify vulnerable "MAC" patterns in real API authentication.

---

## Prerequisites

- [Day 029 — Symmetric Encryption and ECB Weakness](DAY-0029-Symmetric-Encryption-and-ECB-Weakness.md)

---

## Main Content — Part 1: Hash Function Properties

### 1. What a Cryptographic Hash Function Does

A hash function `H(m)` takes an arbitrary-length input and produces a
fixed-length output (the digest). The security requirements:

| Property | Definition | Broken by |
|---|---|---|
| **Pre-image resistance** | Given `h`, hard to find `m` such that `H(m) = h` | Brute force 2^n ops |
| **Second pre-image resistance** | Given `m`, hard to find `m'≠m` such that `H(m)=H(m')` | Brute force 2^n ops |
| **Collision resistance** | Hard to find any `m, m'` where `H(m) = H(m')` | Birthday attack 2^(n/2) ops |

---

### 2. Current Status of Common Hash Functions

| Hash | Output | Security Status | Use |
|---|---|---|---|
| **MD5** | 128-bit | **Broken** — collisions trivial | Never for security; only checksums |
| **SHA-1** | 160-bit | **Broken** — SHAttered (2017), collision cost ≈ $110K GPU | Deprecated everywhere; forbidden in TLS |
| **SHA-256** | 256-bit | Secure | Digital signatures, HMAC, certificates |
| **SHA-512** | 512-bit | Secure | Higher security margin than SHA-256 |
| **SHA-3 (Keccak)** | Variable | Secure | Sponge construction — not Merkle-Damgård |
| **BLAKE2/BLAKE3** | Variable | Secure | Fastest secure option; used in Argon2 |

**The SHAttered attack (2017):** Google/CWI produced two different PDF files
with the same SHA-1 hash. Cost: ~6,500 CPU years. Now, chosen-prefix SHA-1
collisions cost ~$45K worth of GPU time (2020 estimate). SHA-1 is dead.

---

### 3. Birthday Attack

The birthday attack exploits the fact that finding a collision is much
easier than finding a preimage.

**Intuition — Birthday Paradox:** How many people must be in a room before
two share a birthday? Answer: ~23 people gives 50% probability. Not 183
(half of 365). The probability grows as n²/2N for n people in N outcomes.

**For hash functions:**
- Finding a preimage to a specific hash: requires ~2^n operations.
- Finding any two inputs with the same hash: requires only ~2^(n/2) ops.

| Hash | Output | Preimage resistance | Collision resistance |
|---|---|---|---|
| MD5 | 128-bit | 2^128 | 2^64 (trivial for GPU farms) |
| SHA-1 | 160-bit | 2^160 | 2^80 (broken in 2017) |
| SHA-256 | 256-bit | 2^256 | 2^128 (secure) |

**Practical impact:** SHA-256 certificates are safe. SHA-1 code-signing
certificates can be used to forge malicious binaries with a matching hash.

---

## Main Content — Part 2: The Merkle–Damgård Construction

### 4. How SHA-256 Processes Data Internally

SHA-256 uses the Merkle–Damgård construction:

```
H0 = IV (fixed constants defined in the spec)
H1 = compress(H0, Pad(Block1))
H2 = compress(H1, Block2)
H3 = compress(H2, Block3)
...
Final hash = H_last
```

**Padding:** Before processing, the message is padded to a multiple of
the block size (512 bits = 64 bytes for SHA-256):
```
1 bit → message
0 bits → filler
64-bit big-endian integer → total message length in bits
```

**The vulnerability:** The internal state after processing `H(secret || message)`
is visible to anyone who has the hash. Given the output of SHA-256 and the
message length, you can resume compression from where it left off —
appending data without knowing the secret.

---

### 5. Length Extension Attack

**Scenario:** An API uses this pattern for authentication:

```python
# Server computes:
mac = sha256(secret_key + message)

# Client sends:
message + "?user=alice" + mac

# Server verifies:
expected = sha256(secret_key + received_message)
if expected == received_mac: process()
```

**The vulnerability:** This is not HMAC. It is `H(secret || message)` — a
naive MAC construction vulnerable to length extension.

**Attack:**

Given:
- `mac = H(secret || message)` (you have this from a legitimate request)
- `len(secret)` (you might know this, or can brute-force it 1–64 bytes)
- You want to forge: `H(secret || message || padding || extra_data)`

The hash `H(secret || message)` is the internal state after processing
`secret || message`. SHA-256 just continues from that state, appending
`padding || extra_data`. The resulting hash is valid because the server
will compute `H(secret || message || padding || extra_data)` and arrive
at the same value.

**Practical attack with `hashpumpy`:**

```python
import hashpumpy

# You have:
known_mac = "validmachere..."     # hex digest from a legitimate request
known_message = "user=alice&action=read"
secret_length = 16                # guessed or known

# You want to append:
data_to_append = "&action=delete"

# Compute the forged MAC:
new_mac, new_message = hashpumpy.hashpump(
    known_mac,
    known_message,
    data_to_append,
    secret_length
)

print(f"New message: {new_message}")
print(f"Forged MAC:  {new_mac}")

# Send: new_message with new_mac
# Server computes H(secret || new_message) and it matches new_mac
```

---

### 6. Real-World Length Extension Vulnerabilities

**Flickr API (2009):** Used `md5(secret + params)` for request signing.
Length extension allowed forging API calls with additional parameters.

**Generic sign-then-extend APIs:** Any API that:
1. Uses `hash(secret + data)` as a MAC.
2. Allows you to append to the data in a subsequent request.
3. Does not use HMAC.

**How to spot it in the wild:**

```bash
# The API uses a token like:
# sha256(api_secret + request_body)
# or documented as "HMAC-SHA256" but actually just "SHA256(secret+data)"

# Test: get a valid MAC for a known message
# Add padding bytes + your data
# Compute the extended hash with hashpumpy
# Submit — if it's accepted, you found a length extension flaw
```

**The fix:** Use HMAC instead of `H(secret || message)`:

```python
import hmac, hashlib

# Correct MAC:
mac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

# HMAC is: H(key XOR opad || H(key XOR ipad || message))
# Two nested hash operations prevent length extension
```

---

## Key Takeaways

1. **MD5 and SHA-1 are broken for security purposes.** Collisions are
   computationally feasible. Use SHA-256 or SHA-3 minimum.
2. **Finding a collision is 2^(n/2) work, not 2^n.** SHA-256's collision
   resistance is 2^128, not 2^256. SHA-1 at 2^80 is broken.
3. **`H(secret || message)` is not a secure MAC.** Merkle–Damgård hashes
   (MD5, SHA-1, SHA-2 family) are vulnerable to length extension.
   Use HMAC — it is specifically designed to prevent this.
4. **HMAC is two nested hash operations.** This prevents the internal state
   from being visible even if you have the output.
5. **SHA-3 (Keccak) uses a sponge construction** — not Merkle–Damgård.
   It is inherently immune to length extension. But HMAC-SHA256 is fine
   and widely deployed; no need to switch for this reason alone.

---

## Exercises

### Exercise 1 — MD5 Collision

```python
# Two files with the same MD5 (pre-computed by researchers)
# These are the famous "identical twins" collision files:
import hashlib, urllib.request

url1 = "https://www.mscs.dal.ca/~selinger/md5collision/hello"
url2 = "https://www.mscs.dal.ca/~selinger/md5collision/erase"

# Or use hashclash pre-computed collision blocks:
# https://www.win.tue.nl/hashclash/

# Verify yourself:
data1 = open("hello", "rb").read()
data2 = open("erase", "rb").read()

print(hashlib.md5(data1).hexdigest())
print(hashlib.md5(data2).hexdigest())
# Both should produce the same MD5
# SHA-256 should differ
print(hashlib.sha256(data1).hexdigest())
print(hashlib.sha256(data2).hexdigest())
```

### Exercise 2 — Length Extension Attack Lab

```python
# Vulnerable server implementation
import hashlib, hmac

SECRET_KEY = b"supersecret_api"

def generate_mac(data: bytes) -> str:
    return hashlib.sha256(SECRET_KEY + data).hexdigest()

def verify_mac(data: bytes, mac: str) -> bool:
    expected = hashlib.sha256(SECRET_KEY + data).hexdigest()
    return expected == mac

# Legitimate request:
message = b"user=alice&action=read"
valid_mac = generate_mac(message)
print(f"Original MAC: {valid_mac}")
print(f"Verifies:     {verify_mac(message, valid_mac)}")

# Your task: using hashpumpy, forge a MAC for
# message || padding || b"&action=delete"
# without knowing SECRET_KEY (but knowing len(SECRET_KEY) = 15)
import hashpumpy
new_mac, new_msg = hashpumpy.hashpump(
    valid_mac, message.decode(), "&action=delete", len(SECRET_KEY))
print(f"Forged message: {new_msg}")
print(f"Forged MAC:     {new_mac}")
print(f"Verifies:       {verify_mac(new_msg, new_mac)}")
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 029 — Symmetric Encryption and ECB Weakness](DAY-0029-Symmetric-Encryption-and-ECB-Weakness.md)*
*Next: [Day 031 — MACs, HMACs and Forgery Lab](DAY-0031-MACs-HMACs-and-Forgery-Lab.md)*
