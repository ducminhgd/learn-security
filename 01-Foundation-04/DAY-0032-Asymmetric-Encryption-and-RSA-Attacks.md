---
title: "Asymmetric Encryption and RSA Attacks"
tags: [foundation, cryptography, RSA, ECC, asymmetric, public-key,
       textbook-RSA, small-exponent, common-modulus, key-pairs]
module: 01-Foundation-04
day: 32
related_topics:
  - MACs HMACs and Forgery Lab (Day 031)
  - TLS Handshake PKI and Cert Chains (Day 033)
  - JWT Structure and JWT Attack Lab (Day 042)
---

# Day 032 — Asymmetric Encryption and RSA Attacks

## Goals

By the end of this lesson you will be able to:

1. Explain asymmetric encryption: public key encrypts, private key decrypts.
2. Describe RSA key generation at a high level: modulus, public exponent,
   private exponent.
3. Explain three textbook RSA weaknesses: small exponent, textbook RSA
   without padding, common modulus.
4. Explain why RSA-PKCS#1v1.5 is broken and what replaced it.
5. Explain Elliptic Curve Cryptography at a conceptual level.
6. List the key sizes considered secure today for RSA and ECC.

---

## Prerequisites

- [Day 031 — MACs, HMACs and Forgery Lab](DAY-0031-MACs-HMACs-and-Forgery-Lab.md)

---

## Main Content — Part 1: Asymmetric Encryption Fundamentals

### 1. The Key Pair Concept

Asymmetric cryptography uses mathematically related key pairs:

```
Alice's key pair:
  Public key  (share with everyone) → encrypt data / verify signature
  Private key (keep secret)         → decrypt data / create signature
```

**Encryption:** Bob encrypts with Alice's public key → only Alice can
decrypt with her private key.

**Digital signature:** Alice signs with her private key → anyone with
Alice's public key can verify the signature.

**Why not just use symmetric encryption?** Because Alice and Bob need to
agree on a key without meeting first — the key exchange problem. Asymmetric
cryptography solves this by allowing secure key exchange over an insecure
channel (Diffie-Hellman, RSA key exchange).

---

### 2. RSA — How It Works

**Key generation:**

```
1. Choose two large primes: p, q
2. n = p × q       (the modulus — published in the public key)
3. φ(n) = (p-1)(q-1)   (Euler's totient)
4. Choose e = 65537     (the public exponent — almost always 65537)
5. d = e^(-1) mod φ(n)  (the private exponent — kept secret)

Public key:  (n, e)
Private key: (n, d)
```

**Encryption and decryption:**

```
Encrypt: C = M^e mod n
Decrypt: M = C^d mod n

Property: (M^e)^d mod n = M   (modular inverse relationship)
```

**Security:** Given `n` and `e`, finding `d` requires factoring `n` into
`p × q`. For a 2048-bit `n`, this is computationally infeasible.
For a 512-bit `n` — it was broken in 1999. Use RSA-2048 minimum; RSA-4096
for long-term security.

---

## Main Content — Part 2: RSA Attacks

### 3. Textbook RSA — No Padding

**Textbook RSA** is RSA without padding. It is **semantically insecure**:

- **Deterministic:** The same message always produces the same ciphertext.
  An attacker can test if a known plaintext is encrypted in a ciphertext.
- **Multiplicative malleability:** If `C = M^e mod n`, then
  `C' = C × 2^e mod n = (2M)^e mod n`.
  An attacker can multiply the ciphertext by `2^e` and get the encryption
  of `2×M` — without knowing M.

**Real attack (Bleichenbacher 1998 against PKCS#1 v1.5):** TLS used RSA
with PKCS#1 v1.5 padding for key exchange. Bleichenbacher showed that
error messages when the padding was invalid allowed a chosen-ciphertext
attack that could decrypt any ciphertext with ~1 million oracle queries.
This was rediscovered as the **ROBOT attack (2017)** affecting many modern
TLS implementations.

**Fix:** Use RSA-OAEP (Optimal Asymmetric Encryption Padding) for
encryption; use RSA-PSS for signatures.

---

### 4. Small Exponent Attack (e = 3)

If `e = 3` and the message `M` is small relative to `n`:

```
C = M^3 mod n
If M^3 < n, then C = M^3 exactly (no modular reduction occurred)
Attack: take the cube root of C to recover M
```

**Broadcasting attack:** If the same `M` is encrypted with `e=3` using
three different moduli (n1, n2, n3):

```
C1 = M^3 mod n1
C2 = M^3 mod n2
C3 = M^3 mod n3
```

By the Chinese Remainder Theorem, the attacker can reconstruct `M^3 mod
(n1 × n2 × n3)`. Since `M < n_i` for each i, `M^3 < n1 × n2 × n3`,
and taking the cube root gives `M`.

**Why `e = 65537`?** It's a Fermat prime (2^16 + 1), large enough to
prevent small exponent attacks, and has low Hamming weight (fast
exponentiation — only 17 ones in binary).

---

### 5. Common Modulus Attack

If the same modulus `n` is used with two different public exponents
`e1` and `e2` that are coprime:

```
C1 = M^e1 mod n
C2 = M^e2 mod n
```

Using the extended Euclidean algorithm to find `a, b` such that
`a×e1 + b×e2 = 1` (Bezout's identity):

```
M = C1^a × C2^b mod n
```

No need to factor `n`. **Sharing a modulus between users is catastrophic.**

---

### 6. Elliptic Curve Cryptography (ECC)

ECC achieves equivalent security to RSA with much smaller key sizes:

| Security level | RSA key size | ECC key size |
|---|---|---|
| 80 bits | 1024-bit | 160-bit |
| 112 bits | 2048-bit | 224-bit |
| 128 bits | 3072-bit | 256-bit (P-256 or Curve25519) |
| 256 bits | 15360-bit | 521-bit |

**Commonly used curves:**
- **P-256** (secp256r1 / NIST P-256): Standard in TLS, HTTPS.
- **Curve25519**: Designed for Diffie-Hellman (X25519); preferred in
  modern protocols (Signal, WireGuard, TLS 1.3).
- **secp256k1**: Bitcoin's curve (not recommended for general use).

**ECC security concerns:**
- NIST curves (P-256, P-384) have design parameters of uncertain origin
  ("nothing up my sleeve" numbers not published). Curve25519 was designed
  with transparent criteria.
- **Invalid curve attacks:** If the implementation doesn't validate that
  the peer's public key is actually on the correct curve, an attacker can
  submit a point on a weak curve.

---

### 7. Key Size Recommendations (2026)

| Algorithm | Minimum | Recommended | Avoid |
|---|---|---|---|
| RSA | 2048-bit | 4096-bit | < 2048-bit (all) |
| ECC (NIST) | P-256 | P-384 | secp128r1, secp192k1 |
| ECC (modern) | Curve25519 | Curve25519 | — |
| DSA | 2048-bit | Deprecated → use ECDSA | DSA-1024 |
| DH | 2048-bit | 4096-bit | < 1024-bit |

---

## Key Takeaways

1. **Textbook RSA is semantically insecure.** Always use RSA-OAEP for
   encryption and RSA-PSS for signatures. PKCS#1 v1.5 for signatures is
   still acceptable but PKCS#1 v1.5 for encryption must be avoided.
2. **`e = 65537` is the correct public exponent.** Small exponents like
   `e = 3` enable broadcast attacks. `e = 65537` is the standard.
3. **Never share an RSA modulus.** Common modulus attacks require only
   two ciphertexts encrypted with the same `n` to recover the plaintext.
4. **ECC at 256 bits ≈ RSA at 3072 bits** for security. P-256 and
   Curve25519 are the current standard. Use them for TLS, code signing,
   and key exchange.
5. **Factoring attacks improve with time.** RSA-1024 was broken in 2010.
   RSA-768 in 2009. RSA-512 routinely. The NIST recommendation is to
   retire 2048-bit RSA by 2030 and migrate to 3072+ or ECC.

---

## Exercises

### Exercise 1 — RSA CTF (Basic)

```python
from Crypto.PublicKey import RSA
import gmpy2

# Vulnerable RSA: very small p and q for demo
p = 61
q = 53
n = p * q          # 3233
e = 17
phi = (p-1) * (q-1)

# Compute private key
d = int(gmpy2.invert(e, phi))

# Encrypt
m = 65            # Message
c = pow(m, e, n)  # c = m^e mod n
print(f"Ciphertext: {c}")

# Decrypt (knowing d)
decrypted = pow(c, d, n)
print(f"Decrypted: {decrypted}")

# Now: given only n, e, c — factor n to get d
# (Easy for small n; infeasible for 2048-bit n)
from sympy import factorint
factors = factorint(n)
print(f"Factors: {factors}")
```

### Exercise 2 — Common Modulus Attack

```python
# Same message encrypted with same n but different e values
from math import gcd
from sympy.core.numbers import igcdex  # Extended GCD

n = 3233
e1, e2 = 17, 19
m = 42
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

# Extended Euclidean algorithm to find a, b: a*e1 + b*e2 = 1
_, a, b = igcdex(e1, e2)
print(f"Bezout: {a}×{e1} + {b}×{e2} = {a*e1 + b*e2}")

# Recover plaintext without factoring n:
# M = C1^a × C2^b mod n (handling negative exponents via modular inverse)
if a < 0:
    c1_inv = pow(c1, -1, n)
    recovered = (pow(c1_inv, -a, n) * pow(c2, b, n)) % n
else:
    recovered = (pow(c1, a, n) * pow(c2, b, n)) % n
print(f"Original message: {m}")
print(f"Recovered message: {recovered}")
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 031 — MACs, HMACs and Forgery Lab](DAY-0031-MACs-HMACs-and-Forgery-Lab.md)*
*Next: [Day 033 — TLS Handshake, PKI and Cert Chains](DAY-0033-TLS-Handshake-PKI-and-Cert-Chains.md)*
