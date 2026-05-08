---
title: "RSA Attack Lab — Small Exponent, Common Modulus, Broadcast Attack"
tags: [cryptography, RSA, small-exponent, broadcast-attack, common-modulus,
  CRT, CWE-327, T1600, textbook-RSA, Håstad, math-attack]
module: 09-Crypto-01
day: 567
prerequisites:
  - Day 032 — Asymmetric Encryption and RSA Attacks (theory)
related_topics:
  - ECB Cut-and-Paste (Day 566)
  - Diffie-Hellman Attacks (Day 568)
  - Cryptopals Set 5 (Day 575)
---

# Day 567 — RSA Attack Lab

> "RSA is not broken. Textbook RSA is. The padding, the exponent choice, the
> key reuse — every deviation from the standard is an attack surface. Today
> you exploit three of them."
>
> — Ghost

---

## Goals

- Implement and run the small public exponent attack (e=3, Håstad's broadcast).
- Exploit the common modulus attack when the same message is encrypted under
  two different public exponents sharing the same modulus.
- Understand why OAEP padding exists and what it prevents.

**Prerequisites:** Day 032 (RSA math, key pairs, textbook RSA weaknesses).
**Estimated study time:** 3 hours (theory + lab).

---

## 1. Attack 1 — Small Public Exponent (e=3)

### What It Is

When RSA is used without padding and `e=3`, encrypting a short message `m` gives:

```
c = m³ mod n
```

If `m³ < n` (i.e., the cube is smaller than the modulus), then `c = m³` in the
integers — the modular reduction never fires. Taking the cube root of `c` directly
(no modular arithmetic needed) recovers `m`.

### Why It Works

RSA security assumes the modular reduction is what makes cube root computationally
infeasible. If the message is small enough that `m^e < n`, the reduction does
not happen and the cube root is trivially computed.

### Minimal Exploit

```python
#!/usr/bin/env python3
"""
rsa_small_exponent.py — recover plaintext when m^3 < n
"""
from __future__ import annotations

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5   # NOT used in the vulnerable version
import gmpy2

def integer_cube_root(n: int) -> int:
    """Integer cube root using Newton's method via gmpy2."""
    # gmpy2.iroot(n, k) returns (root, is_exact)
    root, exact = gmpy2.iroot(n, 3)
    return int(root), exact

# Simulate a textbook RSA system with e=3, no padding
# n is a real 2048-bit RSA modulus for the example
from Crypto.PublicKey import RSA
import secrets

# Generate a key pair with e=3 (unusual but possible with RSA spec)
key = RSA.generate(2048, e=3)
n = key.n
e = key.e   # = 3

# Short message — must satisfy: m < n^(1/3)
# For 2048-bit n, n^(1/3) ≈ 2^683 → any message under 683 bits works
m_plain = b"Attack at dawn"   # 14 bytes = 112 bits << 683 bits
m_int   = int.from_bytes(m_plain, 'big')

# Encrypt: c = m^3 mod n (textbook, no OAEP)
c = pow(m_int, e, n)

print(f"[*] n (bits): {n.bit_length()}")
print(f"[*] e: {e}")
print(f"[*] m (int):  {m_int}")
print(f"[*] c (int):  {c}")
print(f"[*] m^e < n:  {m_int**3 < n}")   # True → modular reduction did nothing

# Attack: take cube root of c (no mod n needed)
root, exact = integer_cube_root(c)
print(f"\n[+] Cube root of c: {root}")
print(f"[+] Is exact integer root: {exact}")
print(f"[+] Recovered m: {root.to_bytes((root.bit_length() + 7) // 8, 'big')}")
# → b"Attack at dawn"
```

---

## 2. Attack 2 — Håstad's Broadcast Attack

### What It Is

If the same message `m` is encrypted (without padding) under `e=3` different
RSA public keys `(n₁, e)`, `(n₂, e)`, `(n₃, e)`, an attacker who intercepts
all three ciphertexts can recover `m` using the Chinese Remainder Theorem (CRT).

### Why It Works

```
c₁ = m^e mod n₁
c₂ = m^e mod n₂
c₃ = m^e mod n₃
```

By CRT, there is a unique `x < n₁n₂n₃` such that:
```
x ≡ c₁ (mod n₁)
x ≡ c₂ (mod n₂)
x ≡ c₃ (mod n₃)
```

Since the `nᵢ` are all larger than `m`, and `m^e < n₁n₂n₃` (for small `m`
or small `e`), `x = m^e` exactly — then taking the `e`-th root of `x` gives `m`.

### Minimal Exploit

```python
#!/usr/bin/env python3
"""
hastad_broadcast.py — CRT-based broadcast attack for e=3
"""
from __future__ import annotations

import gmpy2
from functools import reduce

def crt(remainders: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem — solve system of congruences."""
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        # Modular inverse of Mi mod m
        _, inv, _ = gmpy2.gcdext(Mi, m)
        result += r * Mi * int(inv)
    return result % M

# Generate three 1024-bit RSA keys with e=3
from Crypto.PublicKey import RSA

keys = [RSA.generate(1024, e=3) for _ in range(3)]
n_list = [k.n for k in keys]
e = 3

# Encrypt the same message under all three keys (no padding — textbook RSA)
message = b"Broadcast secret"
m_int   = int.from_bytes(message, 'big')

ciphertexts = [pow(m_int, e, n) for n in n_list]
print("[*] Same message encrypted under 3 different keys (e=3, no padding)")
for i, c in enumerate(ciphertexts):
    print(f"    c{i+1} = {c}")

# Attack: CRT to find m^3 in the integers
x = crt(ciphertexts, n_list)
print(f"\n[*] CRT result x = m^{e} (in integers)")

# Integer cube root
m_recovered, exact = gmpy2.iroot(x, e)
m_recovered_int = int(m_recovered)
print(f"[+] Is exact: {exact}")
print(f"[+] Recovered: {m_recovered_int.to_bytes((m_recovered_int.bit_length()+7)//8, 'big')}")
# → b"Broadcast secret"
```

---

## 3. Attack 3 — Common Modulus Attack

### What It Is

If two RSA public keys share the same modulus `n` but have different public
exponents `e₁` and `e₂` (with `gcd(e₁, e₂) = 1`), and the same message `m`
is encrypted under both keys, the message can be recovered without the private key.

### Why It Works

```
c₁ = m^e₁ mod n
c₂ = m^e₂ mod n
```

By Bézout's identity: since `gcd(e₁, e₂) = 1`, there exist integers `a, b` such that:
```
a×e₁ + b×e₂ = 1
```

Then:
```
c₁^a × c₂^b ≡ m^(a×e₁) × m^(b×e₂) ≡ m^(a×e₁ + b×e₂) ≡ m^1 ≡ m (mod n)
```

One of `a` or `b` will be negative. Handle this with `pow(c, abs(b), n)` and
take the modular inverse.

### Minimal Exploit

```python
#!/usr/bin/env python3
"""
common_modulus.py — recover m when same modulus is used with two exponents
"""
from __future__ import annotations

import gmpy2
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# Generate a single 2048-bit RSA modulus
p = getPrime(1024)
q = getPrime(1024)
n = p * q

# Two different exponents sharing the modulus
e1 = 65537
e2 = 65539   # Different prime, gcd(e1, e2) = 1

message  = b"Common modulus fail"
m_int    = bytes_to_long(message)

# Encrypt same message under both exponents
c1 = pow(m_int, e1, n)
c2 = pow(m_int, e2, n)
print(f"[*] n (bits): {n.bit_length()}")
print(f"[*] e1={e1}, e2={e2}, gcd={gmpy2.gcd(e1, e2)}")

# Attack: extended Euclidean algorithm
g, a, b = gmpy2.gcdext(e1, e2)
assert g == 1, "gcd(e1,e2) must be 1"

a, b = int(a), int(b)

# m = c1^a * c2^b mod n  (handling negative exponents via modular inverse)
if a < 0:
    c1_a = pow(gmpy2.invert(c1, n), -a, n)
else:
    c1_a = pow(c1, a, n)

if b < 0:
    c2_b = pow(gmpy2.invert(c2, n), -b, n)
else:
    c2_b = pow(c2, b, n)

m_recovered = (c1_a * c2_b) % n
print(f"\n[+] Recovered: {long_to_bytes(m_recovered)}")
# → b"Common modulus fail"
```

---

## 4. Why OAEP Prevents These Attacks

### RSA-OAEP (PKCS#1 v2.2)

OAEP (Optimal Asymmetric Encryption Padding) prepends a random seed and hash
to the message before encryption:

```
padded_message = OAEP_Encode(random_seed, hash_of_labels, message)
ciphertext     = padded_message^e mod n
```

**Why it defeats these attacks:**
- **Small exponent / broadcast:** The random seed means two encryptions of the
  same message under the same key produce different ciphertexts. `m^e` is now
  `OAEP(m, random)^e` — the cube root of the ciphertext is a large padded blob,
  not `m` itself.
- **Common modulus:** Same reason — the OAEP-padded plaintexts differ due to
  the random seed, so `c₁` and `c₂` encrypt different padded messages even
  though the underlying message is the same.

```python
# FIXED: use RSA-OAEP for encryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey())
ciphertext = cipher.encrypt(b"Common modulus fail")
# → Each call produces a different ciphertext (randomised padding)
# → All three attacks above are defeated
```

---

## 5. Real-World Cases

| CVE / Incident | Attack | Impact |
|---|---|---|
| Multiple TLS stacks (pre-2014) | Textbook RSA key exchange in some cipher suites | Passive decryption of recorded sessions |
| SSH1 CRC-32 compensation flaw (1998) | Textbook RSA key exchange | Active MITM; SSH1 is obsolete as a result |
| Java `BigInteger.modPow(m, 1, n)` misuse | Common modulus accident in custom code | Message recovery in internal APIs |
| DKIM key reuse (2012) | Common modulus between DKIM signing keys | Email signing key recovery — Google, Yahoo affected |

---

## Key Takeaways

1. Textbook RSA — exponentiation with no padding — is never safe. The three
   attacks here all require `m` to be small or for keys to be shared in unsafe
   ways. OAEP eliminates all of them by randomising the padded message.
2. Choosing `e=3` for performance is a known risk. Modern standards require
   `e=65537` (Fermat number F4) as a minimum. Some implementations even reject
   `e < 65537`.
3. Sharing an RSA modulus between two key pairs is catastrophic. Every RSA key
   pair must have its own freshly generated modulus. Key generation is cheap;
   common-modulus recovery is free.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q567.1, Q567.2 …).

---

## Navigation

← Previous: [Day 566 — ECB Cut-and-Paste](DAY-0566-ECB-Cut-and-Paste.md)
→ Next: [Day 568 — Diffie-Hellman Attacks](DAY-0568-Diffie-Hellman-Attacks.md)
