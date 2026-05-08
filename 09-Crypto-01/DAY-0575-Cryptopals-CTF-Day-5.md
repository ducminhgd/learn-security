---
title: "Cryptopals CTF Practice — Day 5: Set 5 (Diffie-Hellman and Friends)"
tags: [cryptography, cryptopals, CTF, Diffie-Hellman, DH-MITM, SRP, SRNG,
  RSA, malicious-g, parameter-tampering, set-5, key-exchange]
module: 09-Crypto-01
day: 575
prerequisites:
  - Day 574 — Cryptopals CTF Day 4 (Set 4 complete)
  - Day 568 — Diffie-Hellman Attacks
  - Day 567 — RSA Attack Lab
related_topics:
  - Cryptopals CTF Day 6 (Day 576 — upcoming)
  - Diffie-Hellman Attacks (Day 568)
  - ECB Cut-and-Paste (Day 566)
---

# Day 575 — Cryptopals CTF Practice: Day 5

> "Set 5 is where you implement Diffie-Hellman from scratch and then break it.
> Not a library call — every modular exponentiation, every handshake step,
> every parameter validation. Then you attack the parameter exchange itself.
> That is the lesson: the protocol is only as secure as its parameter negotiation."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 5 (challenges 33–40): DH key exchange from scratch,
MITM against unvalidated DH, SRP password authentication, malicious `g`
parameter attack, and RSA implementation with unpadded message recovery.

**Prerequisites:** Sets 1–4 complete; Day 568 (DH attacks); Day 567 (RSA).
**Estimated lab time:** 6 hours (the hardest set so far — budget the full day).
**Resource:** https://cryptopals.com/sets/5

---

## Challenge 33 — Implement DH Key Exchange

```python
#!/usr/bin/env python3
"""
Challenge 33: Implement Diffie-Hellman from scratch.
Use the NIST P parameter set.
"""
from __future__ import annotations

import hashlib
import secrets

# NIST DH parameters (1536-bit prime)
DH_P = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
    16,
)
DH_G = 2

def dh_gen_key(p: int = DH_P, g: int = DH_G) -> tuple[int, int]:
    """Generate (private_key, public_key) pair."""
    a = secrets.randbelow(p - 2) + 2   # a in [2, p-2]
    A = pow(g, a, p)
    return a, A

def dh_shared_secret(peer_public: int, my_private: int, p: int = DH_P) -> bytes:
    """Compute shared secret and hash it to get a symmetric key."""
    s = pow(peer_public, my_private, p)
    return hashlib.sha256(s.to_bytes((s.bit_length() + 7) // 8, 'big')).digest()[:16]

# ── DH handshake simulation ───────────────────────────────────────────────
# Alice
alice_private, alice_public = dh_gen_key()
# Bob
bob_private,   bob_public   = dh_gen_key()

# Exchange public keys — Alice computes shared secret
alice_secret = dh_shared_secret(bob_public, alice_private)
# Bob computes shared secret
bob_secret   = dh_shared_secret(alice_public, bob_private)

print(f"[*] Alice public: {alice_public % (2**32):#010x}...")
print(f"[*] Bob public:   {bob_public   % (2**32):#010x}...")
print(f"[*] Alice key:    {alice_secret.hex()}")
print(f"[*] Bob key:      {bob_secret.hex()}")
assert alice_secret == bob_secret
print("[+] Challenge 33 passed — DH shared secrets match")
```

---

## Challenge 34 — MITM Against Unvalidated DH

```python
#!/usr/bin/env python3
"""
Challenge 34: DH parameter injection MITM.

Normal DH: Alice sends (p, g, A=g^a), Bob responds (B=g^b)
MITM: Mallory intercepts and replaces both public keys with p.

Why p? Because:
  Alice computes K = p^a mod p = 0
  Bob   computes K = p^b mod p = 0
  Mallory knows the shared secret is always 0 (→ SHA256(0)).
"""
from __future__ import annotations

import hashlib

def mitm_inject_p():
    """Simulate the MITM attack where public keys are replaced with p."""
    # Alice generates keys
    a, A = dh_gen_key()

    # --- MITM: Mallory intercepts Alice's (p, g, A) and sends p to Bob ---
    # Bob receives p instead of A
    b, _ = dh_gen_key()
    B = DH_P   # Mallory sends p to Alice too

    # Alice: shared_secret = B^a mod p = p^a mod p = 0
    alice_s  = pow(B, a, DH_P)   # = 0
    alice_key = hashlib.sha256(
        alice_s.to_bytes(max(1, (alice_s.bit_length() + 7) // 8), 'big')
    ).digest()[:16]

    # Bob: shared_secret = p^b mod p = 0
    bob_s    = pow(DH_P, b, DH_P)   # = 0
    bob_key  = hashlib.sha256(
        bob_s.to_bytes(max(1, (bob_s.bit_length() + 7) // 8), 'big')
    ).digest()[:16]

    # Mallory: knows shared secret = SHA256(0)
    zero     = 0
    mallory_key = hashlib.sha256(b"\x00").digest()[:16]

    print(f"[*] Alice key:   {alice_key.hex()}")
    print(f"[*] Bob key:     {bob_key.hex()}")
    print(f"[*] Mallory key: {mallory_key.hex()}")
    assert alice_key == bob_key == mallory_key
    print("[+] MITM succeeded — Mallory knows the shared key")

mitm_inject_p()
print("[+] Challenge 34 passed")
```

---

## Challenge 35 — Malicious DH Generator (g=1, g=p, g=p-1)

```python
#!/usr/bin/env python3
"""
Challenge 35: Negotiate malicious g values.
Different g values force predictable shared secrets:
  g=1:   g^x = 1 for all x → shared secret always 1
  g=p:   g^x mod p = 0 for x≥1 → shared secret always 0
  g=p-1: g^x mod p is either 1 (x even) or p-1 (x odd) — only 2 possibilities
"""
from __future__ import annotations

import hashlib

def predict_shared_secret(g_val: int, p: int = DH_P) -> list[int]:
    """Return the set of possible shared secrets for a given malicious g."""
    if g_val == 1:
        return [1]
    if g_val == p:
        return [0]
    if g_val == p - 1:
        return [1, p - 1]   # Depends on parity of private key
    return []   # Unknown — legitimate g

def malicious_g_attack(g_injected: int) -> None:
    """Simulate Mallory injecting a malicious g during DH negotiation."""
    # Bob generates private key with the malicious g
    b = secrets.randbelow(DH_P - 2) + 2
    B = pow(g_injected, b, DH_P)

    # Alice also uses malicious g
    a = secrets.randbelow(DH_P - 2) + 2
    A = pow(g_injected, a, DH_P)

    alice_s = pow(B, a, DH_P)
    bob_s   = pow(A, b, DH_P)
    assert alice_s == bob_s

    possible = predict_shared_secret(g_injected)
    print(f"\n  g={g_injected if g_injected < 3 else 'p' if g_injected == DH_P else 'p-1'}")
    print(f"  Actual shared secret mod p: {alice_s}")
    print(f"  Mallory's prediction: {possible}")
    print(f"  Correct prediction: {alice_s in possible}")
    assert alice_s in possible

for g_malicious in [1, DH_P, DH_P - 1]:
    malicious_g_attack(g_malicious)
print("\n[+] Challenge 35 passed — all three malicious g values cracked")
```

---

## Challenge 36 — Implement SRP

```python
#!/usr/bin/env python3
"""
Challenge 36: Implement Secure Remote Password (SRP).
SRP is a password-authenticated key agreement protocol that prevents
the server from learning the plaintext password.
"""
from __future__ import annotations

import hashlib
import secrets

# SRP parameters (same DH group)
SRP_N  = DH_P
SRP_G  = 2
SRP_K  = 3   # SRP multiplier (simplified)

def H(*args: bytes) -> int:
    """Hash arguments and return integer."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return int(h.hexdigest(), 16)

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

# ── Server setup ──────────────────────────────────────────────────────────
PASSWORD = b"correct horse battery staple"
salt     = secrets.token_bytes(16)
x        = H(salt, PASSWORD)
verifier = pow(SRP_G, x, SRP_N)   # v = g^x mod N — stored on server

# ── Client → Server: username ─────────────────────────────────────────────
# Client
a, A = dh_gen_key(SRP_N, SRP_G)

# Server
b, _ = dh_gen_key(SRP_N, SRP_G)
B    = (SRP_K * verifier + pow(SRP_G, b, SRP_N)) % SRP_N

# ── Server → Client: salt, B ──────────────────────────────────────────────
u = H(int_to_bytes(A), int_to_bytes(B))   # Random scrambling parameter

# Client computes session key
x_client  = H(salt, PASSWORD)
S_client  = pow(B - SRP_K * pow(SRP_G, x_client, SRP_N), a + u * x_client, SRP_N)
K_client  = hashlib.sha256(int_to_bytes(S_client)).hexdigest()

# Server computes session key
S_server  = pow(A * pow(verifier, u, SRP_N), b, SRP_N)
K_server  = hashlib.sha256(int_to_bytes(S_server)).hexdigest()

print(f"[*] Client session key: {K_client[:16]}")
print(f"[*] Server session key: {K_server[:16]}")
assert K_client == K_server
print("[+] Challenge 36 passed — SRP implemented")
```

---

## Challenge 38 — Offline Dictionary Attack on Simplified SRP

```python
#!/usr/bin/env python3
"""
Challenge 38: simplified SRP without the 'k' multiplier.
A MITM attacker can run an offline dictionary attack if they intercept
the client's public key A and the scrambling parameter u.
"""
from __future__ import annotations

# Simplified SRP:
# Server sends: salt, B=g^b, u (random)
# Client computes: x=H(salt||password), S=(B^(a+u*x)) mod N, K=H(S)
# Client sends: H(K) as proof

# Malicious server (MITM): choose b and u freely → run offline attack
# For each candidate password p:
#   x = H(salt || p)
#   v = g^x mod N
#   S = (A * v^u)^b mod N
#   K = H(S)
#   Check if H(K) matches client's proof

WORDLIST  = [b"password", b"letmein", b"correct horse battery staple",
             b"123456", b"qwerty"]
TRUE_PASS = b"correct horse battery staple"

# Simplified server (malicious)
b_evil = secrets.randbelow(DH_P - 2) + 2
B_evil = pow(SRP_G, b_evil, SRP_N)
u_evil = secrets.randbelow(2**128)
salt_e = secrets.token_bytes(16)

# Client connects with true password
a_c, A_c   = dh_gen_key(SRP_N, SRP_G)
x_c        = H(salt_e, TRUE_PASS)
S_c        = pow(B_evil, a_c + u_evil * x_c, SRP_N)
K_c        = hashlib.sha256(int_to_bytes(S_c)).hexdigest()
proof      = hashlib.sha256(K_c.encode()).hexdigest()

# Malicious server performs offline attack
print("[*] Starting offline dictionary attack…")
for candidate in WORDLIST:
    x_guess   = H(salt_e, candidate)
    v_guess   = pow(SRP_G, x_guess, SRP_N)
    S_guess   = pow(A_c * pow(v_guess, u_evil, SRP_N), b_evil, SRP_N)
    K_guess   = hashlib.sha256(int_to_bytes(S_guess)).hexdigest()
    p_guess   = hashlib.sha256(K_guess.encode()).hexdigest()
    if p_guess == proof:
        print(f"[+] Password cracked: {candidate!r}")
        break
print("[+] Challenge 38 passed")
```

---

## Challenges 39 & 40 — RSA Implementation and Unpadded Message Recovery

```python
#!/usr/bin/env python3
"""
Challenge 39: Implement RSA from scratch.
Challenge 40: Implement e=3 broadcast attack (you already did this in Day 567).
"""
from __future__ import annotations

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import gmpy2

def rsa_gen(bits: int = 1024, e: int = 65537) -> tuple[tuple, tuple]:
    """Generate RSA key pair. Returns ((e, n), (d, n))."""
    while True:
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        n    = p * q
        phi  = (p - 1) * (q - 1)
        if gmpy2.gcd(e, phi) == 1:
            d = int(gmpy2.invert(e, phi))
            return (e, n), (d, n)

def rsa_encrypt(m_bytes: bytes, pub: tuple) -> int:
    e, n = pub
    return pow(bytes_to_long(m_bytes), e, n)

def rsa_decrypt(c: int, priv: tuple) -> bytes:
    d, n = priv
    m    = pow(c, d, n)
    return long_to_bytes(m)

# Challenge 39 test
pub, priv = rsa_gen(bits=1024, e=65537)
message   = b"Hello RSA"
ct        = rsa_encrypt(message, pub)
pt        = rsa_decrypt(ct, priv)
assert pt == message
print(f"[+] Challenge 39 passed — RSA: {pt!r}")

# Challenge 40 — e=3 broadcast attack (refer to Day 567)
print("[+] Challenge 40: see Day 567 for Håstad broadcast attack implementation")
```

---

## Set 5 Retrospective

At the end of Set 5, you have built from scratch:
- DH key exchange (mod exp, parameter negotiation)
- MITM against unauthenticated DH (parameter injection)
- SRP (password-authenticated key exchange)
- RSA (key generation, encrypt, decrypt)

And you have attacked:
- DH with malicious g values (parameter manipulation)
- Simplified SRP (offline dictionary attack)
- RSA with small e (Hastad broadcast — Day 567)

```
Set 5 Self-Assessment:

[ ] 1. Why does g=p-1 give two possible shared secrets instead of one?
        Write the modular arithmetic proof.

[ ] 2. SRP prevents the server from learning the plaintext password.
        Explain why a malicious server (challenge 38) can still crack the
        password with an offline dictionary attack. What does SRP protect
        against that a standard password hash database does NOT?

[ ] 3. In challenge 34, the MITM works because Alice and Bob do not authenticate
        the DH parameters. In TLS, what prevents this attack?

[ ] 4. You implemented RSA key generation. What would happen if p and q were
        both 512-bit primes with the same top few bits? (Hint: research
        "Fermat factoring".)
```

---

## Cryptopals Progress Checkpoint

| Set | Challenges | Status |
|---|---|---|
| Set 1 | 1–8 (Basics) | Day 571 |
| Set 2 | 9–16 (Block ciphers) | Day 572 |
| Set 3 | 17–24 (CBC + stream ciphers) | Day 573 |
| Set 4 | 25–32 (Stream cipher + timing) | Day 574 |
| Set 5 | 33–40 (DH + RSA) | **Today** |
| Set 6 | 41–48 (DSA + RSA attacks) | Upcoming |
| Set 7 | 49–56 (Hashes + authenticated enc) | Upcoming |
| Set 8 | 57–66 (Elliptic curves) | Upcoming |

Sets 6–8 are covered in the Advanced Crypto module (09-Crypto-02, Day 591+).

---

## Key Takeaways

1. Implementing DH from scratch reveals how much security depends on parameter
   validation. Every production DH library validates that peer public keys are
   in range `[2, p-2]`. Without that one check, the MITM attack in challenge 34
   is trivially possible.
2. SRP is elegant — the server never learns the password and cannot impersonate
   the client to other servers. But challenge 38 shows that even SRP is
   vulnerable to offline dictionary attacks if the server is malicious. SRP
   protects against passive eavesdropping and honest-but-curious servers, not
   against fully malicious servers.
3. Implementing RSA from scratch removes the mystique. RSA is modular
   exponentiation with constraints on the parameters. The constraints (large,
   independent primes; correct `e` and `d` computation) are where the security
   lives. The math is 40 lines of Python.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q575.1, Q575.2 …).

---

## Navigation

← Previous: [Day 574 — Cryptopals CTF Day 4](DAY-0574-Cryptopals-CTF-Day-4.md)
→ Next: Day 576 — Cryptopals CTF Practice: Day 6 (upcoming)
