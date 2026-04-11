---
title: "Cryptography Competency Check"
tags: [foundation, cryptography, competency-check, self-assessment,
       module-gate, review]
module: 01-Foundation-04
day: 38
related_topics:
  - All 01-Foundation-04 topics (Days 029–037)
  - Foundation Competency Gate (Day 050)
---

# Day 038 — Cryptography Competency Check

## Goals

No new content today. This is a gate. Answer every question correctly
before proceeding to the Authentication module.

---

## Prerequisites

- Days 029–037 (all of 01-Foundation-04)

---

## Self-Assessment — Explain Without Notes

### Symmetric Encryption (Days 029–030)

1. Why does ECB mode leak plaintext patterns? Draw the block diagram.
2. What are the two requirements for a CBC IV? What goes wrong if either is
   violated?
3. What property does GCM add that CBC lacks? Name it precisely.
4. If you encrypt with CTR mode and reuse the nonce, what can an attacker
   recover? Walk through the math.
5. What is PKCS#7 padding? Why does incorrect padding validation matter?

### Hashing (Day 030)

6. What is the birthday attack? Why does SHA-256 have 2^128 collision
   resistance, not 2^256?
7. Why is MD5 broken? What specific attack exists?
8. What is the Merkle–Damgård construction and which hash functions use it?
9. A system signs API requests with `sha256(secret_key + request_body)`.
   What attack is possible? What is the fix?

### MACs and Integrity (Day 031)

10. What is the difference between `HMAC(key, message)` and
    `H(key || message)`? Why does the latter fail?
11. Why is "Encrypt-then-MAC" correct and "MAC-then-Encrypt" dangerous?
12. A developer compares two HMAC values with Python's `==`. What attack
    does this enable? What is the fix?

### Asymmetric Encryption (Day 032)

13. What are the two weaknesses of textbook RSA (no padding)?
14. If an attacker has two ciphertexts for the same plaintext with the
    same modulus `n` but different public exponents, how do they recover
    the plaintext? (Common modulus attack.)
15. Why is `e = 3` a dangerous public exponent?
16. At what key size is RSA considered secure in 2026?
17. What does ECDH provide that RSA key exchange does not?

### TLS and PKI (Day 033)

18. Trace TLS 1.3 handshake steps. What is ECDHE and what is HKDF?
19. What is forward secrecy and why does ECDHE provide it?
20. What is OCSP stapling and what problem does it solve?
21. How do Certificate Transparency logs enable attacker reconnaissance?
22. What would a `testssl.sh` run tell you about a target?

### Password Hashing (Day 034)

23. Why is SHA-256 wrong for password storage? Be specific (hash rate).
24. What are the three Argon2 variants and which is recommended?
25. What is a rainbow table and why does salting defeat it?
26. Identify this hash format: `$2b$12$LQv3c1yq...`. What algorithm,
    what cost factor, what's included in the string?

### PRNG (Day 035)

27. What is the difference between `random.random()` and `secrets.token_hex()`
    in Python at the implementation level?
28. How many consecutive MT19937 outputs do you need to fully predict
    future outputs?
29. A reset token is `sha256(time.time())`. What is the attack?

---

## Lab Submission — Required for Module Completion

Submit solutions to at least three of these before marking the module
complete:

### Lab A — ECB Oracle Attack

Implement the ECB block boundary detection:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Oracle: appends your input to a secret suffix and encrypts with ECB
SECRET = b"admin=true;extra=secret_data_here"
KEY = os.urandom(16)

def oracle(your_input: bytes) -> bytes:
    plaintext = pad(your_input + SECRET, 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# Task: determine the length of SECRET using only oracle calls
# Then recover SECRET byte by byte using block-boundary alignment
```

### Lab B — Length Extension Attack

Using `hashpumpy` or implementing manually, forge a valid MAC for:
- Original: `user=alice&action=read`
- Forged: `user=alice&action=read[padding]&action=delete`

Confirm it verifies against the same server-side check.

### Lab C — PRNG Token Prediction

Set up the time-seeded token generator from Day 035. Write a script
that brute-forces the seed and predicts the next 5 tokens the server
will generate (given you know the current token).

### Lab D — Cryptopals Set 1

Submit completed solutions for Challenges 3, 4, and 6 from
https://cryptopals.com/sets/1

---

## Gap Analysis

```markdown
| Topic | Gap | Review Day |
|---|---|---|
```

Do not proceed to Day 039 until:
- [ ] All 29 self-assessment questions answered correctly.
- [ ] At least 3 lab submissions completed.
- [ ] The synthesis diagram from Day 037 Exercise 3 drawn from memory.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 037 — Crypto in the Wild: CVE Review](DAY-0037-Crypto-in-the-Wild-CVE-Review.md)*
*Next: Day 039 — Auth vs Authz and Password Storage (01-Foundation-05)*
