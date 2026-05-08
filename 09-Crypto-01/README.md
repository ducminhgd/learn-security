---
title: "09-Crypto-01 — Cryptographic Attacks: Classical Exploits"
tags: [cryptography, padding-oracle, timing-attack, length-extension, CBC,
  HMAC, SHA-256, module-readme]
module: 09-Crypto-01
---

# Module 09-Crypto-01 — Cryptographic Attacks: Classical Exploits

> "Cryptography is the one discipline where being almost right is completely
> wrong. A cipher that is broken 0.01% of the time is broken. This module
> covers the attacks that exploit the gap between 'almost right' and
> 'cryptographically secure'."
>
> — Ghost

---

## Module Overview

| Property | Value |
|---|---|
| Days | 561–570 |
| Track | Year 2 — Deep Dive |
| Prerequisites | Day 029–038 (crypto foundations), Day 031 (HMACs) |
| Goal | Exploit real cryptographic weaknesses in deployed systems |

---

## Lesson Map

| Day | File | Topic |
|---|---|---|
| 561 | `DAY-0561-Padding-Oracle-Attack.md` | CBC padding oracle — byte-by-byte decryption |
| 562 | `DAY-0562-Padding-Oracle-Lab.md` | Lab: decrypt token + forge admin session |
| 563 | `DAY-0563-Timing-Attacks.md` | Timing side-channel — HMAC comparison leak |
| 564 | `DAY-0564-Length-Extension-Attack.md` | SHA-256 length extension — forge signed requests |
| 565 | `DAY-0565-Length-Extension-Lab.md` | Lab: forge API request without the secret |
| 566 | `DAY-0566-ECB-Cut-and-Paste.md` | ECB block manipulation (upcoming) |
| 567 | `DAY-0567-RSA-Attack-Lab.md` | RSA small exponent + common modulus (upcoming) |
| 568 | `DAY-0568-Diffie-Hellman-Attacks.md` | Small subgroup, LOGJAM (upcoming) |
| 569 | `DAY-0569-ECDSA-Nonce-Reuse.md` | Nonce reuse → private key recovery (upcoming) |
| 570 | `DAY-0570-ECDSA-Lab.md` | Lab: recover ECDSA private key (upcoming) |

---

## The Ghost Method Applied to Crypto

| Stage | What you do |
|---|---|
| **Recon** | Understand the cryptographic construction being attacked |
| **Exploit** | Run the attack on a controlled target — recover plaintext or forge |
| **Detect** | Identify the observable signal of the attack (traffic pattern, error rates) |
| **Harden** | Replace the broken construction with the correct one (AES-GCM, HMAC, etc.) |

---

## Key Tools

| Tool | Purpose |
|---|---|
| `hlextend` (Python) | Length extension attack — SHA-1/SHA-256/SHA-512 |
| `padbuster` | Automated padding oracle attack |
| `hashpump` | Command-line length extension |
| `pycryptodome` | Low-level crypto primitives for exploit development |
| `cryptography` (Python) | Production-quality implementations for comparisons |
| Custom Python scripts | Padding oracle client, timing measurement |

---

## Quick Reference — Which Hash is Safe for What?

| Use case | Safe choice | Vulnerable choice |
|---|---|---|
| Message integrity (MAC) | `HMAC-SHA256` | `SHA256(secret + data)` |
| Data authentication | `AES-GCM` | `AES-CBC` without MAC |
| Value comparison | `hmac.compare_digest()` | `==` on strings/bytes |
| Password hashing | `Argon2`, `bcrypt` | `SHA256(password)` |
| Session tokens | `AES-GCM` encrypted | `AES-CBC` encrypted |
