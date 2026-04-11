---
title: "Password Hashing and Cracking"
tags: [foundation, cryptography, password-hashing, bcrypt, argon2, scrypt,
       hashcat, rainbow-tables, salt, credential-storage]
module: 01-Foundation-04
day: 34
related_topics:
  - Hashing Collisions and Length Extension (Day 030)
  - Authentication vs Authorisation (Day 039)
  - SQL Injection Post-Exploitation (Day 079)
  - Credential Stuffing and Password Spraying (Day 108)
---

# Day 034 — Password Hashing and Cracking

## Goals

By the end of this lesson you will be able to:

1. Explain why cryptographic hashes (SHA-256) are wrong for passwords.
2. Describe bcrypt, Argon2, and scrypt: the properties that make them
   suitable for password storage.
3. Identify hash algorithm from the hash format string.
4. Set up hashcat and crack: MD5, SHA-256, bcrypt, and Argon2 hashes.
5. Explain rainbow tables and why salting defeats them.
6. Recommend correct password hashing parameters for 2026.

---

## Prerequisites

- [Day 030 — Hashing, Collisions and Length Extension](DAY-0030-Hashing-Collisions-and-Length-Extension.md)

---

## Main Content — Part 1: Why Fast Hashes Fail for Passwords

### 1. The Problem with SHA-256 for Passwords

SHA-256 processes ~10 billion hashes per second on a modern GPU.
A 6-character alphanumeric password space = 62^6 ≈ 56 billion combinations.
Time to brute-force: **5 seconds**.

Even SHA-512 offers no protection — it's still ~1 billion/s on a GPU.

**Why fast is bad for passwords:** Password hashing must be intentionally
slow so that brute-forcing is computationally expensive.

---

### 2. bcrypt — The Standard for 15 Years

bcrypt was designed in 1999 specifically for password hashing. It uses the
Blowfish cipher in a modified key schedule.

**Key properties:**
- **Work factor (cost):** An integer parameter. Higher = slower.
  `cost = 12` means 2^12 iterations.
- **Built-in 128-bit random salt:** Never needs salting separately.
- **Output includes the algorithm, cost, and salt** in the hash string.

**bcrypt hash format:**

```
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8UlQqB3mj
└┤ └┤ └────────────────────────────────────────────┘
 │  │  22-char salt (128 bits) + 31-char hash
 │  │
 │  cost factor (12 = 2^12 = 4096 iterations)
 │
 version ($2b = current recommended)
```

**Performance:** At cost=12, bcrypt computes ~200 hashes/second on modern
hardware (intentionally). A password cracker is ~100,000× slower than
against SHA-256.

**When to use bcrypt:** For any user password where you control the backend.
Don't use cost < 10 in 2026; recommend cost = 12–14.

---

### 3. Argon2 — The Modern Standard

Argon2 won the Password Hashing Competition (2015). It is the current
recommended algorithm.

**Three variants:**
- **Argon2i:** Optimised for resistance to side-channel attacks.
- **Argon2d:** Faster; optimised for GPU cracking resistance.
- **Argon2id:** Hybrid of both → **recommended** for general use.

**Three tuning parameters:**
- **Memory cost (m):** Kilobytes of RAM required. Higher → harder to
  parallelise on GPU (GPU has less RAM).
- **Time cost (t):** Number of iterations.
- **Parallelism (p):** Number of threads.

**Argon2id hash format:**

```
$argon2id$v=19$m=65536,t=3,p=4$salt_base64$hash_base64
```

**Recommended parameters (2026):**
- `m=65536` (64 MB), `t=3`, `p=4` — interactive login
- `m=1048576` (1 GB), `t=4`, `p=8` — high-security storage (HSM-grade)

---

### 4. scrypt

scrypt (2009) was designed to be memory-hard before Argon2 existed. Still
widely deployed (e.g., Litecoin, many password managers).

Parameters: `N` (CPU/memory cost), `r` (block size), `p` (parallelism).

```
scrypt(password, salt, N=32768, r=8, p=1)
```

Argon2id is generally preferred for new systems, but scrypt is secure when
properly configured.

---

## Main Content — Part 2: Salting and Rainbow Tables

### 5. Rainbow Tables and Why Salting Defeats Them

**Rainbow table:** A precomputed table mapping hash values → passwords.
Build it once; crack hashes instantly (no brute-force needed).

```
# MD5 rainbow table entry:
5f4dcc3b5aa765d61d8327deb882cf99 → "password"
098f6bcd4621d373cade4e832627b4f6 → "test"
```

**Attack:** Look up any MD5 hash in the table → instant result.
Tables exist for MD5 and SHA-1 covering all 8-character passwords.

**Salting defeats rainbow tables:**

```
password_hash = HASH(salt + password)
```

Where `salt` is a random value unique per password.

```
# Same password, different salts → completely different hashes:
SHA-256("xF3k7" + "password") = 4a5c...
SHA-256("mP2qR" + "password") = 7e91...
```

A rainbow table built for `salt_A + words` cannot crack `salt_B + words`.
The attacker must build a separate table (or brute-force) per salt.
Since bcrypt and Argon2 include the salt in the hash string, this is
handled automatically.

---

## Main Content — Part 3: Password Cracking

### 6. hashcat Basics

```bash
# Install hashcat
apt install hashcat

# Or download from https://hashcat.net/hashcat/

# Basic syntax:
hashcat -m MODE -a ATTACK_TYPE hash_or_file wordlist

# Common modes:
# 0    = MD5
# 100  = SHA-1
# 1400 = SHA-256
# 1800 = sha512crypt ($6$ — Linux shadow file)
# 3200 = bcrypt ($2*$)
# 13400 = KeePass
# 22000 = WPA-PMKID/WPA2 (WiFi)
```

**Attack types:**

| Type | Flag | Description |
|---|---|---|
| Dictionary | `-a 0` | Wordlist |
| Combination | `-a 1` | Combine two wordlists |
| Brute force / Mask | `-a 3` | `?l?l?l?d?d` patterns |
| Rule-based | `-a 0 -r rules/best64.rule` | Mutate dictionary words |
| Hybrid | `-a 6 / -a 7` | Dictionary + mask |

**Cracking MD5 password hash:**

```bash
# Create test hash:
echo -n "password123" | md5sum
# 482c811da5d5b4bc6d497ffa98491e38

# Crack with rockyou:
hashcat -m 0 -a 0 482c811da5d5b4bc6d497ffa98491e38 \
    /usr/share/wordlists/rockyou.txt

# With rules (test common mutations: Password1!, passw0rd, etc.):
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule
```

**Cracking bcrypt (slow — shows the difference):**

```bash
# bcrypt hash (cost 10):
HASH='$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'

hashcat -m 3200 -a 0 "$HASH" /usr/share/wordlists/rockyou.txt
# ~200 H/s on CPU vs ~10B H/s for MD5 — ~50 million times slower
```

**Cracking Linux shadow hashes:**

```bash
# /etc/shadow format: $6$salt$hash
# sha512crypt, mode 1800
hashcat -m 1800 -a 0 shadow_hashes.txt rockyou.txt
```

---

### 7. Identifying Hash Types

```
$2b$12$... or $2y$12$... → bcrypt
$argon2id$v=19$...       → Argon2id
$6$salt$...              → sha512crypt (Linux)
$5$salt$...              → sha256crypt (Linux)
$1$salt$...              → md5crypt (old Linux)
$P$...                   → phpbb / WordPress bcrypt variant
{SSHA}base64...          → salted SHA-1 (LDAP)
32 hex chars             → MD5
40 hex chars             → SHA-1
64 hex chars             → SHA-256
128 hex chars            → SHA-512
```

**hashcat can auto-detect:**

```bash
hashcat --identify hash.txt
```

**`hash-identifier` Python tool:**

```bash
hash-identifier
# Paste hash → get likely algorithm(s)
```

---

## Key Takeaways

1. **Never use unsalted SHA-256 or MD5 for passwords.** They are too fast.
   A GPU cracks 10 billion MD5 hashes per second. A 8-char password takes
   seconds.
2. **Use bcrypt (cost ≥ 12) or Argon2id** for any new system. They are
   intentionally slow and resistant to GPU parallelism.
3. **Salt defeats rainbow tables.** bcrypt and Argon2id include the salt
   in the hash output — salting is built in and automatic.
4. **Argon2id is the 2026 recommendation.** It is memory-hard (defeats GPU
   cracking) and parameterisable to scale with hardware improvements.
5. **Database dumps from breaches + hashcat = plaintext passwords.**
   This is why password reuse is catastrophic — one breach leads to
   credential stuffing attacks against every site the user has an account on.

---

## Exercises

### Exercise 1 — Hash Identification and Cracking

```bash
# These hashes were extracted from a "breached" lab database.
# Identify each one and crack it with rockyou.txt:
HASHES=(
    "5f4dcc3b5aa765d61d8327deb882cf99"
    "da4b9237bacccdf19c0760cab7aec4a8359010b0"
    "ef92b778bafe771e89245b89ecbc08a44a4e166c56659f28024dc"
    '$2b$12$JH.x3SWBExu9ABSmpAcWc.s4QWMXdcxwFimEWN0/g8RFjJrR9eHhS'
)
```

### Exercise 2 — Write a Correct Password Storage Function

```python
# Using passlib for Argon2id in Python:
from passlib.hash import argon2

# Hash a password:
hashed = argon2.hash("super_secret_password",
                     memory_cost=65536, time_cost=3, parallelism=4)
print(hashed)

# Verify (constant-time):
print(argon2.verify("super_secret_password", hashed))  # True
print(argon2.verify("wrong_password", hashed))          # False

# Using bcrypt:
from passlib.hash import bcrypt
hashed = bcrypt.hash("super_secret_password", rounds=12)
print(bcrypt.verify("super_secret_password", hashed))
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 033 — TLS Handshake, PKI and Cert Chains](DAY-0033-TLS-Handshake-PKI-and-Cert-Chains.md)*
*Next: [Day 035 — Randomness and PRNG Attacks](DAY-0035-Randomness-and-PRNG-Attacks.md)*
