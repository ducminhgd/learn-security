---
title: "Cryptographic Attacks — Competency Check (Day 610)"
tags: [cryptography, competency-check, gate, self-assessment, module-complete,
  RSA, ECDSA, lattice, Coppersmith, HNP, padding-oracle, MT19937,
  module-09-crypto-02]
module: 09-Crypto-02
day: 610
prerequisites:
  - Days 561–609 — Complete Module 09 (Crypto-01 + Crypto-02)
related_topics:
  - Malware Analysis Setup (Day 611)
  - Milestone 600 (Day 600)
---

# Day 610 — Cryptographic Attacks: Competency Check

> "You have spent 50 days on cryptography. Fifty days to go from 'I know what
> RSA is' to 'I can recover private keys from biased nonces using lattice
> reduction'. Today I find out whether that happened — or whether you read
> the material without building the skill. There is no shame in the latter.
> There IS a consequence: you do not advance until the skill is there.
> Take the check honestly."
>
> — Ghost

---

## Goals

Verify mastery of Module 09 (Days 561–609) before advancing to Malware
Analysis. Three parts: written knowledge check, live lab, self-assessment.

**Prerequisites:** All of Module 09.
**Time budget:** 4 hours total.

---

## Part 1 — Written Explanation (20 minutes)

Without notes, write a clear explanation of each attack. Aim for 3–5 sentences
each. Include: what the attack does, when it applies, and the correct defence.

### Question 1
```
Explain the CBC Padding Oracle attack. Include:
  - What information the oracle leaks
  - How the byte-by-byte decryption works
  - Why this attack requires no knowledge of the encryption key
  - The correct defensive fix

Answer:
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
```

### Question 2
```
Explain Coppersmith's method for RSA partial plaintext recovery. Include:
  - The mathematical condition that enables the attack
  - The relationship between e, N, and the unknown bits
  - When it fails (bound exceeded)
  - What the defender should do

Answer:
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
```

### Question 3
```
Explain the Hidden Number Problem attack on ECDSA. Include:
  - What "biased nonce" means
  - How the lattice encodes the bias
  - How many signatures are needed for an 8-bit bias
  - The RFC 6979 fix

Answer:
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________
```

**Scoring Part 1:** 10 points per question, 30 total.
Pass threshold for Part 1: ≥ 21/30.

---

## Part 2 — Live Lab (90 minutes)

Two challenges. Open SageMath and Python. No time pressure on learning —
only on execution. You know the techniques. Apply them.

### Challenge A: "The Encrypted Vote" (RSA Coppersmith)

```
A voting system encrypts each vote as:
  m = "VOTE:" + candidate_name_padded_to_fixed_length

Parameters:
  N = (generate a fresh 512-bit N using random_prime in SageMath)
  e = 3

Generate your own challenge:
  1. In SageMath: N = random_prime(2**256) * random_prime(2**256)
  2. m = "VOTE:ALICE" + "\x00" * 6  (80-bit message)
  3. c = power_mod(int(m_int), 3, int(N))
     where m_int = int.from_bytes(m.encode(), "big")

Attack:
  - Known: "VOTE:" prefix (5 bytes = 40 bits)
  - Unknown: candidate name + padding (7 bytes = 56 bits)
  - N is 512-bit, e=3
  - Bound: 2^56 < N^(1/3) ≈ 2^171 → Coppersmith applies

Recover m_int. Extract the candidate name.
```

```python
# Your solve goes here
# Time started: ___________
# Time ended:   ___________
```

### Challenge B: "Repeated Tokens" (MT19937 + Session Prediction)

```
A web service generates authentication tokens using Python's random module.
Each token is an 8-hex-character string (32 bits from getrandbits(32)).

You have collected the following 624 consecutive tokens (generate your own):
  tokens = [random.getrandbits(32) for _ in range(624)]

The service generates a special "admin upgrade" token immediately after
the 624th regular token. This token is also 32 bits.

Attack:
  1. Clone MT19937 from the 624 tokens.
  2. Predict the admin upgrade token (the 625th 32-bit output).
  3. Use the token to "log in" as admin (print the predicted value).
```

```python
# Your solve goes here — implement without looking at Day 595
# Time started: ___________
# Time ended:   ___________
```

**Scoring Part 2:** Challenge A = 35 points. Challenge B = 35 points.
**Pass threshold:** ≥ 50/70 (at least one full + meaningful progress on second).

---

## Part 3 — Self-Assessment Review (20 minutes)

Review your Module 09 checklist from Day 605. Score each item honestly:

```
1 = Theoretical only (read it, haven't done it)
3 = Can do in lab with notes
5 = Can do under time pressure without notes

Category          | My Score | Evidence (what I built / solved)
------------------|----------|----------------------------------
CBC Padding Oracle|          |
CBC-R             |          |
GCM Forbidden Atk |          |
SHA-2 Length Ext  |          |
RSA e=3 cube root |          |
RSA Håstad        |          |
RSA Wiener        |          |
RSA Coppersmith   |          |
Franklin-Reiter   |          |
ECDSA Nonce Reuse |          |
ECDSA HNP         |          |
LLL (SageMath)    |          |
MT19937 Clone     |          |
LCG Seed Recovery |          |
LFSR Berlekamp-M  |          |
```

**Self-assessment scoring:**

- Items ≥ 3: Ready
- Items = 1: Not ready — revisit before advancing
- Average score ≥ 3.0 across all items: Module 09 complete

```
Average score:   ___________
Items below 3:   ___________
Plan for items below 3:  ___________________________________________
```

---

## Overall Pass Criteria

| Part | Maximum | Pass Threshold |
|---|---|---|
| Part 1 — Written | 30 | ≥ 21 |
| Part 2 — Lab | 70 | ≥ 50 |
| Part 3 — Self-assessment | Pass/Fail | Avg ≥ 3.0 |
| **All three parts pass** | — | **Advance to Module 10** |

If any part fails:
- Part 1 < 21: Re-study the three failed questions. Re-take Part 1 only.
- Part 2 < 50: Spend 2 days drilling the failed challenge type. Re-take Part 2.
- Part 3 avg < 3.0: Complete lab exercises for every item below 3 in Module 09.

---

## Module 09 Summary

You have covered 50 days of cryptographic attacks (Days 561–609):

**Symmetric attacks:**
CBC padding oracle → CBC-R encryption oracle → GCM nonce reuse →
CRIME compression oracle → CBC-MAC forgery → CTR nonce reuse

**Hash attacks:**
SHA-2 length extension → timing side-channel → Joux multicollision → herding

**RSA attacks:**
Small exponent → Håstad broadcast → common factor → Wiener's attack →
Coppersmith partial plaintext → Franklin-Reiter related messages →
short pad → stereotyped messages → Bleichenbacher oracle → parity oracle

**ECDSA / DSA:**
Nonce reuse → HNP biased nonces → key recovery from known k →
DSA parameter tampering → invalid curve attack

**Lattice:**
LLL → Merkle-Hellman knapsack → Coppersmith small roots →
HNP lattice construction

**PRNG:**
MT19937 clone → Java LCG recovery → LFSR Berlekamp-Massey →
truncated LCG → Bellcore DFA on RSA-CRT

**PQC:**
Shor's threat model → NIST standards (Kyber, Dilithium, SPHINCS+, FALCON) →
LWE hardness → PQC implementation attack surface

The next module is **Malware Analysis** (Days 611–650). The skills shift from
mathematical to behavioural: reverse engineering, dynamic analysis, sandbox
evasion detection, and report writing.

Before Day 611: install FlareVM or REMnux (see Day 611 for setup guide).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q610.1, Q610.2 …).

---

## Navigation

← Previous: [Day 609 — Crypto Catch-Up](DAY-0609-Crypto-Catch-Up.md)
→ Next: [Day 611 — Malware Analysis Setup](../10-MalwareAnalysis-01/DAY-0611-Malware-Analysis-Setup.md)
