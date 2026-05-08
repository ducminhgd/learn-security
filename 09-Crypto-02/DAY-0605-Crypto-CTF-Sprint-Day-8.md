---
title: "Crypto CTF Sprint — Day 8: Review, Pattern Recognition, and Module Wrap-Up"
tags: [cryptography, CTF, review, pattern-recognition, module-wrap-up,
  checklist, attack-tree, sprint, module-09-crypto-02]
module: 09-Crypto-02
day: 605
prerequisites:
  - Day 604 — Crypto CTF Sprint Day 7 (Timed Exam)
  - Days 561–604 — Complete crypto module
related_topics:
  - Crypto Competency Check (Day 610)
  - Malware Analysis Setup (Day 611)
---

# Day 605 — Crypto CTF Sprint: Day 8 (Review and Module 09 Wrap-Up)

> "Day 605. You have spent 45 days on cryptographic attacks — longer than
> most security engineers spend on crypto in their entire career. What you
> do today determines whether those 45 days stick or fade. Review. Pattern.
> Catalogue. Then build the attack tree that lives in your head. The next
> time you see a crypto CTF challenge, the first 60 seconds of analysis
> should be automatic. Today we build that automatic response."
>
> — Ghost

---

## Goals

Review all solutions from the Crypto CTF Sprint (Days 583–604), build the
master crypto attack decision tree, complete the Module 09 checklist, and
prepare for the competency check on Day 610.

**Prerequisites:** Days 583–604 (all CTF sprints + timed exam).
**Time budget:** 4–5 hours.

---

## Part 1 — Timed Exam Solutions Review (Day 604)

Work through each Day 604 problem with full notes open. For each:
- Compare your approach to the optimal approach.
- Note where you went wrong or took a suboptimal path.
- Write a 2-sentence summary of each technique you missed.

```
Problem 1 (RSA Coppersmith — known high bits):
  My approach:    ___________________________________________
  Optimal:        ___________________________________________
  What I missed:  ___________________________________________

Problem 2 (HNP — fixed top nonce bits):
  My approach:    ___________________________________________
  Optimal:        ___________________________________________
  Key insight:    ___________________________________________

Problem 3 (GCM nonce wrap):
  My approach:    ___________________________________________
  Optimal:        Nonce wraps → same (key, nonce) → forbidden attack
  GHASH key H:    ___________________________________________

Problem 4 (MT19937 clone):
  Time taken:     ___________________________________________
  Were all 5 correct? ______________________________________

Problem 5 (Unknown LCG):
  m:   _______   a:   _______   b:   _______
  x_10: ___________________________________________
```

---

## Part 2 — Master Crypto Attack Decision Tree

This is the single most important output of the entire crypto module.
Memorise it. When you see a crypto challenge, you should reach the correct
branch in under 2 minutes.

```
                        CRYPTO CHALLENGE
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    SYMMETRIC              ASYMMETRIC           HASH / PRNG
         │                    │                    │
    ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
    │         │          │         │          │         │
   CBC       GCM        RSA      ECDSA/DSA   HASH     PRNG
    │         │          │         │          │         │
    ├── Padding oracle?  ├── Small e?         ├── Length ├── MT19937?
    │   → Day 561        │   ├── 3 cts?       │   extension? → 624 outputs
    │                    │   │ → Håstad       │   → Day 564  → Day 595
    ├── Nonce reuse?     │   └── Partial PT?  │             │
    │   → BEAST          │     → Coppersmith  ├── Timing?  ├── LCG/LFSR?
    │                    │       Day 589      │   → Day 563 → Days 596,599
    ├── IV predictable?  ├── Large e (d small)?│            │
    │   → Bit-flip       │   → Wiener Day 592 └── Collision  └── Unknown params
    │                    │                       → HMAC forge  → GCD attack
    └── Key=IV?          ├── Related messages?
        → CBC-R           │   → Franklin-Reiter
                          │     Day 591
                          ├── Biased nonce?
                          │   ├── Exact reuse → Day 569
                          │   └── Partial bias → HNP Day 593
                          ├── Known nonce k?
                          │   → DSA key recovery Day 577
                          └── DH / ECDH?
                              ├── Small subgroup → Pohlig-Hellman Day 568
                              ├── Invalid curve → Day 568
                              └── MITM (param injection) → Day 575
```

---

## Part 3 — Module 09 Complete Checklist

Mark each item as ✓ (can do from memory), △ (need reference), or ✗ (need review):

### Symmetric Attacks (Days 561–566, 572–574, 580–582, 585)

```
[ ] CBC Padding Oracle — manual byte-by-byte decryption script
[ ] CBC Bit-Flip Attack — flip target bit in previous block
[ ] CBC-R — encrypt with decryption oracle
[ ] CBC Key-as-IV — recover key from IV leak
[ ] CBC-MAC Length Extension — same key as enc
[ ] CTR Bit-Flip — direct 1:1 flip
[ ] CTR Nonce Reuse — XOR keystreams, frequency analysis
[ ] GCM Nonce Reuse — Forbidden Attack: recover H and S
[ ] GCM Tag Forgery — from H and S, forge any tag
[ ] ECB Byte-at-a-Time Oracle — recover plaintext byte by byte
[ ] ECB Cut-and-Paste — role escalation
[ ] CRIME Compression Oracle — recover secret from compressed stream
```

### Hash Attacks (Days 563–564, 580, 582)

```
[ ] HMAC Timing Attack — statistical measurement, constant-time fix
[ ] SHA-2 Length Extension — forge signed requests
[ ] CBC-MAC Forgery (IV manipulation)
[ ] Joux Multicollision — 2^k collisions in k*|block| time
[ ] Herding Attack — chosen-prefix collision
```

### RSA Attacks (Days 567, 575–579, 583, 589–592)

```
[ ] Small exponent e=3: cube root attack
[ ] Håstad Broadcast (3 ciphertexts, same e)
[ ] Common Modulus Attack
[ ] Wiener's Attack (small d via continued fractions)
[ ] Coppersmith — partial plaintext (known high/low bits)
[ ] Franklin-Reiter — related messages (m2 = a*m1 + b)
[ ] Short Pad Attack (Coppersmith + Franklin-Reiter)
[ ] Stereotyped Messages (known format + Coppersmith)
[ ] Bleichenbacher e=3 Forgery (RSA PKCS#1 sig)
[ ] Bleichenbacher PKCS#1 v1.5 Oracle (padding oracle on decrypt)
[ ] RSA Parity Oracle
[ ] RSA Unpadded Oracle
[ ] RSA Common Factor (GCD of two moduli)
```

### ECDSA / DSA Attacks (Days 569–570, 577–578, 593–594)

```
[ ] ECDSA Nonce Reuse — exact same k
[ ] ECDSA HNP — biased nonce via lattice
[ ] DSA Key Recovery from Known Nonce k
[ ] DSA Repeated-r Attack (nonce reuse detection)
[ ] DSA Parameter Tampering (magic signature r=0, s=0)
[ ] DSA Weak Nonce (small k)
[ ] Invalid Curve Attack (ECDH)
```

### Key Exchange (Days 568, 575)

```
[ ] DH Parameter Injection MITM
[ ] DH Small Subgroup (Pohlig-Hellman)
[ ] DH Weak Parameters (p-1 smooth, LOGJAM)
[ ] ECDH Invalid Curve Point
```

### Lattice Attacks (Days 586–594)

```
[ ] LLL — SageMath Matrix(ZZ, ...).LLL()
[ ] Merkle-Hellman Knapsack via LLL
[ ] Coppersmith small_roots() — univariate
[ ] Coppersmith — bivariate / resultant method
[ ] HNP on ECDSA biased nonces
[ ] Truncated LCG via lattice
```

### PRNG Attacks (Days 595–596, 599)

```
[ ] MT19937 untemper
[ ] MT19937 clone from 624 outputs
[ ] Java Random LCG seed from 2 outputs
[ ] Unknown LCG modulus from GCD of differences
[ ] Truncated LCG (lattice)
[ ] LFSR Berlekamp-Massey
```

---

## Part 4 — Quick Reference Card

Print this or copy to your toolkit reference:

```
TOOL          | COMMAND / USAGE
--------------|-------------------------------------------------
SageMath LLL  | Matrix(ZZ, B).LLL()
small_roots() | PR(Zmod(N), 'x').gen(); f.small_roots(X=..., beta=1.0)
MT untemper   | untemper(y) → 20 lines of XOR-shift inversions
LCG modulus   | gcd(|x[i+2] - 2*x[i+1] + x[i]| for i in range)
LFSR B-M      | berlekamp_massey(bits) → returns connection poly
Wiener        | convergents(continued_fraction(e, N)) → check each k,d
GCM H         | H = AES_k(0^128); T = GHASH(H, A, C) XOR AES_k(N||1)
Padding Oracle| 16*256 queries per block; byte by byte from last to first
```

---

## Part 5 — What Comes Next

Module 10 starts on Day 611: **Malware Analysis**.

**Before Day 611:**
- Install FlareVM (Windows VM) or REMnux (Linux) — see Day 611 for setup
- Download a safe malware sample from MalwareBazaar (create account at bazaar.abuse.ch)
- Read: "The Art of Memory Forensics" Chapter 1 (available as PDF sample)

**The shift in mindset:**

```
Module 09 (Crypto): Mathematical attacks — you break the algorithm or its
implementation. Precision, algebra, polynomials.

Module 10 (Malware Analysis): Adversarial reverse engineering — you figure
out what the attacker deployed and what it does. Dynamic, behavioural,
pattern-matching. A completely different tool set and mental mode.
```

---

## Module 09 Final Score Card

```
Total days in module:      45 (Days 561–605)
Days with labs completed:  _____ / 45
Competency check (Day 610): [ ] Not yet  [ ] Passed  [ ] Re-attempt needed

Module 09 grade:
  [ ] Complete — all items ✓ or △ in checklist
  [ ] Partial — 5+ items ✗ in checklist (revisit before Day 610)
  [ ] Incomplete — return to theory days before proceeding

Strongest attack category:  ___________________________________________
Weakest attack category:    ___________________________________________
```

---

## Key Takeaways

1. **Pattern recognition is the skill.** The techniques are fixed. Your job
   is to identify which technique applies in ≤ 2 minutes. The decision tree
   above is your shortcut — but you must build it in your head, not look
   it up.
2. **SageMath is your primary crypto weapon.** LLL, small_roots(), GCD,
   polynomial ring arithmetic — all available, all fast. If you are not
   comfortable with SageMath syntax, spend one hour today running practice
   commands until it is automatic.
3. **45 days of crypto is not enough to become a cryptographer.** It IS
   enough to exploit the vast majority of cryptographic vulnerabilities that
   appear in production systems and CTFs. That was the goal.
4. **Module 10 is a gear shift.** Malware analysis is dynamic, behavioural,
   and tool-heavy in a different way. Come in fresh. The skills you built
   in binary exploitation (Day 366+) and reverse engineering (Day 431+) will
   be your foundation.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q605.1, Q605.2 …).

---

## Navigation

← Previous: [Day 604 — Crypto CTF Sprint Day 7](DAY-0604-Crypto-CTF-Sprint-Day-7.md)
→ Next: [Day 606 — Advanced Crypto: Post-Quantum Preview](DAY-0606-Post-Quantum-Preview.md)
