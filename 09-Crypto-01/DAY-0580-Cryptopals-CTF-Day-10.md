---
title: "Cryptopals CTF Practice — Day 10: Set 7 Part 1 (CBC-MAC Forgery)"
tags: [cryptography, cryptopals, CTF, CBC-MAC, MAC-forgery, length-extension,
  message-length, multi-block, IV-manipulation, set-7, challenge-49,
  challenge-50, CWE-327]
module: 09-Crypto-01
day: 580
prerequisites:
  - Day 579 — Cryptopals CTF Day 9 (Bleichenbacher complete)
  - Day 572 — Cryptopals CTF Day 2 (CBC bit-flipping)
related_topics:
  - Cryptopals CTF Day 11 (Day 581)
  - CBC Bit-Flipping (Day 572)
  - CBC Padding Oracle (Day 561)
---

# Day 580 — Cryptopals CTF Practice: Day 10

> "CBC-MAC looks like authentication but it is not. If the verifier doesn't
> include the message length in what's MACed, an attacker can append any block
> they like by XORing with the current MAC. Challenges 49 and 50 are the two
> most common ways banking systems have been broken."
>
> — Ghost

---

## Goals

Complete Cryptopals Set 7 Challenges 49 and 50: forge a CBC-MAC request by
exploiting a missing message length field (Ch.49) and by prepending an
arbitrary block to an existing CBC-MAC chain (Ch.50 — JavaScript sandbox
escape via HMAC collision).

**Prerequisites:** Sets 1–6 complete; Day 572 (CBC bit-flip, block boundaries).
**Estimated lab time:** 4 hours.
**Resource:** https://cryptopals.com/sets/7

---

## CBC-MAC: How It Works and Why It Is Fragile

CBC-MAC is `AES-CBC(message, key, IV=0)[last block]`. For a fixed-length
message, it is a secure MAC. For variable-length messages without length
inclusion, it is broken in two ways:

```
Forgery 1 (free IV): If the attacker controls IV, they can redirect the MAC
  chain to authenticate a different first block.

Forgery 2 (length extension): If IV=0 and message length is variable,
  the attacker appends block B XOR (current MAC) to extend the authenticated
  chain without invalidating the MAC.
```

---

## Challenge 49 — CBC-MAC Message Forgery (Captured IV)

### Scenario

A bank API accepts transfer messages:

```
message = "from=<id>&to=<id>&amount=<N>"
MAC     = CBC-MAC(key, IV=random, message)
request = IV || message || MAC
```

The server verifies by: recompute `CBC-MAC(key, IV_from_message, message)` and
compare with the MAC in the request. The IV is **included** in the request, not
fixed to zero.

**Vulnerability:** The attacker controls IV. If they can capture a valid request
from victim `A` to attacker `B`, they can modify the first block of the message
by adjusting IV, because:

```
Block 1 decryption in CBC: P1 = AES_k_decrypt(C1) XOR IV
If we flip bits in IV, we flip the same bits in P1
```

```python
#!/usr/bin/env python3
"""
Challenge 49: CBC-MAC forgery by IV manipulation.

Scenario: steal victim's valid MAC request, modify the first block
(which contains "from=VICTIM") to "from=ATTACKER" by flipping IV bits,
keeping the MAC valid.
"""
from __future__ import annotations

import os
from Crypto.Cipher import AES


BLOCK = 16
KEY   = os.urandom(BLOCK)


def pad(data: bytes) -> bytes:
    """PKCS#7 padding to 16-byte boundary."""
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n] * n)


def cbc_mac(msg: bytes, key: bytes, iv: bytes = bytes(BLOCK)) -> bytes:
    """Return the CBC-MAC of msg (last 16-byte ciphertext block)."""
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct     = cipher.encrypt(pad(msg))
    return ct[-BLOCK:]


def server_verify(iv: bytes, msg: bytes, mac: bytes) -> bool:
    """Verify: recompute CBC-MAC with the IV from the request."""
    return cbc_mac(msg, KEY, iv) == mac


# ── Victim transaction ────────────────────────────────────────────────────────
# Attacker observes: from=victim&to=attacker&amount=1000000
victim_id   = b"victim"
attacker_id = b"attacker"

# Victim's legitimate transfer to attacker for $1 (attacker wants $1,000,000)
victim_msg = pad(b"from=victim&to=" + attacker_id + b"&amount=1      ")
victim_iv  = os.urandom(BLOCK)
victim_mac = cbc_mac(victim_msg, KEY, victim_iv)

print(f"[*] Victim message: {victim_msg!r}")
print(f"[*] MAC valid: {server_verify(victim_iv, victim_msg, victim_mac)}")


# ── Forgery: flip bits in IV to change the first block ────────────────────────
# We want "from=victim&..." → "from=ATTACKER..."
# The first block of victim_msg is "from=victim&to=a" (16 bytes, PKCS#7 padded)
# We want first block to be "from=ATTACKER..." — but that changes plaintext
# and would normally need a different MAC.
#
# However: because IV is user-supplied and the server uses it verbatim,
# flipping bit i in IV flips bit i in the decrypted first plaintext block.
# The CBC chain continues unchanged from block 2 onward.
# So the MAC is still valid!

# First block of victim message (as plaintext)
P1_original = victim_msg[:BLOCK]

# Desired first block
# Keep same format length so following blocks still parse
P1_desired  = b"from=ATTACKER456"   # 16 bytes, same length
assert len(P1_desired) == BLOCK

# XOR the difference into the IV
# new_IV = victim_IV XOR P1_original XOR P1_desired
forged_iv = bytes(v ^ o ^ d for v, o, d in zip(victim_iv, P1_original, P1_desired))

# The rest of the message is unchanged; MAC is reused
forged_msg = P1_desired + victim_msg[BLOCK:]
forged_mac = victim_mac   # MAC is unchanged!

print(f"\n[+] Forged message: {forged_msg!r}")
print(f"[+] Server accepts: {server_verify(forged_iv, forged_msg, forged_mac)}")
assert server_verify(forged_iv, forged_msg, forged_mac)
print("[+] Challenge 49 (part 1) passed — IV manipulation forgery")


# ── Part 2: forge without controlling IV (IV = 0 fixed, message extension) ───
# If IV is fixed to 0, we can extend the authenticated message:
# Given MAC_1 = CBC-MAC(key, IV=0, M1),
# the MAC of M1 || (M1_extension XOR MAC_1) == CBC-MAC(key, IV=0, M1 || forged_block)
# because feeding MAC_1 as the "IV" for block 2 exactly reproduces the continuation.

msg1  = b"from=victim&to=attacker&amount=1"
mac1  = cbc_mac(pad(msg1), KEY)   # IV=0

extra_block = b"&from=attacker&to=attacker&amount=1000000"[:BLOCK]
# XOR extra block with mac1 so that when CBC processes it, the XOR cancels
forged_block = bytes(a ^ b for a, b in zip(extra_block, mac1))
extended_msg = pad(msg1) + forged_block

mac_extended = cbc_mac(extended_msg, KEY)   # Should equal CBC-MAC(K, extra_block, mac1)
mac_expected = cbc_mac(extra_block, KEY, mac1)

print(f"\n[+] MAC of extended message: {mac_extended.hex()}")
print(f"[+] Expected:                {mac_expected.hex()}")
assert mac_extended == mac_expected
print("[+] Challenge 49 (part 2) passed — CBC-MAC length extension")
```

---

## Challenge 50 — CBC-MAC JavaScript Sandbox Escape

A JavaScript sandbox computes `MD4_CBC_MAC(javascript_code)` and verifies the
resulting hash. An attacker wants to inject malicious code while keeping the same
MAC — essentially finding a "collision" by exploiting the CBC structure.

The key insight: you can prepend any block `B` followed by `B XOR CBC_MAC(original)`
to any existing authenticated code. The MAC remains the same because the XOR
cancels the CBC state at the boundary.

```python
#!/usr/bin/env python3
"""
Challenge 50: Forge a CBC-MAC to inject arbitrary JavaScript.

Original authenticated code: alert('MZA who was that?')
Attacker goal: authenticate: alert('Ayo, the Wu is back!');...
while keeping the same CBC-MAC.
"""
from __future__ import annotations

import os
from Crypto.Cipher import AES


BLOCK = 16
KEY   = b"YELLOW SUBMARINE"


def cbc_mac_fixed_iv(msg: bytes, key: bytes = KEY) -> bytes:
    """CBC-MAC with IV=0 (challenge 50 uses IV=0)."""
    padded = pad(msg)
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(BLOCK))
    return cipher.encrypt(padded)[-BLOCK:]


# ── Original authenticated code ───────────────────────────────────────────────
original_js  = b"alert('MZA who was that?');\n"
original_mac = cbc_mac_fixed_iv(original_js)
print(f"[*] Original MAC: {original_mac.hex()}")

# ── Attacker's payload ────────────────────────────────────────────────────────
inject_js = b"alert('Ayo, the Wu is back!');//"
assert len(inject_js) % BLOCK == 0, "Injected code must be block-aligned"

# Step 1: Compute CBC-MAC of inject_js up to its last block
inject_mac = cbc_mac_fixed_iv(inject_js)

# Step 2: Build a "bridge block" that reconnects the chain to the original code.
# After processing inject_js, the CBC state is inject_mac.
# We want the next block to produce the same CBC state as after the original code.
# We need to "restart" the original code chain from inject_mac:
#   AES_k(bridge XOR inject_mac) = AES_k(original_padded[:BLOCK] XOR 0)
# where the right side is the first step of the original MAC computation.
#
# So: bridge XOR inject_mac = original_padded[:BLOCK]
#     bridge = original_padded[:BLOCK] XOR inject_mac

original_padded = pad(original_js)
bridge_block    = bytes(o ^ m for o, m in zip(original_padded[:BLOCK], inject_mac))

# Step 3: Append bridge + rest of original_padded (from block 2 onward)
forged_code = inject_js + bridge_block + original_padded[BLOCK:]

# Step 4: Verify the MAC matches
forged_mac = cbc_mac_fixed_iv(forged_code)
print(f"[*] Forged MAC:   {forged_mac.hex()}")
assert forged_mac == original_mac
print(f"[+] Forged code:\n{forged_code.decode(errors='replace')}")
print("[+] Challenge 50 passed — CBC-MAC JavaScript injection")
```

---

## Why CBC-MAC Breaks for Variable-Length Messages

The failure mode is structural, not implementation-specific:

| Weakness | Attack | Mitigation |
|---|---|---|
| IV attacker-controlled | Flip first block via IV | Fix IV to zero; include IV in MAC |
| No length field | Length extension (append M2 XOR MAC_1) | Prefix message with length |
| Prefix-free MAC | CBC-MAC forgery | Use CMAC (standardised, includes length) |

**CMAC** (NIST SP 800-38B) fixes all three: it prepends the message length,
uses a fixed zero IV, and XORs the final block with a derived subkey. HMAC
is an alternative that avoids block-cipher MAC entirely.

---

## Self-Assessment

```
[ ] 1. In challenge 49 (IV manipulation), the attacker modifies the IV to change
        the first block. Why can't the attacker use the same technique to change
        block 2 of the message?

[ ] 2. Challenge 50's bridge block is: original_padded[:16] XOR inject_mac.
        Trace through the CBC-MAC computation step-by-step to verify that this
        produces the same final MAC as the original code.

[ ] 3. CMAC prepends the message length. Explain how this single addition
        defeats the length extension attack from challenge 49 part 2.

[ ] 4. A production API uses CBC-MAC with a secret key and a fixed IV=0.
        The API accepts messages of any length. Design an attack that forges a
        transfer request from victim to attacker for any amount, given only one
        oracle query against a legitimate request.
```

---

## Key Takeaways

1. **CBC-MAC is only secure for fixed-length messages.** For variable-length
   messages, an adversary can extend or splice authenticated messages without
   knowing the key.
2. **The IV is part of the MAC input.** If the IV is attacker-controlled, the
   first block can be changed freely. The IV must be fixed (zero) and not
   included in the transmitted message.
3. **Use CMAC or HMAC instead of raw CBC-MAC.** Both address the structural
   weaknesses. CMAC is preferred for block-cipher-based MACs; HMAC is preferred
   for hash-based MACs.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q580.1, Q580.2 …).

---

## Navigation

← Previous: [Day 579 — Cryptopals CTF Day 9](DAY-0579-Cryptopals-CTF-Day-9.md)
→ Next: [Day 581 — Cryptopals CTF Day 11](DAY-0581-Cryptopals-CTF-Day-11.md)
