---
title: "ECDSA Lab — Recover Private Key from Two Signatures with the Same Nonce"
tags: [cryptography, ECDSA, nonce-reuse, lab, private-key-recovery, secp256k1,
  CWE-338, T1600, hands-on, Bitcoin, PS3]
module: 09-Crypto-01
day: 570
prerequisites:
  - Day 569 — ECDSA Nonce Reuse (theory + math)
related_topics:
  - ECDSA Nonce Reuse (Day 569)
  - Cryptopals Set 6 (upcoming)
  - RSA Attack Lab (Day 567)
---

# Day 570 — ECDSA Lab

> "Theory says two equations with the same k give you d. The lab says: now
> prove it. Find the vulnerable signatures, run the math, recover the key,
> sign a message as someone else. Understand every step — or you have not
> done the lab."
>
> — Ghost

---

## Goals

- Deploy a signing service with a deliberately flawed PRNG that occasionally
  reuses nonces.
- Write a scanner to detect nonce reuse from the service's public signature log.
- Recover the private key and forge a valid signature.
- Patch the service to use RFC 6979 deterministic nonces.

**Prerequisites:** Day 569 — theory and math are required before the lab.
**Estimated lab time:** 2.5 hours.

---

## Lab Environment

```yaml
# docker-compose.yml
version: "3.9"
services:
  signing-service:
    build: ./signing-service
    ports:
      - "9191:9191"
    environment:
      FLAG: "CTF{k_reuse_is_private_key_recovery}"
    networks:
      - lab-net

networks:
  lab-net:
    driver: bridge
```

```python
# signing-service/app.py — deliberately vulnerable signing service
"""
SecureSig API v1.0
Provides ECDSA signing and verification on secp256k1.
"""
from __future__ import annotations

import hashlib
import json
import os
import random  # BUG: random, not secrets — intentionally weak
from flask import Flask, request, jsonify
from ecdsa import SigningKey, SECP256k1, BadSignatureError
from ecdsa.numbertheory import inverse_mod

app = Flask(__name__)

# Generate key pair at startup
SK = SigningKey.generate(curve=SECP256k1)
VK = SK.get_verifying_key()
N  = SECP256k1.order
D  = SK.privkey.secret_multiplier  # Private key integer

# Public signature log — all signatures are recorded
signature_log: list[dict] = []

def weak_nonce() -> int:
    """
    BUG: uses random.randint with a limited seed pool (only 1000 possible seeds).
    This causes nonce collisions with high probability after ~50 signatures.
    """
    random.seed(random.randint(0, 999))  # Tiny seed space = repeated k values
    return random.randint(1, N - 1)

def sign_message(message: bytes) -> tuple[int, int]:
    """Sign using a vulnerable weak nonce."""
    G = SECP256k1.generator
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big') % N
    k = weak_nonce()
    R = k * G
    r = R.x() % N
    if r == 0:
        return sign_message(message)  # Retry on r=0
    s = (inverse_mod(k, N) * (z + r * D)) % N
    if s == 0:
        return sign_message(message)
    return r, s

@app.route('/sign', methods=['POST'])
def sign():
    data = request.get_json()
    message = data.get('message', '').encode()
    r, s = sign_message(message)
    entry = {
        "message": data.get('message'),
        "r": r,
        "s": s,
        "pubkey": VK.to_string().hex(),
    }
    signature_log.append(entry)
    return jsonify(entry)

@app.route('/signatures')
def signatures():
    """Return all recorded signatures (public log)."""
    return jsonify(signature_log)

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    message = data.get('message', '').encode()
    r = int(data['r'])
    s = int(data['s'])
    try:
        # Convert (r,s) to DER format and verify
        from ecdsa.util import sigencode_string, sigdecode_string
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        VK.verify(raw_sig, message,
                  hashfunc=hashlib.sha256,
                  sigdecode=sigdecode_string)
        return jsonify({"valid": True})
    except BadSignatureError:
        return jsonify({"valid": False}), 403

@app.route('/admin')
def admin():
    """Only accessible with a valid signature from the private key."""
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').encode()
    r = int(data.get('r', 0))
    s = int(data.get('s', 0))
    try:
        from ecdsa.util import sigdecode_string
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        VK.verify(raw_sig, message,
                  hashfunc=hashlib.sha256,
                  sigdecode=sigdecode_string)
        return jsonify({
            "access": "granted",
            "flag": os.environ.get('FLAG', 'flag-not-set'),
        })
    except BadSignatureError:
        return jsonify({"access": "denied"}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9191)
```

**Start the lab:**
```bash
cd ecdsa-lab
docker compose up -d
```

---

## Challenge

### Part 1 — Trigger Nonce Reuse

```bash
# Sign 60 messages to trigger a nonce collision (seed pool = 1000)
for i in $(seq 1 60); do
  curl -s -X POST http://localhost:9191/sign \
    -H 'Content-Type: application/json' \
    -d "{\"message\": \"message_$i\"}" > /dev/null
done

# Retrieve the signature log
curl -s http://localhost:9191/signatures | python3 -m json.tool | head -80
```

### Part 2 — Detect Nonce Reuse

```python
#!/usr/bin/env python3
"""
detect_nonce_reuse.py — scan signature log for repeated r values
"""
from __future__ import annotations

import requests

def get_signatures(base_url: str) -> list[dict]:
    resp = requests.get(f"{base_url}/signatures")
    return resp.json()

def find_reused_r(sigs: list[dict]) -> list[tuple[dict, dict]]:
    """Return pairs of signatures sharing the same r value."""
    r_to_sig: dict[int, dict] = {}
    pairs: list[tuple[dict, dict]] = []
    for sig in sigs:
        r = sig['r']
        if r in r_to_sig:
            pairs.append((r_to_sig[r], sig))
        else:
            r_to_sig[r] = sig
    return pairs

base_url = "http://localhost:9191"
sigs = get_signatures(base_url)
print(f"[*] Total signatures in log: {len(sigs)}")

pairs = find_reused_r(sigs)
print(f"[*] Nonce reuse pairs found:  {len(pairs)}")

for i, (s1, s2) in enumerate(pairs):
    print(f"\n[!] Pair {i+1}:")
    print(f"    msg1 = {s1['message']!r}")
    print(f"    msg2 = {s2['message']!r}")
    print(f"    r    = {s1['r']}")
    print(f"    s1   = {s1['s']}")
    print(f"    s2   = {s2['s']}")
```

### Part 3 — Recover the Private Key

```python
#!/usr/bin/env python3
"""
recover_key.py — recover ECDSA private key from nonce-reused signatures
"""
from __future__ import annotations

import hashlib
import requests
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

BASE_URL = "http://localhost:9191"
N        = SECP256k1.order

def recover_private_key(
    msg1: str, r1: int, s1: int,
    msg2: str, r2: int, s2: int,
) -> int:
    """Recover private key d from two signatures with the same nonce k."""
    assert r1 == r2, "r values must be equal (same nonce k)"

    z1 = int.from_bytes(hashlib.sha256(msg1.encode()).digest(), 'big') % N
    z2 = int.from_bytes(hashlib.sha256(msg2.encode()).digest(), 'big') % N

    # k = (z1 - z2) / (s1 - s2) mod n
    k = ((z1 - z2) * inverse_mod((s1 - s2) % N, N)) % N

    # d = (s1*k - z1) / r1 mod n
    d = ((s1 * k - z1) % N * inverse_mod(r1, N)) % N

    return d

# Step 1: get the first nonce-reuse pair
from detect_nonce_reuse import get_signatures, find_reused_r
sigs  = get_signatures(BASE_URL)
pairs = find_reused_r(sigs)
assert pairs, "No nonce reuse found — sign more messages first"

s1_data, s2_data = pairs[0]
print(f"[*] Using pair:")
print(f"    msg1 = {s1_data['message']!r}")
print(f"    msg2 = {s2_data['message']!r}")

d_recovered = recover_private_key(
    s1_data['message'], s1_data['r'], s1_data['s'],
    s2_data['message'], s2_data['r'], s2_data['s'],
)
print(f"\n[+] Recovered private key (int): {d_recovered}")

# Step 2: create a SigningKey from the recovered integer
from ecdsa import SigningKey, SECP256k1, NIST384p
import hashlib
from ecdsa.util import sigencode_string

sk_recovered = SigningKey.from_secret_exponent(d_recovered, curve=SECP256k1)
vk_recovered = sk_recovered.get_verifying_key()

# Verify it matches the server's public key
pubkey_hex = sigs[0]['pubkey']
print(f"\n[*] Server public key:    {pubkey_hex[:32]}...")
print(f"[*] Recovered public key: {vk_recovered.to_string().hex()[:32]}...")
print(f"[*] Match: {vk_recovered.to_string().hex() == pubkey_hex}")
# → True
```

### Part 4 — Forge a Signature and Get the Flag

```python
#!/usr/bin/env python3
"""
forge_signature.py — use recovered private key to access /admin endpoint
"""
from __future__ import annotations

import hashlib
import requests
from ecdsa import SigningKey, SECP256k1

# Use d_recovered from Part 3
D_RECOVERED = 0  # Paste recovered private key integer here

sk = SigningKey.from_secret_exponent(D_RECOVERED, curve=SECP256k1)

# Sign a fresh message
admin_msg = b"grant admin access"
raw_sig   = sk.sign(admin_msg, hashfunc=hashlib.sha256)

r = int.from_bytes(raw_sig[:32], 'big')
s = int.from_bytes(raw_sig[32:], 'big')

print(f"[*] Forged signature for: {admin_msg!r}")
print(f"    r = {r}")
print(f"    s = {s}")

resp = requests.get(
    "http://localhost:9191/admin",
    json={"message": admin_msg.decode(), "r": r, "s": s},
)
print(f"\n[*] Response: {resp.json()}")
# → {"access": "granted", "flag": "CTF{k_reuse_is_private_key_recovery}"}
```

---

## Challenge Flag

`CTF{k_reuse_is_private_key_recovery}`

---

## Part 5 — Patch the Service

```python
# FIXED: signing-service/app.py — RFC 6979 deterministic nonce
# Replace the weak_nonce() + sign_message() functions:

from ecdsa import SigningKey, SECP256k1
import hashlib

SK = SigningKey.generate(curve=SECP256k1)

# The ecdsa library uses RFC 6979 deterministic k by default.
# Simply call sk.sign() — no manual k management needed.
def sign_message_fixed(message: bytes) -> tuple[int, int]:
    raw_sig = SK.sign(message, hashfunc=hashlib.sha256)
    r = int.from_bytes(raw_sig[:32], 'big')
    s = int.from_bytes(raw_sig[32:], 'big')
    return r, s

# Verify the fix: sign the same message twice
m = b"same message twice"
sig1 = sign_message_fixed(m)
sig2 = sign_message_fixed(m)

print(f"sig1.r == sig2.r: {sig1[0] == sig2[0]}")   # True — same k for same msg
print(f"sig1.s == sig2.s: {sig1[1] == sig2[1]}")   # True — deterministic
# Deterministic but different messages will produce different r values:
sig3 = sign_message_fixed(b"different message")
print(f"sig1.r == sig3.r: {sig1[0] == sig3[0]}")   # False — different k
```

---

## Key Takeaways

1. The nonce reuse scanner runs in `O(n log n)` — sorting signatures by `r`
   and looking for duplicates. It is trivially fast on any blockchain or
   signature log. This is exactly how Bitcoin nonce reuse thefts were
   discovered at scale.
2. RFC 6979 makes nonce reuse structurally impossible. The deterministic k is
   derived from `HMAC-DRBG(private_key, message_hash)` — no PRNG involved, no
   randomness quality requirement, no seed management.
3. The real PS3 vulnerability was not a weak PRNG — it was a constant `k`.
   The engineering failure was simpler than any statistical attack: the
   developers simply never changed the nonce. Code review would have caught it.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q570.1, Q570.2 …).

---

## Navigation

← Previous: [Day 569 — ECDSA Nonce Reuse](DAY-0569-ECDSA-Nonce-Reuse.md)
→ Next: [Day 571 — Cryptopals CTF Practice: Day 1](DAY-0571-Cryptopals-CTF-Day-1.md)
