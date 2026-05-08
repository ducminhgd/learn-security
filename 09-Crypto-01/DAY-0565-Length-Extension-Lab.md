---
title: "Length Extension Lab — Forge an HMAC via Length Extension"
tags: [cryptography, length-extension, SHA-256, lab, API-forgery, hlextend,
  CWE-310, T1600, hands-on, forge-mac, API-auth]
module: 09-Crypto-01
day: 565
prerequisites:
  - Day 564 — Length Extension Attack (theory)
  - Day 031 — MACs, HMACs and Forgery Lab
related_topics:
  - Length Extension Attack (Day 564)
  - ECB Cut-and-Paste (Day 566)
  - Timing Attacks (Day 563)
---

# Day 565 — Length Extension Lab

> "Theory is the blueprint. This lab is the construction site. Run the attack
> until you understand exactly which bytes change, why the server accepts them,
> and what the fix looks like in running code. If you cannot explain every byte
> in your forged request, you have not learned it."
>
> — Ghost

---

## Goals

- Deploy a vulnerable API that uses `SHA256(secret + params)` for request signing.
- Use `hlextend` (or your own implementation) to forge an elevated-privilege
  API request.
- Retrieve the flag using the forged request.
- Patch the application to use HMAC-SHA256 and verify the attack no longer works.

**Prerequisites:** Day 564 (length extension theory, `hlextend` usage).
**Estimated lab time:** 2.5 hours.

---

## Lab Environment

### Setup

```yaml
# docker-compose.yml
version: "3.9"
services:
  length-ext-app:
    build: ./length-ext-app
    ports:
      - "8181:8181"
    environment:
      API_SECRET: ""  # Random 12-byte secret generated at startup
      FLAG: "CTF{sha256_prefix_mac_is_not_a_mac}"
    networks:
      - lab-net

networks:
  lab-net:
    driver: bridge
```

```python
# length-ext-app/app.py — vulnerable API server
"""
TechCorp Data API v1.2
Request signing: GET /api/data?user=X&action=Y&sig=SHA256(secret+params)
"""
from __future__ import annotations

import hashlib
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = os.urandom(12)  # 12-byte secret — attacker does not know this
print(f"[DEBUG] Secret (base64): {__import__('base64').b64encode(SECRET).decode()}")
# This line is only for the lab — in a real app the secret would never be logged


def compute_sig(params: str) -> str:
    """Vulnerable: uses SHA256(secret + params) instead of HMAC."""
    return hashlib.sha256(SECRET + params.encode()).hexdigest()


def verify_sig(params: str, sig: str) -> bool:
    expected = compute_sig(params)
    # Vulnerable: also uses == (timing oracle as a bonus bug)
    return expected == sig


@app.route('/api/data')
def api_data():
    user = request.args.get('user', '')
    action = request.args.get('action', '')
    sig = request.args.get('sig', '')
    # Reconstruct the signed string from query params (order matters)
    params = f"user={user}&action={action}"

    if not verify_sig(params, sig):
        return jsonify({"error": "invalid signature"}), 403

    if action == 'read':
        return jsonify({
            "status": "ok",
            "data": f"Public records for user {user}",
        })
    elif action == 'admin':
        flag = os.environ.get('FLAG', 'flag-not-set')
        return jsonify({
            "status": "ok",
            "flag": flag,
            "data": "Administrative access granted",
        })
    else:
        return jsonify({"error": "unknown action"}), 400


@app.route('/api/sign')
def sign():
    """
    Helper endpoint: returns a valid signature for a low-privilege request.
    In the real world this is the API response that includes a signature
    the attacker can observe.
    """
    user = request.args.get('user', 'alice')
    params = f"user={user}&action=read"
    sig = compute_sig(params)
    return jsonify({
        "params": params,
        "sig": sig,
        "request": f"/api/data?{params}&sig={sig}",
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8181)
```

**Start the lab:**
```bash
cd length-ext-lab
docker compose up -d
```

---

## Challenge

### Part 1 — Obtain a Valid Signed Request

```bash
# Request a valid read signature from the API
curl -s "http://localhost:8181/api/sign?user=alice"
# → {
#     "params": "user=alice&action=read",
#     "sig": "a3b4c5d6e7f8...",
#     "request": "/api/data?user=alice&action=read&sig=a3b4c5d6..."
#   }

# Verify the signed request works
curl -s "http://localhost:8181/api/data?user=alice&action=read&sig=a3b4c5d6..."
# → {"data": "Public records for user alice", "status": "ok"}

# Attempt to access admin directly — fails
curl -s "http://localhost:8181/api/data?user=alice&action=admin&sig=a3b4c5d6..."
# → {"error": "invalid signature"}
```

### Part 2 — Determine the Secret Length

The secret length is required for the attack. Try lengths 1–20:

```python
#!/usr/bin/env python3
"""
guess_secret_length.py — determine secret length by testing forged requests
"""
from __future__ import annotations

import requests
import hlextend   # pip install hlextend
import urllib.parse

BASE_URL = "http://localhost:8181"

def get_signed_request(user: str = "alice") -> tuple[str, str]:
    resp = requests.get(f"{BASE_URL}/api/sign", params={"user": user})
    data = resp.json()
    return data["params"], data["sig"]

def try_secret_length(params: str, sig: str, secret_len: int,
                      extension: bytes) -> tuple[bytes, str] | None:
    """Attempt a length extension with a given secret length."""
    sha = hlextend.new("sha256")
    forged_mac, forged_data = sha.extend(
        extension,
        params.encode(),
        secret_len,
        sig,
        raw=True,
    )
    # URL-encode the forged data (it contains binary padding bytes)
    forged_params = urllib.parse.quote(forged_data, safe="=&")
    # Test against the server
    url = f"{BASE_URL}/api/data?{forged_params}&sig={forged_mac}"
    resp = requests.get(url)
    if resp.status_code == 200 and "flag" in resp.json():
        return forged_data, forged_mac
    if resp.status_code == 200:
        # Valid sig but action=read not admin — wrong parse
        return None
    return None

# Main attack loop
params, sig = get_signed_request("alice")
print(f"[*] Known params: {params}")
print(f"[*] Known sig:    {sig}\n")

extension = b"&action=admin"
for length in range(1, 25):
    print(f"[*] Trying secret length = {length}…")
    result = try_secret_length(params, sig, length, extension)
    if result:
        forged_data, forged_mac = result
        print(f"\n[+] Secret length found: {length}")
        print(f"[+] Forged data:   {forged_data!r}")
        print(f"[+] Forged MAC:    {forged_mac}")
        break
else:
    print("[-] Secret length not found in range 1–24")
```

### Part 3 — Forge the Admin Request

Once you know the secret length:

```python
#!/usr/bin/env python3
"""
forge_admin.py — forge a signed admin request using length extension
"""
from __future__ import annotations

import requests
import hlextend
import urllib.parse

BASE_URL = "http://localhost:8181"

# Fill these in from Part 2:
KNOWN_PARAMS = "user=alice&action=read"
KNOWN_SIG    = "PASTE_SIG_HERE"
SECRET_LEN   = 12  # Found in Part 2

def forge_admin_request(params: str, sig: str,
                        secret_len: int) -> tuple[bytes, str]:
    """Forge a request to gain admin action."""
    sha = hlextend.new("sha256")
    extension = b"&action=admin"
    forged_mac, forged_data = sha.extend(
        extension,
        params.encode(),
        secret_len,
        sig,
        raw=True,
    )
    return forged_data, forged_mac

forged_data, forged_mac = forge_admin_request(KNOWN_PARAMS, KNOWN_SIG, SECRET_LEN)

# Build the URL — the forged_data contains binary bytes (the padding),
# so it must be URL-encoded before sending
encoded_data = urllib.parse.quote(forged_data, safe="=&")
url = f"{BASE_URL}/api/data?{encoded_data}&sig={forged_mac}"

print(f"[*] Forged URL:\n    {url}\n")

resp = requests.get(url)
print(f"[*] Status:  {resp.status_code}")
print(f"[*] Response:\n    {resp.json()}")
# → {"data": "Administrative access granted",
#    "flag": "CTF{sha256_prefix_mac_is_not_a_mac}",
#    "status": "ok"}
```

```bash
# Alternative: use the hashpump command-line tool
# hashpump -s <known_sig> -d <original_data> -a <extension> -k <secret_len>

hashpump \
  -s "a3b4c5d6e7f8..." \
  -d "user=alice&action=read" \
  -a "&action=admin" \
  -k 12
# Output:
# New signature: <forged_mac>
# New string (hex): 757365723d616c6963652...8000000...266163...
```

---

## Challenge Flag

`CTF{sha256_prefix_mac_is_not_a_mac}`

---

## Part 4 — Fix the Application

Modify `length-ext-app/app.py` to use HMAC-SHA256:

```python
# FIXED: length-ext-app/app.py — HMAC-SHA256
import hmac
import hashlib

def compute_sig(params: str) -> str:
    """Fixed: uses HMAC-SHA256 — not vulnerable to length extension."""
    return hmac.new(SECRET, params.encode(), hashlib.sha256).hexdigest()

def verify_sig(params: str, sig: str) -> bool:
    expected = compute_sig(params)
    # Fixed: constant-time comparison — no timing oracle
    return hmac.compare_digest(expected, sig)
```

**Verify the fix:**
```python
# Re-run forge_admin.py — the forged MAC should now be rejected
resp = requests.get(url)
assert resp.status_code == 403
print("[+] Fix verified — forged request rejected with HMAC-SHA256")
```

---

## Understanding What You Forged

Let's look at exactly what the forged data contains:

```python
#!/usr/bin/env python3
"""
inspect_forged.py — inspect the binary content of the forged request
"""
forged_data = b"user=alice&action=read" + \
              b"\x80" + b"\x00" * 25 + b"\x00\x00\x00\x00\x00\x00\x01\x78" + \
              b"&action=admin"
# ^^ approximate — actual padding depends on secret length

print("Byte-by-byte inspection:")
for i, b in enumerate(forged_data):
    if b in range(32, 127):
        print(f"  [{i:3d}] 0x{b:02x} = '{chr(b)}'")
    else:
        print(f"  [{i:3d}] 0x{b:02x}  (non-printable)")

# The server parses query parameters AFTER URL decoding.
# url-encoded %80 = the 0x80 byte
# The parser sees: user=alice and action=read%80%00...%00%01x8&action=admin
# PHP's and Python's query parsers take the LAST value of a repeated key.
# So action = "admin" (the extension wins over the original "read").
```

**Key insight:** The forged data contains the PKCS-padding bytes embedded
in the value of `action`. The server's query parser sees two values for
`action`: `read<padding bytes>` and `admin`. Most server frameworks use the
last value for a repeated parameter — so `action=admin` wins.

---

## Key Takeaways

1. The padding bytes embedded in the forged data are not random noise — they
   are the exact PKCS-style SHA-256 padding that was appended to the original
   message before hashing. Understanding where they come from is understanding
   the attack.
2. Query parameter parsing ambiguity (last value wins for repeated keys) is
   what enables the forged extension to override the original action. The
   cryptographic attack and the application behaviour combine to produce the
   exploit.
3. HMAC-SHA256 is not harder to use than SHA-256 — it is three additional
   characters in Python (`hmac.new(key, data, hashlib.sha256).hexdigest()`).
   There is no performance argument for using SHA-256 as a MAC.
4. `hashpump` is the fastest way to run this attack in a real engagement.
   Know how it works before using it (see Day 564 for the theory).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q565.1, Q565.2 …).

---

## Navigation

← Previous: [Day 564 — Length Extension Attack](DAY-0564-Length-Extension-Attack.md)
→ Next: [Day 566 — ECB Cut-and-Paste](DAY-0566-ECB-Cut-and-Paste.md)
