---
title: "Authentication vs Authorisation and Password Storage"
tags: [foundation, auth, authentication, authorisation, password-storage,
       credential-stuffing, OWASP, broken-auth, attacker-mindset]
module: 01-Foundation-05
day: 39
related_topics:
  - Password Hashing and Cracking (Day 034)
  - Session Management and Broken Session Lab (Day 040)
  - Credential Stuffing and Spraying (Day 108)
  - Broken Access Control (Day 045)
---

# Day 039 — Authentication vs Authorisation and Password Storage

## Goals

By the end of this lesson you will be able to:

1. Define authentication and authorisation precisely and state where each
   check belongs in the application stack.
2. Map the OWASP Top 10 categories that cover auth failures.
3. Identify seven patterns in login code that lead to vulnerabilities.
4. Enumerate common username enumeration vectors beyond error messages.
5. Explain the correct password storage pipeline (Argon2id, with salt).
6. Explain credential stuffing and why password reuse is so damaging.

---

## Prerequisites

- [Day 034 — Password Hashing and Cracking](../01-Foundation-04/DAY-0034-Password-Hashing-and-Cracking.md)

---

## Main Content — Part 1: Definitions

### 1. Authentication vs Authorisation

These are distinct concepts that are frequently confused — and
vulnerabilities often arise at their boundary.

| | Authentication (AuthN) | Authorisation (AuthZ) |
|---|---|---|
| **Question answered** | "Who are you?" | "What are you allowed to do?" |
| **When** | Login / session creation | Every subsequent request |
| **Failure** | Fake identity | Legitimate identity, wrong access |
| **OWASP category** | A07: Identification and Authentication Failures | A01: Broken Access Control |
| **Example attack** | Password brute force, session hijacking | IDOR, privilege escalation, forced browsing |

**The critical rule:** Authentication answers "who," but it does not answer
"may." An authenticated user is not automatically authorised to access every
resource. Both checks must be present for every request.

---

### 2. Where Each Check Belongs

**Authentication:**
- Before session creation.
- Before issuing a JWT or API token.
- On every request, verifying the session/token is valid (not expired,
  not revoked, signature intact).

**Authorisation:**
- On every request to every protected resource.
- In the data access layer — not just the HTTP handler.
- Must check "does the currently authenticated user have access to THIS
  specific resource?" — not just "is any user authenticated?"

---

## Main Content — Part 2: Authentication Vulnerabilities

### 3. Vulnerable Login Code Patterns

**Pattern 1 — Username enumeration via different error messages:**

```python
# Vulnerable:
if not user_exists(username):
    return "User not found"          # Different message!
if not check_password(username, password):
    return "Incorrect password"

# Fix:
if not user_exists(username) or not check_password(username, password):
    return "Invalid username or password"
```

**Pattern 2 — Username enumeration via response time:**

If user lookup hits a DB and password check uses bcrypt, a non-existent
user returns faster (no bcrypt check). Fix: always run bcrypt even for
non-existent users (using a dummy hash).

```python
# Fix — dummy hash comparison to normalise response time:
DUMMY_HASH = argon2.hash("dummy_password")

def login(username, password):
    user = db.get_user(username)
    if user is None:
        argon2.verify(password, DUMMY_HASH)  # Normalise timing
        return False
    return argon2.verify(password, user.password_hash)
```

**Pattern 3 — SQL injection in login:**

```python
# Vulnerable:
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
# Input: username = "admin'--" → logs in as admin with any password

# Fix: parameterised queries
cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s",
               (username, password_hash))
```

**Pattern 4 — Plaintext password comparison:**

```python
# Vulnerable:
if user.password == password:  # Plaintext stored in DB!

# Fix: bcrypt / Argon2 verify
```

**Pattern 5 — Missing rate limiting on login:**

No rate limit → unlimited brute force. Fix: exponential backoff, account
lockout with unlock mechanism, CAPTCHA after N failures.

**Pattern 6 — Account lockout is itself an attack vector:**

An attacker who knows valid usernames can lock out all accounts:
```
for user in user_list:
    send 5 wrong-password requests → all accounts locked → DoS
```
Fix: IP-based lockout in addition to (or instead of) account lockout;
alerting on distributed lockout patterns.

**Pattern 7 — "Remember Me" via predictable token:**

```python
# Vulnerable: sequential or time-based remember-me token
token = hashlib.md5(str(user.id) + str(time.time())).hexdigest()

# Fix: CSPRNG
token = secrets.token_urlsafe(32)
db.store_remember_token(user.id, hashlib.sha256(token.encode()).hexdigest())
```

---

### 4. Username Enumeration Beyond Error Messages

Even with identical error messages, enumeration is possible via:

- **Response time:** bcrypt on a valid user vs. instant return for invalid.
- **HTTP status codes:** `400` for invalid format, `403` for valid username
  with account lockout vs. `401` for wrong password.
- **Cookie setting:** Some apps set a session cookie even on failed login.
- **Redirect behaviour:** Successful auth redirects to `/dashboard`; failure
  redirects to `/login?error=1`.
- **Registration endpoint:** "Username already taken" confirms existence.
- **Password reset:** "We sent an email" vs "No account found for that email."
- **Subdomain-based:** `user.app.com` exists for real users; returns 200
  vs. 404 for non-existent users.

---

## Main Content — Part 3: Password Storage and Credential Stuffing

### 5. The Complete Password Storage Pipeline

```python
from passlib.hash import argon2
import secrets

# Registration:
def register_user(email: str, password: str) -> dict:
    # 1. Validate password complexity
    if len(password) < 12:
        raise ValueError("Password too short")

    # 2. Check against HaveIBeenPwned API (optional but recommended)
    # sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    # prefix = sha1_hash[:5]
    # suffix = sha1_hash[5:]
    # response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    # if suffix in response.text: raise ValueError("Password in breach database")

    # 3. Hash with Argon2id
    password_hash = argon2.using(
        type="ID",          # Argon2id
        memory_cost=65536,  # 64 MB
        time_cost=3,
        parallelism=4
    ).hash(password)

    # 4. Store hash (never the plaintext)
    return {"email": email, "password_hash": password_hash}

# Login:
def verify_password(plaintext: str, stored_hash: str) -> bool:
    return argon2.verify(plaintext, stored_hash)
    # argon2.verify uses constant-time comparison internally
```

---

### 6. Credential Stuffing

**The attack:** A breach at site A exposes email/password pairs. Attackers
use automated tools (OpenBullet, SentryMBA) to test these credentials at
site B, C, D, etc. — because most users reuse passwords.

**Scale:** The 2020 data breach market had >10 billion credential pairs.
Credential stuffing success rates of 0.1–2% are typical, meaning millions
of successful account takeovers per campaign.

**For defenders:**
- Enforce MFA — stuffed credentials fail without the second factor.
- Check against HaveIBeenPwned at registration and login.
- Monitor for abnormal login velocity (many attempts from many IPs against
  many accounts = stuffing; many attempts from one IP = spraying).
- Implement CAPTCHA or bot challenges.
- Use device fingerprinting to detect new device logins.

---

## Key Takeaways

1. **Authentication ≠ authorisation.** A correct login check does not
   mean access control is correct. Both are required on every request.
2. **Username enumeration is a vulnerability** even though no direct damage
   occurs. It halves the search space for brute force and enables targeted
   attacks. Identical error messages and constant-time responses are
   required.
3. **Argon2id is the correct password hash for 2026.** Never MD5, SHA-256,
   bcrypt at cost < 10. Never unsalted anything.
4. **Rate limiting on login is not optional.** Without it, any password
   in the rockyou list is reachable against any account.
5. **Password reuse makes credential stuffing trivially effective.**
   One breach → access to every site where the user reused the password.
   MFA and password manager adoption are the only systemic defences.

---

## Exercises

### Exercise 1 — Enumerate DVWA Usernames

In DVWA's Brute Force module:
1. Try login with username `admin` + wrong password. Note the error.
2. Try login with username `notauser` + wrong password. Note the error.
3. Are they different? If yes — username enumeration is confirmed.
4. Try timing both — is there a measurable difference?

### Exercise 2 — Write a Secure Login Handler

Write a Flask login endpoint that:
- Uses Argon2id for password verification.
- Returns identical messages for "user not found" and "wrong password."
- Runs the hash verification even for non-existent users (dummy hash).
- Implements a 5-attempt IP-based lockout using Redis.

### Exercise 3 — HaveIBeenPwned Integration

```python
import hashlib, requests

def is_password_pwned(password: str) -> int:
    """Returns the number of times this password appears in breach data."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in resp.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0

# Test it:
print(is_password_pwned("password"))       # Should be > 0 (millions)
print(is_password_pwned("correct horse battery staple"))
print(is_password_pwned(secrets.token_hex(16)))  # Should be 0
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 038 — Cryptography Competency Check](../01-Foundation-04/DAY-0038-Crypto-Competency-Check.md)*
*Next: [Day 040 — Session Management and Broken Session Lab](DAY-0040-Session-Management-and-Broken-Session-Lab.md)*
