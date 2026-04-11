---
title: "Auth Detection, Logging and Hardening"
tags: [foundation, auth, detection, logging, SIEM, brute-force, anomaly,
       hardening, rate-limiting, account-lockout, audit-log]
module: 01-Foundation-05
day: 47
related_topics:
  - Password Reset Flaws and Account Takeover (Day 046)
  - Foundation Complete Review (Day 048)
  - Security Monitoring Architecture (Blue Cell B-01)
  - Threat Hunting (Blue Cell B-02)
---

# Day 047 — Auth Detection, Logging and Hardening

## Goals

By the end of this lesson you will be able to:

1. Write log events that capture every authentication action with enough
   context to reconstruct an attack.
2. Build a Sigma rule that detects brute force, credential stuffing,
   and session anomalies.
3. Explain five hardening controls and map each to the vulnerability it closes.
4. Describe what a complete auth hardening checklist looks like for a
   production web application.

---

## Prerequisites

- [Day 046 — Password Reset Flaws and Account Takeover](DAY-0046-Password-Reset-Flaws-and-Account-Takeover.md)

---

## Main Content — Part 1: What to Log

### 1. Auth Event Logging Requirements

Every authentication event must be logged. Every. Single. One.

**Minimum fields per event:**

| Field | Type | Why |
|---|---|---|
| `timestamp` | ISO 8601 UTC | Timeline reconstruction |
| `event_type` | string | What happened |
| `user_id` | string or null | Who (null on pre-auth events) |
| `username_attempted` | string | What credential was tried |
| `source_ip` | string | Attribution, geo-anomaly |
| `user_agent` | string | Device fingerprinting |
| `session_id` | string or null | Session chain correlation |
| `result` | success/failure | Outcome |
| `failure_reason` | string or null | Why it failed (server-side only) |
| `request_id` | uuid | Correlate with application logs |

**Event types to log:**

```
auth.login.success
auth.login.failure          ← include failure_reason
auth.logout
auth.mfa.challenge_sent
auth.mfa.success
auth.mfa.failure
auth.token.issued
auth.token.refreshed
auth.token.revoked
auth.password.reset.requested
auth.password.reset.completed
auth.password.changed
auth.session.created
auth.session.expired
auth.session.invalid         ← someone presented a non-existent session ID
auth.account.locked
auth.account.unlocked
auth.permission.denied       ← log every access control failure
```

**Example log line (JSON structured):**

```json
{
  "timestamp": "2026-04-11T08:14:33.421Z",
  "event_type": "auth.login.failure",
  "user_id": null,
  "username_attempted": "alice@corp.com",
  "source_ip": "185.234.219.12",
  "user_agent": "python-requests/2.28.0",
  "session_id": null,
  "result": "failure",
  "failure_reason": "invalid_password",
  "request_id": "f4a1b2c3-d4e5-6789-abcd-ef0123456789"
}
```

**What NOT to log:**
- Passwords (plaintext or hashed)
- Full session tokens or JWT payloads
- Full credit card numbers, SSN
- Access tokens or API keys

---

## Main Content — Part 2: Detection Rules

### 2. Brute Force Detection

**Sigma rule — password brute force (single account):**

```yaml
title: Password Brute Force - Single Account
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Multiple failed logins against a single account from one or more IPs
author: Ghost
date: 2026-04-11
logsource:
  category: application
  product: web_auth
detection:
  selection:
    event_type: "auth.login.failure"
  timeframe: 5m
  condition: selection | count(source_ip) by username_attempted > 10
falsepositives:
  - Legitimate user typing wrong password repeatedly
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
```

**Sigma rule — credential stuffing (many accounts, many IPs):**

```yaml
title: Credential Stuffing Attack
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  High volume of login failures across many different accounts,
  consistent with automated credential stuffing
author: Ghost
logsource:
  category: application
  product: web_auth
detection:
  selection:
    event_type: "auth.login.failure"
  timeframe: 10m
  condition: selection | count(username_attempted) by source_ip > 50
falsepositives:
  - Load testing
level: high
tags:
  - attack.credential_access
  - attack.t1110.004
```

**Sigma rule — session anomaly (impossible travel):**

```yaml
title: Session Impossible Travel
id: c3d4e5f6-a7b8-9012-cdef-012345678902
status: experimental
description: >
  Same session used from two geographically distant locations
  within a short time window
author: Ghost
logsource:
  category: application
  product: web_auth
detection:
  selection:
    event_type: "auth.session.used"
  condition: |
    selection
    | aggregate session_id, source_country
    | where count(distinct source_country) > 1 within 30m
level: high
tags:
  - attack.credential_access
  - attack.t1078
```

---

### 3. Anomaly Patterns to Alert On

| Anomaly | Threshold / Logic | ATT&CK |
|---|---|---|
| Login at unusual hour | Outside user's normal ±2 hour window | T1078 |
| New device / new browser fingerprint | First time this UA+IP combination | T1078 |
| Successful login after many failures | Success after N failures from same IP | T1110 |
| MFA bypass attempt (step skip) | `full_auth` not set but protected resource accessed | T1078.003 |
| JWT with `alg: none` | Any JWT header with `alg=none` | T1550.001 |
| API key used from new IP | First use from this IP for this key | T1078.004 |
| Password reset for high-value account | Admin/root account reset + IP geolocation | T1078 |

---

## Main Content — Part 3: Hardening Controls

### 4. The Complete Auth Hardening Map

Each vulnerability from Days 039–046, mapped to its fix.

---

**Control 1 — Rate limiting and account lockout**

Closes: brute force (Day 039), OTP brute force (Day 041).

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")            # IP-based
@limiter.limit("20 per hour")
def login():
    ...
```

Redis-backed account lockout:

```python
import redis
r = redis.Redis()

def check_lockout(username: str) -> bool:
    key = f"lockout:{username}"
    attempts = r.get(key)
    return int(attempts or 0) >= 5

def record_failure(username: str):
    key = f"lockout:{username}"
    r.incr(key)
    r.expire(key, 900)   # 15-minute window

def clear_failures(username: str):
    r.delete(f"lockout:{username}")
```

---

**Control 2 — Session hardening**

Closes: session fixation, XSS session theft, CSRF (Day 040).

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_NAME='__Host-session',  # __Host- prefix = Secure+Path=/ enforced
)
```

---

**Control 3 — JWT hardening**

Closes: alg:none, algorithm confusion, weak secret (Day 042).

```python
# Never trust the alg from the token header.
# Always specify the algorithm explicitly.
payload = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],       # Exact whitelist
    options={"require": ["exp", "iat", "jti"]}
)

# Maintain a jti blocklist for revoked tokens:
if redis.sismember("jwt_blocklist", payload["jti"]):
    raise jwt.InvalidTokenError("Token has been revoked")
```

---

**Control 4 — OAuth hardening**

Closes: CSRF on OAuth, redirect_uri bypass, Implicit flow (Days 043–044).

```
Checklist:
☑ state parameter: CSPRNG, stored in session, validated on callback
☑ redirect_uri: exact match enforced by auth server
☑ PKCE: required for public clients (SPAs, mobile)
☑ Implicit flow: disabled
☑ Token storage: httpOnly cookie or server-side session (never localStorage)
☑ Token lifetime: access_token ≤ 1h, refresh_token ≤ 24h with rotation
```

---

**Control 5 — Password reset hardening**

Closes: predictable tokens, host header injection, race conditions (Day 046).

```
Checklist:
☑ Token: secrets.token_urlsafe(32), stored as SHA-256 hash
☑ Token lifetime: 15 minutes maximum
☑ Token invalidation: atomic UPDATE WHERE used_at IS NULL
☑ Base URL: hardcoded from environment variable, never from Host header
☑ Rate limit: 3 resets per email per hour
☑ Email enumeration: identical response whether email exists or not
☑ Old tokens: invalidated when new password is set
☑ Session: invalidated for all sessions after password change
```

---

### 5. Auth Hardening Checklist — Production

```
AUTHENTICATION
☑ Argon2id for password storage (m=65536, t=3, p=4)
☑ Constant-time comparison for all credential checks
☑ Identical error messages for user-not-found vs wrong-password
☑ Login rate limiting (IP + account)
☑ MFA enforced for admin/privileged accounts
☑ FIDO2/WebAuthn available for high-value accounts

SESSION
☑ CSPRNG session IDs (128+ bits)
☑ Session regeneration on privilege change (login, sudo, role change)
☑ HttpOnly; Secure; SameSite=Strict on session cookie
☑ Idle timeout (15–30 min), absolute timeout (8–24 hr)
☑ Session invalidation on logout (server-side)
☑ Full session invalidation on password change

TOKENS
☑ JWTs: RS256 or ES256, hardcoded algorithm list
☑ Short exp (≤ 15 min access, ≤ 24 hr refresh)
☑ jti claim + server-side blocklist for logout
☑ API keys: hashed at rest, scoped, revocable

RESET
☑ CSPRNG reset tokens, stored hashed
☑ 15-minute expiry, one-use, atomic invalidation
☑ Hardcoded base URL (no Host header)
☑ Rate limited, same response for all emails

ACCESS CONTROL
☑ Default-deny: every route requires explicit permission
☑ Ownership check in addition to role check
☑ All access control failures logged
☑ No sensitive endpoints exposed at discoverable paths

LOGGING
☑ All auth events logged (structured JSON)
☑ Sensitive data never logged
☑ Brute force alert: >10 failures/5 min per account
☑ Stuffing alert: >50 failures/10 min per IP
☑ Anomaly alerts: new device, impossible travel, unusual hour
```

---

## Key Takeaways

1. **Logging is the blue team's data source.** Without structured auth logs,
   you cannot detect, respond to, or investigate an auth breach.
2. **Detection rules must be tested.** Write a detection rule, then run the
   exact attack it is supposed to catch, and verify the alert fires. If you
   do not test it, it might be broken.
3. **Hardening is defence in depth.** No single control stops everything.
   Rate limiting + strong tokens + short-lived sessions + anomaly detection
   together make attacks expensive and detectable.
4. **The auth hardening checklist is your pentest adversary.** When you test
   a target, walk through every item. When you build a system, implement every
   item. The same list serves both roles.

---

## Exercises

### Exercise 1 — Build the Log Middleware

Write a Flask middleware (using `@app.before_request` and
`@app.after_request`) that logs every auth-related request as a structured
JSON event. Include all required fields from Section 1.

### Exercise 2 — Sigma Rule Test

Write a Python script that:
1. Sends 15 failed login attempts to a local auth endpoint.
2. Parses the resulting log output.
3. Verifies that an alert would have been triggered based on the Sigma rule
   threshold from Section 2.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 046 — Password Reset Flaws and Account Takeover](DAY-0046-Password-Reset-Flaws-and-Account-Takeover.md)*
*Next: [Day 048 — Foundation Complete Review](DAY-0048-Foundation-Complete-Review.md)*
