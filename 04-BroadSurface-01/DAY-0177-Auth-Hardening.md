---
title: "Auth Hardening — MFA Enforcement, Lockout Policy, Token Binding, Credential Storage"
tags: [hardening, MFA, TOTP, WebAuthn, lockout-policy, token-binding, PBKDF2, Argon2,
       credential-storage, session-security, certificate-binding, ATT&CK, NIST-800-63B]
module: 04-BroadSurface-01
day: 177
related_topics:
  - Credential Stuffing and Spraying (Day 166)
  - JWT Advanced Attacks (Day 169)
  - OAuth Abuse Deep Dive (Day 171)
  - SAML Attacks (Day 173)
  - Kerberoasting and Pass-the-Hash Intro (Day 175)
  - Auth Attack Detection (Day 176)
---

# Day 177 — Auth Hardening

> "I have compromised accounts with TOTP enabled — because the TOTP secret was
> stored in plaintext in the database next to the password hash. The MFA was
> theatre. Hardening is not installing a feature. Hardening is understanding why
> the attack works and removing every assumption the attacker relies on. One
> wrong assumption is all it takes."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Implement each layer of authentication hardening that directly counters
   the attack classes from Days 166–176.
2. Configure a password hashing scheme that is resistant to offline cracking.
3. Design and implement a lockout policy that stops spraying without enabling
   DoS against legitimate users.
4. Enforce MFA correctly — TOTP, WebAuthn, and backup codes with proper
   secret storage.
5. Bind tokens (sessions, JWTs) to a transport property so stolen tokens
   cannot be replayed from a different context.
6. Map each hardening control to the MITRE ATT&CK technique it mitigates.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All auth attack classes | Days 166–176 |
| Python for code examples | Days 11–15 |
| Basic cryptography | Day 34 |
| JWT structure | Day 40 |

---

## Hardening Architecture

Each attack class from Days 166–176 maps to a specific control:

| Attack class | Primary control | Secondary control |
|---|---|---|
| Credential stuffing | Breach detection (HIBP) | Bot-resistant rate limiting |
| Password spraying | Account lockout policy | Alerting on low-and-slow patterns |
| Brute force | Rate limiting per account | Account lockout |
| JWT algorithm confusion | Enforce explicit algorithm | Pre-load key registry |
| JWT kid traversal | Reject non-alphanumeric kid | Pre-load key registry |
| OAuth code theft | Exact redirect_uri matching | PKCE enforced |
| SAML XSW | Validate signed element ID | Library patching |
| Password reset poisoning | Hardcoded base URL in config | Token expiry (15 min) |
| Kerberoasting | AES encryption for Kerberos | Long service account passwords |
| Pass-the-Hash | Credential Guard / Protected Users | Disable NTLM where possible |

---

## Part 1 — Password Hashing

### 1.1 — Which Algorithm to Use

| Algorithm | Use it? | Reason |
|---|---|---|
| MD5 | Never | 100B+ H/s on GPU; trivial to crack |
| SHA-1 | Never | Same issue as MD5 |
| SHA-256 (plain) | Never | Fast; no salt protection per GPU |
| bcrypt | Yes (legacy compatibility) | Adaptive cost; well-understood |
| PBKDF2-SHA256 | Yes (FIPS environments) | NIST-approved; widely supported |
| scrypt | Yes | Memory-hard; good for general use |
| Argon2id | **Yes — preferred** | Memory-hard + side-channel resistant; winner of PHC |

```python
# Argon2id — the correct choice in 2024+
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=3,         # Number of iterations
    memory_cost=65536,   # 64 MB memory requirement
    parallelism=4,       # Parallel threads
    hash_len=32,
    salt_len=16,
)

def hash_password(plaintext: str) -> str:
    """Hash a password with Argon2id. Returns the full encoded hash."""
    return ph.hash(plaintext)

def verify_password(stored_hash: str, plaintext: str) -> bool:
    """Return True if plaintext matches the stored Argon2id hash."""
    try:
        return ph.verify(stored_hash, plaintext)
    except VerifyMismatchError:
        return False

def needs_rehash(stored_hash: str) -> bool:
    """Return True if the hash was created with weaker parameters."""
    return ph.check_needs_rehash(stored_hash)
```

### 1.2 — Migration from a Weaker Algorithm

Never wipe old hashes — users cannot log in. Upgrade on next successful login:

```python
def login(username: str, plaintext: str) -> bool:
    user = db.get_user(username)
    if user is None:
        return False

    if user.hash_algorithm == "bcrypt":
        # Verify with bcrypt
        if not bcrypt.checkpw(plaintext.encode(), user.password_hash):
            return False
        # Upgrade to Argon2id on successful login
        user.password_hash = hash_password(plaintext)
        user.hash_algorithm = "argon2id"
        db.save(user)
        return True

    # Argon2id — normal flow
    if not verify_password(user.password_hash, plaintext):
        return False
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(plaintext)
        db.save(user)
    return True
```

---

## Part 2 — Lockout Policy Design

### The Fundamental Tension

Lockout too aggressively → attacker locks out legitimate users (DoS).
Lockout too leniently → attacker can spray indefinitely.

**The NIST SP 800-63B recommendation:** do not use traditional lockout.
Use rate limiting + MFA instead. If you must use lockout:

| Parameter | Recommended value | Reason |
|---|---|---|
| Max failures before lockout | 10 (not 3–5) | 5 is spray-friendly if window is 15 min |
| Lockout duration | Progressive (2 min → 15 min → 1 hour) | Reduces DoS impact |
| Reset trigger | Successful login or admin unlock | Prevents indefinite lock |
| Lockout scope | Per-account, not per-IP | IP rotation is trivial |
| Lockout bypass | MFA (user can still authenticate with MFA) | Prevents DoS via lockout |

```python
import time
from collections import defaultdict

class AccountLockout:
    def __init__(self):
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lockout_until: dict[str, float] = {}
        self.thresholds = [
            (5,  120),   # 5 failures → 2 min lockout
            (8,  900),   # 8 failures → 15 min lockout
            (10, 3600),  # 10 failures → 1 hour lockout
        ]
        self.window = 1800   # 30-minute rolling window

    def is_locked(self, username: str) -> bool:
        until = self._lockout_until.get(username, 0)
        return time.time() < until

    def record_failure(self, username: str) -> None:
        now = time.time()
        # Prune failures outside the window
        self._failures[username] = [
            t for t in self._failures[username]
            if now - t < self.window
        ]
        self._failures[username].append(now)
        count = len(self._failures[username])
        # Apply progressive lockout
        for threshold, duration in reversed(self.thresholds):
            if count >= threshold:
                self._lockout_until[username] = now + duration
                break

    def record_success(self, username: str) -> None:
        self._failures.pop(username, None)
        self._lockout_until.pop(username, None)
```

### 2.1 — Spray-Resistant Lockout

The lockout above protects against brute force. Against spray, add this:

```python
# Redis-backed per-IP cross-account failure counter
import redis

r = redis.Redis()

def record_global_failure(src_ip: str, username: str) -> None:
    key = f"spray:{src_ip}"
    r.zadd(key, {username: time.time()})
    r.expire(key, 1800)   # 30-minute window

def is_spraying(src_ip: str) -> bool:
    key = f"spray:{src_ip}"
    now = time.time()
    # Count distinct usernames attempted in the last 30 minutes
    r.zremrangebyscore(key, 0, now - 1800)
    return r.zcard(key) > 30   # More than 30 distinct accounts → block
```

---

## Part 3 — MFA Enforcement

### 3.1 — TOTP Implementation

TOTP (RFC 6238) is the minimum viable MFA. It is not phishing-resistant
(a real-time phishing proxy can relay the OTP), but it stops credential
stuffing and most spraying campaigns.

```python
import pyotp
import secrets
import qrcode

def setup_totp(user_id: str, username: str) -> dict:
    """Generate a TOTP secret and return setup data."""
    # secret must be stored encrypted at rest, not in plaintext
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="YourApp",
    )
    return {
        "secret": secret,          # Encrypt this before storing to DB
        "provisioning_uri": provisioning_uri,
        "backup_codes": generate_backup_codes(),
    }

def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate single-use backup codes. Hash each one before storing."""
    import hashlib
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()   # 10-char hex code
        codes.append(raw)
    return codes   # Caller hashes these before storage

def verify_totp(secret: str, submitted_otp: str) -> bool:
    """Verify a TOTP code. Allow ±1 time window for clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(submitted_otp, valid_window=1)
```

**Critical storage requirements:**

| Data | Storage method |
|---|---|
| TOTP secret | Encrypted at rest (AES-256-GCM with a KMS key) |
| Backup codes | Hashed with Argon2id before storage — one per row |
| Recovery phone | Encrypted at rest |

### 3.2 — WebAuthn (Phishing-Resistant MFA)

WebAuthn (FIDO2) is the gold standard — the credential is cryptographically
bound to the origin domain. A phishing site on `evil.com` cannot receive a
WebAuthn assertion for `target.com` because the authenticator verifies the
rpId (relying party ID) against the current browser origin.

```python
# Using the webauthn library (pip install webauthn)
import webauthn

# Registration — challenge generation
def begin_registration(user_id: str, username: str) -> dict:
    options = webauthn.generate_registration_options(
        rp_id="target.com",
        rp_name="Target App",
        user_id=user_id.encode(),
        user_name=username,
        attestation=webauthn.AttestationConveyancePreference.NONE,
        authenticator_selection=webauthn.AuthenticatorSelectionCriteria(
            user_verification=webauthn.UserVerificationRequirement.REQUIRED,
        ),
    )
    # Store options.challenge in the session for verification
    return webauthn.options_to_json(options)

# Authentication — verify assertion
def verify_assertion(
    stored_credential: dict,
    assertion: dict,
    challenge: bytes,
) -> bool:
    try:
        webauthn.verify_authentication_response(
            credential=assertion,
            expected_challenge=challenge,
            expected_rp_id="target.com",
            expected_origin="https://target.com",
            credential_public_key=stored_credential["public_key"],
            credential_current_sign_count=stored_credential["sign_count"],
            require_user_verification=True,
        )
        return True
    except webauthn.helpers.exceptions.InvalidAuthenticationResponse:
        return False
```

### 3.3 — MFA Bypass Prevention

| Bypass technique | Prevention |
|---|---|
| OTP reuse | Mark OTP as used in Redis with TTL = 30 seconds |
| Backup code reuse | Delete backup code row on use; never allow reuse |
| MFA fatigue (push spam) | Rate-limit MFA push notifications (max 3/hour) |
| Account recovery without MFA | Require MFA on recovery; out-of-band verification |
| Attacker removes MFA | Notify user on MFA change; require current MFA to modify |

---

## Part 4 — JWT Hardening

Direct counter to the JWT attacks from Day 169:

```python
from jwt import PyJWT, InvalidAlgorithmError
import jwt

# ─── Keys loaded ONCE at startup — never from DB or file system at runtime ───
import os

ALGORITHM = "RS256"   # Hard-coded — never taken from the token header

with open(os.environ["JWT_PRIVATE_KEY_PATH"], "rb") as f:
    PRIVATE_KEY = f.read()
with open(os.environ["JWT_PUBLIC_KEY_PATH"], "rb") as f:
    PUBLIC_KEY = f.read()

def issue_token(sub: str, role: str) -> str:
    """Issue a JWT. kid is a registry key, not a file path."""
    return jwt.encode(
        {"sub": sub, "role": role, "iat": int(time.time()), "exp": int(time.time()) + 3600},
        PRIVATE_KEY,
        algorithm=ALGORITHM,
        headers={"kid": "2024-01"},   # Opaque identifier — no path components
    )

# Allowlisted kid → public key. If kid is not in this dict, reject.
KEY_REGISTRY: dict[str, bytes] = {
    "2024-01": PUBLIC_KEY,
    # Add new keys here during rotation; keep old keys for transition period
}

def verify_token(token: str) -> dict:
    """Verify a JWT. Rejects any token with an unknown or malformed kid."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        raise ValueError(f"Malformed JWT header: {e}") from e

    # Reject any algorithm other than RS256
    if header.get("alg") != ALGORITHM:
        raise ValueError(f"Rejected algorithm: {header.get('alg')}")

    # Reject jku / x5u — never fetch keys from a URL in the token
    if "jku" in header or "x5u" in header:
        raise ValueError("jku/x5u headers are not permitted")

    # Reject embedded JWK
    if "jwk" in header:
        raise ValueError("Embedded JWK headers are not permitted")

    kid = header.get("kid", "")
    if kid not in KEY_REGISTRY:
        raise ValueError(f"Unknown kid: {kid!r}")

    return jwt.decode(
        token,
        KEY_REGISTRY[kid],
        algorithms=[ALGORITHM],   # Explicit allowlist — no algorithm negotiation
        options={"verify_exp": True},
    )
```

---

## Part 5 — OAuth Hardening

Direct counter to the OAuth attacks from Day 171:

```python
# Flask OAuth Authorization Server — hardened configuration

REGISTERED_CLIENTS = {
    "lab-client": {
        "secret": "...",
        "redirect_uris": [
            "https://app.target.com/callback",
            "https://mobile.target.com/callback",
        ],
        "grant_types": ["authorization_code"],   # No implicit
        "require_pkce": True,
        "client_type": "public",
    },
}

def validate_redirect_uri(client_id: str, submitted_uri: str) -> bool:
    """Exact match only — no prefix, no path traversal."""
    client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        return False
    return submitted_uri in client["redirect_uris"]   # Set membership: exact match

def validate_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify PKCE. Reject 'plain' method — require S256."""
    if method != "S256":
        return False   # 'plain' is insecure; reject it
    import hashlib, base64
    digest = hashlib.sha256(code_verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return expected == code_challenge
```

---

## Part 6 — Session Hardening

### 6.1 — Token Binding (TLS Channel Binding)

Token binding cryptographically ties a token to the TLS connection. A token
stolen from one connection cannot be replayed over a different TLS connection
because the new connection has a different channel binding value.

```python
# Practical alternative — bind session token to browser fingerprint
# True TLS token binding requires server + client + browser support (limited)

import hashlib, hmac

def create_session_token(user_id: str, user_agent: str, ip: str) -> str:
    """Create a session token bound to UA + IP. Not as strong as TLS binding
    but significantly raises the bar for token replay."""
    binding = f"{user_agent}:{ip}"
    secret = os.environ["SESSION_SECRET"].encode()
    mac = hmac.new(secret, binding.encode(), hashlib.sha256).hexdigest()
    # Store (user_id, mac) in session store; include mac as opaque binding_key
    session_id = secrets.token_urlsafe(32)
    session_store[session_id] = {"user_id": user_id, "binding_key": mac}
    return session_id

def validate_session_token(session_id: str, user_agent: str, ip: str) -> str | None:
    """Return user_id if the session is valid and the binding matches."""
    session = session_store.get(session_id)
    if not session:
        return None
    binding = f"{user_agent}:{ip}"
    secret = os.environ["SESSION_SECRET"].encode()
    expected_mac = hmac.new(secret, binding.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(session["binding_key"], expected_mac):
        # Possible token theft from a different context — invalidate and alert
        del session_store[session_id]
        return None
    return session["user_id"]
```

### 6.2 — Session Cookie Configuration

```python
# Flask session cookie — hardened defaults
from flask import Flask

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,     # Not accessible via JavaScript
    SESSION_COOKIE_SAMESITE="Lax",   # CSRF protection
    SESSION_COOKIE_NAME="__Host-session",   # __Host- prefix: Secure + no domain
    PERMANENT_SESSION_LIFETIME=3600,  # 1-hour absolute expiry
)
```

---

## Part 7 — Kerberos and AD Hardening

Counter to Kerberoasting and PtH from Day 175:

### Kerberoasting Mitigations

```powershell
# 1. Enforce AES-only Kerberos tickets (prevents RC4 → hashcat mode 13100)
#    Set msDS-SupportedEncryptionTypes = 24 (AES128 + AES256 only)
Set-ADUser svc_mssql -KerberosEncryptionType AES128,AES256

# 2. Use Group Managed Service Accounts (gMSA) — 240-char auto-rotating passwords
#    Kerberoasting is useless if the password is 240 random chars
New-ADServiceAccount -Name gMSA_MSSQL `
  -DNSHostName sqlserver.domain.local `
  -PrincipalsAllowedToRetrieveManagedPassword "SQLServers"

# 3. Audit all SPN-enabled accounts regularly
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
  Select-Object Name, SamAccountName, ServicePrincipalName, PasswordLastSet |
  Export-Csv spn-audit.csv
```

### Pass-the-Hash Mitigations

```powershell
# 1. Enable Credential Guard — protects LSASS from memory extraction
# Group Policy: Computer Config → Windows Settings → Security Settings →
#   Device Guard → "Turn On Virtualization Based Security"

# 2. Add high-value accounts to Protected Users security group
#    Members cannot use NTLM, RC4, or DES — forces Kerberos AES only
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator","svc_backup"

# 3. Disable NTLM entirely where possible
#    Group Policy: Network Security → Restrict NTLM: NTLM authentication
#    in this domain → Deny all
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "RestrictSendingNTLMTraffic" -Value 2   # Deny all outbound NTLM

# 4. Enable SMB signing (prevents NTLM relay)
Set-SmbServerConfiguration -RequireSecuritySignature $true
Set-SmbClientConfiguration -RequireSecuritySignature $true
```

---

## Part 8 — Breach Detection Integration

Check new passwords against known-breached credentials at registration and
password change — NIST SP 800-63B Section 5.1.1.2 requirement:

```python
import httpx
import hashlib

async def is_password_pwned(password: str) -> tuple[bool, int]:
    """
    Check a password against the HIBP Pwned Passwords API using k-anonymity.
    Returns (is_pwned, count). Does NOT send the full password to the API.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        )
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return True, int(count)
    return False, 0

# Use in password change/registration handler:
# pwned, count = await is_password_pwned(new_password)
# if pwned:
#     raise ValueError(f"This password appeared in {count:,} breaches. Choose another.")
```

---

## Hardening Checklist

```
Password storage:
[ ] Argon2id with time_cost ≥ 3, memory_cost ≥ 65536
[ ] Migration path from legacy bcrypt/scrypt
[ ] Breach check at password change/registration

Lockout policy:
[ ] Progressive lockout (5 → 8 → 10 failures)
[ ] Per-account scope (not per-IP)
[ ] MFA can bypass lockout for legitimate users
[ ] Spray detection: cross-account failure counter per IP

MFA:
[ ] TOTP secret encrypted at rest with KMS key
[ ] Backup codes hashed with Argon2id (not stored in plaintext)
[ ] MFA required for: login, password change, email change, API key generation
[ ] WebAuthn for high-privilege accounts

JWT:
[ ] Algorithm hard-coded server-side (never from token header)
[ ] kid validated against pre-loaded allowlist (not file system lookup)
[ ] jku / x5u / jwk headers rejected at parse time
[ ] Tokens expire within 1 hour; refresh tokens expire within 14 days

OAuth:
[ ] redirect_uri: exact match only (not prefix/regex)
[ ] PKCE required for all public clients (S256 method only)
[ ] Implicit flow disabled
[ ] State parameter validated before code exchange

Session cookies:
[ ] Secure; HttpOnly; SameSite=Lax
[ ] __Host- prefix for strict origin binding
[ ] Absolute expiry (not just inactivity timeout)

Active Directory:
[ ] AES-only Kerberos (msDS-SupportedEncryptionTypes = 24)
[ ] gMSA for all service accounts
[ ] Protected Users group for tier-0 accounts
[ ] SMB signing required domain-wide
[ ] Credential Guard enabled on all workstations
```

---

## ATT&CK Mapping — Controls to Techniques

| Control | Mitigates |
|---|---|
| Argon2id hashing | T1110.002 — Password Cracking |
| Progressive lockout | T1110.001 — Brute Force; T1110.003 — Password Spraying |
| Breach password check | T1110.004 — Credential Stuffing |
| TOTP / WebAuthn | T1078 — Valid Accounts (requires credential + second factor) |
| JWT algorithm enforcement | T1550 — Use Alternate Authentication Material |
| OAuth PKCE + exact URI | T1550 — Use Alternate Authentication Material |
| AES Kerberos + gMSA | T1558.003 — Kerberoasting |
| Protected Users + Credential Guard | T1550.002 — Pass-the-Hash |
| SMB signing | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay |

---

## Key Takeaways

1. **Argon2id is the only password hashing algorithm you should implement
   from scratch today.** bcrypt is acceptable if you are maintaining existing
   systems. MD5, SHA-1, and plain SHA-256 are never acceptable for passwords.
2. **Lockout policy is a DoS vector if misconfigured.** Progressive lockout
   with MFA bypass is the correct balance between security and availability.
3. **TOTP is better than nothing; WebAuthn is better than TOTP.** TOTP
   does not protect against real-time phishing proxies. WebAuthn does, because
   the credential is bound to the origin domain.
4. **JWT hardening is three rules:** hard-code the algorithm, load keys at
   startup into a registry, reject any header field that changes key selection.
5. **Kerberoasting goes from High to Near-Zero impact** when service accounts
   use gMSA (240-char random password that rotates automatically).

---

## Exercises

1. Implement the `AccountLockout` class in Python. Write a unit test that
   confirms: 5 failures triggers a 2-minute lockout, a 6th failure within
   the window does not extend the lockout beyond 15 minutes (second threshold
   is 8 failures). Test that a successful login clears the failure count.
2. Set up TOTP registration in a Flask app. Store the TOTP secret encrypted
   with `cryptography.fernet.Fernet`. Verify that a correctly timed OTP logs
   the user in and that reusing the same OTP within 30 seconds fails.
3. On the Day 170 JWT lab: apply the JWT hardening code from Part 4. Run
   all four attack objectives from Day 170 against the hardened version.
   Confirm every attack fails. Document which specific check stopped each one.
4. On a test AD lab (GOAD or any HTB AD box): set `msDS-SupportedEncryptionTypes`
   to AES-only on a service account and re-run Kerberoasting. What mode does
   hashcat need now? How does the crack time change compared to RC4?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q177.1, Q177.2 …).
> Follow-up questions use hierarchical numbering (Q177.1.1, Q177.1.2 …).

---

## Navigation

← Previous: [Day 176 — Auth Attack Detection](DAY-0176-Auth-Attack-Detection.md)
→ Next: [Day 178 — Auth Attacks Review](DAY-0178-Auth-Attacks-Review.md)
