---
title: "MFA and MFA Bypass"
tags: [foundation, auth, MFA, TOTP, FIDO2, WebAuthn, SMS-OTP, SIM-swap,
       OTP-interception, phishing-resistant, bypass]
module: 01-Foundation-05
day: 41
related_topics:
  - Session Management (Day 040)
  - JWT Structure (Day 042)
  - Auth Detection and Hardening (Day 047)
---

# Day 041 — MFA and MFA Bypass

## Goals

By the end of this lesson you will be able to:

1. Explain three MFA factor categories (knowledge, possession, inherence).
2. Trace a TOTP (RFC 6238) computation step-by-step.
3. Identify five MFA bypass techniques used in real attacks.
4. Explain why FIDO2/WebAuthn is phishing-resistant and SMS/TOTP is not.
5. Describe SIM swapping and how it breaks SMS-based MFA.

---

## Prerequisites

- [Day 040 — Session Management and Broken Session Lab](DAY-0040-Session-Management-and-Broken-Session-Lab.md)

---

## Main Content — Part 1: MFA Factor Categories

### 1. Three Factor Types

| Type | What it is | Examples | Threat |
|---|---|---|---|
| **Knowledge** | Something you know | Password, PIN, security question | Phishing, guessing, database breach |
| **Possession** | Something you have | SMS code, TOTP app, hardware key | SIM swap, malware, theft |
| **Inherence** | Something you are | Fingerprint, face recognition | Biometric spoofing, data breach |

**True MFA = two different factor types.** Two passwords = not MFA.
Password + TOTP = MFA (knowledge + possession).

---

## Main Content — Part 2: TOTP Deep Dive

### 2. How TOTP Works (RFC 6238)

TOTP is a 6-digit code that changes every 30 seconds, derived from:

```
TOTP = HOTP(shared_secret, time_step)

Where:
  time_step = floor(unix_time / 30)
  HOTP(key, counter) = HMAC-SHA1(key, counter) → truncated to 6 digits
```

**Step-by-step:**

```python
import hmac, hashlib, struct, time, base64

def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    # Decode the base32-encoded shared secret
    key = base64.b32decode(secret.upper())

    # Compute the time counter
    counter = int(time.time()) // period

    # Compute HMAC-SHA1
    counter_bytes = struct.pack('>Q', counter)  # 8-byte big-endian
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = mac[-1] & 0x0F
    code = struct.unpack('>I', mac[offset:offset+4])[0] & 0x7FFFFFFF

    # Return 6-digit code
    return str(code % (10 ** digits)).zfill(digits)

# Usage:
secret = "JBSWY3DPEHPK3PXP"  # Example base32 secret (from QR code)
print(totp(secret))           # Current TOTP code
```

**The shared secret** is set during enrollment (the QR code scan). Both
the authenticator app and the server compute TOTP independently from the
same secret + current time. A ±1 time step tolerance is standard.

---

## Main Content — Part 3: MFA Bypass Techniques

### 3. Bypass 1 — OTP Interception (Phishing)

**Attack:** A real-time phishing site sits between the victim and the
legitimate site. The victim enters their OTP on the phishing site, which
immediately relays it to the real site.

```
Victim → phishing.evil.com (looks like target) → target.com
         ← renders target.com's login page ← ← fetches

When victim submits OTP:
  phishing.evil.com captures OTP
  immediately relays to target.com
  gets valid session cookie → attacker-controlled session
```

**Why it works:** TOTP codes are valid for 30–90 seconds. A fast MITM
phishing proxy can capture and replay within that window.

**Why SMS/TOTP cannot prevent this:** Both are "real-time" codes. The
attacker just needs to relay before expiry. TOTP codes are not bound to
a specific origin.

---

### 4. Bypass 2 — SIM Swap

**Attack:** Attacker convinces the victim's mobile carrier to transfer
the phone number to a new SIM under the attacker's control. All incoming
SMS (including OTPs) now go to the attacker.

**How it's done:**
- Social engineering the carrier support line with stolen PII (name,
  address, last 4 digits of SSN — from prior breaches).
- Bribery of carrier insiders.
- Exploiting carrier web portals.

**High-profile cases:** Twitter CEO Jack Dorsey (2019), Reddit founder
Alexis Ohanian, dozens of crypto exchange executives.

---

### 5. Bypass 3 — MFA Response Manipulation

Some apps check MFA in a separate request and only check the result:

```
POST /mfa/verify
{"code": "123456"}

Response on success:  {"status": "success", "redirect": "/dashboard"}
Response on failure:  {"status": "failed"}
```

**Attack:** Intercept the failure response in Burp and change it to success:

```
{"status": "failed"} → {"status": "success", "redirect": "/dashboard"}
```

If the client-side JavaScript uses this response to redirect (and the
server doesn't independently verify before serving the dashboard),
the MFA is bypassed client-side.

**Fix:** MFA verification must set a server-side flag. The dashboard must
check that flag server-side, not rely on the client redirecting correctly.

---

### 6. Bypass 4 — Skip the MFA Step

Some apps implement MFA as a separate step but don't enforce it:

```
Step 1: POST /login → returns session_id with partial auth flag
Step 2: POST /mfa/verify → sets full_auth flag

Attack: use the session_id from step 1 to directly access /dashboard
        without completing step 2
```

If `/dashboard` only checks that the user is logged in (not that
full_auth = true), MFA is bypassed by skipping step 2.

**Fix:** Every protected endpoint must verify `full_auth` flag.

---

### 7. Bypass 5 — Brute-Force OTP

TOTP codes are 6 digits = 1,000,000 possibilities. If there's no rate
limiting on the OTP endpoint:

```python
# Brute force a 6-digit OTP with no rate limiting:
for code in range(1000000):
    response = requests.post('/mfa/verify', json={'code': f'{code:06d}'})
    if response.json()['status'] == 'success':
        print(f"OTP found: {code:06d}")
        break
```

Average: 500,000 attempts. At 10 req/s = 14 hours. At 1000 req/s = 8.3
minutes. Rate limiting is essential.

---

## Main Content — Part 4: FIDO2/WebAuthn

### 8. Why FIDO2 is Phishing-Resistant

WebAuthn (FIDO2) uses public-key cryptography tied to the **origin**:

**Enrollment:**
1. Browser generates a new key pair.
2. Private key stored securely in the authenticator (hardware key, TPM,
   phone secure enclave).
3. Public key + credential ID sent to the server.

**Authentication:**
1. Server sends a `challenge` (random nonce).
2. The server also sends the expected `rpId` (relying party ID = domain).
3. The authenticator signs `challenge + origin + rpId` with the private key.
4. **The origin is included in the signed data.** The authenticator checks
   that the origin in the request matches the registered `rpId`.

**Why this prevents phishing:**

If the user visits `phishing.evil.com`:
- The browser sends `rpId = evil.com` to the authenticator.
- The authenticator looks up the credential for `evil.com` — doesn't exist.
- No signature produced → no way to relay to `target.com`.

The credential is cryptographically bound to the domain. No domain = no
credential = phishing fails even if the user "thinks" they're on target.com.

**Summary of MFA security ranking:**

| MFA Method | Phishing resistant | SIM swap resistant | Recommended |
|---|---|---|---|
| FIDO2/WebAuthn hardware key | Yes | Yes | Best |
| FIDO2/WebAuthn passkey | Yes | Depends | Excellent |
| TOTP (Authenticator app) | No | Yes | Good |
| Email OTP | No | No | Marginal |
| SMS OTP | No | No | Avoid |
| Voice call OTP | No | No | Avoid |

---

## Key Takeaways

1. **TOTP and SMS OTP are not phishing-resistant.** A real-time phishing
   proxy can relay them within the validity window. For high-value accounts,
   use FIDO2.
2. **SIM swap breaks SMS MFA completely.** Carriers can be socially
   engineered. Never rely on SMS for high-security MFA.
3. **MFA bypass is often a server-side logic flaw, not a crypto attack.**
   Check for: response manipulation, step skipping, no rate limiting on OTP.
4. **Rate-limit OTP endpoints.** 6-digit codes = 1M possibilities.
   Without rate limiting, brute force is possible.
5. **FIDO2 is the gold standard.** Origin is in the signed data — the
   authenticator itself rejects any phishing attempt at the hardware level.

---

## Exercises

### Exercise 1 — TOTP from Scratch

Implement the TOTP function from this lesson. Verify it against Google
Authenticator or a TOTP web tool (enter the same base32 secret and confirm
the codes match).

### Exercise 2 — MFA Step Skip

Set up a two-step auth flow (Flask + session flag). Implement it
vulnerably (only `/mfa/verify` sets `full_auth`, but `/dashboard` only
checks `logged_in`). Then:
1. Complete step 1 (login) but skip step 2.
2. Directly access `/dashboard` — confirm bypass.
3. Fix: `/dashboard` must check `full_auth`.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 040 — Session Management and Broken Session Lab](DAY-0040-Session-Management-and-Broken-Session-Lab.md)*
*Next: [Day 042 — JWT Structure and JWT Attack Lab](DAY-0042-JWT-Structure-and-JWT-Attack-Lab.md)*
