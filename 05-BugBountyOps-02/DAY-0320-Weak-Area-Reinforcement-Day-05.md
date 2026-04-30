---
title: "Weak Area Reinforcement Day 5 — OAuth 2.0 Deep Dive"
tags: [reinforcement, OAuth, SSO, account-takeover, CSRF, redirect-uri, practice,
       bug-bounty]
module: 05-BugBountyOps-02
day: 320
related_topics:
  - Weak Area Reinforcement Day 4 (Day 319)
  - Authentication Attacks (R-03)
  - JWT Advanced Attacks (Day 169)
---

# Day 320 — Weak Area Reinforcement Day 5: OAuth 2.0 Deep Dive

---

## Goals

Drill OAuth 2.0 attack surface end-to-end.
OAuth bugs are consistently high-severity (often account takeover) and
underrepresented in bug hunters' toolkits because the flow is complex.

**Time budget:** 3 hours.

---

## Part 1 — OAuth Flow Reconnaissance

### Recon: Identify the Flow

```
Step 1: Find the OAuth login button. Note the provider.
Step 2: Click it. Capture the authorization request in Burp.

Authorization request parameters to check:
  response_type: code (auth code) / token (implicit — avoid!)
  client_id: the app's ID with the OAuth provider
  redirect_uri: where the code/token is sent after auth
  scope: what permissions are being requested
  state: CSRF protection token — MUST be present, MUST be validated
  code_challenge: PKCE — present in secure implementations

Red flags:
  - state missing or static
  - redirect_uri is a broad pattern (https://TARGET/*)
  - response_type=token (implicit flow — token in URL)
  - scope includes dangerous permissions (openid + email + write)
```

### Lab: Map the OAuth Flow

```
Provider: ___
Authorization URL: ___
Parameters:
  client_id:     ___
  redirect_uri:  ___
  scope:         ___
  state:         ___  (present: Y/N)
  code_challenge:___  (present: Y/N → PKCE: Y/N)

Response type: code / token
Token endpoint: ___
```

---

## Part 2 — State Parameter CSRF

### Why Missing State = Account Takeover

```
The state parameter ties the auth flow to the user's browser session.
If state is missing or not validated:
  1. Attacker generates a valid authorization URL pointing to the real provider.
  2. Attacker does NOT complete the flow — saves the code.
  3. Victim clicks attacker's CSRF link.
  4. Victim's browser sends the attacker's code to the app's callback.
  5. App completes auth flow — attacker's OAuth identity is linked to victim's account.

Result: Attacker logs into victim's account via OAuth.
Severity: P1 account takeover.
```

### Exploit Lab

```
PortSwigger: "OAuth authentication — CSRF"

Step 1: Log in with your own OAuth account. Intercept the callback:
  GET /oauth-callback?code=CODE&state=STATE

Step 2: Drop the callback request (do not complete your own login).

Step 3: Copy the callback URL to a <img src="URL"> or <iframe> CSRF payload.

Step 4: Deliver to victim. If state is not validated, victim's browser sends
        your code → victim's account is linked to your OAuth identity.

  <img src="https://TARGET.com/oauth-callback?code=YOUR_CODE&state=YOUR_STATE">

Flag after attack: ___
Time: ___ min
```

---

## Part 3 — Redirect URI Manipulation

### Why redirect_uri Bypass = Token Theft

```
If the authorization server does not validate redirect_uri strictly:
  Legitimate: https://TARGET.com/oauth-callback
  Attack:     https://TARGET.com.attacker.com/oauth-callback
              https://TARGET.com/oauth-callback?extra=../../evil
              https://TARGET.com/@attacker.com/oauth-callback
              https://attacker.com (if whitelist is broken)

Token flow:
  Provider sends code/token to the attacker's URI.
  Attacker exchanges code for tokens at the provider's token endpoint.
  Attacker is now authenticated as victim.

Impact: Account takeover via stolen authorization code.
```

### Exploit Lab

```
PortSwigger: "OAuth authentication — redirect_uri bypass"

Step 1: Intercept authorization request.
Step 2: Modify redirect_uri parameter:
  - Add path traversal: /oauth-callback/../post?postId=1
  - Use open redirect: /oauth-callback?next=https://attacker.com
  - Use different subdomain: https://attacker.TARGET.com/

Step 3: Check if authorization server accepts modified URI.
Step 4: If accepted — victim's code is delivered to controlled endpoint.

Bypass that worked: ___
Code received: Y/N
Exchange for token: Y/N
Flag: ___
```

---

## Part 4 — JWT id_token Attacks in OpenID Connect

```
OpenID Connect (OIDC) adds an id_token (JWT) to OAuth flows.
Same JWT attacks apply here — the id_token makes claims about the user.

Attack: forge id_token with different user's sub or email claim
  → if the app trusts the JWT without verifying the signature: account takeover

Check: does the app send the id_token to its own backend for verification,
       or does it read claims client-side and trust them?

Burp Scanner → look for id_token claims being read without signature verification.
```

```
id_token present in flow: Y/N
Algorithm in header: ___
Verification bypassed: Y/N
Technique used: ___
```

---

## Post-Drill Rating

```
Area                       | Before | After
---------------------------|--------|-------
OAuth — state CSRF         |   /5   |  /5
OAuth — redirect_uri bypass|   /5   |  /5
OAuth — implicit flow risks|   /5   |  /5
OIDC — id_token attacks    |   /5   |  /5

Most common OAuth bug in real bug bounty programmes:
  (Based on HackerOne Hacktivity research): ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q320.1, Q320.2 …).

---

## Navigation

← Previous: [Day 319 — Weak Area Reinforcement Day 4](DAY-0319-Weak-Area-Reinforcement-Day-04.md)
→ Next: [Day 321 — Weak Area Reinforcement Day 6](DAY-0321-Weak-Area-Reinforcement-Day-06.md)
