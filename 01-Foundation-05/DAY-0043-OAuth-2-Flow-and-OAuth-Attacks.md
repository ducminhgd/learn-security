---
title: "OAuth 2 Flow and OAuth Attacks"
tags: [foundation, auth, OAuth2, authorization-code, redirect-uri, CSRF,
       state-parameter, open-redirect, token-leakage, implicit-flow]
module: 01-Foundation-05
day: 43
related_topics:
  - JWT Structure and JWT Attack Lab (Day 042)
  - OpenID Connect, SAML and SSO Attacks (Day 044)
  - Auth Detection and Hardening (Day 047)
---

# Day 043 — OAuth 2 Flow and OAuth Attacks

## Goals

By the end of this lesson you will be able to:

1. Trace the OAuth 2.0 Authorization Code flow step-by-step.
2. Explain what the `state` parameter protects against and how to exploit its absence.
3. Exploit a `redirect_uri` bypass to steal an authorization code.
4. Explain why the Implicit flow is deprecated and what leaks the token.
5. Identify four OAuth misconfiguration patterns in real applications.

---

## Prerequisites

- [Day 042 — JWT Structure and JWT Attack Lab](DAY-0042-JWT-Structure-and-JWT-Attack-Lab.md)

---

## Main Content — Part 1: OAuth 2.0 Authorization Code Flow

### 1. The Flow — Step by Step

OAuth 2.0 delegates authorization. A user grants a third-party application
access to their resources on another server — without sharing their password.

```
┌──────────┐     ┌─────────────────┐     ┌────────────────┐
│  User's  │     │  Client App     │     │ Auth Server    │
│  Browser │     │  (third-party)  │     │ (e.g. Google)  │
└────┬─────┘     └────────┬────────┘     └───────┬────────┘
     │                    │                       │
     │  1. User clicks    │                       │
     │  "Login with X"    │                       │
     │──────────────────▶ │                       │
     │                    │  2. Redirect to auth  │
     │                    │  server with:         │
     │                    │  client_id            │
     │                    │  redirect_uri         │
     │                    │  scope                │
     │                    │  state=RANDOM         │
     │ ◀──────────────────│                       │
     │                                            │
     │  3. Browser follows redirect               │
     │  ─────────────────────────────────────────▶│
     │                                            │
     │  4. User logs in, grants consent           │
     │  ◀─────────────────────────────────────────│
     │                                            │
     │  5. Auth server redirects back:            │
     │  redirect_uri?code=AUTH_CODE&state=RANDOM  │
     │──────────────────▶ │                       │
     │                    │                       │
     │                    │  6. POST /token        │
     │                    │  code=AUTH_CODE        │
     │                    │  client_secret         │
     │                    │  ─────────────────────▶│
     │                    │                       │
     │                    │  7. access_token       │
     │                    │  ◀─────────────────────│
     │                    │                       │
     │                    │  8. Fetch user data    │
     │                    │  with access_token     │
     │                    │  ─────────────────────▶│
```

**Key parameters:**

| Parameter | Who sends it | Purpose |
|---|---|---|
| `client_id` | Client | Identifies the application |
| `client_secret` | Client (step 6, server-side only) | Proves the client is legitimate |
| `redirect_uri` | Client | Where to send the code |
| `scope` | Client | What permissions are requested |
| `state` | Client | CSRF protection — random nonce |
| `code` | Auth server | One-time auth code (expires in 60–600 s) |
| `access_token` | Auth server | Credential for the resource server |

**Why the code exchange matters:**
The auth code travels through the browser (visible in URLs, logs, referer
headers). The access token does not — it is exchanged server-to-server using
the client secret. This is the core security property of the Authorization Code
flow.

---

## Main Content — Part 2: Attack 1 — Missing `state` (CSRF on OAuth)

### 2. CSRF on OAuth Login — CWE-352

**What it is:**
If the `state` parameter is absent or not validated, an attacker can force
a victim to link the attacker's OAuth account to the victim's application
account (account takeover via CSRF).

**Why it works:**
Without `state`, there is nothing tying the auth code to the specific user
who initiated the flow. An attacker can initiate their own OAuth flow, get
an auth code, then trick the victim's browser into completing the code exchange
with the attacker's code.

**Attack flow:**

```
1. Attacker initiates OAuth with target.com using their own identity:
   GET /auth?client_id=X&redirect_uri=https://app.com/callback
   → Attacker gets: https://app.com/callback?code=ATTACKER_CODE

2. Attacker stops here — does NOT visit the callback URL.

3. Attacker tricks victim into visiting:
   https://app.com/callback?code=ATTACKER_CODE
   (via CSRF, phishing, image tag, etc.)

4. app.com exchanges ATTACKER_CODE for access token.
   app.com retrieves the attacker's Google profile.
   app.com links the attacker's Google account to the victim's session.

5. Now the attacker can log into app.com using "Login with Google"
   with their own Google account → lands in the victim's account.
```

**Fix:**
```python
import secrets, flask

# Step 1: Generate and store state before redirecting
@app.route('/login/oauth')
def oauth_start():
    state = secrets.token_urlsafe(32)
    flask.session['oauth_state'] = state
    return redirect(
        f"https://auth.server.com/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&scope=openid+email"
    )

# Step 2: Validate state on callback
@app.route('/callback')
def oauth_callback():
    returned_state = request.args.get('state')
    expected_state = flask.session.pop('oauth_state', None)
    if not expected_state or not hmac.compare_digest(returned_state, expected_state):
        abort(400, "Invalid state parameter — possible CSRF attack")
    code = request.args.get('code')
    # ... exchange code for token ...
```

---

## Main Content — Part 3: Attack 2 — `redirect_uri` Bypass

### 3. Stealing the Authorization Code — CWE-601

**What it is:**
If the auth server validates `redirect_uri` loosely, an attacker can redirect
the auth code to a URL they control.

**Why it works:**
OAuth servers are supposed to enforce exact match on `redirect_uri`. Many
have bugs:

| Bypass technique | Example |
|---|---|
| Path traversal | `https://app.com/callback/../attacker` |
| Subdomain wildcard | `https://evil.app.com/callback` (if `*.app.com` allowed) |
| Open redirect on callback | `https://app.com/callback?next=https://evil.com` |
| Fragment injection | `https://app.com/callback%23.evil.com` |
| Query parameter suffix | `https://app.com/callback?state=x&redirect=evil` |

**Attack using open redirect:**

```
1. Target app has an open redirect:
   https://app.com/redirect?url=https://attacker.com/steal

2. Register this as redirect_uri in the OAuth request:
   ?redirect_uri=https://app.com/redirect?url=https://attacker.com/steal

3. If the auth server accepts it (path prefix match only),
   the code is delivered to https://attacker.com/steal?code=AUTH_CODE

4. Attacker exchanges AUTH_CODE for access_token.
```

**Real-world case:**
Facebook's OAuth redirect_uri validation in 2013 had a flaw where an
additional query parameter could be injected into the registered URI,
allowing code exfiltration. Nir Goldshlager reported it.

**Fix for auth servers:**
```
Enforce exact string match on redirect_uri.
No wildcard subdomains. No prefix match. No path traversal.
Compare registered_uri == submitted_uri — byte for byte.
```

---

## Main Content — Part 4: The Implicit Flow and Token Leakage

### 4. Why Implicit Flow is Deprecated

The Implicit flow was designed for single-page apps before CORS existed.
Instead of a code, the auth server returns the `access_token` directly in
the URL fragment:

```
https://app.com/callback#access_token=TOKEN&token_type=bearer
```

**Problems:**

1. **Token in URL** — visible in browser history, server logs, referer headers.
2. **No `client_secret`** — no proof of client identity.
3. **No refresh tokens** in spec — tokens must be short-lived.
4. **Token leakage via referer** — if the page loads a third-party resource
   after receiving the fragment, the token can leak via the `Referer` header
   in some older implementations.

**Current guidance:** Use Authorization Code + PKCE for SPAs instead.
PKCE (Proof Key for Code Exchange) replaces the client secret for public clients.

**PKCE in 30 seconds:**
```python
import hashlib, base64, secrets

# Client generates:
code_verifier = secrets.token_urlsafe(64)    # Random string (43–128 chars)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

# Step 1: Send code_challenge in auth request
# ?code_challenge=<hash>&code_challenge_method=S256

# Step 2: Send code_verifier in token exchange
# The server recomputes SHA256(verifier) and compares to stored challenge
# An intercepted auth code is useless without the original verifier
```

---

## Main Content — Part 5: Other OAuth Misconfigurations

### 5. Four More Things That Go Wrong

**Misconfiguration 1 — Scope escalation:**
The client requests `scope=read` but the auth server returns a token valid for
`scope=admin`. Always verify the granted scope in the token response.

**Misconfiguration 2 — Storing access tokens in localStorage:**
SPA reads `access_token` from the callback URL fragment and stores it in
`localStorage`. XSS → token theft → account takeover.
Fix: Server-side session stores the token; client gets a session cookie.

**Misconfiguration 3 — Accepting expired codes:**
An auth code should be valid for ≤10 minutes (RFC 6749 recommends ≤10 min).
If a server accepts codes from days ago, an attacker who captured a code
from a network tap or log can replay it later.

**Misconfiguration 4 — `client_secret` in client-side code:**
Mobile apps or SPAs that bundle the `client_secret` in JavaScript. Anyone
can extract it.
Fix: SPAs must use PKCE. Mobile apps must use PKCE with dynamic client
registration or a backend proxy.

---

## Key Takeaways

1. **State is mandatory.** Absent or predictable state = CSRF on the OAuth
   flow = account takeover. It must be a CSPRNG value tied to the user's
   session.
2. **redirect_uri must be exact-match.** Prefix match, wildcard, or open
   redirect chaining all allow auth code theft. The server enforces this —
   clients cannot fix it.
3. **The Implicit flow is deprecated.** Use Authorization Code + PKCE for
   public clients. The token-in-fragment design was always a mistake.
4. **The auth code is one-use, short-lived, and useless without the client
   secret.** This is the core security model of the flow. Anything that breaks
   these properties (no expiry, reuse allowed, no secret check) breaks OAuth.
5. **OAuth delegates authentication but is not an authentication protocol.**
   That is what OpenID Connect adds. Using OAuth for "who is this user?" without
   OIDC is a design error.

---

## Exercises

### Exercise 1 — State Parameter Lab

Build a minimal Flask OAuth client that:
1. Generates a state and stores it in the session.
2. Includes it in the auth redirect.
3. Validates it on the callback — returns 400 on mismatch.

Test: manually change the `state` in the callback URL. Confirm rejection.

### Exercise 2 — redirect_uri Test

Against a test OAuth provider (use `oauth2c`, a standalone test OAuth server):
1. Register `https://app.com/callback` as the valid redirect_uri.
2. Try variations: with a trailing slash, with a path appended, with a query
   parameter added, with `%2F` encoding.
3. Document which variants the server accepts — each accepted variant is a
   finding.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 042 — JWT Structure and JWT Attack Lab](DAY-0042-JWT-Structure-and-JWT-Attack-Lab.md)*
*Next: [Day 044 — OpenID Connect, SAML and SSO Attacks](DAY-0044-OpenID-Connect-SAML-and-SSO-Attacks.md)*
