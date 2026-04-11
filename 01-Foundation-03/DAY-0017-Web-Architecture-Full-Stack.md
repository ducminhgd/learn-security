---
title: "Web Architecture Full Stack"
tags: [foundation, web, architecture, HTTP, DNS, TLS, server, database,
       full-stack, attacker-mindset, browser]
module: 01-Foundation-03
day: 17
related_topics:
  - DNS Deep Dive (Day 003)
  - HTTP Cookies Sessions and TLS (Day 005)
  - HTTP Headers and Security Headers (Day 018)
  - Web Exploitation — SQL Injection (Day 076)
---

# Day 017 — Web Architecture Full Stack

## Goals

By the end of this lesson you will be able to:

1. Trace a browser request from URL typed to HTML rendered — every hop.
2. Name the component responsible for each stage and what can go wrong at
   each one from an attacker's perspective.
3. Explain where in the stack each major web vulnerability class lives:
   SQLi (DB), XSS (browser), SSRF (server-side HTTP), IDOR (app logic).
4. Read a server technology stack from HTTP response headers alone.
5. Explain the difference between server-side and client-side rendering
   and why it matters for finding attack surface.

---

## Prerequisites

- [Day 003 — UDP, ICMP and DNS Deep Dive](../01-Foundation-01/DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md)
- [Day 005 — HTTP Cookies, Sessions and TLS](../01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)

---

## Main Content — The Full Stack Request Journey

### 1. The Seven Hops: Browser to Database and Back

When a user visits `https://app.example.com/dashboard`, here is what happens:

```
User types URL
     │
     ▼
① Browser — URL parsing, cache check, HSTS lookup
     │
     ▼
② DNS Resolution — stub resolver → recursive resolver → authoritative NS
     │  (returns IP of app.example.com)
     ▼
③ TCP Connection — three-way handshake to port 443
     │
     ▼
④ TLS Handshake — certificate validation, session keys negotiated
     │
     ▼
⑤ HTTP Request — GET /dashboard HTTP/2 + headers (Cookie, Authorization, etc.)
     │
     ▼
⑥ Web Server / Reverse Proxy — nginx/Apache/CDN terminates TLS,
   │  routes to application, applies rules (rate limits, WAF, headers)
     │
     ▼
⑦ Application Server — business logic, session lookup, access control
     │
     ▼
⑧ Database / Cache / External APIs — data retrieval, write operations
     │
     ▼
Response flows back up: DB → App → Server → TLS → TCP → Browser
     │
     ▼
Browser renders HTML/JS/CSS — DOM construction, JS execution, sub-requests
```

---

### 2. Hop-by-Hop Attack Surface

#### Hop ① — Browser

- **Stores:** Cookies, localStorage, sessionStorage, IndexedDB, cache.
- **Attacks:** XSS executes here. DOM manipulation, cookie theft, credential
  capture, browser history theft.
- **What to look for:** JavaScript files that trust user-controlled input,
  dangerous sinks (`innerHTML`, `eval`, `document.write`).

#### Hop ② — DNS

- **Attacks:** DNS hijacking (attacker controls resolver), DNS rebinding
  (bypass SOP for internal services), subdomain takeover (CNAME to dead
  service).
- **What to look for (as attacker):** Dangling CNAME records, NS records
  pointing to unregistered domains.

#### Hop ③+④ — TCP/TLS

- **Attacks:** Expired or mis-issued certs, weak cipher suites, certificate
  transparency monitoring for new sub-domains, TLS stripping on mixed content.
- **What to look for:** `curl -v` shows the cipher suite negotiated; test
  with `testssl.sh` for weak configs.

#### Hop ⑤ — HTTP Request Layer

- **Attacks:** Header injection, HTTP request smuggling (when server and
  proxy disagree on request length — affects CDN → app server chains).
- **What to look for:** `Transfer-Encoding` vs `Content-Length` disagreements.

#### Hop ⑥ — Reverse Proxy / CDN / WAF

- **Attacks:** IP bypass via direct-to-origin (if origin IP is known),
  `X-Forwarded-For` header spoofing to bypass IP restrictions, CDN cache
  poisoning via unkeyed headers, WAF bypass via encoding.
- **What to look for:** `Server: cloudflare` or `Via:` headers revealing
  proxy layer; try `curl -H "X-Forwarded-For: 127.0.0.1"`.

#### Hop ⑦ — Application Server

- **Attacks:** This is where most web vulns live:
  - **IDOR / Broken Access Control:** App doesn't verify you own the
    resource you're requesting.
  - **SSRF:** App makes HTTP requests to URLs you supply — you redirect it
    at internal services.
  - **Business logic flaws:** Race conditions, negative price attacks,
    workflow skipping.
  - **Injection (second layer):** Data from the DB is re-rendered without
    escaping (stored XSS, second-order SQLi).

#### Hop ⑧ — Database / Cache / External APIs

- **Attacks:**
  - **SQLi:** Your input is interpolated into a SQL query.
  - **NoSQL injection:** MongoDB `$where`, `$gt` operator injection.
  - **Redis/Memcache SSRF:** App server connects to caches on localhost;
    SSRF can hit them.
  - **API key exposure:** Credentials for third-party services (Stripe,
    SendGrid) stored in DB and exposed via data leaks.

---

### 3. Reading the Stack from HTTP Headers

A passive fingerprint before touching a single endpoint:

```bash
curl -I https://target.example.com/

# Typical responses and what they reveal:
Server: nginx/1.18.0 (Ubuntu)      → nginx version + OS
Server: Apache/2.4.41 (Ubuntu)     → Apache version
X-Powered-By: PHP/7.4.33           → PHP version (often disabled)
X-Powered-By: Express              → Node.js / Express framework
X-Generator: Drupal 9              → CMS
Set-Cookie: PHPSESSID=...          → PHP session (PHP backend)
Set-Cookie: JSESSIONID=...         → Java servlet container
Set-Cookie: ASP.NET_SessionId=...  → ASP.NET / IIS
Set-Cookie: __cfduid=...           → Cloudflare CDN
X-AspNet-Version: 4.0.30319        → .NET version
X-Frame-Options: DENY              → Security header (modern app)
```

**Stack fingerprinting one-liner:**

```bash
curl -sI https://target.example.com/ | \
    grep -iE "server:|x-powered-by:|via:|set-cookie:|x-generator:|x-drupal"
```

---

### 4. Server-Side vs Client-Side Rendering — Attack Surface Difference

**Server-Side Rendering (SSR):**
- HTML is generated on the server and sent fully formed.
- All business logic in server-side code.
- Parameters: URL path, query string, POST body, cookies.
- Attack surface: injection points in server code that touch URL/POST params.

**Client-Side Rendering (CSR) / SPAs:**
- Server sends minimal HTML + JavaScript bundle.
- JS fetches data via APIs (REST or GraphQL) and builds the DOM.
- Attack surface is split:
  - **JavaScript files** — endpoints, API keys, internal routes, feature flags
    (often accessible without auth).
  - **API endpoints** — JSON-based; CORS, auth, IDOR all apply.
  - **DOM** — dangerous sinks that process API response data.

**For attackers: SPA = larger API attack surface, often with less mature auth.**
Find the JS bundle, extract all `/api/` endpoints, test them all.

```bash
# Extract endpoints from a JS bundle
curl -s https://target.com/static/js/main.abc123.js | \
    grep -oE '"/api/[^"]*"' | sort -u
```

---

### 5. The Attacker's Mental Model

Every request passing through this stack can be intercepted and modified
(given a man-in-the-middle position or a proxy). As a web attacker, you
operate through a proxy (Burp Suite) that puts you between the browser and
server — giving you access to modify every request.

**Your control surface with Burp:**
- Every HTTP header (including `Host`, `Referer`, `Content-Type`)
- Every URL parameter
- Every POST body field
- Every cookie value
- Every JSON/XML body field

**Your mental model for each endpoint:**
1. What does this endpoint *do*? (read / write / delete / trigger)
2. What user input does it take?
3. Where does that input go? (SQL query? HTML template? OS command?
   File path? URL for an outbound request?)
4. Is there an access control check before the operation?
5. What does the response leak? (version numbers, stack traces, internal
   hostnames, other users' data?)

---

## Key Takeaways

1. **Every hop is an attack surface.** Most students focus on the app layer.
   DNS rebinding, CDN cache poisoning, and HTTP request smuggling happen at
   layers most people ignore.
2. **Read HTTP headers before touching endpoints.** They reveal the full
   technology stack, proxy chain, and which security controls are or are not
   in place.
3. **CSR/SPA apps hide API endpoints in JavaScript.** Always spider the JS
   before assuming you've found all endpoints via the UI.
4. **SSRF lives at hop ⑦.** The app server makes outbound requests on your
   behalf. If you control the URL, you can reach internal services at
   hops ⑥–⑧ that are not accessible from the internet.
5. **Access control failures are the application layer's most common flaw.**
   They happen at hop ⑦ and manifest as: seeing another user's data, reaching
   admin functions as a regular user, or skipping workflow steps.

---

## Exercises

### Exercise 1 — Stack Fingerprinting

Pick three different public websites (not ones you intend to hack — just
for learning):

1. Run `curl -sI <URL>` on each one.
2. Build a technology profile: server, language/framework, CDN/proxy,
   session mechanism.
3. For each, identify which headers reveal information and which are
   deliberately withheld or hardened.

---

### Exercise 2 — Request Journey Trace

For a request to `https://example.com/login`:

1. Use `curl -v` to see the full TLS handshake and HTTP exchange.
2. Use Wireshark (or `tcpdump`) to capture the DNS resolution and TCP
   handshake for the same request.
3. Draw the seven-hop diagram with the actual values filled in
   (IP addresses, TLS version, HTTP version, server header).

---

### Exercise 3 — JS Endpoint Mining

1. Pick a public SPA (many open-source projects have demo sites).
2. Find the main JavaScript bundle in DevTools → Sources.
3. Search for `/api/`, `fetch(`, `axios.get(`, `XMLHttpRequest`.
4. List every API endpoint you find. How many are there vs how many the
   visible UI uses?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 016 — Linux Hardening and Forensic Artefacts](../01-Foundation-02/DAY-0016-Linux-Hardening-and-Forensic-Artefacts.md)*
*Next: [Day 018 — HTTP Headers and Security Headers](DAY-0018-HTTP-Headers-and-Security-Headers.md)*
