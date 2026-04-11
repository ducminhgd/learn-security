---
title: "Web Architecture Hardening and Review"
tags: [foundation, web, hardening, review, OWASP, security-headers,
       CORS, CSP, cookies, nginx, architecture]
module: 01-Foundation-03
day: 27
related_topics:
  - HTTP Headers and Security Headers (Day 018)
  - Same-Origin Policy and CORS (Day 019)
  - CSP and Web Cache Behaviour (Day 025)
  - Web Architecture Competency Check (Day 028)
---

# Day 027 — Web Architecture Hardening and Review

## Goals

This is a **consolidation and hardening day**. You have attacked all of these
concepts. Today you apply every fix. By the end you will be able to:

1. Write a complete nginx security configuration from scratch.
2. Produce a CSP policy that is both strict and functional.
3. Fix a CORS misconfiguration in Node.js/Python.
4. Set the correct cookie flags for a session token.
5. Map every topic in this module to the relevant OWASP Top 10 category.
6. Write a five-minute verbal security review of any web architecture.

---

## Prerequisites

- Days 017–026 (entire 01-Foundation-03 module)

---

## Main Content — Part 1: nginx Security Configuration

### 1. Complete nginx Hardening Template

```nginx
# /etc/nginx/nginx.conf — Security-hardened template

http {
    # ── Server identity hiding ──────────────────────────────────────────
    server_tokens off;                 # Don't expose nginx version

    # ── Global security headers (apply to all virtual hosts) ────────────
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy
        "camera=(), microphone=(), geolocation=(), payment=()" always;

    # ── TLS configuration ─────────────────────────────────────────────
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
                :ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
                :ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;           # Disable for forward secrecy
    ssl_stapling on;
    ssl_stapling_verify on;

    server {
        listen 443 ssl http2;
        server_name app.example.com;

        # ── HSTS ──────────────────────────────────────────────────────
        add_header Strict-Transport-Security
            "max-age=31536000; includeSubDomains; preload" always;

        # ── CSP (tune per application) ────────────────────────────────
        add_header Content-Security-Policy
            "default-src 'self';
             script-src 'self' 'nonce-$request_id';
             style-src 'self' 'unsafe-inline';
             img-src 'self' data: https:;
             font-src 'self';
             connect-src 'self' https://api.example.com;
             frame-ancestors 'none';
             base-uri 'self';
             form-action 'self';
             object-src 'none';
             upgrade-insecure-requests;
             report-uri /csp-report" always;

        # ── Proxy to app server ───────────────────────────────────────
        location / {
            proxy_pass http://app_upstream;

            # Strip dangerous headers before forwarding:
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            # Never trust Host header from the client — use server_name:
            proxy_set_header Host $host;

            # Remove server info from proxied responses:
            proxy_hide_header X-Powered-By;
            proxy_hide_header Server;
        }

        # ── Deny access to hidden files ───────────────────────────────
        location ~ /\. {
            deny all;
        }

        # ── Force HTTPS redirect ──────────────────────────────────────
    }

    server {
        listen 80;
        server_name app.example.com;
        return 301 https://$host$request_uri;
    }
}
```

---

### 2. Secure Cookie Configuration

```
Set-Cookie: session=TOKEN; HttpOnly; Secure; SameSite=Strict; Path=/;
            Max-Age=3600; Domain=app.example.com
```

| Flag | Purpose | Risk if missing |
|---|---|---|
| `HttpOnly` | Prevents JS access | XSS steals the cookie |
| `Secure` | HTTPS-only transmission | Cookie sent over HTTP → MITM |
| `SameSite=Strict` | No cross-origin sending | CSRF possible |
| `SameSite=Lax` | GET cross-origin OK | Weaker CSRF protection |
| `Domain=` | Restricts to specific domain | Subdomain can access the cookie |
| `Path=` | Restricts to specific path | Every path on the domain gets the cookie |
| `Max-Age=` | Session lifetime | Long-lived sessions → hijacking window |

**Express.js example:**

```javascript
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',  // HTTPS only
        sameSite: 'strict',
        maxAge: 3600000,   // 1 hour
    }
}));
```

---

### 3. CORS Secure Configuration

```javascript
// Node.js / Express — secure CORS
const ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://www.example.com',
];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.setHeader('Access-Control-Allow-Headers',
            'Content-Type, Authorization');
        res.setHeader('Vary', 'Origin');  // Prevent cache confusion
    }
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Max-Age', '86400');
        return res.status(204).end();
    }
    next();
});
```

**Python / FastAPI:**

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],  # Never use ["*"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)
```

---

## Main Content — Part 2: OWASP Top 10 Mapping

### 4. Module Topics → OWASP Top 10 (2021)

| OWASP Category | Topics Covered This Module |
|---|---|
| **A01: Broken Access Control** | IDOR (Day 020), CORS misconfiguration (Day 019), Host header attacks (Day 026) |
| **A02: Cryptographic Failures** | Insecure cookie flags, no HTTPS (Days 018, 027) |
| **A03: Injection** | Covered in depth in 03-WebExploit-01 |
| **A04: Insecure Design** | Mass assignment (Day 020), client-trusted params (Day 023) |
| **A05: Security Misconfiguration** | Missing security headers (Day 018), open CORS (Day 019), CSP issues (Day 025) |
| **A06: Vulnerable Components** | Stack disclosure via headers (Day 018), version fingerprinting |
| **A07: Auth Failures** | WebSocket auth bypass (Day 021), session storage (Day 021) |
| **A08: Software/Data Integrity** | Cache poisoning (Day 025), CDN bypass (Day 026) |
| **A09: Logging/Monitoring Failures** | Covered in Blue Cell track |
| **A10: SSRF** | Mentioned in architecture (Day 017); deep dive in 03-WebExploit |

---

### 5. Quick Reference — Attack vs Defence Mapping

| Attack | Root Cause | One-Line Fix |
|---|---|---|
| Clickjacking | Missing `X-Frame-Options` | `frame-ancestors 'none'` in CSP |
| MIME sniffing | Missing `nosniff` | `X-Content-Type-Options: nosniff` |
| SSL stripping | No HSTS | `Strict-Transport-Security` with `preload` |
| Host header injection | Trust `Host` for URL construction | Hardcode domain in app config |
| CORS credential theft | Reflect `Origin` + `Allow-Credentials` | Explicit origin allowlist |
| IP bypass via `X-Forwarded-For` | App trusts header from untrusted source | Only trust from known proxy IPs |
| Password reset poisoning | Build reset URL from `Host` | Hardcode domain from config |
| CSWSH | No Origin validation on WebSocket upgrade | Validate Origin server-side |
| localStorage token theft | Store JWT in localStorage | Use `httpOnly` cookies |
| Cache poisoning | Unkeyed headers reflected in response | Add unkeyed headers to cache key |
| Mass assignment | Bind all request body fields to model | Explicit allowlist of permitted fields |

---

## Main Content — Part 3: Web Architecture Review Checklist

### 6. How to Review a Web Architecture

When reviewing a new application, run through this in order:

```
□ Technology stack identified? (Server, language, framework, DB, CDN)
□ HTTP headers audited? (Security headers present/absent, info leakage)
□ HTTPS enforced with HSTS?
□ Cookies use HttpOnly + Secure + SameSite?
□ CORS policy explicit and allowlisted?
□ CSP present? Contains unsafe-inline or eval?
□ Authentication mechanism? (Session cookies, JWTs, OAuth)
□ Session tokens in localStorage? (should be HttpOnly cookies)
□ WebSocket endpoints? Origin header validated?
□ REST or GraphQL? Introspection enabled? Mass assignment possible?
□ Client-side storage? What sensitive data is stored?
□ X-Forwarded-For trusted for access control?
□ Host header used to build URLs?
□ CDN in front? Direct origin access possible?
□ Verbose error messages in responses?
□ Directory listing enabled?
```

---

## Key Takeaways

1. **Defence in depth.** No single header or config option stops all
   attacks. nginx hardening + CSP + CORS allowlist + secure cookies +
   HSTS together create overlapping controls.
2. **Hardcode your domain name in your application config.** This single
   change prevents: Host header injection, password reset poisoning, OAuth
   redirect construction attacks, and SSO SSRF chains.
3. **CSP's `nonce` model is the strongest XSS mitigation available.** Each
   page render gets a fresh nonce. Only scripts with that nonce execute.
   No wildcard domains, no `unsafe-inline`.
4. **Secure cookies are non-negotiable.** `HttpOnly` + `Secure` +
   `SameSite=Strict` is the baseline. Everything else is a misconfiguration.
5. **The OWASP Top 10 is a map, not a checklist.** Understanding why each
   category exists — the underlying design or implementation assumption being
   violated — matters more than memorising the list.

---

## Exercises

### Exercise 1 — Complete Hardening

Take the DVWA Docker container and configure nginx in front of it with:
- All security headers.
- HTTPS (self-signed cert is fine for the lab).
- HSTS.
- A basic CSP.

Run a `curl -sI` against it and verify every header is present.

### Exercise 2 — Architecture Review

Review this fictional application architecture:
- Frontend: React SPA served from S3 via CloudFront.
- API: Node.js/Express on EC2, behind an ALB.
- Auth: JWT stored in localStorage.
- DB: PostgreSQL.

Write a five-bullet security review identifying the top five risks.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 026 — Load Balancers, Proxies and Host Headers](DAY-0026-Load-Balancers-Proxies-Host-Headers.md)*
*Next: [Day 028 — Web Architecture Competency Check](DAY-0028-Web-Architecture-Competency-Check.md)*
