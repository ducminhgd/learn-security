---
title: "CSP and Web Cache Behaviour"
tags: [foundation, web, CSP, content-security-policy, web-cache,
       cache-poisoning, CPDoS, cache-keys, bypass, attacker-mindset]
module: 01-Foundation-03
day: 25
related_topics:
  - HTTP Headers and Security Headers (Day 018)
  - XSS Filter Bypass Techniques (Day 094)
  - Load Balancers Proxies Host Headers (Day 026)
  - CSP Deep Dive and Bypass (Day 098)
---

# Day 025 — CSP and Web Cache Behaviour

## Goals

By the end of this lesson you will be able to:

1. Read a CSP header and explain what each directive restricts.
2. Identify five CSP bypass patterns (unsafe-inline, unsafe-eval,
   JSONP endpoints, open redirects, base-uri).
3. Explain what a cache key is and how unkeyed headers create
   poisoning opportunities.
4. Demonstrate web cache deception and web cache poisoning conceptually.
5. Explain CPDoS (Cache Poisoned Denial of Service).

---

## Prerequisites

- [Day 018 — HTTP Headers and Security Headers](DAY-0018-HTTP-Headers-and-Security-Headers.md)
- [Day 019 — Same-Origin Policy and CORS](DAY-0019-Same-Origin-Policy-and-CORS.md)

---

## Main Content — Part 1: Content Security Policy

### 1. CSP — What It Does

CSP is a response header that tells the browser which resources it is
allowed to load and execute. It is the primary XSS mitigation that works
even if user input reaches a page unescaped.

```
Content-Security-Policy: default-src 'self';
    script-src 'self' https://cdn.example.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    connect-src 'self' https://api.example.com;
    frame-ancestors 'none';
    report-uri https://csp-reports.example.com/collect
```

**Key directives:**

| Directive | Controls | Dangerous values |
|---|---|---|
| `default-src` | Fallback for all resource types | `*`, `'unsafe-inline'`, `'unsafe-eval'` |
| `script-src` | JavaScript sources | `'unsafe-inline'`, `'unsafe-eval'`, wildcard CDN |
| `style-src` | CSS sources | `'unsafe-inline'` |
| `img-src` | Image sources | `*` (data: exfil possible) |
| `connect-src` | fetch/XHR destinations | `*` (XSS exfil possible) |
| `frame-ancestors` | Who can embed this page | `*` (clickjacking) |
| `base-uri` | `<base>` tag target | Not restricted → base-uri hijack |
| `form-action` | Form POST destinations | Not restricted → phishing redirect |
| `object-src` | Flash/plugin sources | Should always be `'none'` |

---

### 2. CSP Bypass Techniques

#### Bypass 1 — `'unsafe-inline'` Present

If `script-src` includes `'unsafe-inline'`, inline scripts are allowed:

```html
<script>alert('CSP bypassed')</script>
```

The CSP is essentially meaningless for XSS protection.

#### Bypass 2 — Wildcard CDN Domain

```
Content-Security-Policy: script-src 'self' https://cdn.company.com
```

If the CDN serves user-uploaded content or has a JSONP endpoint:

```html
<!-- If cdn.company.com allows uploading a JS file: -->
<script src="https://cdn.company.com/user-uploads/evil.js"></script>

<!-- If cdn.company.com has a JSONP callback endpoint: -->
<script src="https://cdn.company.com/jsonp?callback=alert(1)//"></script>
```

#### Bypass 3 — JSONP Endpoint on Trusted Domain

A JSONP endpoint wraps a callback function call:

```
https://trusted.example.com/api/data?callback=YOURFUNCTION
# Response: YOURFUNCTION({"data":"..."});
```

If `trusted.example.com` is in `script-src`, you can use its JSONP
endpoint to execute arbitrary JavaScript by setting `callback` to your
payload:

```html
<script src="https://trusted.example.com/api/data?callback=alert(1)//"></script>
```

#### Bypass 4 — Missing `base-uri` Directive

Without `base-uri 'self'`, an injected `<base>` tag redirects all relative
URLs to the attacker's domain:

```html
<!-- Injected into the page: -->
<base href="https://attacker.com/">

<!-- Now all relative script sources load from attacker.com: -->
<script src="/app.js"></script>
<!-- Loads: https://attacker.com/app.js -->
```

#### Bypass 5 — `'nonce-'` Leakage

Nonce-based CSP is strong when nonces are random and per-request:

```
Content-Security-Policy: script-src 'nonce-r4nd0m1234'
```

Only scripts with `<script nonce="r4nd0m1234">` are allowed. Attacks:
- If the nonce is predictable or reused → guess it.
- If the page reflects the nonce in the HTML source via injection → use
  the reflected nonce in the injected script tag.
- CSP with `'strict-dynamic'` + `'nonce'` is resistant to most bypasses.

---

## Main Content — Part 2: Web Cache Behaviour

### 3. How Web Caches Work

Caches (CDNs like Cloudflare, Fastly, AWS CloudFront; reverse proxies like
Varnish, nginx proxy_cache) store HTTP responses and replay them to
subsequent users.

**Cache key:** The set of request attributes used to identify a cached
response. Typically: scheme + host + path + some query parameters.

**Unkeyed inputs:** Request attributes (headers, cookies, parameters) that
influence the response but are NOT part of the cache key. This is where
web cache poisoning lives.

---

### 4. Web Cache Poisoning

**Concept:** Inject a malicious response into the cache that will be
served to all subsequent users.

**Requirements:**
1. An unkeyed input that the server reflects into the response.
2. Sufficient control over the reflected content (can inject headers or
   HTML).

**Classic example — X-Forwarded-Host:**

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Vulnerable server reflects X-Forwarded-Host into the response:
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
...
<script src="https://evil.com/script.js"></script>
```

If `X-Forwarded-Host` is not part of the cache key, this poisoned response
is served to ALL users of `target.com` until the cache expires.

**Testing for unkeyed headers:**

```bash
# Send request with a unique unkeyed header value
curl -s -H "X-Forwarded-Host: UNIQUE-CANARY-12345.com" \
    https://target.com/ | grep "UNIQUE-CANARY"

# If "UNIQUE-CANARY" appears in the response body → the header is reflected
# Now check: is it cached?
# Remove the header from a second request — does the canary still appear?
```

---

### 5. Web Cache Deception

Different attack: trick the cache into storing a private response and
then retrieve it.

**Concept:**
1. Attacker tricks victim into visiting a crafted URL:
   `https://target.com/account/profile/nonexistent.css`
2. The app ignores the `.css` extension and serves the profile page.
3. The cache sees `.css` (a static file extension) and caches the response.
4. Attacker requests the same URL → receives the cached private profile.

**Test:**

```bash
# Does the server serve account pages at arbitrary extensions?
curl https://target.com/account/profile.css
# Does it return profile data?

# Does the cache key NOT include the file extension?
# → cached response can be read by anyone who knows the URL
```

---

### 6. CPDoS — Cache Poisoned Denial of Service

Inject a malicious header that causes the origin server to return an
error — then cache that error response.

**Example — Header size overflow:**

```
GET / HTTP/1.1
Host: target.com
X-Oversized-Header: [30,000 bytes of padding]

# Server returns: 400 Bad Request
# Cache: stores the 400 as the response for GET /
# All subsequent users of GET / receive a 400
```

**Other CPDoS vectors:**
- `X-HTTP-Method-Override: DELETE` (some servers honour this, return 405)
- `X-Cache-Status: invalid` (some caching layers mishandle this)
- Malformed `Content-Length` or `Transfer-Encoding`

---

## Key Takeaways

1. **`'unsafe-inline'` in CSP = no XSS protection.** If the CSP allows
   unsafe-inline, it cannot prevent inline script injection. Every
   `<script>` tag works.
2. **JSONP endpoints on trusted domains bypass CSP.** Before adding a
   domain to `script-src`, check all its endpoints for JSONP. One JSONP
   endpoint on a CDN you whitelist breaks your entire CSP.
3. **Cache keys are invisible to most scanners.** Web cache poisoning
   requires manual testing: inject unique canary values in headers and
   check if they appear in uncached responses.
4. **Web cache deception reads private responses.** If an app serves
   profile pages at `.css` paths and the cache is keyed on extension,
   private data can be cached and read by anyone.
5. **`base-uri 'self'` is a frequently forgotten directive.** Without it,
   a single `<base>` tag injection redirects all relative resources to the
   attacker's domain.

---

## Exercises

### Exercise 1 — CSP Audit

Run a CSP audit against any site you own:

```bash
curl -sI https://target.com/ | grep -i "content-security-policy"
```

1. Parse each directive.
2. Identify any dangerous values.
3. Check if `base-uri` is set; check if `object-src` is `'none'`.
4. Look up every whitelisted domain in `script-src` for JSONP endpoints.

### Exercise 2 — CSP Bypass Lab

Set up a simple HTML page with a strict-ish CSP:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' https://ajax.googleapis.com">
```

Can you bypass it using a JSONP endpoint on `ajax.googleapis.com`?
(Hint: search `https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.js`
— does any Google endpoint have a JSONP callback parameter?)

### Exercise 3 — Cache Behaviour

1. Using Burp, intercept a request to a cached page.
2. Add `X-Forwarded-Host: CANARY-VALUE` to the request.
3. Search the response for `CANARY-VALUE`.
4. If found, send the same request without the custom header — is the
   canary still in the response? (Would mean it was cached.)

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 024 — Burp Lab Episode 2](DAY-0024-Burp-Lab-Episode-2.md)*
*Next: [Day 026 — Load Balancers, Proxies and Host Headers](DAY-0026-Load-Balancers-Proxies-Host-Headers.md)*
