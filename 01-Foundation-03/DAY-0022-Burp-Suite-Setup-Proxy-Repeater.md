---
title: "Burp Suite Setup, Proxy and Repeater"
tags: [foundation, tools, Burp-Suite, proxy, repeater, intruder, CA-cert,
       scope, intercept, web-testing, attacker-mindset]
module: 01-Foundation-03
day: 22
related_topics:
  - Web Architecture Full Stack (Day 017)
  - HTTP Headers and Security Headers (Day 018)
  - Burp Lab Episode 1 (Day 023)
  - Burp Lab Episode 2 (Day 024)
---

# Day 022 — Burp Suite Setup, Proxy and Repeater

## Goals

By the end of this lesson you will be able to:

1. Install and configure Burp Suite Community with browser proxy settings.
2. Install the Burp CA certificate in the browser to intercept HTTPS.
3. Configure scope to filter noise and focus on the target.
4. Use the Proxy to intercept, inspect, and modify live requests.
5. Use Repeater to replay and modify captured requests efficiently.
6. Use Intruder for simple parameter fuzzing (Community rate is slow
   but the technique must be understood).
7. Describe what Scanner, Collaborator, and extensions add in Pro.

---

## Prerequisites

- [Day 017 — Web Architecture Full Stack](DAY-0017-Web-Architecture-Full-Stack.md)
- [Day 018 — HTTP Headers and Security Headers](DAY-0018-HTTP-Headers-and-Security-Headers.md)
- [Day 020 — REST APIs, JSON and GraphQL](DAY-0020-REST-APIs-JSON-and-GraphQL.md)

---

## Main Content — Part 1: Setup

### 1. Installation and Initial Config

**Download:** https://portswigger.net/burp/communitydownload

Burp Suite Community is free. Burp Suite Professional adds:
- Active scanner (automated vulnerability detection)
- Burp Collaborator (out-of-band interaction testing — critical for
  blind SSRF, blind XSS, blind SQLi)
- Unlimited Intruder speed
- Extensions marketplace access

```bash
# Linux: download and run
chmod +x burpsuite_community_linux_*.sh
./burpsuite_community_linux_*.sh

# macOS: drag to Applications
# Windows: standard installer
```

---

### 2. Browser Proxy Configuration

Burp listens on `127.0.0.1:8080` by default.

**Option A — FoxyProxy (recommended for Firefox):**

1. Install the FoxyProxy Standard extension.
2. Add a proxy: `127.0.0.1:8080`.
3. Toggle on/off with one click.

**Option B — Chromium with dedicated profile:**

```bash
chromium --proxy-server="127.0.0.1:8080" \
         --ignore-certificate-errors \
         --user-data-dir=/tmp/burp-chrome-profile
```

**Option C — System proxy (macOS/Linux):**

```bash
# macOS
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080

# Linux (gsettings)
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http host '127.0.0.1'
gsettings set org.gnome.system.proxy.http port 8080
```

---

### 3. Installing the Burp CA Certificate

HTTPS traffic is TLS-encrypted. Without the CA cert, Burp cannot read it.
Burp acts as a man-in-the-middle: it decrypts your TLS, reads/modifies the
traffic, then re-encrypts it to the server using its own cert signed by its
own CA.

**Step 1:** Navigate to `http://burp` or `http://127.0.0.1:8080` with
the browser proxied through Burp.

**Step 2:** Click "CA Certificate" → download `cacert.der`.

**Step 3 — Firefox:**
- Preferences → Privacy & Security → Certificates → View Certificates.
- Authorities tab → Import `cacert.der`.
- Check: "Trust this CA to identify websites."

**Step 4 — Chrome/Chromium:**
- Settings → Privacy → Security → Manage certificates.
- Import into "Trusted Root Certification Authorities."

**Step 5 — Verify:** Navigate to `https://example.com` — the certificate
in the browser should show "PortSwigger CA" as the issuer.

---

## Main Content — Part 2: Core Tools

### 4. Proxy — Intercept and Traffic History

**Intercept mode:** Burp holds each request until you manually forward it.
Use this for: modifying a request before it reaches the server.

```
Proxy → Intercept → "Intercept is on"
→ Request appears in the panel
→ Modify the request (add parameters, change values, inject payloads)
→ Click "Forward"
```

**HTTP History:** Every request that passes through Burp (whether
intercepted or not) appears here. This is your research starting point.

```
Proxy → HTTP history
→ Right-click any request → "Send to Repeater"
→ Right-click → "Send to Intruder"
→ Right-click → "Send to Scanner" (Pro only)
→ Right-click → "Copy as curl command"
```

**Useful history columns:**
- Method, URL, Status, Length, MIME type, Time.
- Add: Request comment, Response received (Pro).

**Scope filter:** Without scope, Burp captures everything — including
analytics, CDN requests, and third-party scripts. Noisy and slow.

---

### 5. Scope Configuration

```
Target → Scope → Add
→ Specify target: https://target.example.com
→ In Proxy → Options → check "Drop all requests outside of scope"
```

**Or right-click a target in Site Map and "Add to scope".**

Scope uses a regex under the hood. For bug bounty:

```
# Scope for a wildcard domain:
Protocol: https
Host: .*\.example\.com
Port: 443
File: .*
```

---

### 6. Repeater — The Most Important Tool

Repeater lets you send a single captured request repeatedly with
modifications. This is where you manually test every injection point.

**Workflow:**

1. Find interesting request in HTTP History.
2. Right-click → "Send to Repeater."
3. Tab opens in Repeater.
4. Modify the request (change parameter value, add header, etc.).
5. Click "Send."
6. Analyse response on the right side.
7. Repeat until you find the interesting behaviour.

**Keyboard shortcut:** `Ctrl+R` sends to Repeater from Proxy.
`Ctrl+Shift+R` re-sends in Repeater.

**What to do in Repeater:**

```
Original request:
GET /api/v1/user?id=1234 HTTP/1.1
Authorization: Bearer TOKEN

Test 1: Change id to another user's ID
GET /api/v1/user?id=1235 HTTP/1.1

Test 2: Remove authorization
GET /api/v1/user?id=1234 HTTP/1.1
(no Authorization header)

Test 3: Change method
POST /api/v1/user?id=1234 HTTP/1.1

Test 4: Inject into the parameter
GET /api/v1/user?id=1234'+OR+'1'='1 HTTP/1.1
```

---

### 7. Intruder — Fuzzing

Intruder automates sending many requests with varying payloads. **In
Community, it is throttled to ~1 request/second.** This is by design.
For real speed, you need Pro or dedicated tools (ffuf, sqlmap).

**Intruder attack types:**

| Type | Use case |
|---|---|
| **Sniper** | Test one parameter at a time with a wordlist |
| **Battering Ram** | Same payload in all marked positions simultaneously |
| **Pitchfork** | Paired wordlists — username list + password list |
| **Cluster Bomb** | All combinations of multiple wordlists (credential stuffing) |

**Setting up a Sniper attack:**

1. Send a request to Intruder (right-click → Send to Intruder).
2. In "Positions" tab, mark the injection point:
   `id=§1234§`
3. In "Payloads" tab, add a payload list (numbers 1–100, wordlist, etc.).
4. Start attack.
5. Sort results by Status code or Response Length to find anomalies.

---

### 8. Other Key Burp Components

**Target → Site Map:** Tree view of everything Burp has seen about the
target. Spider results appear here. Great for mapping an app before
testing.

**Decoder:** Encode/decode Base64, URL encoding, HTML entities, hex. Use
it when you see encoded values in cookies or parameters:

```
# A cookie value: dXNlcjoxMjM0
# Paste into Decoder → Decode as Base64 → user:1234
# IDOR opportunity: what if we encode user:1235?
```

**Comparer:** Diff two responses byte-by-byte. Critical for detecting
subtle differences between error messages (username enumeration, blind
injection response differences).

**Logger++ (extension — install via BApp Store):** Better request logging
with colour coding and search.

---

## Key Takeaways

1. **Burp Proxy is your single pane of glass.** Every request the browser
   makes flows through it. You see what the app sends and can change it.
2. **Repeater is where the real work happens.** Not automated scanning —
   manual modification and analysis of individual requests.
3. **HTTP History is your research tool.** Before touching anything, browse
   the full app with intercept off and study what requests are made,
   what parameters appear, and what endpoints exist.
4. **Install the CA cert correctly or you'll miss all HTTPS traffic.**
   Most bugs are in HTTPS endpoints. If Burp isn't intercepting HTTPS,
   you're working blind.
5. **Set scope before you start testing** — otherwise you're analysing noise
   from a hundred third-party tracking scripts.

---

## Exercises

### Exercise 1 — Burp Setup Validation

1. Install and configure Burp with the CA cert in Firefox.
2. Navigate to `https://portswigger.net/web-security` with intercept on.
3. Confirm you can see the raw HTTPS request in Burp.
4. Add an `X-Ghost-Was-Here: true` header and forward.
5. Confirm the page loaded correctly (the custom header was transparent to
   the server but you could have inserted anything).

### Exercise 2 — Repeater Exploration

1. Set up DVWA (`docker run -p 80:80 vulnerables/web-dvwa`).
2. Log in and capture the login request.
3. Send it to Repeater.
4. Replay it with the wrong password and observe the response difference.
5. Send both responses to Comparer and identify the exact bytes that differ.

### Exercise 3 — Intruder IDOR Discovery

In DVWA (any logged-in session):

1. Capture a request that includes your user ID.
2. Send to Intruder → Sniper on the user ID value.
3. Set payload: numbers 1–10.
4. Run the attack.
5. Sort results by response length — different length = different data
   returned = IDOR confirmed.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 021 — WebSockets and Client-Side Storage](DAY-0021-WebSockets-and-Client-Side-Storage.md)*
*Next: [Day 023 — Burp Lab Episode 1](DAY-0023-Burp-Lab-Episode-1.md)*
