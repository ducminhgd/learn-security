---
title: "Burp Lab Episode 1 — Intercept, Modify, Replay"
tags: [foundation, lab, Burp-Suite, proxy, repeater, parameter-tampering,
       login-bypass, request-modification, web-testing]
module: 01-Foundation-03
day: 23
related_topics:
  - Burp Suite Setup (Day 022)
  - HTTP Headers and Security Headers (Day 018)
  - REST APIs (Day 020)
  - Burp Lab Episode 2 (Day 024)
---

# Day 023 — Burp Lab Episode 1: Intercept, Modify, Replay

## Goals

This is a **lab day**. By the end you will have demonstrated ability to:

1. Intercept a live login request and modify it in Burp.
2. Bypass a client-side restriction that the server trusts.
3. Replay a modified authenticated request and observe the difference.
4. Identify at least three parameters in the target application that
   the server trusts but shouldn't.
5. Document findings in a one-line finding format.

---

## Prerequisites

- [Day 022 — Burp Suite Setup, Proxy and Repeater](DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md)

---

## Lab Setup

```bash
# DVWA — Damn Vulnerable Web Application
docker run -d --name dvwa -p 80:80 vulnerables/web-dvwa

# Browse to: http://localhost/setup.php
# Click "Create / Reset Database"
# Login: admin / password
# Set security level to "Low" initially
```

**Alternative targets (PortSwigger Web Academy — free):**
- https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
- https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

---

## Lab Tasks

### Task 1 — Map the Application

Before touching a single vulnerability:

1. Configure Burp scope to `http://localhost`.
2. Turn intercept **off**.
3. Browse every page of DVWA as admin: login, all modules, profile, logout.
4. Review the HTTP History. Answer:
   - How many unique endpoints did you find?
   - Which parameters appear in GET requests? POST requests? Cookies?
   - What does the session cookie look like — is it predictable?
   - What does the `security` cookie contain and what happens if you
     change it?

**Key discovery:** There is a `security` cookie set to `low`. If you
change it to `impossible`, `high`, or `medium` — the security level
changes. Can you confirm this by changing it and testing a module?

---

### Task 2 — Cookie Manipulation

The DVWA security level is controlled by a cookie:

```
Cookie: PHPSESSID=xxxxxxxx; security=low
```

1. In Burp Proxy → HTTP History, find any request with the `security`
   cookie.
2. Send it to Repeater.
3. Change `security=low` to `security=medium` and replay.
4. Confirm the response changes (the security level display on the page
   changes).
5. Now try: what happens if you set `security=hack_me`? Does the server
   handle invalid values gracefully?

**Finding template:**
```
The application uses a client-controlled cookie to determine security
level. An attacker who can set security=low can bypass restrictions
designed for higher security levels. The security level should be a
server-side session attribute, not a client-controlled value.
```

---

### Task 3 — Login Request Manipulation

1. Log **out** of DVWA.
2. Turn Burp intercept **on**.
3. Submit a login with wrong credentials.
4. Observe the intercepted POST request:
   ```
   POST /login.php HTTP/1.1
   ...
   username=ghost&password=wrong&Login=Login&user_token=CSRFTOKEN
   ```
5. In Burp, change `username=admin` and `password=password` before
   forwarding.
6. Confirm you are now logged in.

**What this demonstrates:** Any client-side restriction (disabled submit
button, JavaScript validation, hidden form fields) is trivially bypassed
via the proxy. The server must validate — not the client.

---

### Task 4 — Parameter Tampering in DVWA

#### 4a — IDOR via File Inclusion Module

1. Navigate to DVWA → File Inclusion.
2. Observe the URL: `http://localhost/vulnerabilities/fi/?page=include.php`
3. In Repeater, change `page=include.php` to:
   - `page=../../../etc/passwd`
   - `page=file:///etc/passwd`
   - `page=/etc/passwd`
4. Which form of path traversal succeeds? What is in the response?

#### 4b — Reflected XSS Parameter

1. Navigate to DVWA → XSS Reflected.
2. Submit normal input, capture the request in Burp History.
3. Send to Repeater.
4. Replace the `name` parameter value with `<script>alert(1)</script>`.
5. Does the script execute in your browser?
6. Without a browser: in Repeater, look for your payload unescaped in the
   response body — that confirms the reflection.

#### 4c — SQL Injection Parameter

1. Navigate to DVWA → SQL Injection.
2. Submit `1` as the user ID.
3. In Repeater, try: `id=1' OR '1'='1`
4. Does the response contain more rows than expected?
5. Try: `id=1' UNION SELECT 1,version()-- -`
6. What database version does the response reveal?

---

### Task 5 — Bypass a Client-Side Restriction

1. Navigate to DVWA → Upload.
2. Try uploading a `.php` file directly — it may be blocked by JavaScript.
3. In Burp, intercept the upload request.
4. Observe the form — the JavaScript restriction runs in the browser before
   the request is sent.
5. Bypass by: uploading a valid image first, then in the intercepted
   request change the filename from `image.jpg` to `shell.php`.
6. Does the server check the file type, or did it trust the JavaScript
   client-side check?

---

### Task 6 — Enumerate Hidden Parameters

The DVWA command injection page takes a `ping` parameter. What other
parameters might exist but not be visible in the form?

```
# In Burp Intruder → Sniper:
# Original request:
# POST /vulnerabilities/exec/ HTTP/1.1
# ip=127.0.0.1&Submit=Submit

# Mark 'ip' parameter value as injection point
# Payload: common parameter names from SecLists
# (Discover/Web-Content/burp-parameter-names.txt)

# Look for: different response lengths or status codes
# → indicates the parameter exists and has an effect
```

---

## Findings Summary Template

Document every finding you discovered today:

```markdown
## Day 023 Lab Findings

### F-01 — Client-Controlled Security Level Cookie
**Severity:** High
**Parameter:** Cookie: security=low
**Reproduction:** Change cookie value to "low" after it was set to higher
**Impact:** Attacker can downgrade security controls to their weakest state

### F-02 — Path Traversal in ?page= Parameter
**Severity:** Critical
**Parameter:** GET ?page=../../../etc/passwd
**Reproduction:** Replace page value with traversal string
**Impact:** Read arbitrary files from the filesystem as the web server user

### F-03 — [next finding]
...
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 022 — Burp Suite Setup, Proxy and Repeater](DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md)*
*Next: [Day 024 — Burp Lab Episode 2](DAY-0024-Burp-Lab-Episode-2.md)*
