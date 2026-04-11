---
title: "Web Architecture Competency Check"
tags: [foundation, web, competency-check, self-assessment, Burp-Suite,
       review, OWASP, module-gate]
module: 01-Foundation-03
day: 28
related_topics:
  - All 01-Foundation-03 topics (Days 017–027)
  - Foundation Competency Gate (Day 050)
---

# Day 028 — Web Architecture Competency Check

## Goals

This day has no new content. It is a gate. You pass it by demonstrating
the skills — not by reading about them.

Criteria to pass and move to Day 029:

1. Can explain every item in the self-assessment list below without notes.
2. Can execute all three live demos in Burp Suite.
3. Can write the correct security header block for nginx from memory.

If you cannot do all three — go back to the specific day that covers the
gap. One hour of re-doing the lab beats three hours of re-reading.

---

## Prerequisites

- Days 017–027 (all of 01-Foundation-03)

---

## Self-Assessment — Explain These Without Notes

Answer each question out loud. If you stumble, note the topic and review.

### Architecture

1. What component sits between a browser and the application server in a
   typical production deployment? What does each component do?
2. What is the difference between a CDN and a reverse proxy?
3. Name two ways an attacker discovers the real origin IP behind a CDN.
4. A web application uses `request.headers['Host']` to build a password
   reset link. What attack does this enable, and what is the fix?

### HTTP Headers

5. Name four security response headers and the attack each prevents.
6. What does `X-Content-Type-Options: nosniff` protect against?
7. What is the difference between `X-Frame-Options: DENY` and
   `Content-Security-Policy: frame-ancestors 'none'`? Which is preferred?
8. A response contains `Server: Apache/2.4.38 (Debian)`. Why does this
   matter to an attacker?

### SOP and CORS

9. Two URLs: `https://app.example.com/page` and
   `https://api.example.com/data`. Are they same-origin? Why or why not?
10. What does SOP block that allows CSRF to still be a vulnerability?
11. A server returns:
    ```
    Access-Control-Allow-Origin: https://evil.com
    Access-Control-Allow-Credentials: true
    ```
    When would a server return this? What is the impact?
12. Name three CORS misconfiguration patterns beyond reflected origin.

### APIs

13. A PUT request to `/api/users/1234` includes `{"role":"admin"}`.
    The user's role is updated. What vulnerability is this, and what is
    the root cause?
14. You run a GraphQL introspection query. The server returns schema data.
    What do you do next and why?
15. Name two GraphQL-specific attack patterns.

### Client-Side

16. Why is storing a JWT in `localStorage` riskier than storing it in an
    `httpOnly` cookie?
17. What is CSWSH and what header must the server validate to prevent it?
18. List the five client-side storage mechanisms. Which can be made
    inaccessible to JavaScript?

### CSP and Cache

19. A CSP contains `script-src 'self' https://cdn.example.com`. The CDN
    serves user uploads and has a JSONP endpoint. How do you bypass the CSP?
20. What is a cache key? What is an unkeyed input?
21. Describe web cache poisoning in one sentence.
22. What is web cache deception and how does it differ from poisoning?

---

## Live Demo 1 — Intercept and Modify

**Target:** DVWA or any lab app.

1. Configure Burp proxy with CA cert.
2. Intercept a form submission.
3. Add a custom header `X-Ghost-Test: true`.
4. Change a POST parameter to an unexpected value.
5. Forward and observe the effect.

**Pass criteria:** You can intercept, modify, and forward in under 3 minutes.

---

## Live Demo 2 — CORS Test

**From the command line (no browser required):**

```bash
# Test a target API for reflected-origin CORS
curl -sI https://YOUR_LAB_API/api/user \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=YOUR_TOKEN" | \
    grep -i "access-control"
```

Interpret the response:
- Does `Access-Control-Allow-Origin: https://evil.com` appear? → Vulnerable.
- Is `Access-Control-Allow-Credentials: true` also present? → Critical.

**Pass criteria:** You can identify and interpret CORS misconfiguration
from raw headers.

---

## Live Demo 3 — Security Header Audit

```bash
#!/bin/bash
TARGET="${1:-https://example.com}"
RESP=$(curl -sI "$TARGET")

echo "Target: $TARGET"
echo ""

headers=(
    "Strict-Transport-Security|HSTS — SSL stripping protection"
    "Content-Security-Policy|XSS mitigation"
    "X-Content-Type-Options|MIME sniffing protection"
    "X-Frame-Options|Clickjacking protection (legacy)"
    "Referrer-Policy|Referrer leakage control"
    "Permissions-Policy|Browser API restriction"
)

for entry in "${headers[@]}"; do
    header="${entry%%|*}"
    desc="${entry##*|}"
    if echo "$RESP" | grep -qi "$header"; then
        echo "  [✓] $header"
    else
        echo "  [✗] MISSING: $header ($desc)"
    fi
done

echo ""
echo "Info-disclosure:"
for h in "Server" "X-Powered-By" "X-AspNet-Version" "Via" "X-Generator"; do
    val=$(echo "$RESP" | grep -i "^${h}:")
    [ -n "$val" ] && echo "  [!] $val"
done
```

Run it against a target. Interpret the output.

**Pass criteria:** You can explain every finding the script reports.

---

## Gap Analysis

If you struggled with any question, record it here:

```markdown
## Gaps Identified — Day 028

| Topic | Gap | Review Day |
|---|---|---|
| [topic] | [what I couldn't explain] | [day number] |
```

Do not proceed to Day 029 until you have re-done the labs for any identified
gaps. The cryptography module builds on the understanding of TLS and HTTP
that you've developed here.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 027 — Web Architecture Hardening and Review](DAY-0027-Web-Architecture-Hardening-and-Review.md)*
*Next: Day 029 — Symmetric Encryption and ECB Weakness (01-Foundation-04)*
