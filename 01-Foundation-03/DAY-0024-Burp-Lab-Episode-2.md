---
title: "Burp Lab Episode 2 — Fuzzing and Hidden Endpoint Discovery"
tags: [foundation, lab, Burp-Suite, intruder, fuzzing, endpoint-discovery,
       parameter-discovery, hidden-endpoints, web-testing]
module: 01-Foundation-03
day: 24
related_topics:
  - Burp Lab Episode 1 (Day 023)
  - Burp Suite Setup (Day 022)
  - Directory and Endpoint Fuzzing (Day 065)
  - REST APIs (Day 020)
---

# Day 024 — Burp Lab Episode 2: Fuzzing and Hidden Endpoint Discovery

## Goals

This is a **lab day** focused on discovery via fuzzing. By the end you
will have demonstrated ability to:

1. Use Burp Intruder to fuzz a parameter with a wordlist.
2. Discover hidden directories and endpoints using ffuf via Burp proxy.
3. Identify hidden form parameters by fuzzing parameter names.
4. Perform HTTP verb tampering and observe different server behaviour.
5. Use Burp Decoder to decode/manipulate obfuscated parameters.

---

## Prerequisites

- [Day 023 — Burp Lab Episode 1](DAY-0023-Burp-Lab-Episode-1.md)

---

## Lab Setup

```bash
# Use same DVWA instance from Day 023 plus a target with more endpoints:
docker run -d --name juice -p 3000:3000 bkimminich/juice-shop

# Juice Shop: http://localhost:3000
# (No login required for initial exploration)

# Also install ffuf for faster fuzzing:
go install github.com/ffuf/ffuf/v2@latest
# Or: apt install ffuf
```

**Install SecLists** (required wordlists):

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
    /opt/SecLists
```

---

## Lab Tasks

### Task 1 — Directory Discovery with ffuf via Burp

Route ffuf through Burp to capture results in HTTP History:

```bash
ffuf -u http://localhost:3000/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/big.txt \
     -x http://127.0.0.1:8080 \
     -mc 200,301,302,401,403 \
     -o day024-dirs.json \
     -of json

# -mc: match these status codes only (filter 404s)
# -x: proxy through Burp
# -fs: filter by response size (useful to filter identical-length 404s)
```

**Analysis in Burp:**
All 200 and 3xx responses now appear in HTTP History. Sort by status
code or response size. What unexpected directories exist?

**Expected Juice Shop finds:**
- `/api/` — REST API base
- `/rest/` — alternative API base
- `/socket.io/` — WebSocket endpoint
- `/b2b/` — hidden B2B endpoint
- `/metrics` — application metrics (information disclosure)

---

### Task 2 — API Endpoint Discovery

Juice Shop has a REST API. Discover its endpoints:

```bash
# Fuzz the /api/v1/ path:
ffuf -u http://localhost:3000/api/v1/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
     -x http://127.0.0.1:8080 \
     -mc 200,201,400,401,403,405

# Also try the /rest/ base:
ffuf -u http://localhost:3000/rest/FUZZ \
     -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
     -x http://127.0.0.1:8080 \
     -mc 200,201,400,401,403
```

**Tip:** A `401 Unauthorized` or `403 Forbidden` is still a finding —
it confirms the endpoint exists. Add it to your list with a note
"auth required — test after getting a token."

---

### Task 3 — JavaScript Endpoint Mining

Juice Shop is a SPA. All API calls are embedded in the JS bundle.

```bash
# Find JS files:
curl -s http://localhost:3000/ | grep -oE 'src="[^"]+\.js"' | \
    cut -d'"' -f2

# Download and mine:
MAIN_JS=$(curl -s http://localhost:3000/ | \
    grep -oE '"(/[^"]+main\.[^"]+\.js)"' | head -1 | tr -d '"')
curl -s "http://localhost:3000${MAIN_JS}" | \
    grep -oE '"/[a-zA-Z0-9/_-]+"' | \
    grep -E '"/(api|rest)/' | \
    sort -u | head -50
```

**In browser DevTools:**
1. Open DevTools → Sources → find `main.js`.
2. Pretty-print it (the `{ }` button).
3. Ctrl+F: search for `this.http.get`, `this.http.post` — Angular API calls.
4. Build a complete list of every API endpoint the client uses.

**Compare this list to what ffuf found** — endpoints in the JS but not
found by ffuf need to be tested directly.

---

### Task 4 — HTTP Verb Tampering

Some servers handle unexpected HTTP methods differently:

```bash
# Normal GET:
curl http://localhost:3000/api/Users/

# Try other methods:
curl -X POST http://localhost:3000/api/Users/ \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com","password":"test","role":"admin"}'

curl -X DELETE http://localhost:3000/api/Users/1
curl -X HEAD http://localhost:3000/api/Users/
curl -X OPTIONS http://localhost:3000/api/Users/ -i

# PUT with mass assignment attempt:
curl -X PUT http://localhost:3000/api/Users/YOUR_USER_ID \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -d '{"role":"admin"}'
```

**What to look for:**
- A method that returns `200` but was not listed in `Allow` header.
- A method that bypasses authorisation checks (DELETE without auth).
- A PUT that accepts fields it shouldn't (mass assignment).

---

### Task 5 — Parameter Name Fuzzing via Intruder

The Juice Shop login endpoint accepts `email` and `password`. Are there
undocumented parameters?

1. Capture a POST to `/rest/user/login`.
2. Send to Intruder → Sniper.
3. Mark the parameter name (not value) as the injection point:
   `email=test@test.com&§password§=test`
   Change to fuzz the name: `email=test@test.com&§paramname§=test`
4. Load payload: `/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt`
5. Run and sort by response length — different length indicates the
   parameter was recognised.

**Also try: sending extra parameters to PUT/POST endpoints:**

```bash
# Normal update:
{"email": "new@email.com"}

# With extra fields:
{"email": "new@email.com", "isAdmin": true, "role": "admin",
 "totpSecret": "ABCDEF", "deletedFlag": false}

# Which fields does the server silently accept and write to the DB?
```

---

### Task 6 — Decode and Manipulate Obfuscated Values

Juice Shop uses JWTs. After logging in:

1. Find your JWT in Burp HTTP History (the login response body or
   `Authorization` header in subsequent requests).
2. Send it to Burp Decoder.
3. Split at the `.` → three Base64url-encoded parts.
4. Decode each part:
   - Part 1 (Header): algorithm and token type.
   - Part 2 (Payload): user ID, email, role, issued-at, expiry.
   - Part 3 (Signature): binary — don't decode.
5. In the payload, find your user ID.
6. Change the email in the payload to `admin@juice-sh.op`.
7. Re-encode and try using this modified token.
8. Does it work? Why or why not? (Answer: the signature won't match —
   this is intentionally a setup for Day 042 JWT attacks.)

---

## Findings Summary

Document every hidden endpoint or unexpected behaviour you discovered:

```markdown
## Day 024 Lab Findings

### E-01 — Unauthenticated API endpoint discovery
**Tool:** ffuf + JS mining
**Found:** /api/Users/ returns 200 without authentication
**Impact:** User enumeration (read full user list without auth)

### E-02 — Metrics endpoint exposed
**Path:** /metrics
**Data exposed:** Application performance metrics, request counts
**Impact:** Information disclosure — reveals internal implementation details

### E-03 — PUT method accepts undocumented fields
**Endpoint:** PUT /api/Users/:id
**Field:** role
**Impact:** Potential privilege escalation if server trusts this field

### E-04 — [next finding]
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 023 — Burp Lab Episode 1](DAY-0023-Burp-Lab-Episode-1.md)*
*Next: [Day 025 — CSP and Web Cache Behaviour](DAY-0025-CSP-and-Web-Cache-Behaviour.md)*
