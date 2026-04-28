---
title: "Mobile Practice Day 3 — API Testing and IDOR Hunting Sprint"
tags: [android, ios, practice, API-testing, IDOR, BOLA, mass-assignment,
       Burp-Suite, version-abuse, deprecated-API]
module: 04-BroadSurface-03
day: 225
related_topics:
  - Mobile API Attack Surface (Day 219)
  - BOLA and BFLA (Day 148)
  - Mass Assignment and API Injection (Day 149)
  - API Rate Limiting and DoS (Day 153)
---

# Day 225 — Mobile Practice Day 3: API Testing and IDOR Hunting

> "The API is where the money is. The app is just the UI. Today you stop
> looking at the app and start treating the intercepted traffic as your
> target. Every request is a test case. Every ID in a URL is a candidate
> for IDOR. Every POST body is a candidate for mass assignment."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Built a complete API endpoint inventory from a mobile app's traffic.
2. Tested every numeric ID in captured requests for IDOR.
3. Tested at least 5 endpoints for mass assignment.
4. Tested at least 3 API version variations for deprecated version access.
5. Documented every finding (including non-findings — document what you tested).

**Time budget:** 6–8 hours.

---

## Practice Block 1 — InsecureBankv2 API Deep Dive (3 hours)

```bash
# Start the backend server
cd Android-InsecureBankv2/AndroLabServer
python3 app.py &

# Configure app + Burp proxy
# Bypass pinning if needed
# Use every feature of the app
```

### API Inventory

Build a table of every unique endpoint:

| Method | Path | Auth Required? | Parameters | Response Fields |
|---|---|---|---|---|
| POST | /login | No | username, password | token, user_id |
| GET | /getaccounts | Yes | — | accounts, balances |
| … | … | … | … | … |

### IDOR Test Matrix

For every endpoint with a user-specific ID:

```
1. Log in as User A
2. Capture: GET /api/getstatement?user=A_USERNAME
3. Change A_USERNAME to B_USERNAME (use another account you created)
4. Does the server return B's data? → IDOR finding
```

### Mass Assignment Tests

```
POST /api/changepassword
Original body: {"newpassword": "test123", "oldpassword": "old123"}
Test: add "is_admin": true, "role": "admin", "account_balance": 9999999

POST /api/transfer
Original: {"to_account": "X", "amount": 100}
Test: add "from_account": "ANOTHER_USER", "amount": -100
```

---

## Practice Block 2 — Real App API Recon (2 hours)

Choose a free app from the Play Store (your own accounts only).

### Endpoint Discovery Workflow

```bash
# After 30 min of Burp-intercepted usage:
# 1. Export Burp site map: Target → Site Map → right-click → Save selected items

# 2. Extract unique paths
cat burp_sitemap.xml | grep '<url>' | \
    grep -oP '(?<=<url>)[^<]+' | \
    sed 's|https://[^/]*||' | \
    sort -u > endpoints.txt

cat endpoints.txt

# 3. For each endpoint with a numeric ID in the path, add to IDOR test list
grep -E '/[0-9]+' endpoints.txt | head -20
```

### Version Abuse

For every endpoint found:

```bash
# Extract base path and version pattern
# e.g., /api/v3/users/me → try /api/v1/users/me, /api/v2/users/me

# Script to try all versions
BASE_PATH="/users/me"
TOKEN="your_jwt_token"
for version in v0 v1 v2 v3 v4 beta old internal dev; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "https://api.target.com/api/$version$BASE_PATH")
    echo "$version: $response"
done
```

---

## Practice Block 3 — Rate Limiting Tests (1 hour)

```bash
# Test: does the login endpoint have rate limiting?
for i in $(seq 1 50); do
    curl -s -o /dev/null -w "%{http_code} " \
        -X POST https://api.target.com/login \
        -d '{"username":"test@test.com","password":"wrong'$i'"}'
done
# If all 50 return 401 without 429: no rate limiting

# Test: does OTP verification have rate limiting?
# (If the app has OTP/2FA)
```

---

## Reflection and Gap Analysis

After today:

1. How many unique endpoints did you find?
2. Did you find any IDOR? If yes: what was the ID type (numeric, UUID, username)?
3. Did any deprecated API version respond? Was the response different?
4. Rate limiting: which endpoints had it? Which did not?
5. What would be the highest-severity finding from today's work?

---

## Navigation

← Previous: [Day 224 — Mobile Practice Day 2](DAY-0224-Mobile-Practice-Day-2.md)
→ Next: [Day 226 — Mobile Practice Day 4](DAY-0226-Mobile-Practice-Day-4.md)
