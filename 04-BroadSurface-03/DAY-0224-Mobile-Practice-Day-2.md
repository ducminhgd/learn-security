---
title: "Mobile Practice Day 2 — Dynamic Analysis and Frida Scripting Sprint"
tags: [android, practice, frida, dynamic-analysis, objection, hooking,
       runtime-patching, certificate-pinning-bypass]
module: 04-BroadSurface-03
day: 224
related_topics:
  - Android Dynamic Analysis with Frida (Day 214)
  - Certificate Pinning Bypass (Day 215)
  - Android Insecure Storage (Day 216)
---

# Day 224 — Mobile Practice Day 2: Dynamic Analysis and Frida Sprint

> "You should be faster today than you were on Day 221. Frida up, pinning
> bypassed, proxy running — target five minutes. If it takes longer than
> that, your setup is broken. Fix the setup. Then find the bugs."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Bypassed certificate pinning on at least 2 different apps using different
   methods (objection, custom script, Network Security Config patch).
2. Written 3 original Frida scripts targeting specific method hooks.
3. Captured and analysed at least 20 unique API requests from a target app.
4. Completed DIVA challenges 3 (Parts 2–4) and 4 (Input Validation).

**Time budget:** 6–8 hours.

---

## Practice Block 1 — Frida Script Writing (2 hours)

Write all three scripts from scratch. No copying from Day 214 notes.
Refer to the Frida API docs if needed: https://frida.re/docs/javascript-api/

### Script 1: Credential Interceptor

```
Task: Hook SharedPreferences.getString() and SharedPreferences.Editor.putString()
Goal: Log every key-value pair read or written to SharedPreferences
Target: DIVA app or InsecureBankv2
```

### Script 2: Crypto Key Extractor

```
Task: Hook javax.crypto.spec.SecretKeySpec constructor
Goal: Log the algorithm name and key bytes (as hex) every time a symmetric
      key is created
Validation: Trigger an encryption operation in the app and see the key logged
```

### Script 3: HTTP Header Dumper

```
Task: Hook okhttp3.Request.header() or HttpURLConnection.setRequestProperty()
Goal: Log every outbound HTTP header — especially Authorization headers
Validation: Trigger a login and confirm the JWT or session token is logged
```

---

## Practice Block 2 — DIVA Challenges (2 hours)

```
Challenge 3 — Insecure Data Storage Part 2:
  Credentials stored in SQLite database
  Goal: extract from the database using adb + sqlite3

Challenge 3 — Part 3:
  Data stored in a temporary file
  Goal: find the file path from code; extract via adb

Challenge 3 — Part 4:
  Data stored in external storage
  Goal: find via static analysis; confirm with adb ls /sdcard/

Challenge 4 — Input Validation Issues:
  SQL injection in a local Content Provider
  Goal: inject SQL into the query to extract data from another table
```

---

## Practice Block 3 — Live App API Capture (2 hours)

Choose any free Android app from the Play Store (something you own an account
for, e.g., your own bank app in a test account, or a food delivery app with
a test account created for this purpose):

```
[ ] Configure Burp proxy + Frida pinning bypass
[ ] Use the app for 30 minutes — exercise every feature
[ ] In Burp: Site Map → count unique endpoints
[ ] Identify the auth token format
[ ] Replay one request without the auth token — does it require auth?
[ ] Find at least one response field that is not shown in the app UI
[ ] Check if there is any API versioning in the URL path
```

⚠️ **Ethics reminder:** test only with accounts you own and control. Do not
test for IDOR or mass assignment against real users. Observe and document only.

---

## Reflection

1. How long did it take to get Frida running and pinning bypassed today vs Day 221?
2. Which Frida script was hardest to write? Why?
3. What did you see in the API traffic that surprised you?
4. What would you test first if this were a bug bounty target?

---

## Navigation

← Previous: [Day 223 — Mobile Practice Day 1](DAY-0223-Mobile-Practice-Day-1.md)
→ Next: [Day 225 — Mobile Practice Day 3](DAY-0225-Mobile-Practice-Day-3.md)
