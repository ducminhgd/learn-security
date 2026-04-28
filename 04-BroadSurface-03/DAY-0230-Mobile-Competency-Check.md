---
title: "Mobile Security Competency Check — Self-Assessment and Lab Submission"
tags: [mobile, competency-check, self-assessment, MASVS, Android, iOS,
       gate, bug-bounty, lab-submission, certificate-pinning, Frida]
module: 04-BroadSurface-03
day: 230
related_topics:
  - Mobile Security Overview (Day 211)
  - Mobile Full Assessment Lab (Day 221)
  - Mobile Bug Bounty Methodology (Day 220)
  - Network Exploitation and PrivEsc (Day 231)
---

# Day 230 — Mobile Security Competency Check

> "Today you prove it. Not to me — to yourself. A correct answer in a lesson
> is easy. Doing it cold, on an unknown target, under a clock — that is the
> real test. If you pass this, you are mobile-ready. If you don't, you know
> exactly what to fix before moving on."
>
> — Ghost

---

## Structure

| Section | Format | Time |
|---|---|---|
| Part 1: Conceptual Questions | Written, no notes | 30 min |
| Part 2: Static Analysis Sprint | Hands-on, provided APK | 45 min |
| Part 3: Dynamic Analysis Sprint | Hands-on, device + Burp | 30 min |
| Part 4: Finding Report | Written submission | 30 min |
| **Total** | | **~2.5 hours** |

---

## Part 1 — Conceptual Questions

Answer all 10. No notes. No browser. Write your answers in the Questions
section at the bottom of this file.

**Q1.** An Android app has the following in its manifest:

```xml
<activity android:name=".AdminPanelActivity"
          android:exported="true" />
```

(a) What is the security impact?
(b) Write the `adb shell am start` command to exploit it.
(c) What is the fix?

**Q2.** You decompile an APK and find this code:

```java
webView.addJavascriptInterface(new NativeApi(this), "App");
webView.loadUrl(getIntent().getStringExtra("url"));
```

What are the two security issues? Describe the attack for each.

**Q3.** Explain the difference between `kSecAttrAccessibleAlways` and
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` in iOS Keychain. Why does
this matter for a bug bounty finding?

**Q4.** You run `objection -g com.target.app explore` and type
`android sslpinning disable`. The app still shows SSL errors in your proxy.
Name 3 reasons this might happen and what you would try next.

**Q5.** A mobile app sends all API calls to `https://api.example.com/v3/`.
You manually test `https://api.example.com/v1/users/me` with the same token
and get a full user object with 20 extra fields not shown in the app.
(a) What is the vulnerability class?
(b) What is the OWASP API Top 10 category?
(c) What is the CVSS severity range you would assign?

**Q6.** You find this in decompiled Android code:

```java
editor.putString("payment_token", tok_xyz123);
editor.putString("cvv", "456");
editor.apply();
```

(a) What MASVS requirement does this violate?
(b) What is the CWE number?
(c) What is the correct implementation?

**Q7.** Explain how an APK backup attack works. What condition must be true
in the AndroidManifest.xml? What adb command triggers the backup? What data
can an attacker recover?

**Q8.** You find a Retrofit interface in decompiled code:

```java
@GET("/api/v2/admin/users")
Call<List<User>> getAllUsers(@Header("Authorization") String token);
```

The endpoint is not accessible in normal app flow. What steps do you take
to test whether a regular user's token can call this endpoint?

**Q9.** An app implements root detection using 5 Java checks. You bypass all
5 with Frida. But the app still refuses to launch and shows "Device compromised."
What might be happening? Name 2 possible explanations.

**Q10.** Certificate pinning bypass with objection works. You can see HTTPS
traffic in Burp. You intercept a login request:

```
POST /api/v3/auth/login
Authorization: (none)
Content-Type: application/json

{"email": "test@example.com", "password": "test123"}
```

Response:

```json
{"token": "eyJhbGciOiJSUzI1NiJ9...", "user_id": 12345,
 "role": "user", "is_admin": false, "internal_score": 9.2}
```

Identify and describe every potential finding in this exchange.

---

## Part 2 — Static Analysis Sprint (45 min)

Download the challenge APK (provided by your lab environment or instructor):

```bash
# Lab-provided APK:
wget http://localhost:9090/competency/mobile-check.apk -O check.apk
# OR from course materials:
# cp /lab/mobile/competency_check.apk ./check.apk
```

Complete the following within 45 minutes:

```
[ ] 1. Unzip and inventory the APK structure
[ ] 2. Decode with apktool; read the full AndroidManifest.xml
[ ] 3. Decompile with jadx
[ ] 4. Find and document:
       - All exported components with no permission guard
       - All hardcoded strings that could be secrets
       - The base URL and all API endpoints
       - Any WebView usage with addJavascriptInterface
       - What and where tokens are stored
[ ] 5. Produce a numbered finding list with file + line number for each
```

**Submission:** paste your finding list into the Questions section.

---

## Part 3 — Dynamic Analysis Sprint (30 min)

Using the same APK or a provided backend:

```
[ ] 1. Start Frida server
[ ] 2. Bypass certificate pinning (any method — document which one you used)
[ ] 3. Configure Burp proxy and confirm HTTPS interception
[ ] 4. Perform login and capture the auth request + response
[ ] 5. Test one IDOR: change the user_id parameter to a different value
[ ] 6. Pull SharedPreferences and paste the XML content
```

Time yourself: how long did Part 3 take?

---

## Part 4 — Finding Report (30 min)

Write one complete report for your highest-severity finding from Parts 2–3.
Use the standard format (title, severity, CVSS, MASVS, description, steps
to reproduce, evidence, impact, remediation).

Paste the report into the Questions section.

---

## Competency Gate Criteria

You have passed this gate when:

| Criterion | Minimum bar |
|---|---|
| Conceptual questions | ≥ 8/10 correct without notes |
| Static analysis | ≥ 4 findings with file+line in 45 min |
| Dynamic analysis | Pinning bypassed + traffic intercepted in ≤ 15 min |
| Report quality | Reproducible by a stranger without asking you anything |

If you do not pass: identify which criterion you failed. Return to the
specific lesson(s) and re-do the relevant practice day before re-taking
the check.

---

## What Comes Next

Module 04-BroadSurface-03 is complete. You now have a working mobile
security toolkit:

- Static analysis (jadx, apktool, grep patterns)
- Dynamic analysis (Frida, objection, Burp)
- Certificate pinning bypass (3 methods)
- Android-specific attacks (WebView, Intents, storage)
- iOS fundamentals (Keychain, ATS, jailbreak detection bypass)
- Mobile API exploitation (IDOR, version abuse, mass assignment)
- Bug bounty methodology and report writing

The next module expands to **network exploitation and privilege escalation**:
ARP spoofing, SMB relay, Linux privesc, Windows privesc, and C2 concepts.

---

## Questions and Competency Check Answers

> Part 1 — Write your answers below. Label Q1 through Q10.

> Part 2 — Paste your static analysis finding list.

> Part 3 — Document your dynamic analysis result.

> Part 4 — Paste your complete bug report.

> General questions use numbering Q230.1, Q230.2 …

---

## Navigation

← Previous: [Day 229 — Mobile Practice Day 7](DAY-0229-Mobile-Practice-Day-7.md)
→ Next: [Day 231 — MITM and ARP Spoofing Lab](../04-BroadSurface-04/DAY-0231-MITM-ARP-Spoofing-Lab.md)
