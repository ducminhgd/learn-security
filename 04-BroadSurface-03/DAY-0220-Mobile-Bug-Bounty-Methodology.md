---
title: "Mobile Bug Bounty Methodology — Programmes, Scope Analysis, Workflow, Payout Patterns"
tags: [bug-bounty, mobile, methodology, HackerOne, Bugcrowd, scope-analysis, triage,
       MASVS, report-writing, payout, Android, iOS]
module: 04-BroadSurface-03
day: 220
related_topics:
  - Mobile Security Overview (Day 211)
  - Mobile API Attack Surface (Day 219)
  - Bug Bounty Reporting (Days 161–165)
  - Bug Bounty Platforms Overview (Day 261)
---

# Day 220 — Mobile Bug Bounty Methodology

> "Most researchers look at the mobile scope and see 'certificate pinning' and
> move on. That is your edge. Learn to bypass it in ten minutes, spend the next
> four hours finding what the app does with the intercepted traffic, and you will
> find bugs that have been sitting unreported for two years. The payout for a
> mobile Critical is rarely less than $5,000. Some are $50,000. For bugs that
> require no working CVE exploit — just a decompiler and an afternoon."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Identify which bug bounty programmes have meaningful mobile scope and
   are worth your time.
2. Read and interpret a mobile programme scope table to determine what is
   in scope, what is explicitly excluded, and where the highest-value targets are.
3. Execute a structured, reproducible mobile assessment methodology from
   scope review to report submission.
4. Write a professional mobile bug report with a reproducible PoC.
5. Understand payout patterns for mobile bugs by severity and category.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All Android module lessons | Days 211–219 |
| Bug Bounty Report Writing | Days 161–165 |
| Bug Bounty Platforms | Day 261 (preview) |

---

## Part 1 — Which Programmes Are Worth Your Time

Not all programmes with mobile scope are equal. Prioritise:

### 1.1 — Programme Tier Selection

| Tier | Characteristics | Examples |
|---|---|---|
| **Tier 1 — High Signal** | Large company, mobile is primary product, generous payouts, fast triage | Banking apps, fintech, healthcare |
| **Tier 2 — Solid** | Mid-size company, mobile is important, reasonable payouts | SaaS with mobile client, ride-hailing |
| **Tier 3 — Low Signal** | Mobile is secondary, low payouts, slow triage, many dupes | E-commerce apps, media apps |

**Look for:**

- Mobile listed explicitly in scope (not just `*.example.com`)
- Android AND iOS both in scope (doubles the attack surface)
- Public disclosure allowed (you can publish write-ups)
- Payout table showing Critical > $1,000

**Avoid initially:**

- Programmes where mobile is `*.example.com` domain only (they mean web, not app)
- No mobile payout table
- Community feedback of slow response or non-actionable triages

### 1.2 — Finding Mobile Programmes

```
HackerOne:
  → Programmes → Filter by "Asset Type: Android" or "Asset Type: iOS"
  → Sort by "Number of reports resolved" (active triage team)

Bugcrowd:
  → Programs → Filter by "Mobile"

Intigriti:
  → Programs → Filter → App type: Mobile

Immunefi (Web3):
  → Programs → Filter → Platform: Mobile (DeFi apps with mobile wallets)
```

---

## Part 2 — Reading Mobile Scope Tables

### 2.1 — Example Scope Analysis

```
Programme: ExampleFinancial Bug Bounty

In-Scope Assets:
  - com.examplefinancial.android (Android app, latest version on Play Store)
  - com.examplefinancial.ios (iOS app, latest version on App Store)
  - api.examplefinancial.com (backend API)

Out-of-Scope:
  - Third-party libraries (report to the library maintainer)
  - Denial of service attacks
  - Rate limiting on unauthenticated endpoints
  - SSL configuration issues below CVSS 4.0
  - Version-specific issues on apps older than 2 major versions

Payout Table:
  Critical:   $5,000–$15,000
  High:       $1,500–$5,000
  Medium:     $300–$1,500
  Low:        $100–$300
```

**How to read this as an attacker:**

- `api.examplefinancial.com` is in scope → mobile API attacks are valid
- Third-party libraries out of scope → report hardcoded API key to programme, not to the library
- `SSL configuration issues below CVSS 4.0` out of scope → certificate pinning bypass + MitM
  data exposure (CVSS ≥ 7.0) is still in scope
- Older app versions excluded → get the latest version from Play Store/App Store

### 2.2 — Clarifying Ambiguous Scope

Before spending time on a target, if scope is ambiguous:

- Check the programme's "Hall of Fame" reports to see what was accepted
- Look at "Activity" tab — has the programme responded recently?
- Check if there is a programme FAQ or ask via HackerOne's submission Q&A
- Never test grey-area targets without confirmation

---

## Part 3 — The Mobile Bug Bounty Methodology

### 3.1 — Phase 1: App Acquisition (Day 0, 30 min)

```bash
# Android
adb devices                              # confirm device connected
adb shell pm list packages | grep <app>  # find package name
adb pull <apk-path> target.apk           # pull APK

# iOS
# Download IPA from jailbroken device via frida-ios-dump
# OR: find the App Store download link → use ipatool

# Verify download
file target.apk
unzip -l target.apk | head -20
```

### 3.2 — Phase 2: Static Analysis (Day 0–1, 2–4 hours)

Structured checklist:

```
[ ] Read AndroidManifest.xml / Info.plist
    - Exported components without permission guards
    - Deep link URL schemes
    - Dangerous flags (debuggable, allowBackup, ATS disabled)
    - Network Security Config (certificate pinning or cleartext)

[ ] Secret hunting (grep patterns from Day 212)
    - API keys (AWS, Google, Stripe, Twilio, SendGrid, Firebase)
    - Hardcoded credentials (username, password, admin flags)
    - Internal endpoints (IP addresses, .internal domains)
    - Private keys / certificates in assets/

[ ] Endpoint enumeration
    - Retrofit / OkHttp client base URL
    - All @GET, @POST annotations
    - URL string patterns in code
    - String resources: strings.xml / InfoPlist.strings

[ ] Auth flow review
    - How is the JWT / session token obtained?
    - How is it stored? (SharedPreferences, Keychain, NSUserDefaults?)
    - Is there a refresh token? Where is it stored?
    - Is there client-side role checking? (always bypassable)

[ ] WebView review (Android)
    - addJavascriptInterface present?
    - setJavaScriptEnabled(true)?
    - loadUrl() takes external input?
    - File access settings?

[ ] Crypto review
    - ECB mode AES?
    - Hardcoded IV?
    - Hardcoded key?
    - Weak algorithm (MD5, SHA1 for passwords)?
```

### 3.3 — Phase 3: Dynamic Setup (Day 1, 1–2 hours)

```bash
# 1. Start Frida server on device
adb shell su -c "/data/local/tmp/frida-server &"

# 2. Bypass pinning and start proxy
frida -U -f com.target.app -l ssl_bypass.js --no-pause &
# Configure Burp proxy on device

# 3. Install Burp CA
adb push burp_ca.der /sdcard/
# Device: Settings → Install certificate → burp_ca.der

# 4. Verify interception
# Open app, trigger a login → confirm Burp shows the request

# 5. Set up adb logcat
adb logcat -s com.target.app:V > app_logcat.txt &
```

### 3.4 — Phase 4: Traffic Analysis and API Testing (Days 1–3, 4–8 hours)

```
Systematic workflow in Burp:
1. Use every major app feature:
   - Registration / login / logout
   - Profile update / password change
   - Main business functions (payments, messaging, etc.)
   - Admin features if visible

2. For each request in Burp History:
   - Check if auth is required (replay without token → 401 or 200?)
   - Check for IDOR (change numeric ID to another user's ID)
   - Check for mass assignment (add extra fields to POST body)
   - Note any sensitive data in the response

3. Test API versions:
   - Note current version in path
   - Test v1, v2, v0, /old/, /beta/ variations

4. Check rate limiting:
   - Login: try 50 wrong passwords — lockout?
   - OTP: try sequential codes — lockout?

5. Test exported components (Android):
   adb shell am start -n <package>/<activity> --es param value
```

### 3.5 — Phase 5: Storage and Logging (Day 2, 1 hour)

```bash
# Pull app storage
adb shell su -c "ls /data/data/com.target.app/"
adb shell su -c "cat /data/data/com.target.app/shared_prefs/*.xml"
adb shell su -c "ls /data/data/com.target.app/databases/"

# Pull and read SQLite
adb shell su -c "cp /data/data/com.target.app/databases/*.db /sdcard/"
adb pull /sdcard/*.db .
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# Read logcat for token leakage
grep -i "(auth|token|password|session)" app_logcat.txt
```

### 3.6 — Phase 6: Report (Day 3, 1–2 hours per finding)

For each confirmed finding, write a structured report (see Day 162 format):

```
Title: [Short, precise, punchy — includes the vuln class and impact]
e.g.: "Hardcoded Firebase API Key Allows Unauthorised Database Access"
      "IDOR in /api/v1/users/{id} Exposes All User PII"
      "Deprecated API v1 Endpoint Bypasses Rate Limiting on OTP"

Severity: CVSS 3.1 score + critical/high/medium/low
MASVS: [Requirement if applicable]

Description: [2–3 paragraphs. What, why, and impact.]

Steps to Reproduce:
1. Download APK from [Play Store link]
2. Decompile with jadx: jadx target.apk -d output/
3. Open output/sources/com/example/NetworkClient.java
4. Line 42: Firebase API key found: AIzaSyXXXXXXXXXXXXXXXXXXXXXX
5. Verify: curl "https://[project].firebaseio.com/.json?auth=AIzaSy..."
   → Returns entire database contents.

Impact:
[Specific, quantified. Who is affected, what data, what actions.]

Evidence:
- Screenshot of jadx showing the key at line 42
- curl response showing database contents (redacted PII)
- Screenshot of Firebase console showing data accessible

Remediation:
[Specific fix. Not "improve security". Exactly what to change.]
```

---

## Part 4 — Mobile Payout Patterns

Based on HackerOne and Bugcrowd public data:

| Vulnerability Class | Typical Mobile Payout | Notes |
|---|---|---|
| Hardcoded API key with backend impact | $1,000–$10,000 | Depends on what the key accesses |
| Authentication bypass (exported Activity) | $1,500–$8,000 | High if it bypasses login entirely |
| IDOR in mobile API | $500–$5,000 | Same as web; mobile context not higher |
| Deprecated API version exposes PII | $500–$3,000 | "Data exposure" category |
| JWT forging / auth token bypass | $3,000–$15,000 | Critical if it achieves ATO |
| WebView RCE via JS bridge | $5,000–$30,000 | Device-level impact |
| Certificate pinning bypass alone | $0–$100 | Not a standalone finding; it's a prerequisite |
| Insecure Keychain storage | $500–$2,000 | Requires physical jailbroken device to exploit |
| SQL injection in Content Provider | $1,000–$5,000 | Classic vuln in mobile context |

**Key insight:** certificate pinning bypass is **not** a standalone finding.
It is the prerequisite that lets you find real findings. Do not submit it
alone — it will be triaged as Informational or N/A.

---

## Part 5 — Common Mobile Finding Gotchas

### 5.1 — Root / Jailbreak Required

If exploiting your finding requires a rooted/jailbroken device:

- State it explicitly in your report
- Most programmes accept "rooted device required" findings at one severity
  level lower than they would without that requirement
- Physical access + jailbreak is often a precondition the programme excludes —
  read the policy

### 5.2 — Physical Access Required

If the attacker needs physical access to the device:

- Most programmes consider this out of scope or low severity
- Exception: if the finding allows remote exploitation (e.g., IDOR or API bug)
  discovered through static analysis, no physical access is required for the
  actual attack

### 5.3 — SDK Version Scope

- Many programmes say "latest version in app store only"
- Do not test against an old APK downloaded from a third-party mirror
- If the finding exists in the current version, it is valid

### 5.4 — Third-Party Libraries

If the hardcoded API key is in a vendored third-party library (e.g., Firebase
Analytics hardcoded by Google), report it to the programme anyway — they may
still have misconfigured access controls. But do not blame the library version.

---

## Key Takeaways

1. **Mobile scope is underserved.** Certificate pinning is the velvet rope.
   Researchers who get past it find bugs that have been sitting unreported
   for years. This is your competitive advantage.
2. **Static analysis first, always.** You can write a full report from jadx
   output alone: hardcoded key + curl PoC. No proxy, no device required.
3. **The API is the real target.** The app is just a client. All your web
   API skills (IDOR, mass assignment, version abuse) apply directly to
   the mobile backend.
4. **Certificate pinning bypass is a prerequisite, not a finding.** Submit it
   as a standalone only if the programme explicitly pays for it. Otherwise,
   use it to find the real bugs.
5. **Mobile Criticals pay more than web Criticals on many programmes.**
   Fewer researchers submit them, so programmes value the reports higher.
   A mobile RCE via WebView bridge can exceed a web SQLi payout by 3–5x.

---

## Exercises

1. Find three bug bounty programmes on HackerOne that list Android apps
   explicitly in scope. For each: note the payout range, the asset type, and
   whether the API backend is also in scope. Rank them by estimated value.

2. For one of those programmes: download the app and spend 30 minutes on
   static analysis. List the five most interesting things you found in that
   time.

3. Write a mock report for the "Hardcoded API Key" finding you might find in
   exercise 2 (use a fictional key if needed). Follow the report structure
   from Part 3.6. Rate your own report: is it complete enough to be accepted?

4. Research: what does "Safe Harbour" mean in a bug bounty programme policy?
   Find a programme that explicitly states safe harbour protections and
   a programme that does not. What is the practical difference for a researcher?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q220.1, Q220.2 …).
> Follow-up questions use hierarchical numbering (Q220.1.1, Q220.1.2 …).

---

## Navigation

← Previous: [Day 219 — Mobile API Attack Surface](DAY-0219-Mobile-API-Attack-Surface.md)
→ Next: [Day 221 — Mobile Full Assessment Lab](DAY-0221-Mobile-Full-Assessment-Lab.md)
