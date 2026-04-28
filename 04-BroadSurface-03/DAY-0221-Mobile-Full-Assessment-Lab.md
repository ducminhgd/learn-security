---
title: "Mobile Full Assessment Lab — Complete Android Assessment from APK to Report"
tags: [android, lab, full-assessment, static-analysis, dynamic-analysis, frida,
       certificate-pinning, IDOR, API-testing, report-writing, MASVS]
module: 04-BroadSurface-03
day: 221
related_topics:
  - Android Static Analysis (Day 212)
  - Android Dynamic Analysis with Frida (Day 214)
  - Certificate Pinning Bypass (Day 215)
  - Mobile Bug Bounty Methodology (Day 220)
---

# Day 221 — Mobile Full Assessment Lab

> "This is not a guided walkthrough. I will not hold your hand through this.
> You have everything you need from the past ten days. APK is ready. Device
> is ready. Timer starts now. Document everything. Report every finding.
> If you get stuck, go back to first principles — not to a hint list."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Completed a full, end-to-end Android security assessment without step-by-step
   guidance.
2. Produced a finding list with at least 4 confirmed vulnerabilities across
   different categories.
3. Documented every finding in professional report format with a reproducible
   PoC.
4. Bypassed certificate pinning and intercepted at least 10 API requests.
5. Identified and tested at least one finding that chains two vulnerabilities
   for higher impact.

**Estimated time:** 6–8 hours for a student at the Week 3 mobile level.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Complete Days 211–220 | All mobile lessons |
| Rooted Android emulator or device | Day 214 setup |
| Burp Suite configured | Days 22–24 |
| Frida installed | Day 214 |
| jadx and apktool installed | Day 212 |

---

## Lab Setup

### Target: DIVA (Damn Insecure and Vulnerable App) + Custom Backend

**Option A — DIVA for static + dynamic (no network)**

```bash
# DIVA APK download
wget https://github.com/payatu/diva-android/raw/master/DivaApplication.apk \
     -O diva.apk
adb install diva.apk
```

**Option B — InsecureBankv2 with backend (network API testing enabled)**

```bash
# APK
wget https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/\
InsecureBankv2.apk -O insecurebank.apk

# Backend server (Python)
git clone https://github.com/dineshshetty/Android-InsecureBankv2.git
cd Android-InsecureBankv2/AndroLabServer
pip install -r requirements.txt
python3 app.py  # starts on port 8888

# Configure the app to point to your local server IP:port 8888
adb install insecurebank.apk
```

**Option C — Custom Ghost Lab (if lab infrastructure is available)**

```bash
docker run -d \
    -p 8080:8080 \
    -p 9090:9090 \
    --name mobile-lab \
    ghost/mobile-lab-full:latest

# Download APK
wget http://localhost:9090/target.apk -O target.apk
adb install target.apk
```

---

## Assessment Structure

Work through this independently. Document findings as you go. Do not
skip to later phases if earlier phases are incomplete.

---

## Phase 1 — Static Analysis (Aim: 90 min)

### 1.1 — APK Reconnaissance

Gather basic information before opening a decompiler:

```
[ ] Unzip listing — file inventory
[ ] Signing certificate — debug or production?
[ ] Package name
[ ] Min SDK version (from apktool.yml after decoding)
```

### 1.2 — AndroidManifest.xml Audit

Read the full manifest. Document:

```
[ ] All exported components (Activities, Services, Receivers, Providers)
[ ] Any exported component without android:permission guard
[ ] Custom URI schemes (deep links)
[ ] android:debuggable flag
[ ] android:allowBackup flag
[ ] Network Security Config reference (and read the file)
[ ] Dangerous permissions requested
```

Create a table:

| Component | Type | Exported | Permission Guard | Intent Filters |
|---|---|---|---|---|
| MainActivity | Activity | true | none | LAUNCHER |
| … | … | … | … | … |

### 1.3 — jadx Decompile and Code Review

```
[ ] Run jadx: jadx target.apk -d jadx_output/
[ ] Find and read the main network client class
[ ] Find and read the auth/login class
[ ] Find and read any crypto helper class
[ ] Check BuildConfig for API keys, flags
[ ] Check res/values/strings.xml for secrets
[ ] Run grep patterns for secrets (see Day 212)
[ ] List all Retrofit @GET/@POST endpoints (or equivalent)
[ ] Check for WebView usage + addJavascriptInterface
[ ] Check for SharedPreferences writes with sensitive keys
```

---

## Phase 2 — Dynamic Setup (Aim: 30 min)

```
[ ] Start Frida server on device
[ ] Launch app with Frida pinning bypass
[ ] Install Burp CA on device
[ ] Configure proxy on device pointing to Burp
[ ] Verify Burp intercepts at least one HTTPS request from the app
[ ] Start adb logcat capture to file
```

---

## Phase 3 — API Traffic Analysis (Aim: 2 hours)

Use every feature of the app:

```
[ ] Registration / account creation
[ ] Login
[ ] Profile view and update
[ ] Core business function (transfer money, view statements, etc.)
[ ] Password change
[ ] Logout
[ ] Any admin or settings screens
```

For each major API call captured in Burp:

```
[ ] Note: method, path, version, auth header, request body
[ ] Replay without auth header — does it return 401?
[ ] Try changing user ID to another numeric ID (IDOR test)
[ ] Try adding extra fields to POST body (mass assignment test)
[ ] Inspect full response — any fields not shown in UI?
```

Test API version abuse:

```
[ ] Note current API version (e.g. /api/v2/)
[ ] Test /api/v1/ for all endpoints — does the server respond?
[ ] If v1 responds: compare response to v2 — extra fields? Missing auth?
[ ] Test /api/v2/admin/, /api/v2/internal/ paths
```

---

## Phase 4 — Storage Inspection (Aim: 30 min)

```bash
# SharedPreferences
adb shell su -c "ls /data/data/$(adb shell pm list packages | grep target | \
    sed 's/package://g' | tr -d '\r')/shared_prefs/"
adb shell su -c "cat /data/data/<package>/shared_prefs/*.xml"

# SQLite
adb shell su -c "ls /data/data/<package>/databases/"
adb shell su -c "cp /data/data/<package>/databases/*.db /sdcard/"
adb pull /sdcard/*.db .
sqlite3 *.db ".tables"
sqlite3 *.db "SELECT * FROM $(sqlite3 *.db .tables | head -1);"

# External storage
adb shell ls /sdcard/ | grep -i $(echo <package> | cut -d. -f3)

# Logcat for token leakage
grep -i "(token|password|auth|session|secret)" adb_logcat.txt | head -20
```

---

## Phase 5 — Exported Component Testing (Aim: 30 min)

For each exported component without a permission guard (from Phase 1):

```bash
# Activity bypass
adb shell am start -n <package>/<full.activity.name>
# Does it open without authentication?

# Activity with extras
adb shell am start -n <package>/<activity> --es "url" "file:///etc/passwd"
adb shell am start -n <package>/<activity> --es "user_id" "1" \
    --es "role" "admin"

# Deep link invocation
adb shell am start \
    -a android.intent.action.VIEW \
    -d "<scheme>://<host>/<path>?param=<injection>"

# Content Provider SQL injection
adb shell content query \
    --uri "content://<authority>/<table>" \
    --where "1=1"
```

---

## Phase 6 — Findings Documentation

For each finding, write a complete report entry:

### Finding Report Template

```
## Finding [N] — [Title]

**Severity:** [Critical / High / Medium / Low]
**MASVS:** [e.g., MASVS-STORAGE-1]
**CWE:** [e.g., CWE-312]

**Description:**
[2–3 sentences: what the vulnerability is and why it exists]

**Steps to Reproduce:**
1. [Exact, numbered steps. Include commands, screenshots, Burp requests.]

**Evidence:**
- [Screenshot / code snippet / API response]

**Impact:**
[What an attacker can do. Be specific: "attacker can read the auth_token of
any other user by changing the user_id parameter from 100 to 101."]

**Remediation:**
[Exact fix. Code change or configuration.]
```

---

## Minimum Finding Targets

You must document at least one finding from each category:

| Category | Target Finding |
|---|---|
| **Static** | Hardcoded secret (API key, credential, or internal endpoint) |
| **Auth / API** | IDOR or missing auth on an API endpoint |
| **Storage** | Sensitive data in SharedPreferences or SQLite |
| **Component** | Exported component accessible without authentication |
| **Bonus** | Chain two findings for higher impact (e.g., deep link → IDOR) |

---

## Debrief: After the Lab

Answer these questions before moving on:

1. Which finding was hardest to find? Which tool or technique found it?
2. Which finding has the highest real-world impact? Could it cause data
   exposure to a user who is not the attacker?
3. If this were a real programme, which finding would you submit first?
   What severity would you assign it?
4. What did you miss? What would you do differently in the next 30 minutes
   if you had them?
5. What would the fix look like for each finding in a production codebase?

---

## Self-Assessment Rubric

| Criterion | Not yet | Developing | Achieved |
|---|---|---|---|
| Certificate pinning bypassed | Could not intercept | Bypassed with hints | Bypassed independently |
| ≥4 findings documented | 0–2 findings | 3 findings | ≥4 findings |
| Reports are reproducible | Steps are vague | Steps work sometimes | Steps work first try |
| Impact is clearly stated | "This is a bug" | "Data exposed" | "Alice can read Bob's token" |
| Remediation is specific | "Improve security" | "Add validation" | Exact code change |
| Chained finding present | No chain | Chain identified | Chain documented + PoC |

If you are "Achieved" across all rows: you are mobile-assessment ready.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q221.1, Q221.2 …).
> Follow-up questions use hierarchical numbering (Q221.1.1, Q221.1.2 …).

---

## Navigation

← Previous: [Day 220 — Mobile Bug Bounty Methodology](DAY-0220-Mobile-Bug-Bounty-Methodology.md)
→ Next: [Day 222 — Mobile Detection and Hardening](DAY-0222-Mobile-Detection-and-Hardening.md)
