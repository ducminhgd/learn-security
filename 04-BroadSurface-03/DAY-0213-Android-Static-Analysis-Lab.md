---
title: "Android Static Analysis Lab — Reverse APK, Find API Keys and Vulnerable Endpoints"
tags: [android, static-analysis, lab, jadx, apktool, API-keys, secret-hunting,
       exported-components, MASVS, CTF]
module: 04-BroadSurface-03
day: 213
related_topics:
  - Android Static Analysis (Day 212)
  - Android Dynamic Analysis with Frida (Day 214)
  - Certificate Pinning Bypass (Day 215)
---

# Day 213 — Android Static Analysis Lab

> "Theory without a target is trivia. Today you decompile, you read, you find.
> No walkthroughs until you have tried. The decompiler will give you everything —
> but only if you know what you are looking for."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Fully decompiled a purpose-built vulnerable APK using both `apktool` and `jadx`.
2. Audited `AndroidManifest.xml` and found at least two exploitable misconfigurations.
3. Discovered at least one hardcoded API key and one internal API endpoint.
4. Triggered an exported activity via `adb` to confirm exploitability.
5. Written a structured finding report for each discovered vulnerability.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Android Static Analysis theory | Day 212 |
| Linux command line + grep/ripgrep | Days 9–10 |
| ADB installed and working | Day 212 setup |
| Java installed (for jadx/apktool) | System dependency |

---

## Lab Setup

### Target Application: InsecureBank (Customised)

We use a purpose-built vulnerable Android application. Use either:

**Option A — InsecureBankv2 (well-known DAST/SAST training app)**

```bash
# Download InsecureBankv2 APK
wget https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk \
     -O target.apk

# Or from local mirror if internet-restricted:
# cp /lab/mobile/InsecureBankv2.apk ./target.apk
```

**Option B — Custom lab APK (Docker)**

```bash
# If your lab environment provides a custom APK
docker run -d -p 8888:8888 --name mobile-lab ghost/mobile-lab:latest
# Fetch APK
curl http://localhost:8888/download/target.apk -o target.apk
```

**Verify the file:**

```bash
file target.apk
# Expected: Zip archive data (APKs are ZIP files)
sha256sum target.apk
```

---

## Lab Task 1 — Initial Reconnaissance

Before touching a decompiler, gather surface-level information.

```bash
# 1. Inspect APK as a ZIP archive — see what files exist
unzip -l target.apk | head -60

# 2. Extract and read the binary manifest (raw bytes)
unzip -p target.apk AndroidManifest.xml | strings | head -40
# This is mostly unreadable — confirms you need apktool

# 3. Check the signing certificate
keytool -printcert -jarfile target.apk
# Note: who signed it? Debug certificate or release certificate?
```

**Document:**
- App package name
- Minimum and target SDK version (from unzip listing of `classes.dex` timestamp or later from manifest)
- Whether signed with a debug key

---

## Lab Task 2 — apktool Decoding

```bash
# Decode the APK
apktool d target.apk -o decoded/

# Verify output
ls decoded/
```

### Task 2a — Read the Manifest

```bash
cat decoded/AndroidManifest.xml
```

Answer the following by reading the manifest:

1. What is the package name?
2. List all `<activity>`, `<service>`, `<receiver>`, and `<provider>` elements.
3. For each: is `android:exported` set to `true`? Is there a `permission` attribute?
4. Are there any custom URI scheme intent filters (deep links)?
5. Is `android:debuggable="true"` present?
6. Is `android:allowBackup="true"` present?
7. Is there a `android:networkSecurityConfig` reference?

**Expected findings in InsecureBankv2:**
- Several exported activities without permission guards
- `android:allowBackup="true"`
- No network security config (falls back to platform default)

### Task 2b — Read String Resources

```bash
cat decoded/res/values/strings.xml
```

Note any interesting values: server addresses, credentials, API endpoints.

### Task 2c — Read Network Config (if present)

```bash
ls decoded/res/xml/ 2>/dev/null
cat decoded/res/xml/network_security_config.xml 2>/dev/null
```

---

## Lab Task 3 — jadx Decompilation and Code Review

```bash
# Decompile to Java source
jadx target.apk -d jadx_output/

# If jadx-gui is available:
jadx-gui target.apk
```

### Task 3a — Hardcoded Secrets

Run the following grep commands against `jadx_output/`:

```bash
cd jadx_output/

# Generic secret patterns
rg -i "(password|passwd|secret|api_key|apikey|token|credential)" \
   --type java -n | grep -v "//.*password" | head -30

# URL patterns — find all hardcoded URLs
rg '"https?://' --type java -n | head -30

# Internal IP addresses
rg -E '"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
   --type java -n | head -20

# Hardcoded username/password in strings
rg -i '"(admin|root|test|user|password|123|letmein)"' \
   --type java -n | head -20
```

**Document each finding:**

| Finding | File | Line | Value | Severity |
|---|---|---|---|---|
| Hardcoded server IP | `LoginActivity.java` | 42 | `"http://192.168.1.10:8888"` | High |
| Default credentials | `LoginActivity.java` | 67 | `"dinesh" / "Dinesh@123!"` | Critical |

### Task 3b — Auth Flow Review

Find the `LoginActivity` class (or equivalent login logic):

```bash
find jadx_output/ -name "LoginActivity*" -o -name "Login*.java" | head -5
cat jadx_output/sources/com/example/LoginActivity.java
```

Map the login flow:
1. Where is the username/password sent?
2. What HTTP method is used?
3. Is the request sent over HTTP or HTTPS?
4. What does the server return that constitutes "logged in"?
5. Is the session token stored locally? Where?

### Task 3c — Network Client Inspection

Find the Retrofit, OkHttp, or Volley client:

```bash
rg -l "(OkHttpClient|Retrofit|Volley|HttpURLConnection)" \
   --type java jadx_output/
```

Open each file. Check:
- Is there a custom `TrustManager` that accepts all certificates? (`checkServerTrusted` returns void / does nothing)
- Is hostname verification disabled? (`hostnameVerifier((hostname, session) -> true)`)
- Is the `HttpsURLConnection.setDefaultHostnameVerifier` being overridden?

Any of these means traffic is interceptable even without certificate pinning bypass.

---

## Lab Task 4 — Exploit an Exported Activity

InsecureBankv2 has exported activities accessible without authentication.

### Task 4a — Connect a Device/Emulator

```bash
# Start Android emulator (AVD) or connect physical device
adb devices
# Expected: one device listed

# Install the APK
adb install target.apk
```

### Task 4b — Enumerate Exported Activities

Using what you found in Task 2a, list the exported activities.
In InsecureBankv2, one exported activity should be a `ChangePassword` screen.

```bash
# Attempt to launch each exported activity directly (bypass login)
adb shell am start \
    -n com.android.insecurebankv2/.ChangePasswordActivity

# If it opens without requiring login: you found an authentication bypass
```

### Task 4c — Deep Link Invocation

If the app has custom URI schemes, invoke them:

```bash
adb shell am start \
    -a android.intent.action.VIEW \
    -d "scheme://host/path?param=value"
```

Observe: does the activity open? Does it process the parameter? Can you inject
anything into the `param` field?

---

## Lab Task 5 — Writing the Findings

For each vulnerability found, write a structured finding report:

---

### Finding Template

```
Title: [Short title, e.g. "Exported ChangePassword Activity — Auth Bypass"]

Severity: Critical / High / Medium / Low / Informational

MASVS: [e.g. MASVS-PLATFORM-1]
CWE: [e.g. CWE-926: Improper Export of Android Application Components]
ATT&CK: [e.g. T1418 — Exploit Application]

Description:
[One paragraph. What is the vulnerability? Why does it matter?]

Steps to Reproduce:
1. Decompile APK with jadx.
2. Inspect AndroidManifest.xml — identify exported activity.
3. Run: adb shell am start -n <package>/<activity>
4. Observe: activity opens without authentication.

Impact:
[What can an attacker do? Access sensitive data? Change another user's password?]

Evidence:
- Screenshot or adb output
- Relevant code snippet from jadx (file + line number)

Remediation:
[Specific code change. E.g.: Add android:exported="false" to the activity,
or add android:permission="com.example.INTERNAL" and enforce auth in onCreate().]
```

---

## Expected Findings Checklist

By the end of this lab you should have documented:

- [ ] At least 1 exported activity accessible without authentication
- [ ] At least 1 hardcoded credential (username or password in source)
- [ ] At least 1 hardcoded API endpoint (IP address or internal URL)
- [ ] `allowBackup="true"` (low severity, worth noting)
- [ ] At least 1 insecure HTTP endpoint (cleartext traffic)
- [ ] Bonus: custom TrustManager accepting all certificates

If you found all of these: you are doing static analysis correctly.

---

## Debrief Points

1. **InsecureBankv2 is used in real training programmes.** The vulnerability
   classes (exported activities, hardcoded creds, cleartext HTTP) appear
   verbatim in real bug bounty findings. OWASP M8 (Security Misconfiguration)
   and M9 (Insecure Data Storage) are consistently in the top 5 mobile findings
   on HackerOne.

2. **Hardcoded credentials are a Critical finding.** Not High. Not Medium.
   Critical. A threat actor who decompiles the APK can extract credentials that
   work against the production backend — no network access needed, no phishing,
   no social engineering.

3. **Exported components are the mobile equivalent of missing auth on an API
   endpoint.** The developer forgot to add `exported="false"`. The attacker
   does not need to exploit anything — they just call the component.

4. **adb is your PoC tool.** Every finding involving an exported component needs
   an `adb shell am start` command as the reproduction step. If you can
   reproduce it with `adb`, the finding is valid and demonstrable.

5. **Static analysis findings are complete findings.** You do not need to
   intercept traffic to report a hardcoded API key. The code is the evidence.
   A screenshot of jadx with the key highlighted + the file path and line
   number is a complete PoC.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q213.1, Q213.2 …).
> Follow-up questions use hierarchical numbering (Q213.1.1, Q213.1.2 …).

---

## Navigation

← Previous: [Day 212 — Android Static Analysis](DAY-0212-Android-Static-Analysis.md)
→ Next: [Day 214 — Android Dynamic Analysis with Frida](DAY-0214-Android-Dynamic-Analysis-Frida.md)
