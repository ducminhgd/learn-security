---
title: "Android Static Analysis — jadx, apktool, Manifest Inspection, Secret Hunting"
tags: [android, static-analysis, jadx, apktool, reverse-engineering, hardcoded-secrets,
       AndroidManifest, APK, MASVS-CODE, MITRE-T1418]
module: 04-BroadSurface-03
day: 212
related_topics:
  - Mobile Security Overview (Day 211)
  - Android Static Analysis Lab (Day 213)
  - Android Dynamic Analysis with Frida (Day 214)
---

# Day 212 — Android Static Analysis

> "The source code is sitting there inside the APK. Developers assume no one
> will look. You will look. And you will find exactly what they put in there —
> API keys, internal endpoints, hardcoded credentials, database paths, admin
> flags — because they never expected anyone to unzip their app and read it."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Set up a complete Android static analysis environment.
2. Decompile an APK with `apktool` (smali bytecode) and `jadx` (Java source).
3. Inspect `AndroidManifest.xml` for dangerous exported components and
   permission over-requests.
4. Hunt for hardcoded secrets using grep patterns and automated tools.
5. Map findings to OWASP MASVS requirements and MITRE ATT&CK T1418.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Mobile Security Overview | Day 211 |
| Linux command line | Days 9–10 |
| Basic Java/Kotlin reading ability | (no lesson — read Java syntax guide if needed) |

---

## Part 1 — Tool Setup

### 1.1 — Required Tools

```bash
# jadx — decompile .dex → Java source
# https://github.com/skylot/jadx
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/tools/jadx
export PATH="$PATH:$HOME/tools/jadx/bin"

# apktool — decode resources + smali bytecode
# https://apktool.org/
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
     -O ~/tools/apktool.jar
echo '#!/bin/bash\njava -jar ~/tools/apktool.jar "$@"' > ~/bin/apktool
chmod +x ~/bin/apktool

# adb — Android Debug Bridge (from Android SDK platform-tools)
sudo apt install android-tools-adb

# grep / ripgrep — secret hunting
sudo apt install ripgrep
```

### 1.2 — Get an APK

Three ways to obtain an APK for analysis:

```bash
# Method 1 — From a connected device (requires USB debugging enabled)
# List installed packages
adb shell pm list packages | grep <app-name>
# Find the APK path
adb shell pm path com.example.app
# Pull it
adb pull /data/app/com.example.app-1/base.apk ./target.apk

# Method 2 — From an emulator (AVD)
# Start AVD, install APK from Play Store, then pull as above

# Method 3 — APKPure / APKMirror (for open-source/free apps; only for legal testing)
# Download directly from site; treat as untrusted binary
```

---

## Part 2 — apktool: Decoding Resources and Smali

`apktool` decodes the binary `AndroidManifest.xml` back to human-readable XML
and decompiles `.dex` files to smali (low-level assembly-like representation).

```bash
# Decode APK
apktool d target.apk -o decoded/

# Output structure
decoded/
├── AndroidManifest.xml     ← decoded, human-readable
├── res/                    ← decoded resources (strings.xml, layouts, drawables)
├── assets/                 ← unchanged raw assets
├── smali/                  ← Dalvik bytecode in smali format
│   └── com/example/app/
│       ├── MainActivity.smali
│       └── ...
└── apktool.yml             ← apktool metadata for repackaging
```

**When to use smali vs jadx:**

| Need | Tool |
|---|---|
| Modify app behaviour, repack and sign | apktool (smali) |
| Read and understand code | jadx (Java) |
| Both, for cross-validation | Both in parallel |

---

## Part 3 — jadx: Decompiling to Java Source

`jadx` converts `.dex` → readable Java (or Kotlin approximation). It handles
obfuscation reasonably well and is the primary tool for code review.

```bash
# CLI decompilation — output to directory
jadx target.apk -d jadx_output/

# GUI — better for exploration (recommended for most workflows)
jadx-gui target.apk

# Export sources from GUI: File → Save as Gradle project
```

### 3.1 — Navigation in jadx-gui

The left panel shows the package tree. Navigate by:

- **Package** → class → method
- **Search** (`Ctrl+F`) — search within current class
- **Text Search** (`Ctrl+Shift+F`) — global string search across all classes
- **Find Usage** (right-click method/class) — find all callers

### 3.2 — Key Classes to Review First

| Class / Pattern | Why it matters |
|---|---|
| `MainActivity` | Entry point; see what runs at startup |
| `*RetrofitClient*`, `*ApiClient*`, `*NetworkHelper*` | API base URL, auth header construction |
| `*Auth*`, `*Login*`, `*Token*` | Auth logic, token storage, secret comparison |
| `*Database*`, `*DBHelper*`, `*Room*` | SQLite schema, query construction |
| `*Crypto*`, `*Encrypt*`, `*Hash*` | Cryptographic implementation — look for ECB, hardcoded IV/key |
| `*Preference*`, `*SharedPref*` | What is stored in SharedPreferences |
| `BuildConfig` | Build-time constants — API keys, debug flags, internal URLs |

---

## Part 4 — AndroidManifest.xml: What to Hunt For

This file is the blueprint of the application's security posture.
Read it in full before anything else.

### 4.1 — Exported Components

```xml
<!-- DANGEROUS: exported with no permission guard -->
<activity android:name=".AdminDashboardActivity"
          android:exported="true" />

<!-- SAFE: exported but protected by a permission -->
<activity android:name=".PaymentActivity"
          android:exported="true"
          android:permission="com.example.PAYMENT_PERMISSION" />

<!-- DANGEROUS: receiver with no permission, listens to external broadcasts -->
<receiver android:name=".TokenReceiver"
          android:exported="true">
    <intent-filter>
        <action android:name="com.example.ACTION_SEND_TOKEN"/>
    </intent-filter>
</receiver>
```

**Bash: find all exported components:**

```bash
grep -n 'exported="true"' decoded/AndroidManifest.xml
```

### 4.2 — Deep Links / Custom URI Schemes

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open"/>
    </intent-filter>
</activity>
```

Custom URI schemes (`myapp://open`) can be invoked from **any browser or app**.
If the activity processes the URI parameters without validation — that is an
open redirect or injection entry point.

### 4.3 — Dangerous Flags and Permissions

| Flag / Permission | Risk |
|---|---|
| `android:debuggable="true"` | Allows `adb shell run-as <package>` without root on any device |
| `android:allowBackup="true"` | App data backed up to `adb backup` or Google Drive — credential leakage |
| `android:networkSecurityConfig` | Points to NSC file; check if cleartext traffic is allowed |
| `WRITE_EXTERNAL_STORAGE` | App writes to shared storage — other apps may read |
| `READ_EXTERNAL_STORAGE` | App can read files from shared storage |
| `INTERNET` + no certificate pinning | Traffic is interceptable |

```bash
# Check for debuggable flag
grep 'debuggable' decoded/AndroidManifest.xml

# Check for allowBackup
grep 'allowBackup' decoded/AndroidManifest.xml
```

### 4.4 — Network Security Config

If `android:networkSecurityConfig` points to a file, read it:

```bash
cat decoded/res/xml/network_security_config.xml
```

```xml
<!-- BAD: allows cleartext to all domains -->
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system"/>
    </trust-anchors>
</base-config>

<!-- Also bad: user CAs trusted (allows Burp CA on non-rooted device) -->
<base-config>
    <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>    ← this is the key line
    </trust-anchors>
</base-config>
```

If `user` CAs are trusted, you can intercept HTTPS without root by installing
Burp's CA as a user certificate. If only `system` CAs are trusted, you need
root to install the CA — or use Frida to bypass pinning.

---

## Part 5 — Secret Hunting

### 5.1 — Grep Patterns for Secrets

```bash
# Set working directory
cd jadx_output/

# API keys, tokens, secrets (generic)
rg -i "(api[_-]?key|secret|token|password|passwd|credential|auth)" \
   --type java -n

# AWS credentials
rg -i "AKIA[0-9A-Z]{16}" --type java -n
rg -i "(aws_access_key|aws_secret)" --type java -n

# Google / Firebase
rg -i "(AIza[0-9A-Za-z\-_]{35}|google_api_key|firebase)" --type java -n

# URLs — internal or staging endpoints
rg -i "https?://[a-z0-9.-]+(internal|staging|dev|admin|api)" \
   --type java -n

# Hardcoded IPs
rg -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
   --type java -n

# JWT-looking strings
rg -i "eyJ[A-Za-z0-9_-]+" --type java -n

# Private keys
rg -i "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY" --type java -n

# String concatenation building URLs (common pattern for hidden endpoints)
rg '"https://' --type java -n
```

### 5.2 — Check `res/values/strings.xml`

This file often contains configuration values that developers mistakenly believe
are safe to commit:

```bash
cat decoded/res/values/strings.xml | grep -i \
    -e "key" -e "token" -e "secret" -e "password" \
    -e "api" -e "endpoint" -e "url" -e "host"
```

### 5.3 — Check `assets/` Directory

Assets are raw files bundled with the app. Common findings:

```bash
ls -la decoded/assets/
# Look for: .json, .pem, .p12, .keystore, .db, .sqlite, config.*, *.key

# SQLite databases in assets (seeded data)
file decoded/assets/*.db 2>/dev/null

# JSON config files
cat decoded/assets/config.json 2>/dev/null
cat decoded/assets/settings.json 2>/dev/null

# Certificates / private keys
find decoded/assets/ -name "*.pem" -o -name "*.p12" -o \
     -name "*.cer" -o -name "*.crt" -o -name "*.key"
```

### 5.4 — Automated: truffleHog and gitleaks

For apps with decompiled source exported as a Gradle project:

```bash
# truffleHog — entropy-based + regex secret detection
pip install trufflehog
trufflehog filesystem ./jadx_output/ --only-verified

# gitleaks — if the decompiled output looks like a git repo
gitleaks detect --source ./jadx_output/ --no-git
```

---

## Part 6 — Mapping Findings to MASVS and ATT&CK

### MASVS Requirements (relevant to static analysis)

| Finding | MASVS Requirement |
|---|---|
| Hardcoded credentials | MASVS-STORAGE-2 |
| Insecure random number generation | MASVS-CRYPTO-1 |
| Exported component without guard | MASVS-PLATFORM-1 |
| Cleartext traffic allowed | MASVS-NETWORK-1 |
| `debuggable=true` in production | MASVS-CODE-2 |
| Private key bundled in APK | MASVS-STORAGE-2, MASVS-CRYPTO-2 |

### MITRE ATT&CK Mobile

| Technique | ID | Finding |
|---|---|---|
| Exploit Application | T1418 | Exported activity / deep link abuse |
| Access Stored Application Data | T1409 | Hardcoded DB paths, exposed assets |
| Encrypted Channel Traffic | T1521 | Cleartext traffic, no pinning |
| Credentials from Password Store | T1634 | Credentials in SharedPreferences |

---

## Worked Example: Reading a Vulnerable Auth Flow

```java
// Found in: com.example.app.auth.LoginActivity

public class LoginActivity extends AppCompatActivity {

    // BUG 1: hardcoded admin password
    private static final String ADMIN_PASSWORD = "Adm!nP@ss2023";

    // BUG 2: BuildConfig holds API key (visible in decompiled code)
    private String apiKey = BuildConfig.API_KEY;

    private void performLogin(String username, String password) {
        // BUG 3: plaintext comparison — timing attack possible
        if (password.equals(ADMIN_PASSWORD)) {
            launchAdminActivity();
            return;
        }
        // BUG 4: URL construction exposes internal endpoint
        String url = "http://10.0.0.5:8080/api/v1/login";
        // BUG 5: no certificate validation (custom TrustManager that accepts all)
        OkHttpClient client = new OkHttpClient.Builder()
            .hostnameVerifier((hostname, session) -> true)  // trusts all hostnames
            .sslSocketFactory(getTrustAllSSLFactory(), new TrustAllCerts())
            .build();
    }
}
```

**From this 20-line snippet:** 5 findings, 2 are Critical (hardcoded admin cred,
trust-all SSL), 3 are High (internal IP, API key exposure, timing attack).

---

## Key Takeaways

1. **jadx gives you Java.** The decompiled code is readable, searchable, and
   directly reviewable. Treat it like a code review — read the auth flows, the
   network client, the crypto helper, and `BuildConfig` first.
2. **AndroidManifest.xml is the attack surface declaration.** Exported components
   without permission guards are trivially exploitable. Read the manifest before
   reading any code.
3. **Secrets are almost always there.** Developers routinely hardcode API keys,
   internal endpoints, and admin credentials believing the APK is opaque. It is not.
4. **Network Security Config is the certificate pinning status indicator.** If
   `user` CAs are trusted, you can intercept without root. If only `system` CAs
   are trusted, you need Frida or root.
5. **Static analysis is the prerequisite to dynamic analysis.** You cannot
   intercept meaningful traffic if you do not know what API endpoints exist. Find
   them statically, then observe them dynamically.

---

## Exercises

1. Download an open-source APK from F-Droid (e.g. `Signal`, `Bitwarden`, or
   `AntennaPod`). Run `apktool d` on it. List every exported activity and receiver
   in the manifest. Document what permission guards (if any) each exported
   component uses.

2. Decompile the same APK with `jadx`. Search for the string `"password"` and
   `"secret"`. Investigate each hit — is it a hardcoded value or a variable name?
   Produce a one-paragraph assessment.

3. Write a `grep` pipeline that searches a jadx output directory for any string
   that matches `http://` (cleartext), capturing the file path and line number.
   Test it against a decompiled APK.

4. Read the decompiled code of a `LoginActivity`. Draw a flow diagram of the
   authentication process. Identify at least one testable assumption (e.g.,
   "the server-side check is based on a client-provided role parameter").

---

## Questions

> Add your questions here. Each question gets a Global ID (Q212.1, Q212.2 …).
> Follow-up questions use hierarchical numbering (Q212.1.1, Q212.1.2 …).

---

## Navigation

← Previous: [Day 211 — Mobile Security Overview](DAY-0211-Mobile-Security-Overview.md)
→ Next: [Day 213 — Android Static Analysis Lab](DAY-0213-Android-Static-Analysis-Lab.md)
