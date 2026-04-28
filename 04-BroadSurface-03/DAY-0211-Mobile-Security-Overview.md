---
title: "Mobile Security Overview — Android vs iOS Architecture and Attack Surface"
tags: [mobile-security, android, ios, owasp-mobile, attack-surface, APK, IPA,
       sandboxing, inter-process-communication, MITRE-T1409, MITRE-T1426]
module: 04-BroadSurface-03
day: 211
related_topics:
  - Web Architecture (Day 17)
  - API Security (Days 146–159)
  - Certificate Pinning Bypass (Day 215)
  - Mobile Bug Bounty Methodology (Day 220)
---

# Day 211 — Mobile Security Overview

> "Every app on a phone is a small web application — except it is compiled, obfuscated,
> running inside a sandbox, and most developers assume no one will ever look at it.
> That assumption is your invitation. Once you understand the platform, you will find
> the same classes of bugs you found on the web — SQLi, SSRF, insecure storage,
> broken auth — just wrapped in a different format."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Describe the core security architecture of Android and iOS, including how each
   platform enforces isolation, storage, and permission models.
2. Compare the attack surface of an Android app to an iOS app — tools, attack
   classes, and research difficulty.
3. Map mobile vulnerabilities to the OWASP Mobile Application Security Verification
   Standard (MASVS) and OWASP Mobile Top 10 2024.
4. Explain the mobile penetration testing lifecycle — from app acquisition to report.
5. Identify which vulnerabilities are highest value for bug bounty hunters operating
   on mobile programmes.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| HTTP and web architecture | Days 17–28 |
| API security fundamentals | Days 146–159 |
| Burp Suite basic usage | Days 22–24 |
| Linux command line | Days 9–10 |

---

## Part 1 — Why Mobile Matters Now

Mobile applications now handle:

- Banking and payment flows
- OAuth tokens, JWTs, and session cookies
- Health and location data regulated by GDPR, HIPAA
- API calls to the same backend services you target on the web — often with weaker auth

**Bug bounty signal:** HackerOne's 2024 data shows mobile bug reports are
consistently underfiled relative to web reports. The attack surface is large;
the competition is lower. Certificate pinning is the single most common reason
researchers skip mobile — and bypassing it takes less than 10 minutes with
the right tools.

---

## Part 2 — Android Architecture

### 2.1 — Linux Foundation

Android is built on a modified Linux kernel. Each application:

- Runs as a **dedicated Linux user** (UID assigned at install time)
- Has its own **process** and **filesystem sandbox** (`/data/data/<package>/`)
- Cannot read another application's private storage without explicit IPC

```
Hardware
  └── Linux Kernel (modified: Binder IPC, ION allocator, wakelocks)
        └── Android Runtime (ART — compiles .dex → native code)
              └── Application Framework (Activity Manager, Package Manager, …)
                    └── Apps (each in its own UID sandbox)
```

### 2.2 — APK Structure

An APK is a ZIP archive. Key files:

```
app.apk/
├── AndroidManifest.xml      ← permissions, components, intent filters
├── classes.dex              ← compiled Java/Kotlin → Dalvik bytecode
├── classes2.dex             ← overflow if >64K methods (multidex)
├── resources.arsc           ← compiled resources (strings, layouts)
├── res/                     ← uncompiled resources, drawable, layout XML
├── lib/                     ← native .so libraries (arm64-v8a, x86_64)
├── assets/                  ← raw files, sometimes config, certs, keys
└── META-INF/                ← signature files (CERT.RSA, CERT.SF, MANIFEST.MF)
```

**Attack surface from structure alone:**

- `AndroidManifest.xml` — exported components, dangerous permissions, custom URI schemes
- `assets/` — hardcoded endpoints, local HTML for WebViews, bundled API keys
- `lib/` — native code with buffer overflows and format string bugs
- `META-INF/` — certificate pinning implementations, signature bypass targets

### 2.3 — Android Permission Model

Permissions are declared in `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

**Normal vs Dangerous permissions:**

| Type | Granted | Example |
|---|---|---|
| Normal | At install, silently | INTERNET, BLUETOOTH |
| Dangerous | Runtime prompt required (Android 6+) | CAMERA, READ_CONTACTS, LOCATION |
| Signature | Only same-signer apps | Internal platform features |
| Special | Separate system settings page | SYSTEM_ALERT_WINDOW, MANAGE_STORAGE |

**Attacker perspective:** over-requested permissions signal what sensitive data
the app accesses. LOCATION + CONTACTS + CAMERA without obvious UI features = data
harvesting. Find the permission, find the code path.

### 2.4 — Inter-Process Communication (IPC)

Android IPC mechanisms are the most common source of access-control bugs:

| Mechanism | What it does | Attack class |
|---|---|---|
| **Activities** | Screen/UI entry points | Exported activity allows access without auth |
| **Services** | Background tasks | Exported service exposes internal API |
| **Broadcast Receivers** | System/app event listeners | Receive sensitive broadcasts from malicious apps |
| **Content Providers** | Shared data (contacts, calendar, files) | SQL injection; path traversal; unauthorised read/write |
| **Intents** | Message passing between components | Intent redirection; deeplink hijacking |

**Critical AndroidManifest.xml flags:**

```xml
<!-- Exported = any app can invoke this component -->
<activity android:name=".AdminActivity" android:exported="true" />

<!-- Protected = only caller with this permission can invoke -->
<activity android:name=".PaymentActivity"
          android:exported="true"
          android:permission="com.example.PAYMENT" />
```

An exported component with no `android:permission` guard is almost always
a finding. Test with `adb shell am start -n <package>/<activity>`.

---

## Part 3 — iOS Architecture

### 3.1 — Darwin Foundation

iOS runs on Darwin (XNU kernel). Security model is stricter than Android by design:

```
Hardware (Secure Enclave)
  └── XNU Kernel (Mach + BSD hybrid)
        └── iOS Runtime
              └── App Sandbox (mandatory for all App Store apps)
                    └── Apps (signed, entitled, sandboxed)
```

**Secure Enclave** — a dedicated security coprocessor. Handles:
- Biometric authentication (Face ID, Touch ID)
- Device encryption keys
- Apple Pay cryptographic operations

Attackers cannot touch the Secure Enclave directly. Data and keys protected
by it are out of scope for software attacks — the target is the application
layer above.

### 3.2 — IPA Structure

An IPA is also a ZIP archive:

```
App.ipa/
└── Payload/
    └── App.app/
        ├── App              ← compiled binary (Mach-O, fat binary ARM64)
        ├── Info.plist       ← app metadata, URL schemes, permissions
        ├── embedded.mobileprovision ← signing and entitlements
        ├── Frameworks/      ← bundled dynamic libraries
        └── _CodeSignature/  ← code signature hashes
```

### 3.3 — iOS Security Controls (and How They Break)

| Control | Purpose | Attack / Bypass |
|---|---|---|
| **App Sandbox** | Process isolation | Jailbreak escapes sandbox entirely |
| **Code Signing** | Only Apple-approved code runs | Jailbroken devices bypass signature enforcement |
| **Data Protection API** | File encryption based on device lock state | Poor class selection leaves files readable when unlocked |
| **Keychain** | Secure credential storage | Accessible items readable from jailbroken device; backup leakage |
| **ATS (App Transport Security)** | HTTPS enforced by default | `NSAllowsArbitraryLoads = true` in Info.plist disables ATS |
| **Entitlements** | Fine-grained capability declarations | Overly broad entitlements leak access to system resources |
| **Jailbreak Detection** | Detect compromised device | Bypassed via Frida hooks, Liberty Lite, custom tweak |

---

## Part 4 — OWASP Mobile Top 10 (2024)

| # | Category | Android Example | iOS Example |
|---|---|---|---|
| M1 | Improper Credential Usage | Hardcoded API key in `BuildConfig` | Hardcoded API key in `Info.plist` |
| M2 | Inadequate Supply Chain Security | Malicious SDK dependency | Trojanised third-party framework |
| M3 | Insecure Authentication / Auth | Auth bypass via exported Activity | Auth bypass via URL scheme |
| M4 | Insufficient Input / Output Validation | SQLi in Content Provider | Format string in log output |
| M5 | Insecure Communication | Cleartext HTTP; pinning bypass | ATS disabled; cleartext API calls |
| M6 | Inadequate Privacy Controls | Location sent to analytics SDK | PII logged to console |
| M7 | Insufficient Binary Protections | No root detection, debuggable flag | No jailbreak detection, symbols present |
| M8 | Security Misconfiguration | `android:debuggable=true` in prod | `NSAllowsArbitraryLoads=true` |
| M9 | Insecure Data Storage | Credentials in SharedPreferences | Credentials in NSUserDefaults |
| M10 | Insufficient Cryptography | ECB mode AES; hardcoded IV | MD5 for password hashing |

---

## Part 5 — Android vs iOS: Attacker's Comparison

| Dimension | Android | iOS |
|---|---|---|
| **App acquisition** | APK from device via `adb pull`; download from APKPure/APKMirror | IPA from jailbroken device via Frida/SSH; no public store |
| **Decompilation** | Full Java/Kotlin decompilation via jadx; readable code | Binary only; decompile Mach-O → pseudo-C in Ghidra/IDA |
| **Dynamic analysis** | Rooted emulator or device; Frida without jailbreak on some versions | Jailbroken device required for most dynamic analysis |
| **Proxy interception** | Straightforward; add system CA via Magisk | Add CA to keychain; ATS disabling in proxy profiles |
| **Certificate pinning** | Very common; bypassed with Frida + objection in < 10 min | Common; bypassed with SSL Kill Switch 2, Frida on jailbreak |
| **Bug bounty coverage** | More programmes, more tooling, lower bar to entry | Higher-value programmes; harder entry; less competition |
| **IPC attack surface** | Rich: Activities, Services, Receivers, Providers, Intents | Minimal: URL schemes, App Extensions, XPC (limited) |
| **Most common findings** | Insecure storage, exported components, pinning bypass, WebView issues | Insecure Keychain storage, ATS disabled, hardcoded creds |

---

## Part 6 — Mobile Pentest Lifecycle

```
Phase 1: Acquisition
  ├── Android: adb pull (rooted), APK extraction from Play Store backup
  └── iOS: IPA from jailbroken device via frida-ios-dump or AppDecrypt

Phase 2: Static Analysis
  ├── Decompile / disassemble
  ├── Manifest / Info.plist inspection
  ├── Secret hunting (API keys, credentials, endpoints)
  └── Code review for vulnerability classes

Phase 3: Dynamic Analysis
  ├── Traffic interception (Burp Suite + device proxy)
  ├── Certificate pinning bypass
  ├── Runtime function hooking (Frida)
  └── Filesystem inspection during runtime

Phase 4: API Testing
  ├── Replay and modify intercepted traffic
  ├── Auth testing, IDOR, mass assignment
  └── Version abuse, hidden endpoints

Phase 5: Reporting
  ├── Evidence: screenshots, Frida scripts, pcap
  ├── CVSS scoring, MASVS requirement mapping
  └── PoC — reproducible steps on a test device
```

---

## Key Takeaways

1. **Android is Linux with a sandbox.** The sandbox holds as long as apps respect
   the permission model and no component is exported without a guard. The moment
   a developer exports a component unintentionally, you have a free entry point.
2. **iOS is harder to get into but not immune.** The requirement for a jailbroken
   device raises the barrier. Once you have that barrier cleared, the vulnerability
   classes are identical: insecure storage, cleartext comms, hardcoded credentials,
   weak auth.
3. **OWASP Mobile Top 10 maps directly to web classes.** Insecure storage ≈
   information disclosure. Insecure communication ≈ MitM. Insufficient binary
   protections ≈ missing mitigations. The concepts transfer; the syntax is different.
4. **Mobile bug bounty is undercompeted.** Certificate pinning is the primary
   deterrent. Learn to bypass it and you are ahead of 80% of the field.
5. **Static analysis comes first, always.** You cannot dynamically test what you
   do not understand. Decompile, read the manifest, map endpoints, find secrets —
   then intercept traffic.

---

## Exercises

1. Install `jadx-gui` on your lab machine. Download any open-source Android APK
   from F-Droid. Open it in jadx-gui. Answer: how many exported activities does
   it declare? What permissions does it request? Are any activities exported
   without a `permission` guard?

2. Pull the `AndroidManifest.xml` from an APK using `apktool d app.apk`. Look for
   `android:exported="true"` entries. For each one, note: what component type is it?
   What intent filters does it declare?

3. Research: what is the difference between Android's Data Protection API equivalent
   and iOS's Data Protection API? Which protection class makes a file readable
   even when the device is locked?

4. Create a one-page threat model for a fictional mobile banking app that uses:
   biometric auth, a REST API with JWT, local transaction caching in SQLite, and
   push notifications. List the top 5 attack vectors in priority order.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q211.1, Q211.2 …).
> Follow-up questions use hierarchical numbering (Q211.1.1, Q211.1.2 …).

---

## Navigation

← Previous: [Day 210 — Cloud Competency Check](../04-BroadSurface-02/DAY-0210-Cloud-Competency-Check.md)
→ Next: [Day 212 — Android Static Analysis](DAY-0212-Android-Static-Analysis.md)
