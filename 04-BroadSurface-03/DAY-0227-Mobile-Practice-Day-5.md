---
title: "Mobile Practice Day 5 — iOS Static Analysis and Keychain Extraction"
tags: [ios, practice, static-analysis, Keychain, Info.plist, class-dump, Ghidra,
       Frida, jailbreak, ATS, objection]
module: 04-BroadSurface-03
day: 227
related_topics:
  - iOS App Security Overview (Day 218)
  - Certificate Pinning Bypass (Day 215)
  - Android Dynamic Analysis with Frida (Day 214)
---

# Day 227 — Mobile Practice Day 5: iOS Static Analysis and Keychain

> "iOS practice day. No emulator shortcut — you either have a jailbroken device
> or you work on static analysis and the Corellium alternative. Static analysis
> on iOS teaches the same skill set. The binary is harder to read than jadx
> output. That is exactly why you need to practice it."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Statically analysed an iOS IPA or open-source iOS binary.
2. Read and assessed an `Info.plist` for security misconfigurations.
3. Used `class-dump` (ObjC) or Ghidra (Swift) to enumerate an iOS binary.
4. If jailbroken device available: extracted Keychain items via objection.
5. Written a finding report for at least one iOS security issue.

**Time budget:** 5–7 hours.

---

## Setup Options

### Option A — Jailbroken Physical Device or Corellium

```bash
# If you have a jailbroken device:
# Install Frida via Cydia/Sileo
# Install SSL Kill Switch 2
# Sideload a test app (OWASP iGoat-Swift)

# iGoat-Swift download:
# https://github.com/OWASP/iGoat-Swift
# Build from source with Xcode or use a pre-built IPA from the repo

objection -g org.owasp.igoat explore
# Inside REPL:
ios keychain dump
ios nsuserdefaults get --all
ios cookies get
```

### Option B — Static Analysis Only (No Device)

Use open-source iOS apps from GitHub. Examples with security issues:
- OWASP iGoat-Swift (intentionally vulnerable)
- Any iOS app from a GitHub repo with source

---

## Practice Block 1 — Info.plist Audit (1 hour)

```bash
# If working from IPA:
unzip App.ipa -d extracted/
plutil -p extracted/Payload/App.app/Info.plist > info_plist_readable.txt
cat info_plist_readable.txt

# Look for:
grep -i "NSAllowsArbitraryLoads" info_plist_readable.txt
grep -i "CFBundleURLSchemes" info_plist_readable.txt
grep -i "UIFileSharingEnabled" info_plist_readable.txt
grep -i "NSExceptionDomains" info_plist_readable.txt
grep -i "ITSAppUsesNonExemptEncryption" info_plist_readable.txt
```

Build an assessment table:

| Key | Value | Finding |
|---|---|---|
| NSAllowsArbitraryLoads | true | HIGH: cleartext HTTP allowed |
| UIFileSharingEnabled | true | MEDIUM: Documents accessible via iTunes |
| CFBundleURLSchemes | ["myapp"] | Review: deep link handler needs audit |

---

## Practice Block 2 — Binary Analysis (2 hours)

```bash
# ObjC app: class-dump
class-dump -H extracted/Payload/App.app/AppBinary -o headers/
ls headers/
cat headers/AppDelegate.h
cat headers/NetworkManager.h | grep -i "(auth\|token\|pin\|cert)"

# Swift app: Ghidra
# Import binary into Ghidra
# Analysis → Auto Analyse → OK
# Window → Symbol Tree → search for Auth, Login, Certificate

# Search for strings (both):
strings extracted/Payload/App.app/AppBinary | \
    grep -iE "(api[_-]?key|password|secret|https?://|token)" | \
    grep -v "http://www.apple\|https://www.apple" | \
    sort -u
```

---

## Practice Block 3 — iGoat-Swift Challenges (2 hours)

iGoat-Swift has a menu of security challenges. Focus today:

```
1. Data Storage (Insecure) — find data stored in NSUserDefaults and local files
2. Transport Security — find where ATS is disabled
3. Authentication — find the hardcoded PIN or token
4. Broken Cryptography — find where weak or hardcoded keys are used
```

If working with static source:

```bash
# Clone the source
git clone https://github.com/OWASP/iGoat-Swift.git
cd iGoat-Swift

# Search for insecure storage
grep -rn "UserDefaults.standard.set\|NSUserDefaults" . | grep -i "password\|token\|key"

# Search for hardcoded credentials
grep -rn '"password"\|"token"\|"secret"\|"apiKey"' . | grep -v "test\|Test"

# Search for ATS exceptions
find . -name "*.plist" -exec grep -l "NSAllowsArbitraryLoads" {} \;
```

---

## Reflection

1. How does reading a Swift decompiled binary in Ghidra compare to reading
   jadx-decompiled Java? What is harder? What is easier?
2. What is the highest-severity finding from today's iGoat-Swift analysis?
3. If you had a jailbroken device: what are the first 3 objection commands
   you would run after attaching to a new iOS app?

---

## Navigation

← Previous: [Day 226 — Mobile Practice Day 4](DAY-0226-Mobile-Practice-Day-4.md)
→ Next: [Day 228 — Mobile Practice Day 6](DAY-0228-Mobile-Practice-Day-6.md)
