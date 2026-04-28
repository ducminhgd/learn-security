---
title: "iOS App Security Overview — Keychain, Binary Protections, Jailbreak Detection Bypass"
tags: [ios, iphone, keychain, binary-protections, jailbreak, frida, objection,
       code-signing, ATS, MASVS-STORAGE, MASVS-RESILIENCE, corellium]
module: 04-BroadSurface-03
day: 218
related_topics:
  - Mobile Security Overview (Day 211)
  - Certificate Pinning Bypass (Day 215)
  - Android Dynamic Analysis with Frida (Day 214)
  - Mobile API Attack Surface (Day 219)
---

# Day 218 — iOS App Security Overview

> "iOS is the harder platform. Getting in requires a jailbroken device, which
> requires time and the right firmware version. But the reward is worth it —
> iOS bugs are rarer, less reported, and better paid. And once you are in,
> the vulnerability classes are identical to Android: insecure Keychain storage,
> ATS disabled, hardcoded credentials, jailbreak detection that falls over
> in one Frida hook. The moat is higher. The castle is the same."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain iOS's core security model: code signing, sandboxing, entitlements,
   and the Data Protection API.
2. Read and interpret an `Info.plist` file for security misconfigurations
   (ATS, URL schemes, entitlements).
3. Identify insecure Keychain storage patterns — wrong protection class,
   kSecAttrAccessible misuse.
4. Bypass jailbreak detection using Frida hooks and describe the common
   detection methods apps use.
5. Enumerate the binary protections on an iOS binary using `otool` and `class-dump`.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Mobile Security Overview | Day 211 |
| Certificate Pinning Bypass | Day 215 |
| Frida basics | Day 214 |
| TLS and HTTPS concepts | Days 5–6 |

---

## Part 1 — iOS Security Architecture Recap

### 1.1 — Code Signing

Every iOS binary must be signed by a trusted certificate:

- **App Store apps** — signed by Apple after review
- **Enterprise distribution** — signed by an enterprise certificate
- **Developer builds** — signed by a developer certificate (device-registered)
- **Jailbroken** — code signing validation is disabled by the jailbreak

This is the primary reason you need a jailbroken device for full dynamic
analysis. Without disabling code signing enforcement, you cannot inject Frida's
`gadget` into an arbitrary app.

**Alternative without jailbreak:** Frida `gadget` mode — repackage the IPA
with Frida's gadget library injected as a framework. The app re-signs with
your developer certificate. Works on development builds and some free apps.

### 1.2 — Sandboxing and Entitlements

Every iOS app runs in a restricted sandbox:

```
/var/containers/Bundle/Application/<UUID>/App.app/   ← app binary + resources
/var/mobile/Containers/Data/Application/<UUID>/      ← app data (sandbox)
    ├── Documents/        ← user-accessible files, backed up by default
    ├── Library/          ← preferences, caches, application support
    │   ├── Preferences/  ← NSUserDefaults (insecure storage target)
    │   └── Caches/       ← cached data, not backed up
    └── tmp/              ← temporary files, not backed up
```

**Entitlements** are capabilities declared in the app's signed binary and
enforced by the kernel. Examples:

```xml
<!-- Entitlements from embedded.mobileprovision -->
<key>com.apple.developer.icloud-services</key>
<array><string>CloudDocuments</string></array>

<key>com.apple.security.application-groups</key>
<array><string>group.com.example.shared</string></array>
<!-- RISK: shared group data is accessible to other apps in the same group -->

<key>keychain-access-groups</key>
<array><string>com.example.app</string></array>
```

Read entitlements from a binary:

```bash
codesign -d --entitlements - /path/to/App.app/App
# Or from a jailbroken device:
ldid -e /var/containers/Bundle/Application/<UUID>/App.app/App
```

---

## Part 2 — Info.plist Security Review

`Info.plist` is the iOS equivalent of `AndroidManifest.xml`. It declares:
app capabilities, URL schemes, and security configuration.

### 2.1 — App Transport Security (ATS)

ATS enforces HTTPS for all network connections by default.

**Read from IPA:**

```bash
unzip App.ipa -d app_extracted
plutil -p app_extracted/Payload/App.app/Info.plist | grep -A 5 "NSAppTransportSecurity"
```

**Misconfigurations to hunt for:**

```xml
<!-- WORST: disables HTTPS for all connections -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- BAD: disables for specific domain (may reveal internal endpoints) -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>internal.api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```

`NSAllowsArbitraryLoads = true` is an immediate finding and means HTTP traffic
is accessible to a network MitM (coffee shop, rogue AP) without even touching
certificate pinning.

### 2.2 — URL Schemes (Deep Links)

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>    ← custom scheme: myapp://
            <string>fb123456789</string>  ← Facebook SSO callback
        </array>
    </dict>
</array>
```

Custom URL schemes can be registered by any app — there is no uniqueness
enforcement below iOS 18. This enables **URL scheme hijacking**: a malicious
app registers the same scheme and steals OAuth redirect tokens.

### 2.3 — Backup Configuration

```xml
<!-- Marks the app's data as eligible for backup -->
<key>UIFileSharingEnabled</key>
<true/>   ← files in /Documents accessible via iTunes File Sharing
```

If `UIFileSharingEnabled = true`, any file in the app's `Documents/` directory
is downloadable via a connected Mac/PC through Finder or iTunes.

---

## Part 3 — iOS Keychain Security

### 3.1 — What Keychain Is

The iOS Keychain is a hardware-backed encrypted database managed by the OS.
It stores credentials, certificates, and cryptographic keys — securely, when
used correctly.

**Keychain item classes:**

| Class | Used for |
|---|---|
| `kSecClassGenericPassword` | Arbitrary secrets (API keys, passwords) |
| `kSecClassInternetPassword` | URL-associated credentials |
| `kSecClassKey` | Cryptographic keys |
| `kSecClassCertificate` | X.509 certificates |

### 3.2 — Accessibility Attributes (The Critical Setting)

The `kSecAttrAccessible` attribute controls **when** Keychain items can be read:

| Value | Readable when | Security |
|---|---|---|
| `kSecAttrAccessibleAlways` | Always, even when locked | **Dangerous** — backup exposed |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | Always; not in backups | Bad — still unlocked |
| `kSecAttrAccessibleAfterFirstUnlock` | After first unlock since boot | Medium |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | After first unlock; no backup | **Acceptable** for tokens |
| `kSecAttrAccessibleWhenUnlocked` (default) | Only when unlocked | **Recommended** |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Unlocked; no backup | **Best for most secrets** |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Only if passcode set | Best for high-sensitivity |

**Attack:** on a jailbroken device, all Keychain items with `Always` or
`AfterFirstUnlock` accessibility are readable without any user auth bypass.

### 3.3 — Read Keychain on Jailbroken Device

**Via objection:**

```bash
objection -g com.example.app explore
# Inside REPL:
ios keychain dump
```

**Via Frida script:**

```javascript
// Dump all Keychain items readable by the app
ObjC.schedule(ObjC.mainQueue, function () {
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName("Security", "SecItemCopyMatching"),
        "int", ["pointer", "pointer"]
    );

    // Build query dict via ObjC
    var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    var query = NSMutableDictionary.dictionaryWithDictionary_({
        "kSecClass": "kSecClassGenericPassword",
        "kSecReturnAttributes": 1,
        "kSecReturnData": 1,
        "kSecMatchLimit": "kSecMatchLimitAll"
    });

    var resultRef = Memory.alloc(8);
    var status = SecItemCopyMatching(query.handle, resultRef);
    if (status === 0) {
        var result = new ObjC.Object(Memory.readPointer(resultRef));
        console.log(result.description());
    }
});
```

### 3.4 — Finding Keychain Usage in Code

```bash
# On decompiled Mach-O (Ghidra/Hopper) or in Swift/ObjC sources:
# Look for SecItemAdd, SecItemCopyMatching, SecItemUpdate

# If source is available (open source apps):
grep -r "kSecAttrAccessible" . | grep -v "ThisDeviceOnly"
# Anything without ThisDeviceOnly may be in backups
grep -r "kSecAttrAccessibleAlways\b" .  # Critical finding
```

---

## Part 4 — Binary Protections

### 4.1 — Check Binary Security Features

```bash
# On your Mac or within a jailbroken device shell:
# Using otool (macOS)
otool -hv /path/to/binary | grep -E "PIE|STACK"
otool -l /path/to/binary | grep -E "PAGEZERO|stack_size"

# Check for PIE (Position Independent Executable)
otool -hv binary | grep PIE
# "PIE" present = ASLR enabled

# Check for stack canaries
nm binary | grep "___stack_chk_guard"
# Symbol present = stack canaries compiled in

# Check for ARC (Automatic Reference Counting — affects use-after-free risk)
otool -l binary | grep -A 3 "__objc_autoreleasepools"
```

### 4.2 — Class Dump (ObjC Apps)

For Objective-C apps, `class-dump` extracts the full class interface from the
Mach-O binary — equivalent to jadx for Android:

```bash
# Install class-dump
brew install class-dump  # macOS
# Or: https://github.com/nygard/class-dump

# Dump all class interfaces
class-dump -H /path/to/App.app/AppBinary -o headers/

# Review generated headers:
cat headers/AppDelegate.h
cat headers/AuthViewController.h
cat headers/NetworkManager.h
```

This gives method signatures and property names — enough to know what to hook
with Frida even without source code.

For Swift apps, use `Ghidra` or `IDA Pro` (decompilers) — Swift metadata is
present in the binary and parseable.

---

## Part 5 — Jailbreak Detection and Bypass

### 5.1 — Common Jailbreak Detection Methods

Apps detect jailbreaks by checking for artefacts that only exist on
jailbroken devices:

| Check | What it looks for |
|---|---|
| File existence | `/Applications/Cydia.app`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt` |
| File write outside sandbox | Attempt to write to `/private/jailbreak_test` |
| URL scheme | `cydia://` scheme opens → Cydia installed |
| `fork()` / `system()` | Only succeeds on jailbroken devices |
| `dyld_get_image_name` | Check for `MobileSubstrate.dylib`, `Substrate.dylib` |
| `getenv("DYLD_INSERT_LIBRARIES")` | Frida/Substrate injection tells its presence |
| Integrity check | App binary hash mismatch |
| Process list | `ps` output includes `Cydia`, `amfid`, injection agents |

### 5.2 — Bypass with Frida

```javascript
// ios_jailbreak_bypass.js

var f = ObjC.classes;

// Method 1: Hook NSFileManager.fileExistsAtPath
var NSFileManager = ObjC.classes.NSFileManager;
var origFileExists = NSFileManager["- fileExistsAtPath:"];

Interceptor.attach(origFileExists.implementation, {
    onEnter: function (args) {
        var path = ObjC.Object(args[2]).toString();
        if (path.includes("Cydia") || path.includes("substrate") ||
            path.includes("/bin/bash") || path.includes("/usr/sbin/ssh")) {
            // Return false — file doesn't exist
            this.fakeNoFile = true;
            console.log("[+] fileExistsAtPath blocked: " + path);
        }
    },
    onLeave: function (retval) {
        if (this.fakeNoFile) {
            retval.replace(0);  // return NO (0 = false in ObjC BOOL)
        }
    }
});

// Method 2: Block fork() — many jailbreak checks use fork
var fork = Module.findExportByName(null, "fork");
Interceptor.replace(fork, new NativeCallback(function () {
    console.log("[+] fork() blocked — returning -1");
    return -1;
}, "int", []));

// Method 3: Block access() — used to check file existence
var access = Module.findExportByName(null, "access");
Interceptor.replace(access, new NativeCallback(function (path, mode) {
    var pathStr = Memory.readUtf8String(path);
    if (pathStr.includes("Cydia") || pathStr.includes("substrate")) {
        console.log("[+] access() blocked: " + pathStr);
        return -1;
    }
    return this.context.x0;  // call original
}, "int", ["pointer", "int"]));
```

```bash
# Run via spawn
frida -U -f com.example.app -l ios_jailbreak_bypass.js --no-pause
```

**objection one-liner:**

```bash
objection -g com.example.app explore
# Inside REPL:
ios jailbreak disable
```

---

## Part 6 — iOS Analysis Toolkit

| Tool | Purpose | Platform |
|---|---|---|
| `frida-ios-dump` | Decrypt IPA from jailbroken device | Jailbroken iOS |
| `class-dump` | Extract ObjC class headers from binary | macOS |
| `Ghidra` | Decompile Swift/ObjC Mach-O binary | Any |
| `Hopper Disassembler` | Decompile + pseudocode, iOS-optimised | macOS |
| `objection` | Frida REPL for iOS | Jailbroken |
| `SSL Kill Switch 2` | Disable cert validation system-wide | Jailbroken |
| `Keychain Dumper` | Extract all Keychain items | Jailbroken |
| `Clutch` / `bfdecrypt` | Decrypt App Store binaries | Jailbroken |
| `Corellium` | Cloud-hosted virtual iPhone (no physical device needed) | Cloud SaaS |
| `iMazing` | Backup and browse iOS file system | macOS/Windows |

---

## Key Takeaways

1. **The barrier is the jailbreak, not the vulnerability.** Once you have a
   jailbroken device on the right firmware, iOS analysis follows the same
   flow as Android. The tools are different; the concepts are identical.
2. **ATS disabled (`NSAllowsArbitraryLoads`) is a Critical network finding.**
   HTTP traffic is unencrypted and interceptable by a network MitM. No Frida
   required.
3. **Keychain `kSecAttrAccessibleAlways` is a Critical storage finding.**
   Items with this attribute are readable from a jailbroken device without
   any user authentication — and are included in iTunes/iCloud backups.
4. **Jailbreak detection has no reliable bypass-proof implementation.** Every
   file-based, fork-based, and library-based check is hookable. Defence-in-depth
   — multiple checks in native code — slows researchers but does not stop them.
5. **`class-dump` is your jadx for ObjC.** Extract all class interfaces first.
   Find the auth, network, and crypto classes. Hook them with Frida. The workflow
   is identical.

---

## Exercises

1. Download an open-source iOS app IPA (e.g., from `https://iosninja.io`
   or build from the GitHub source of Signal iOS). Extract and read the
   `Info.plist`. Document: ATS configuration, URL schemes declared,
   and `UIFileSharingEnabled` status.

2. Read the Apple documentation for `kSecAttrAccessible`. List all accessibility
   values. Which ones include items in iCloud or iTunes backups? Which ones
   require the device to have a passcode set?

3. Write a Frida script that hooks iOS `NSFileManager.fileExistsAtPath:` and
   logs every path checked. Run it against any installed app and observe which
   paths are polled during startup.

4. Research Corellium. What does it provide that a physical jailbroken device
   does not? What are its limitations? When would you use Corellium vs a
   physical device for iOS security research?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q218.1, Q218.2 …).
> Follow-up questions use hierarchical numbering (Q218.1.1, Q218.1.2 …).

---

## Navigation

← Previous: [Day 217 — Android WebView and Intent Attacks](DAY-0217-Android-WebView-and-Intent-Attacks.md)
→ Next: [Day 219 — Mobile API Attack Surface](DAY-0219-Mobile-API-Attack-Surface.md)
