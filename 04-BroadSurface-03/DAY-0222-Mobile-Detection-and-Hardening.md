---
title: "Mobile Detection and Hardening — Certificate Pinning, Root Detection, Obfuscation, ProGuard"
tags: [android, ios, hardening, certificate-pinning, root-detection, ProGuard, R8,
       obfuscation, MASVS-RESILIENCE, secure-coding, detection, blue-team]
module: 04-BroadSurface-03
day: 222
related_topics:
  - Certificate Pinning Bypass (Day 215)
  - Android Insecure Storage (Day 216)
  - Mobile Detection and Hardening (this lesson)
  - Mobile Bug Bounty Methodology (Day 220)
---

# Day 222 — Mobile Detection and Hardening

> "Now you switch sides. You know every technique in this module. You know how
> to bypass pinning, how to hook root detection, how to dump storage. Now you
> build the defences — not because they are unbreakable, but because every
> layer you add raises the cost of analysis. Cost in time, cost in expertise,
> cost in tooling. Enough cost and the casual attacker moves on to an easier
> target. Your job is to be the hardest door on the street."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Implement network certificate pinning correctly using the Android Network
   Security Config and OkHttp `CertificatePinner`.
2. Design a multi-layer root / jailbreak detection scheme that increases
   analysis cost without relying on any single check.
3. Configure ProGuard / R8 to shrink, obfuscate, and protect an Android app.
4. Apply secure storage patterns: Android Keystore for keys, EncryptedSharedPreferences
   for data.
5. Explain detection signals a blue team can monitor when a mobile app is under
   analysis.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Certificate Pinning Bypass | Day 215 |
| Android Insecure Storage | Day 216 |
| Android WebView and Intent Attacks | Day 217 |
| Full Assessment Lab | Day 221 |

---

## Part 1 — Certificate Pinning: Correct Implementation

### 1.1 — Android Network Security Config (Declarative — Recommended)

The most maintainable approach. No code required for basic pinning.

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>

    <!-- Production API: pin the leaf certificate's public key hash -->
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <!-- Primary pin: current cert SPKI SHA-256 hash -->
            <pin digest="SHA-256">GQNv+6cFEkiGPM0hhWJmAe9L8VEzZXSoMnBFSWdCGHk=</pin>
            <!-- Backup pin: next cert or intermediate CA -->
            <pin digest="SHA-256">klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=</pin>
        </pin-set>
        <!-- Require HTTPS: no cleartext fallback -->
        <trust-anchors>
            <certificates src="system"/>
            <!-- No "user" — Burp CA cannot be trusted -->
        </trust-anchors>
    </domain-config>

    <!-- Default: trust system CAs only, no cleartext -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

</network-security-config>
```

**How to get the SPKI hash:**

```bash
# From a PEM certificate file (current cert)
openssl x509 -in current_cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    base64

# From the live server
openssl s_client -connect api.example.com:443 2>/dev/null | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    base64
```

**Always include a backup pin.** Without a backup, a certificate rotation
will break the app for all users until an app update is deployed.

### 1.2 — OkHttp CertificatePinner (Programmatic)

```kotlin
// In your OkHttpClient builder
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/GQNv+6cFEkiGPM0hhWJmAe9L8VEzZXSoMnBFSWdCGHk=")
    .add("api.example.com", "sha256/klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=") // backup
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### 1.3 — iOS: TrustKit (Best Practice)

TrustKit is an open-source iOS library that implements pinning robustly:

```swift
// In AppDelegate.application(_:didFinishLaunchingWithOptions:)
let trustKitConfig: [String: Any] = [
    kTSKSwizzleNetworkDelegates: true,
    kTSKPinnedDomains: [
        "api.example.com": [
            kTSKEnforcePinning: true,
            kTSKIncludeSubdomains: true,
            kTSKExpirationDate: "2027-01-01",
            kTSKPublicKeyHashes: [
                "GQNv+6cFEkiGPM0hhWJmAe9L8VEzZXSoMnBFSWdCGHk=",
                "klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY="
            ]
        ]
    ]
]
TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
```

### 1.4 — Pinning Anti-Patterns to Avoid

| Anti-Pattern | Why It Fails |
|---|---|
| Pinning without backup hash | Certificate rotation breaks the app |
| Trusting user CAs in debug build (shipped to prod) | Burp intercepts without Frida |
| Pinning only the leaf cert with no expiry management | Certificate renewal breaks the app |
| Implementing custom `TrustManager` with logic errors | Classic "trust all" mistake |
| Pinning to a single intermediate CA | CA compromise breaks all pinned apps |

---

## Part 2 — Root and Jailbreak Detection

### 2.1 — Why Detection Is Still Worth Implementing

Root/jailbreak detection does not stop a skilled researcher. It does:
- Prevent casual automated scanning
- Log tampered environments to your backend
- Provide grounds to terminate sessions or refuse service
- Satisfy compliance requirements (PCI DSS, HIPAA for healthcare apps)
- Make dynamic analysis more expensive (time cost)

The defender's goal: raise the cost, not achieve perfection.

### 2.2 — Android Root Detection Layers

Implement **multiple independent checks**. A bypass must defeat all of them.

```kotlin
object RootDetector {

    fun isDeviceRooted(): Boolean {
        return checkSuBinary()
            || checkSuperuserApk()
            || checkBuildTags()
            || checkWritableSystem()
            || checkTestKeys()
    }

    // Layer 1: Su binary in common locations
    private fun checkSuBinary(): Boolean {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sd/xbin/su", "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup", "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    // Layer 2: Superuser APK
    private fun checkSuperuserApk(): Boolean {
        val packages = listOf(
            "com.noshufou.android.su", "com.thirdparty.superuser",
            "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine"
        )
        val pm = appContext.packageManager
        return packages.any {
            try { pm.getPackageInfo(it, 0); true } catch (e: Exception) { false }
        }
    }

    // Layer 3: Build tags (userdebug or eng = non-production build)
    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    // Layer 4: Attempt to write outside sandbox (only possible on rooted device)
    private fun checkWritableSystem(): Boolean {
        return try {
            val f = File("/system/ghost_test_${System.currentTimeMillis()}")
            f.createNewFile().also { f.delete() }
        } catch (e: Exception) { false }
    }

    // Layer 5: Test keys in build fingerprint
    private fun checkTestKeys(): Boolean {
        return Build.FINGERPRINT.contains("test-keys")
            || Build.FINGERPRINT.contains("generic")
            || Build.FINGERPRINT.startsWith("unknown")
    }
}
```

**Adding a native check (harder to hook):**

```c
// root_check.c — compile into a .so library
// Frida hooks Java; hooking native requires Interceptor.attach on a raw address
#include <jni.h>
#include <sys/stat.h>
#include <string.h>

JNIEXPORT jboolean JNICALL
Java_com_example_NativeRootCheck_isRooted(JNIEnv *env, jobject obj) {
    struct stat st;
    const char *paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        if (stat(paths[i], &st) == 0) return JNI_TRUE;
    }
    return JNI_FALSE;
}
```

### 2.3 — Remote Attestation (The Hard Barrier)

For the highest-assurance apps, implement server-side attestation:

**Android: Play Integrity API**

```kotlin
// Request an integrity verdict from Google's servers
val integrityManager = IntegrityManagerFactory.create(context)
val nonce = generateServerNonce()  // from your server

integrityManager.requestIntegrityToken(
    IntegrityTokenRequest.builder()
        .setNonce(nonce)
        .build()
).addOnSuccessListener { response ->
    // Send token to your server for verification
    // Server calls Google Play Integrity API to verify
    sendToServer(response.token())
}
```

The server verifies the token with Google. The verdict includes:
- Device integrity (was the Android certified? Is it a real device?)
- App integrity (was the APK modified from the signed version?)
- Account details (optional)

This check **cannot be bypassed** by Frida or root detection hooks because
the verdict comes from Google's servers, not from local code.

---

## Part 3 — Obfuscation with ProGuard / R8

### 3.1 — Enable R8 in Release Builds

```groovy
// build.gradle (app module)
android {
    buildTypes {
        release {
            minifyEnabled true        // enable code shrinking and obfuscation
            shrinkResources true      // remove unused resources
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
        debug {
            minifyEnabled false       // never obfuscate debug builds
        }
    }
}
```

### 3.2 — What R8 Does

| Operation | Effect on attacker |
|---|---|
| **Shrinking** | Removes unused classes and methods | Smaller APK; fewer classes to analyse |
| **Obfuscation** | Renames classes, methods, fields to `a`, `b`, `c` | `LoginActivity` becomes `a.b.c`; harder to navigate |
| **Optimisation** | Inlines methods, removes dead code | Fewer code paths to follow |

**Before R8 (in jadx):**

```java
public class LoginActivity extends AppCompatActivity {
    private void checkCredentials(String username, String password) {
        // ...
    }
}
```

**After R8:**

```java
public class b extends a {
    private void a(String a, String b) {
        // ...
    }
}
```

Class and method names are gone. The decompiler output is still correct Java,
but navigating it requires semantic analysis rather than name lookup.

### 3.3 — ProGuard Rules

Keep rules preserve names that must not be obfuscated:

```proguard
# proguard-rules.pro

# Keep model classes used by Gson/Moshi (reflection-based serialisation)
-keepclassmembers class com.example.model.** {
    <fields>;
}

# Keep Retrofit interface method names
-keepclassmembers interface * {
    @retrofit2.http.* <methods>;
}

# Keep native method names
-keepclasseswithmembernames class * {
    native <methods>;
}

# CRITICAL: Do NOT keep your security class names
# Bad: -keep class com.example.security.RootDetector { *; }
# → Attackers see the class name and hook it directly
```

**What attackers do with obfuscated code:** they use semantic markers —
API call names, string literals, library class names — to navigate. An
obfuscated class that calls `CertificatePinner.Builder()` is still the
network client. The work is harder, not impossible.

---

## Part 4 — Secure Storage Implementation

### 4.1 — Android: EncryptedSharedPreferences

```kotlin
// Replace plain SharedPreferences with EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val prefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// Use exactly like regular SharedPreferences
prefs.edit().putString("auth_token", token).apply()
val storedToken = prefs.getString("auth_token", null)
```

The data is encrypted on disk using a key stored in the Android Keystore.
Even with root access, the raw bytes in the XML file are ciphertext.

### 4.2 — Android: Room Database with SQLCipher

```kotlin
// Encrypted Room database
val passphrase = SQLiteDatabase.getBytes("strong_passphrase".toCharArray())
val factory = SupportFactory(passphrase)

val db = Room.databaseBuilder(context, AppDatabase::class.java, "app_db")
    .openHelperFactory(factory)
    .build()
```

### 4.3 — iOS: Keychain Correct Usage

```swift
// Store a token in Keychain with the highest appropriate protection class
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "auth_token",
    kSecValueData as String: tokenData,
    // Use WhenPasscodeSetThisDeviceOnly for the most sensitive data
    kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecAttrSynchronizable as String: false  // never sync to iCloud
]
SecItemAdd(query as CFDictionary, nil)
```

---

## Part 5 — Detection Signals for Blue Teams

When a mobile app is under security analysis, server-side signals include:

| Signal | Observation | Likely cause |
|---|---|---|
| High request rate, identical headers | 100+ requests/min from same device | Burp Intruder / scripted testing |
| Requests to deprecated API versions | `GET /api/v1/` from current app version | Version abuse testing |
| Non-sequential ID enumeration | `/users/1`, `/users/2`, ... `/users/100` | IDOR scan |
| Auth header present but no prior login | Token appears without corresponding login event | Replayed token from Burp |
| Requests from emulator user-agent | `Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_x86_64)` | Emulator analysis |
| Unusual geographic anomaly | Login from Vietnam, request from Germany 2 min later | VPN + real device analysis |
| Out-of-scope parameters in POST | `{"email":"x", "role":"admin"}` | Mass assignment testing |

**Implement server-side:**

```python
# Example: flag requests to deprecated API versions in your API gateway
def log_api_version_abuse(request):
    if request.path.startswith("/api/v1/") and CURRENT_VERSION == "v3":
        security_log.warning(
            "deprecated_version_access",
            path=request.path,
            user=request.user_id,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent")
        )
        # Optional: return 404 or 410 Gone for truly deprecated endpoints
```

---

## Key Takeaways

1. **Pinning without a backup hash is an operational disaster waiting to happen.**
   Certificate rotation without a backup pin breaks every installed app
   immediately. Always pin two: the current cert and the next cert (or
   the intermediate CA).
2. **Root detection should be multi-layered and partially native.** A single
   Java check is one Frida hook away from being bypassed. Mix file checks,
   build property checks, native binary checks, and remote attestation.
   Remote attestation (Play Integrity API) is the only check that is not
   locally bypassable.
3. **R8 obfuscation raises the cost of analysis, not the impossibility.**
   A determined researcher with enough time will understand obfuscated code.
   Your goal is to make casual analysis non-trivial and automated scanning
   worthless.
4. **EncryptedSharedPreferences and the Android Keystore are the correct
   defaults.** There is no reason to use plain `SharedPreferences` for anything
   that could be sensitive. The migration cost is a few lines of code.
5. **Blue team signals exist for mobile too.** Deprecated API version access,
   sequential ID enumeration, and emulator user-agents in production logs
   are high-signal indicators of active security research — or an attacker.

---

## Exercises

1. Take InsecureBankv2 (or your lab app). Implement a multi-layer root
   detection: (a) su binary check, (b) superuser APK check, (c) build tags
   check. Verify that launching the app on a rooted emulator triggers the
   detection.

2. Enable R8 in a simple Android project's release build. Decompile the
   release APK with jadx. Compare: can you still find the class you are looking
   for by name? What do you use instead to navigate the code?

3. Replace all `SharedPreferences.putString("token", value)` calls in
   InsecureBankv2 (or a practice app) with `EncryptedSharedPreferences`.
   Pull the resulting `shared_prefs/*.xml` from the device. Confirm the
   stored values are ciphertext, not plaintext.

4. Write a server-side middleware function (Python/Go/Node) that:
   (a) Logs any request to `/api/v1/` when the server is on `v3`
   (b) Increments a counter per IP for sequential integer parameter values
   (c) Alerts when the same token is used from two different IP addresses
   within 5 minutes.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q222.1, Q222.2 …).
> Follow-up questions use hierarchical numbering (Q222.1.1, Q222.1.2 …).

---

## Navigation

← Previous: [Day 221 — Mobile Full Assessment Lab](DAY-0221-Mobile-Full-Assessment-Lab.md)
→ Next: [Day 223 — Mobile Practice Day 1](DAY-0223-Mobile-Practice-Day-1.md)
