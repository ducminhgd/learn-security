---
title: "Android Dynamic Analysis with Frida — Hooking, Runtime Patching, Function Tracing"
tags: [android, frida, dynamic-analysis, hooking, runtime-patching, function-tracing,
       MASVS-RESILIENCE, MITRE-T1418, javascript, instrumentation]
module: 04-BroadSurface-03
day: 214
related_topics:
  - Android Static Analysis Lab (Day 213)
  - Certificate Pinning Bypass (Day 215)
  - Android WebView and Intent Attacks (Day 217)
  - iOS App Security Overview (Day 218)
---

# Day 214 — Android Dynamic Analysis with Frida

> "Static analysis tells you what the code says. Dynamic analysis tells you
> what the code actually does at runtime. Those two things are often different.
> Frida is the wire you tap into a running process. Every function call, every
> argument, every return value — yours to observe and modify."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Set up Frida on a rooted Android device or emulator.
2. Write Frida JavaScript scripts to hook Java methods and log arguments and
   return values.
3. Modify return values at runtime to bypass security checks.
4. Enumerate loaded classes and methods using Frida's Java API.
5. Use `objection` as a Frida wrapper for rapid one-liner analysis.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Android Static Analysis | Day 212 |
| Static Analysis Lab (know the target) | Day 213 |
| Linux command line, Python 3 | Days 9–10 |
| ADB connected to a rooted device/emulator | Day 212 setup |

---

## Part 1 — Frida Architecture

Frida is a **dynamic binary instrumentation framework**. It works by injecting
a JavaScript engine (QuickJS / Duktape) into a target process. Your JS script
runs inside the target, with access to the process memory and all loaded
libraries.

```
Attacker Machine                  Android Device
┌──────────────────┐              ┌──────────────────────┐
│  frida (client)  │  ←USB/TCP→  │  frida-server        │
│  Python / CLI    │              │  (runs as root)       │
│                  │              │  ├── attaches to app  │
│  Your .js script │              │  └── injects JS      │
└──────────────────┘              └──────────────────────┘
```

**Two modes:**

| Mode | How | When to use |
|---|---|---|
| `spawn` | Frida starts the app itself | Hook from the very first instruction; before security checks |
| `attach` | Frida attaches to running process | Already running app; quick investigation |

---

## Part 2 — Setup

### 2.1 — Install Frida (Host Machine)

```bash
# Install frida tools (Python client)
pip install frida-tools

# Verify
frida --version
frida-ps --help
```

### 2.2 — Install frida-server (Android Device)

The `frida-server` binary must run as root on the device.

```bash
# Find your device architecture
adb shell getprop ro.product.cpu.abi
# Common: arm64-v8a, x86_64 (emulator), armeabi-v7a

# Download matching frida-server from GitHub releases
# https://github.com/frida/frida/releases — find frida-server-<version>-android-<arch>.xz
# Example for arm64:
wget https://github.com/frida/frida/releases/download/16.2.1/\
frida-server-16.2.1-android-arm64.xz
unxz frida-server-16.2.1-android-arm64.xz

# Push to device
adb push frida-server-16.2.1-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server on device (needs root shell)
adb shell su -c "/data/local/tmp/frida-server &"

# Verify connection from host
frida-ps -U  # -U = USB device
# Should list running processes including your target app
```

### 2.3 — Install objection

`objection` is a Frida wrapper that provides a REPL with common mobile security
operations as one-liners.

```bash
pip install objection
```

---

## Part 3 — Frida JavaScript API: Core Concepts

### 3.1 — Hook a Java Method

The most common operation: intercept a Java method, log its arguments,
optionally modify the return value.

```javascript
// Script: hook_login.js
// Hook LoginActivity.checkCredentials(username, password)

Java.perform(function () {
    // Get a reference to the target class
    var LoginActivity = Java.use("com.android.insecurebankv2.LoginActivity");

    // Hook the method by name
    // If overloaded, specify signature: .overload("java.lang.String", "java.lang.String")
    LoginActivity.checkCredentials.implementation = function (username, password) {
        // Log the arguments before the real method runs
        console.log("[*] checkCredentials called");
        console.log("    username: " + username);
        console.log("    password: " + password);

        // Call the original method and capture the return value
        var result = this.checkCredentials(username, password);
        console.log("    return value: " + result);

        return result;  // Return the original result unchanged
    };
});
```

**Run it:**

```bash
# Attach to running app
frida -U -n com.android.insecurebankv2 -l hook_login.js

# Or spawn (start app and hook from the beginning)
frida -U -f com.android.insecurebankv2 -l hook_login.js --no-pause
```

### 3.2 — Modify Return Values

Change what a method returns to bypass checks:

```javascript
Java.perform(function () {
    // Bypass root detection
    var RootDetector = Java.use("com.example.security.RootDetector");

    RootDetector.isDeviceRooted.implementation = function () {
        console.log("[*] isDeviceRooted called — returning false");
        return false;  // Override: tell the app the device is not rooted
    };
});
```

### 3.3 — Hook Constructors

```javascript
Java.perform(function () {
    var SecretKey = Java.use("javax.crypto.spec.SecretKeySpec");

    // Hook constructor to capture the raw key bytes
    SecretKey.$init.overload("[B", "java.lang.String").implementation =
        function (keyBytes, algorithm) {
            var key = "";
            for (var i = 0; i < keyBytes.length; i++) {
                key += ("0" + (keyBytes[i] & 0xff).toString(16)).slice(-2);
            }
            console.log("[*] SecretKeySpec created — algorithm: " + algorithm);
            console.log("    key (hex): " + key);
            this.$init(keyBytes, algorithm);
        };
});
```

### 3.4 — Enumerate All Classes and Methods

When you don't know the class name, enumerate:

```javascript
// List all loaded classes matching a pattern
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.includes("Auth") || className.includes("Login")) {
                console.log("[*] Found class: " + className);
            }
        },
        onComplete: function () {
            console.log("[*] Enumeration complete");
        }
    });
});
```

### 3.5 — Read and Write Object Fields

```javascript
Java.perform(function () {
    // Get a handle on the current Activity
    Java.choose("com.example.app.MainActivity", {
        onMatch: function (instance) {
            // Read a private field
            var token = instance.authToken.value;
            console.log("[*] authToken field: " + token);

            // Write a new value to the field
            instance.isAdmin.value = true;
            console.log("[*] isAdmin field set to true");
        },
        onComplete: function () {}
    });
});
```

---

## Part 4 — objection: The Quick Analysis Tool

`objection` is a Frida-based tool that provides a REPL with pre-built commands.
Use it for rapid exploration before writing custom scripts.

```bash
# Attach to running app
objection -g com.android.insecurebankv2 explore

# Inside the objection REPL:

# List all activities
android hooking list activities

# List all classes
android hooking list classes

# Search for a class
android hooking search classes LoginActivity

# List methods in a class
android hooking list class_methods com.android.insecurebankv2.LoginActivity

# Hook all methods in a class — log every call with arguments
android hooking watch class com.android.insecurebankv2.LoginActivity

# Hook a specific method
android hooking watch method \
    com.android.insecurebankv2.LoginActivity.checkCredentials \
    --dump-args --dump-return

# Bypass SSL pinning (one liner — works on many implementations)
android sslpinning disable

# List stored SharedPreferences
android preferences get --all

# List SQLite databases and dump
android sqlite list
android sqlite execute --query "SELECT * FROM users" --database /data/data/.../app.db
```

---

## Part 5 — Real-World Hook Targets

### 5.1 — Crypto Key Extraction

When an app encrypts data locally, hook the `Cipher` class to capture the key
and IV at the moment encryption/decryption happens:

```javascript
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.init.overload("int", "java.security.Key").implementation =
        function (opmode, key) {
            var keyBytes = key.getEncoded();
            var keyHex = "";
            for (var i = 0; i < keyBytes.length; i++) {
                keyHex += ("0" + (keyBytes[i] & 0xff).toString(16)).slice(-2);
            }
            var mode = opmode === 1 ? "ENCRYPT" : "DECRYPT";
            console.log("[*] Cipher.init called — mode: " + mode);
            console.log("    algorithm: " + this.getAlgorithm());
            console.log("    key (hex): " + keyHex);
            this.init(opmode, key);
        };
});
```

### 5.2 — JWT Token Capture

Hook `OkHttp` or `HttpURLConnection` to capture auth tokens in outbound
requests:

```javascript
Java.perform(function () {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");

    // Hook the newCall method
    OkHttpClient.newCall.implementation = function (request) {
        var url = request.url().toString();
        var auth = request.header("Authorization");
        if (auth) {
            console.log("[*] HTTP Request to: " + url);
            console.log("    Authorization: " + auth);
        }
        return this.newCall(request);
    };
});
```

### 5.3 — Biometric Auth Bypass

Hook the `BiometricPrompt` callback to simulate a successful authentication:

```javascript
Java.perform(function () {
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    var AuthCallback = Java.use(
        "androidx.biometric.BiometricPrompt$AuthenticationCallback"
    );

    AuthCallback.onAuthenticationError.implementation = function (code, msg) {
        console.log("[*] Biometric error intercepted — simulating success");
        // Instead of propagating the error, call the success callback
        this.onAuthenticationSucceeded(
            Java.use("androidx.biometric.BiometricPrompt$AuthenticationResult")
                .$new(null, null)
        );
    };
});
```

---

## Part 6 — Native Code Hooking (Interceptor)

For apps with native `.so` libraries, use Frida's `Interceptor` API (not the
Java API):

```javascript
// Hook a native function in a shared library
// First: find the function address
var libcrypto = Module.findBaseAddress("libcrypto.so");
console.log("[*] libcrypto base: " + libcrypto);

// Hook EVP_EncryptUpdate (OpenSSL encryption)
var EVP_EncryptUpdate = Module.findExportByName("libcrypto.so", "EVP_EncryptUpdate");
console.log("[*] EVP_EncryptUpdate: " + EVP_EncryptUpdate);

Interceptor.attach(EVP_EncryptUpdate, {
    onEnter: function (args) {
        // args[2] = input buffer, args[3] = input length
        var inputLen = args[3].toInt32();
        var inputBuf = Memory.readByteArray(args[2], inputLen);
        console.log("[*] EVP_EncryptUpdate input (" + inputLen + " bytes):");
        console.log(hexdump(inputBuf, { ansi: true }));
    },
    onLeave: function (retval) {}
});
```

---

## Key Takeaways

1. **Frida runs inside the process.** This is not external fuzzing. You are
   a graft on the live application, able to observe and modify every function
   call. There is no anti-analysis measure that survives a properly placed Frida
   hook.
2. **`Java.perform()` is the entry point for all Java hooks.** Everything inside
   runs after the JVM is fully initialised. Everything outside is native JS
   executed immediately.
3. **`spawn` vs `attach` matters.** If the pinning / root detection check runs
   in `Application.onCreate()`, you need `spawn` to hook before that method
   fires. `attach` only works for code not yet executed.
4. **objection is your rapid prototype tool.** Use it to survey the class
   structure and hook methods in one line. Write custom scripts only when you
   need precision or persistence.
5. **Crypto hooks are some of the highest-value hooks.** When you hook
   `SecretKeySpec`, `Cipher.init`, or `MessageDigest.digest`, you capture
   key material and plaintext in one step — no need to reverse the algorithm.

---

## Exercises

1. Set up Frida on a rooted emulator (Android x86_64 AVD). Run
   `frida-ps -U` and confirm you can see the list of processes.

2. Using the InsecureBankv2 app from Day 213: write a Frida script that hooks
   the login check function and logs the username and password each time the
   user attempts to log in. Confirm it works by logging in with a test account.

3. Write a Frida script that bypasses a hypothetical `isRooted()` method in
   class `com.example.security.RootCheck` — make it always return `false`.
   Test by confirming the app no longer shows a "device is rooted" warning.

4. Use `objection`'s `android hooking watch class` command to monitor all
   method calls on the `LoginActivity` class. Log a login attempt and paste
   the captured method calls.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q214.1, Q214.2 …).
> Follow-up questions use hierarchical numbering (Q214.1.1, Q214.1.2 …).

---

## Navigation

← Previous: [Day 213 — Android Static Analysis Lab](DAY-0213-Android-Static-Analysis-Lab.md)
→ Next: [Day 215 — Certificate Pinning Bypass](DAY-0215-Certificate-Pinning-Bypass.md)
