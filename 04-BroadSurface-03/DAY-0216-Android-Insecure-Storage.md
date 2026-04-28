---
title: "Android Insecure Storage — SharedPreferences, SQLite, External Storage, Key Material"
tags: [android, insecure-storage, SharedPreferences, SQLite, external-storage,
       keystore, MASVS-STORAGE, CWE-312, CWE-922, MITRE-T1409, data-at-rest]
module: 04-BroadSurface-03
day: 216
related_topics:
  - Android Static Analysis (Day 212)
  - Android Static Analysis Lab (Day 213)
  - Android Dynamic Analysis with Frida (Day 214)
  - Mobile Detection and Hardening (Day 222)
---

# Day 216 — Android Insecure Storage

> "Applications collect everything. Passwords, tokens, credit card numbers,
> biometric templates, PII. Then they write it to a file or a database — often
> in plaintext — because the developer assumed the sandbox was enough protection.
> The sandbox holds until the device is rooted, the backup is enabled, or
> another app is granted the same permission. Then everything they stored
> is yours."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Identify and read data stored in SharedPreferences, SQLite databases, and
   the external storage (`/sdcard/`).
2. Recognise patterns in decompiled code that indicate sensitive data is stored
   insecurely.
3. Demonstrate extraction of credentials from a running app's storage via `adb`
   and Frida.
4. Explain the Android Keystore system and how it should be used for key material.
5. Map insecure storage findings to MASVS-STORAGE requirements and CWE entries.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Android Static Analysis | Day 212 |
| Android Dynamic Analysis with Frida | Day 214 |
| ADB and rooted emulator | Day 212 setup |

---

## Part 1 — Storage Attack Surface Overview

```
Android Storage Locations
│
├── Internal Storage (private to app)
│   ├── /data/data/<package>/shared_prefs/     ← SharedPreferences XML files
│   ├── /data/data/<package>/databases/        ← SQLite databases
│   ├── /data/data/<package>/files/            ← arbitrary files
│   ├── /data/data/<package>/cache/            ← cached data
│   └── /data/data/<package>/no_backup/        ← excluded from adb backup
│
├── External Storage (shared, world-readable)
│   ├── /sdcard/ or /storage/emulated/0/
│   ├── Readable by any app with READ_EXTERNAL_STORAGE
│   └── Readable without root via adb on debug builds
│
└── System Keystore / Android Keystore
    ├── Backed by hardware (StrongBox) or TEE
    ├── Keys cannot be exported
    └── Only accessible to the app that created them
```

**What attackers do:** on a rooted device or via `adb backup` (if `allowBackup=true`),
pull the entire `/data/data/<package>/` directory and read every file.

---

## Part 2 — SharedPreferences

### 2.1 — What It Is

SharedPreferences stores key-value pairs in XML files. It is designed for
lightweight app configuration — not for secrets.

**File location:**

```
/data/data/com.example.app/shared_prefs/<filename>.xml
```

**Typical content:**

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">alice@example.com</string>
    <string name="password">SuperSecret123!</string>
    <string name="auth_token">eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI...</string>
    <boolean name="is_admin" value="false" />
    <string name="session_id">a4f29d7e-8b1c-...</string>
</map>
```

### 2.2 — Extract via adb (Root Required)

```bash
# Pull all SharedPreferences for a package
adb shell su -c "ls /data/data/com.example.app/shared_prefs/"
adb shell su -c "cat /data/data/com.example.app/shared_prefs/userdata.xml"

# Pull the entire app data directory
adb shell su -c "cp -r /data/data/com.example.app /sdcard/appdata"
adb pull /sdcard/appdata ./appdata_dump
```

### 2.3 — Extract via adb backup (No Root, if allowBackup=true)

```bash
# Trigger backup — user must confirm on device
adb backup -noapk -f backup.ab com.example.app

# Convert Android Backup format (.ab) to tar
python3 -c "
import zlib, sys
data = open('backup.ab', 'rb').read()
# Skip the 24-byte header
compressed = data[24:]
decompressed = zlib.decompress(compressed)
open('backup.tar', 'wb').write(decompressed)
"

tar xf backup.tar
# Navigate to apps/com.example.app/sp/ for SharedPreferences
```

### 2.4 — Extract via Frida (No Root on Some Setups)

```javascript
// Read SharedPreferences at runtime
Java.perform(function () {
    var Context = Java.use("android.app.ActivityThread");
    var currentApp = Context.currentApplication();
    var prefs = currentApp.getSharedPreferences("userdata", 0);

    // Read all keys
    var allEntries = prefs.getAll();
    var iterator = allEntries.entrySet().iterator();
    while (iterator.hasNext()) {
        var entry = iterator.next();
        console.log("[*] " + entry.getKey() + " = " + entry.getValue());
    }
});
```

### 2.5 — Find in Decompiled Code

```bash
# Search for SharedPreferences writes with sensitive-sounding keys
rg -i "(putString|putInt|putBoolean|putFloat|putLong)" \
   --type java jadx_output/ -n | \
   grep -i "(password|token|key|secret|session|credential|pin)"
```

Vulnerable pattern:

```java
// INSECURE: storing credentials in SharedPreferences
SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
SharedPreferences.Editor editor = prefs.edit();
editor.putString("password", userEnteredPassword);  // plaintext password stored
editor.putString("auth_token", jwtToken);
editor.apply();
```

---

## Part 3 — SQLite Databases

### 3.1 — Location and Structure

SQLite databases live in:

```
/data/data/<package>/databases/<name>.db
```

They are binary files readable by any SQLite client.

### 3.2 — Extract and Read

```bash
# List databases
adb shell su -c "ls /data/data/com.example.app/databases/"

# Pull the database
adb shell su -c "cp /data/data/com.example.app/databases/app.db /sdcard/"
adb pull /sdcard/app.db .

# Read with sqlite3
sqlite3 app.db

# Inside sqlite3:
.tables                          -- list all tables
.schema users                    -- show CREATE TABLE statement
SELECT * FROM users;             -- dump all users
SELECT * FROM sessions;          -- dump all sessions
SELECT * FROM messages;          -- private messages?
.quit
```

### 3.3 — Common High-Value Tables

| Table name pattern | What to look for |
|---|---|
| `users`, `accounts` | username, password_hash, email |
| `sessions`, `tokens` | session_id, auth_token, refresh_token |
| `messages`, `chats` | plaintext messages (PII) |
| `payments`, `cards` | PAN, CVV (if stored — Critical finding) |
| `audit_log`, `history` | User actions, transaction logs |
| `settings`, `config` | API keys, feature flags |

### 3.4 — Find SQLite Usage in Code

```bash
# Look for database creation and queries
rg -i "(SQLiteOpenHelper|getWritableDatabase|rawQuery|execSQL|db\.insert)" \
   --type java jadx_output/ -n | head -30

# Look for sensitive column names
rg -i '"(password|token|secret|key|card|cvv|pin|ssn)"' \
   --type java jadx_output/ | grep -i "column\|CREATE\|insert" | head -20
```

**Vulnerable pattern:**

```java
// INSECURE: storing card data in SQLite without encryption
public void storeCard(String cardNumber, String cvv, String expiry) {
    SQLiteDatabase db = this.getWritableDatabase();
    ContentValues values = new ContentValues();
    values.put("card_number", cardNumber);   // plaintext PAN
    values.put("cvv", cvv);                  // plaintext CVV
    values.put("expiry", expiry);
    db.insert("payment_cards", null, values);
}
```

---

## Part 4 — External Storage

### 4.1 — Why This Is High Risk

Files written to `/sdcard/` (external storage) are:
- Readable by **any installed app** with `READ_EXTERNAL_STORAGE` permission
- Readable via `adb pull` without root on debuggable devices
- Included in USB file transfers and cloud backups
- Indexed by `MediaStore` — visible to gallery apps, file managers

### 4.2 — Find in Code

```bash
# Look for external storage writes
rg -i "(getExternalStorage|getExternalFilesDir|DIRECTORY_DOWNLOADS|Environment\.External)" \
   --type java jadx_output/ -n

# Look for file write operations
rg -i "(FileOutputStream|FileWriter|BufferedWriter)" \
   --type java jadx_output/ | grep -v "test\|Test" | head -20
```

**Vulnerable pattern:**

```java
// INSECURE: writing to external storage (world-readable)
File logFile = new File(
    Environment.getExternalStorageDirectory(),
    "app_debug.log"
);
FileWriter writer = new FileWriter(logFile);
writer.write("User token: " + authToken);  // token written to /sdcard/
writer.write("User data: " + userData.toJson());
writer.close();
```

### 4.3 — Check for Logs with Sensitive Data

Developers frequently log sensitive data during development and forget to remove:

```bash
# Search for Log.* calls with sensitive-looking arguments
rg -i "(Log\.(d|i|v|e|w|wtf))\s*\(" --type java jadx_output/ | \
    grep -i "(password|token|secret|key|credential|user)" | head -20
```

On Android, `adb logcat` reads all log output:

```bash
adb logcat -s com.example.app:V | grep -i "(password|token|auth)"
```

If the app logs tokens at `DEBUG` or `VERBOSE` level, you get them from
`logcat` without root.

---

## Part 5 — The Android Keystore

### 5.1 — What It Is (and What Developers Should Use)

The Android Keystore system provides a hardware-backed (or TEE-backed) secure
enclave for cryptographic key material. Keys generated in the Keystore:
- **Cannot be exported** from the device
- **Are bound** to the app that created them
- **Can require user authentication** before use (biometric / PIN)

```java
// CORRECT: generating a key in the Keystore
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);

KeyGenerator keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
);
keyGenerator.init(new KeyGenParameterSpec.Builder(
    "MyKeyAlias",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)  // requires biometric/PIN
    .build()
);
SecretKey key = keyGenerator.generateKey();
```

### 5.2 — What Developers Actually Do (and Why It Breaks)

| Pattern | Problem |
|---|---|
| Key hardcoded in `BuildConfig` or `strings.xml` | Visible in decompiled code |
| Key derived from device IMEI / device serial | Predictable; extractable |
| Key stored in SharedPreferences or file | Readable with root access |
| Key in `assets/` as `.pem` or `.keystore` | Directly extractable from APK |
| AES key as hardcoded byte array in Java class | Visible in jadx as `{0x41, 0x42, ...}` |

```bash
# Find hardcoded byte arrays that could be keys
rg -i "new byte\[\]\s*\{" --type java jadx_output/ | head -10

# Find base64-encoded data that could be keys
rg -i "Base64\.decode\(" --type java jadx_output/ | head -10
```

---

## Part 6 — Extraction Summary: The Attacker Workflow

```
Phase 1 — Static: identify what is stored where
  jadx → search for putString, insert, FileOutputStream
  → note class names, method names, storage paths

Phase 2 — Dynamic: extract at runtime
  Option A (root): adb pull /data/data/<package>/ + sqlite3
  Option B (backup): adb backup + unpack .ab → .tar
  Option C (Frida): hook getSharedPreferences, query()

Phase 3 — Analyse extracted data
  sqlite3 app.db → .tables → SELECT *
  xmllint shared_prefs/prefs.xml → read values
  strings *.dat | grep -E "(pass|token|key)" → unstructured files

Phase 4 — Report
  Document: what data, where stored, how extracted, impact
  MASVS mapping: MASVS-STORAGE-1 (sensitive data in clear)
  CWE: CWE-312 (cleartext storage of sensitive info)
```

---

## Key Takeaways

1. **SharedPreferences is a configuration store, not a secrets store.** Any
   credential or token written to SharedPreferences is recoverable from a rooted
   device or an `adb backup`. Treat findings there as immediate Critical severity
   if the data includes passwords, tokens, or PII.
2. **SQLite is plaintext by default.** SQLCipher (encrypted SQLite) exists but
   requires explicit integration. If you see a `.db` file in the app's data
   directory, assume it is readable.
3. **External storage has no access control.** Writing anything sensitive to
   `/sdcard/` is effectively broadcasting it to every installed app with storage
   permission. This includes log files.
4. **Logs are a rich finding source.** `adb logcat` does not require root.
   If the app logs `auth_token=eyJ...` at debug level, you have a Critical
   finding without touching the filesystem.
5. **The Android Keystore is the correct solution.** Key material should never
   appear outside the Keystore. If you find a key as a hardcoded byte array or
   in a file, the entire cryptographic scheme is broken.

---

## Exercises

1. On a rooted emulator with InsecureBankv2 installed: pull the
   SharedPreferences files after logging in. What credentials or tokens are
   stored? What is the exact file path?

2. Decompile an app of your choice (from F-Droid). Search for all SQLite
   database creation (`CREATE TABLE`) statements. Identify any tables with
   columns that could hold sensitive data.

3. Write a Frida script that hooks `SharedPreferences.Editor.putString` and
   logs every key-value pair written. Test it against InsecureBankv2 during
   a login flow.

4. Research the MASVS-STORAGE-1 requirement. What specific conditions does
   it say should NOT result in sensitive data ending up in unencrypted storage?
   Write a one-paragraph developer guidance note for a mobile team.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q216.1, Q216.2 …).
> Follow-up questions use hierarchical numbering (Q216.1.1, Q216.1.2 …).

---

## Navigation

← Previous: [Day 215 — Certificate Pinning Bypass](DAY-0215-Certificate-Pinning-Bypass.md)
→ Next: [Day 217 — Android WebView and Intent Attacks](DAY-0217-Android-WebView-and-Intent-Attacks.md)
