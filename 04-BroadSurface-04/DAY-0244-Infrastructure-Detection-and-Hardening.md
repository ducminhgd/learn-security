---
title: "Infrastructure Detection and Hardening — DHCP Snooping, DAI, 802.1X, EDR"
tags: [detection, hardening, DHCP-snooping, DAI, 802.1X, EDR, ARP-inspection,
       network-security, Sigma, SIEM, T1557, T1040, ATT&CK, blue-team]
module: 04-BroadSurface-04
day: 244
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Linux PrivEsc Enumeration (Day 234)
  - Windows PrivEsc Enumeration (Day 238)
  - Living off the Land (Day 243)
---

# Day 244 — Infrastructure Detection and Hardening

> "Everything you did in the last two weeks left a trace. ARP poisoning
> creates log entries. Unquoted service exploitation creates Event ID 7040.
> A potato attack leaves 4673 in the Security log. The question is not
> whether the evidence exists — it always exists. The question is whether
> anyone is watching, and whether the detection rule is written correctly
> enough to fire."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Configure DHCP Snooping and Dynamic ARP Inspection to prevent ARP spoofing.
2. Disable LLMNR and NBT-NS across Windows environments via Group Policy.
3. Enforce SMB signing to prevent relay attacks.
4. Interpret Windows Security event logs for PrivEsc activity.
5. Write Sigma rules for the five most common infrastructure attack patterns
   covered in this module.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| ARP spoofing attack mechanics | Day 231 |
| LLMNR/SMB relay attack mechanics | Day 232 |
| Windows PrivEsc attack patterns | Days 238–239 |
| Linux PrivEsc attack patterns | Days 234–237 |
| Sigma rule syntax | Day 142 (or self-study) |

---

## Part 1 — Network Attack Prevention

### DHCP Snooping and Dynamic ARP Inspection

DHCP Snooping builds a binding table: {MAC address, IP address, interface, VLAN,
lease expiry}. Dynamic ARP Inspection (DAI) validates ARP packets against this
table — dropping any ARP reply where the claimed MAC-IP pair does not match a
known DHCP lease.

```
# Cisco IOS configuration (switch level):

# Step 1: Enable DHCP Snooping globally and per-VLAN
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

# Step 2: Mark uplinks as trusted (DHCP server side)
interface GigabitEthernet0/1
 ip dhcp snooping trust
 ip arp inspection trust

# Step 3: Enable Dynamic ARP Inspection per-VLAN
ip arp inspection vlan 10,20,30

# Step 4: (Optional) Rate-limit ARP packets on access ports
interface GigabitEthernet0/2
 ip arp inspection limit rate 100

# Verify:
show ip dhcp snooping binding
show ip arp inspection vlan 10
```

**Linux alternative (for software-based routing):**
```bash
# arptables (arpwatch-based — stops individual hosts from forwarding spoofed ARP)
apt-get install arptables
# Drop ARP replies that claim to be the gateway but come from non-gateway MACs:
arptables -A INPUT --opcode 2 --source-ip 192.168.1.1 \
  ! --source-mac <gateway-real-mac> -j DROP
```

### Disable LLMNR and NBT-NS (Windows)

```powershell
# Group Policy (preferred for domain environments):
# Computer Configuration → Administrative Templates →
# Network → DNS Client → Turn Off Multicast Name Resolution → Enabled

# Registry (manual / PowerShell for standalone machines):
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -Value 0 -Type DWORD

# Disable NBT-NS on all network adapters:
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {
  $_.IPEnabled -eq $true
} | ForEach-Object {
  $_.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
```

### Enforce SMB Signing (Prevents Relay)

```powershell
# Group Policy (domain-wide):
# Computer Configuration → Windows Settings → Security Settings →
# Local Policies → Security Options:
# "Microsoft network client: Digitally sign communications (always)" → Enabled
# "Microsoft network server: Digitally sign communications (always)" → Enabled

# Registry (standalone):
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
  -Name "RequireSecuritySignature" -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "RequireSecuritySignature" -Value 1 -Type DWORD

# Verify current state:
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
```

### 802.1X Port-Based Network Access Control

802.1X prevents rogue devices from connecting to the network at Layer 2.
A device must authenticate (EAP certificate, username/password) before the
switch port becomes active.

```
# Cisco IOS — 802.1X on access port:
aaa new-model
aaa authentication dot1x default group radius
dot1x system-auth-control

interface GigabitEthernet0/5
 switchport mode access
 dot1x port-control auto
 authentication host-mode multi-auth
 spanning-tree portfast
```

**Impact on ARP spoofing:** 802.1X prevents an attacker from plugging a
rogue device into the network. It does not prevent a compromised internal
device from running arpspoof — for that, DAI is still needed.

---

## Part 2 — Linux PrivEsc Hardening

### Audit and Remove Unnecessary SUID Binaries

```bash
# Baseline all SUID binaries on a fresh installation
find / -perm -4000 -type f 2>/dev/null | sort > /var/log/suid-baseline.txt

# Schedule a daily comparison:
cat > /etc/cron.daily/suid-check << 'EOF'
#!/bin/bash
CURRENT=$(find / -perm -4000 -type f 2>/dev/null | sort)
BASELINE=$(cat /var/log/suid-baseline.txt)
DIFF=$(diff <(echo "$BASELINE") <(echo "$CURRENT"))
if [ -n "$DIFF" ]; then
  echo "SUID binary change detected:" | mail -s "SUID Alert" admin@company.com
  echo "$DIFF" | mail -s "SUID Delta" admin@company.com
fi
EOF
chmod +x /etc/cron.daily/suid-check

# Remove SUID from binaries that do not need it:
chmod u-s /usr/bin/at   # if at is not needed
chmod u-s /usr/bin/chfn  # finger info change — rarely needed
```

### Sudoers Hardening

```bash
# Audit sudoers — identify all NOPASSWD entries
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# Remove NOPASSWD for interactive binaries (editors, shells, interpreters):
# BAD: labuser ALL=(ALL) NOPASSWD: /usr/bin/python3
# GOOD: labuser ALL=(ALL) NOPASSWD: /opt/backup/run-backup.sh

# Enable sudo logging to syslog:
# In /etc/sudoers:
Defaults log_output
Defaults!/usr/bin/sudoreplay !log_output

# Set a timeout for sudo sessions (requires re-auth after 5 min):
Defaults timestamp_timeout=5
```

### Cron Security

```bash
# Ensure all cron scripts are root-owned and not world-writable
find /etc/cron* /var/spool/cron -writable 2>/dev/null | \
  grep -v '/var/spool/cron/crontabs/root' | \
  xargs -I{} chown root:root {}
find /etc/cron* -not -perm -o=w 2>/dev/null  # confirm no world-writable

# Restrict cron to root only:
echo "" > /etc/cron.allow
echo "root" > /etc/cron.allow
```

---

## Part 3 — Windows PrivEsc Hardening

### Fix Unquoted Service Paths

```powershell
# Find all unquoted paths:
Get-WmiObject Win32_Service | Where-Object {
  $_.PathName -notmatch '"' -and $_.PathName -match ' '
} | Select-Object Name, PathName | ForEach-Object {
  $name = $_.Name
  $path = $_.PathName
  # Fix: wrap in quotes
  sc.exe config $name binpath= "`"$path`""
  Write-Host "Fixed: $name"
}
```

### Token Privilege Hardening

```
# Reduce SeImpersonatePrivilege on IIS application pools:
# IIS Manager → Application Pools → (pool name) → Advanced Settings
# Identity: Choose "Custom account" with a limited service account
# Do NOT use LocalSystem or NetworkService for application pools

# Alternatively: enforce Windows Defender Credential Guard
# (prevents token theft from LSASS)
# Group Policy: Device Guard → Credential Guard → Enabled with UEFI Lock
```

### Disable AlwaysInstallElevated

```powershell
# Remove both registry keys:
reg delete HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f
```

---

## Part 4 — Detection: Sigma Rules for This Module's Attacks

### ARP Poisoning Detection

```yaml
title: Potential ARP Cache Poisoning — Multiple IPs from Same MAC
logsource:
  product: zeek
  service: arp
detection:
  selection:
    arp.opcode: 2   # ARP reply
  condition: selection | count(arp.src.proto_ipv4) by arp.src.hw_mac > 2
  timeframe: 5m
falsepositives:
  - Legitimate IP address changes (DHCP renewal)
level: high
tags:
  - attack.t1557.002
```

### LLMNR Poisoning Detection

```yaml
title: LLMNR Response from Unexpected Host
logsource:
  product: zeek
  service: dns
detection:
  selection:
    dst_port: 5355
    dns.QR: 1   # response
  filter_known_hosts:
    src_ip:
      - 192.168.1.10  # known internal DNS servers
      - 192.168.1.11
  condition: selection and not filter_known_hosts
level: high
tags:
  - attack.t1557.001
```

### Windows PrivEsc Detection

```yaml
title: Unquoted Service Path Binary Created
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|startswith:
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
    TargetFilename|endswith: '.exe'
  filter_legitimate:
    Image|endswith:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\installer.exe'
  condition: selection and not filter_legitimate
level: medium
tags:
  - attack.t1574.009

---

title: SeImpersonate Potato Attack Pattern
logsource:
  service: security
  product: windows
detection:
  selection_token:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
  selection_system:
    EventID: 4688
    IntegrityLevel: System
    ParentImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection_token and selection_system
  timeframe: 2m
level: high
tags:
  - attack.t1134.001
```

### C2 Beaconing Detection

```yaml
title: Regular Outbound HTTPS Beaconing
logsource:
  product: zeek
  service: conn
detection:
  selection:
    network.protocol: ssl
    destination.port: 443
    duration|lt: 5   # short connections — beacon check-ins
  condition: selection | count() by destination.ip, source.ip > 30
  timeframe: 1h
falsepositives:
  - Browser sync, update services, CDN health checks
level: medium
tags:
  - attack.t1071.001
  - attack.t1573
```

---

## Key Takeaways

1. **Defence is layered for a reason.** DAI stops ARP spoofing. Disabling
   LLMNR stops LLMNR poisoning. SMB signing stops relay. Each control
   addresses one layer — none is sufficient alone. A motivated attacker works
   around single controls; layered defence requires them to overcome all of them.
2. **Detection requires a baseline.** You cannot detect a new SUID binary
   without knowing which ones existed before. You cannot detect unusual process
   trees without knowing the normal parent-child relationships. Building baselines
   is defensive prerequisite work.
3. **Sigma rules are your detection currency.** Write them during offensive work.
   For every attack you execute, write the detection rule immediately after —
   while the technique is fresh. That is how the best detection libraries are built.
4. **Windows Event IDs map to ATT&CK techniques.** 4720 (new account), 4732
   (group membership), 4673 (privilege use), 4688 (process creation), 7040
   (service change). Know these IDs. When you see them in logs, you know what
   happened without reading the message.
5. **Hardening without detection is incomplete.** A perfectly hardened system
   still gets compromised. Detection tells you when hardening failed — and it
   always fails somewhere, given enough time and motivation.

---

## Exercises

1. Build a lab network with a Cisco-compatible switch simulator (GNS3 or EVE-NG)
   and configure DHCP Snooping + DAI. Then attempt an ARP spoofing attack with
   arpspoof. Document what happens — does the attack succeed? What log entries
   does the switch generate?

2. Apply all five Windows hardening controls from Part 3 to a lab VM. Then
   attempt each corresponding attack from Days 238–239. Document which attacks
   are fully blocked, which are only made harder, and which still succeed.

3. Write a Python script that reads Zeek `conn.log` output in real time (via
   `tail -f`) and alerts on: (a) any host making more than 30 HTTPS connections
   per hour to the same destination, (b) any internal host sending traffic
   to UDP port 5355 with QR=1 (LLMNR response).

4. Research: what is Microsoft Defender for Identity (formerly ATP)? What
   specific attack patterns from this module does it detect? How does it differ
   from traditional SIEM-based detection?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q244.1, Q244.2 …).
> Follow-up questions use hierarchical numbering (Q244.1.1, Q244.1.2 …).

---

## Navigation

← Previous: [Day 243 — Living off the Land](DAY-0243-Living-off-the-Land.md)
→ Next: [Day 245 — Infrastructure Practice Day 1](DAY-0245-Infrastructure-Practice-Day-1.md)
