---
title: "Physical and Social Engineering — Pretexting, Vishing, Badge Cloning, USB Drops"
tags: [red-team, social-engineering, pretexting, vishing, badge-cloning, USB-drop,
  Proxmark3, physical-security, ATT&CK, T1566, T1200]
module: 08-RedTeam-02
day: 504
related_topics:
  - Exchange and Email Attacks (Day 503)
  - Phishing Campaign Full Lab (Day 505)
  - OSINT and Passive Recon (Days 51–62)
---

# Day 504 — Physical and Social Engineering

> "The most sophisticated network I ever accessed was not hacked through
> a zero-day. It was accessed through a phone call where I convinced a
> junior IT employee that I was a network engineer from their vendor and
> needed temporary remote access to fix an urgent outage. The vulnerability
> was not in their software. It was in their onboarding process.
> That is harder to patch than any CVE."
>
> — Ghost

---

## Goals

Understand the psychological principles behind social engineering.
Learn pretexting, vishing, and physical intrusion techniques used in red
team engagements.
Understand badge cloning and USB drop methodology.
Know the legal and ethical scope requirements before any physical engagement.

**Prerequisites:** Day 501–503 (red team ops), OSINT (Days 51–62).
**Time budget:** 4 hours.

---

## Part 1 — The Psychology of Influence

Social engineering works by exploiting how humans are wired to trust, comply,
and make decisions under uncertainty. Robert Cialdini's six principles underpin
every technique:

```
Principle       How it is weaponised
──────────────────────────────────────────────────────────────────────
Authority       Impersonate a senior figure, regulator, or vendor.
                "Hi, this is Marcus from your IT security team."
                People comply with perceived authority without verification.

Urgency/Scarcity Create time pressure that bypasses deliberate thought.
                "Your account will be locked in 15 minutes unless you..."
                Urgency disables the internal voice that says "let me verify."

Social proof    "Everyone else in your department has already done this."
                People default to what others are doing when uncertain.

Liking          Build rapport before the ask. Match their language, reference
                a shared connection. People say yes to people they like.

Reciprocity     Offer something first (help, information) before making a
                request. The recipient feels obligated to comply.

Commitment      Small yeses lead to big yeses. Get a trivial agreement first,
                then escalate. "You mentioned you use Outlook — great, so you
                can just click this one link in the email I'm sending..."
```

---

## Part 2 — Pretexting

A pretext is a fabricated scenario that explains why you are present, why you
need access, and why you are credible. A good pretext is:

- **Believable:** grounded in real context (OSINT-driven)
- **Specific:** includes details that only an insider would know
- **Deflecting:** has a built-in reason why you cannot be easily verified

### Pretext Research (OSINT First)

Before building a pretext, gather:

```
From LinkedIn:
  → Employee names, titles, tenure, recent job postings
  → IT vendor relationships (Azure, Cisco, ServiceNow, Workday)
  → Recent IT projects (cloud migration, new office, ERP upgrade)

From company website:
  → Help desk phone number, ticketing system (Jira, ServiceNow)
  → IT policies and guidelines (often published in job listings)

From job postings:
  → Technology stack (which SIEM, which AV, which cloud)
  → Clues about IT maturity and team size

From email headers (from any legitimate email):
  → Email infrastructure (Exchange version, O365, Google Workspace)
  → Internal domain name (corp.local vs corp.com)
```

### Sample Pretext Scripts

```
Scenario: IT Vendor Remote Access
"Hi, this is Alex Chen from NetPulse IT Services — we handle the network
monitoring contract for your team. We've been getting alerts from your
Cisco routers in the 192.168.10.x range, and it looks like a firmware
update from last night may have misconfigured a few interfaces.
I need about 15 minutes of remote access to the monitoring console
to verify the config — your ticket number is NP-2024-81234.
Who would be the right person to set up a quick TeamViewer session?"

Scenario: Audit Team / Compliance
"Good morning. I'm Sarah from your parent company's internal audit team.
We're performing an unannounced physical security spot check — standard
SOX compliance, happens twice a year. I'm going to need a few minutes
with the server room access log and a quick walk-through.
I appreciate your help making this painless."

Scenario: New Employee
"Hey, I'm starting in the finance team today. I didn't get my badge
programmed yet — HR said they're working on it. Is there any chance you
can let me in to grab something from my desk? I'm running late for
a call with my manager."
```

---

## Part 3 — Vishing (Voice Phishing)

Vishing is social engineering over phone calls. Key principles:

```
Before the call:
  1. Research the target (name, role, recent activity)
  2. Spoof the caller ID (appear to call from a trusted number)
     Tool: SpoofCard, Twilio with a spoofed From number
  3. Have a clear objective (credential, click, remote access grant)
  4. Prepare for common objections with prepared responses
  5. Know when to abort (if the target starts demanding verification you
     cannot provide, offer to call back and end the call gracefully)

During the call:
  → Match their energy and vocabulary
  → Use their first name — familiarity creates trust
  → Reference specific internal details from OSINT (ticket numbers, system names)
  → Create urgency without panic ("this could become a problem in a few hours")
  → Make the ask small and incremental (one question, one click, not a password)

After the call:
  → Document the outcome, the pretext used, and what worked/failed
  → If successful: note the exact phrasing that gained compliance
```

### Legal Note

Caller ID spoofing is **illegal in some jurisdictions** when used with intent
to defraud. In a red team engagement, you must have explicit written scope
authorisation that covers social engineering phone calls. The Truth in Caller ID
Act (US) prohibits spoofing with intent to defraud. Verify legal scope with the
client's legal team before executing any vishing campaign.

---

## Part 4 — Badge Cloning

Most corporate access control systems use RFID cards. Low-frequency (125 kHz)
cards (HID Prox, EM4100) are trivially cloneable. High-frequency (13.56 MHz)
cards (HID iCLASS, MIFARE) require more effort.

### Low-Frequency Badge Cloning (HID Prox)

```
Tools:
  Proxmark3 (the standard tool — requires physical proximity to the card)
  Long-range readers: RFID Thief (reads from 30–50 cm inside a bag/jacket)

Attack scenario:
  1. Position near target in elevator, cafeteria, or conference room
  2. Long-range reader captures card data passively (1–3 seconds)
  3. Write captured data to a blank T5577 card (the universal emulator)
  4. Use cloned card to badge in

Proxmark3 commands:
  pm3 → lf search            # detect and identify the card type
  pm3 → lf hid reader        # read HID Prox card data
  pm3 → lf hid clone -r FACILITY_CODE:CARD_NUMBER
  # Write to T5577 blank card → now the blank card is a clone
```

### High-Frequency (iCLASS, MIFARE)

```
MIFARE Classic (widely deployed, old):
  Vulnerable to the nested authentication attack and MFOC/mfcuk tools
  pm3 → hf mf autopwn       # automatic MIFARE Classic attack

HID iCLASS:
  Older iCLASS (SIO not enabled): vulnerable to known key attacks
  iCLASS Elite/SE: significantly harder — requires specific attack chains

Modern systems (OSDP, credential diversification):
  Cloning is not feasible. Focus on other vectors:
  → Tailgating
  → Propping doors open
  → Social engineering the front desk
```

### Legal and Ethical Scope

Physical access testing requires:
- Written "get out of jail free" letter signed by the client's legal authority
- Explicit scope: which buildings, which access points, which hours
- Abort criteria: what to do if confronted by security or law enforcement
- Emergency contact: the client's security team, reachable 24/7

Attempting badge cloning without written authorisation is a criminal offence
(Computer Fraud and Abuse Act 18 U.S.C. § 1030 and equivalents globally).

---

## Part 5 — USB Drop Attacks

USB drops exploit human curiosity: people pick up USB drives they find and plug
them in, especially if the label is enticing ("Payroll Q3 2026", "HR Files").

### USB Drop Payload Types

```
Type 1: HID (Human Interface Device) — Rubber Ducky, Bash Bunny
  The device presents as a keyboard to the OS.
  Executes a keypress sequence automatically (PowerShell download + execute).
  Works even with AutoRun disabled.
  Detection: new USB HID device + rapid keystrokes from it.

  Payload example (Rubber Ducky DuckyScript):
    DELAY 1000
    GUI r
    DELAY 500
    STRING powershell -w hidden -enc BASE64_ENCODED_STAGER
    ENTER

Type 2: O.MG Cable
  A USB cable with an embedded microcontroller.
  Indistinguishable from a standard cable visually.
  Executes HID payloads on connection.
  High-value targets: charging stations, conference rooms.

Type 3: Classic AutoRun (legacy systems only)
  autorun.inf on a USB triggers execution on older Windows.
  Disabled by default since Windows 7 — only relevant on unpatched systems.

Type 4: LNK-based (file lure + shortcut payload)
  USB contains: "Salaries_2026.xlsx.lnk" which looks like an Excel file
  but executes a PowerShell stager when double-clicked.
  Works on any Windows version, no AutoRun needed.
```

### USB Drop Placement Strategy

```
High-yield locations:
  Parking lots near the office (dropped from a "vendor visit")
  Reception desks and waiting areas (left by a "previous visitor")
  Conference room tables (left after a legitimate meeting)
  Cafeteria or break room tables

Label psychology:
  "Payroll Q4 2026 — CONFIDENTIAL"
  "Employee Performance Reviews"
  "Board Meeting Slides — DRAFT"
  "HR Policy Updates — Read Before Friday"

Drop quantity: 5–10 drives across multiple locations.
Success rate historically: 45–98% plug-in rate in documented studies.
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Detection signal |
|---|---|---|
| Vishing / pretexting | T1566 (Phishing) | N/A (human-layer; policy control) |
| Badge cloning / tailgating | T1078 (Valid Accounts) | Physical — badge reader logs |
| USB HID attack | T1200 (Hardware Additions) | New USB HID device event |
| USB LNK drop | T1566.001 (Spearphishing Attachment) | LNK execution Sysmon Event 1 |

---

## Key Takeaways

1. OSINT is the prerequisite to effective social engineering. The more specific
   your pretext (real ticket numbers, real vendor names, real employee names),
   the higher the success rate. Generic pretexts fail against trained employees.
2. Low-frequency RFID cards (HID Prox) are trivially cloneable with a Proxmark3
   and a $20 blank T5577 card. Most buildings still use them. Upgrading to
   iCLASS Elite or mobile credential systems is the only real fix.
3. USB drops work because curiosity and helpfulness are human defaults. Technical
   controls (USB device whitelisting via Intune/GPO) are more reliable than
   user awareness training alone.
4. The legal scope document for physical engagements is more important than for
   network engagements. Security guards call police. Police do not check with your
   client before arresting you. Have the written authorisation on your person.
5. Document social engineering success precisely: which pretext, which target
   role, which information was disclosed. This becomes the most impactful finding
   in the report — because executives understand "someone called and got a
   password" far better than "we exploited CVE-2021-26855."

---

## Exercises

1. Build a pretext for accessing a fictional company's server room as an HVAC
   technician. Research what an HVAC technician would say, what tools they carry,
   and what access they legitimately need. Make it specific enough to be credible
   to a receptionist who is mildly suspicious.
2. Using a Proxmark3 (or the HF/LF emulator in the lab), read the data from a
   125 kHz HID Prox card and write it to a T5577 blank. Verify the clone opens
   the same door as the original.
3. Create a USB drop payload using a Rubber Ducky (or the lab Bash Bunny). The
   payload should open a PowerShell window, run `whoami`, and write the result
   to `C:\Windows\Temp\usb_test.txt`. Verify it executes on a Windows VM within
   5 seconds of plug-in.
4. Write a security policy recommendation for USB device control. Include: the
   technical control (GPO/MDM), the monitoring requirement (SIEM alert for new
   USB HID devices), and the user education component.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q504.1, Q504.2 …).

---

## Navigation

← Previous: [Day 503 — Exchange and Email Attacks](DAY-0503-Exchange-and-Email-Attacks.md)
→ Next: [Day 505 — Phishing Campaign Full Lab](DAY-0505-Phishing-Campaign-Full-Lab.md)
