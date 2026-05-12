---
title: "Phase 5 — Data Exfiltration and Evidence Collection"
tags: [ghost-level, exfiltration, evidence-collection, engagement-report,
  chain-of-custody, module-11-ghost-level]
module: 11-GhostLevel
day: 720
prerequisites:
  - Day 719 — Phase 5: sable-store Access
related_topics:
  - Day 721 — Phase 5: Persistence and C2
  - Day 723 — Phase 6: Timeline Reconstruction
---

# Day 720 — Phase 5: Data Exfiltration and Evidence Collection

> "The engagement report is not something you write after the hack.
> You write it during. Every command has a timestamp. Every finding has
> a screenshot. Every credential has a source. If you cannot prove it
> in the report, you might as well not have found it."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | All targets accessed: Y / N

---

## Goals

Consolidate all evidence gathered across the five targets. Verify that every
finding is backed by concrete proof. Calculate business impact. Stage the
evidence package for the report phases (Days 723–725).

**Target time:** 2 hours.

---

## 1 — Evidence Inventory

Before writing the report, verify that every finding has proof.

```
FINDING INVENTORY — PROOF VERIFICATION

FINDING F-01: sable-web JWT Authentication Bypass
  Type: Authentication bypass
  CWE: CWE-345 or CWE-287
  Evidence needed: admin access screenshot, token value, decoded payload
  Evidence on disk: Y / N
  File: screenshots/___________  log: recon/web/__________

FINDING F-02: sable-web SSRF in Report Generator
  Type: SSRF
  CWE: CWE-918
  Evidence needed: request showing internal URL, response with internal data
  Evidence on disk: Y / N
  File: ___________________________________________________________

FINDING F-03: sable-web Shell (if code execution obtained)
  Type: RCE
  Evidence needed: id output, hostname, shell screenshot
  Evidence on disk: Y / N
  File: ___________________________________________________________

FINDING F-04: sable-svc Binary Exploitation (RCE)
  Type: Stack/Heap Buffer Overflow
  CWE: CWE-121 or CWE-122
  Evidence needed: exploit script, shell proof (id/hostname/uname)
  Evidence on disk: Y / N
  File: engagement/exploits/sable_broker_exploit.py
        screenshots/sable_svc_shell.png

FINDING F-05: SABLE.LOCAL Domain Compromise (DA)
  Type: Privilege Escalation
  Evidence needed: DCSync output, whoami on DC, net group DA
  Evidence on disk: Y / N
  File: recon/dcsync_hashes.txt, screenshots/da_proof.png

FINDING F-06: sable-iot Exploitation (RCE)
  Type: Command Injection / Hardcoded Credentials
  CWE: CWE-78 or CWE-798
  Evidence needed: injection payload, shell proof
  Evidence on disk: Y / N
  File: ___________________________________________________________

FINDING F-07: sable-store Sensitive Data Exposure
  Type: Misconfigured Access Control
  CWE: CWE-200
  Evidence needed: share listing, sensitive files recovered
  Evidence on disk: Y / N
  File: recon/sable-store/__________

Findings WITHOUT adequate proof: __________________________________
  Action: re-run the exploit to capture missing screenshot
```

---

## 2 — Evidence Packaging Script

```bash
#!/usr/bin/env bash
# Day 720 — Engagement evidence packaging
# Run this script to organise all evidence before report writing.

EVIDENCE_DIR="engagement/evidence-package"
mkdir -p "$EVIDENCE_DIR"/{web,binary,ad,iot,store,screenshots}

# ─── Web findings ─────────────────────────────────────────────────────
cp recon/web/*.txt          "$EVIDENCE_DIR/web/"
cp recon/web_crawl.txt      "$EVIDENCE_DIR/web/" 2>/dev/null
cp recon/login_response.txt "$EVIDENCE_DIR/web/" 2>/dev/null

# ─── Binary exploitation ──────────────────────────────────────────────
cp engagement/exploits/sable_broker_exploit.py "$EVIDENCE_DIR/binary/"
cp recon/svc_strings.txt "$EVIDENCE_DIR/binary/" 2>/dev/null
cp recon/svc_probe.txt   "$EVIDENCE_DIR/binary/" 2>/dev/null

# ─── Active Directory ─────────────────────────────────────────────────
cp recon/dcsync_hashes.txt      "$EVIDENCE_DIR/ad/"
cp recon/kerberoast_cracked.txt "$EVIDENCE_DIR/ad/" 2>/dev/null
cp recon/bloodhound/*.zip       "$EVIDENCE_DIR/ad/"
cp Administrator.ccache         "$EVIDENCE_DIR/ad/"

# ─── IoT ──────────────────────────────────────────────────────────────
cp recon/sable-iot/*.txt "$EVIDENCE_DIR/iot/" 2>/dev/null
cp recon/binwalk_scan.txt "$EVIDENCE_DIR/iot/" 2>/dev/null

# ─── sable-store ──────────────────────────────────────────────────────
cp recon/sable-store/*.txt "$EVIDENCE_DIR/store/" 2>/dev/null
ls -lR firmware/extracted/ > "$EVIDENCE_DIR/store/firmware_tree.txt"

# ─── Screenshots (must be manually placed) ───────────────────────────
echo "Screenshots required in $EVIDENCE_DIR/screenshots/:"
echo "  - web_jwt_bypass.png"
echo "  - web_admin_console.png"
echo "  - sable_svc_shell.png"
echo "  - da_proof.png  (whoami on sable-dc)"
echo "  - iot_shell.png"
echo "  - store_share_listing.png"

# ─── Manifest ─────────────────────────────────────────────────────────
tree "$EVIDENCE_DIR" > "$EVIDENCE_DIR/manifest.txt"
echo ""
echo "Evidence package created at: $EVIDENCE_DIR"
echo "Manifest:"
cat "$EVIDENCE_DIR/manifest.txt"
```

---

## 3 — Business Impact Calculation

```
BUSINESS IMPACT ASSESSMENT — PROJECT SABLE

Impact on CONFIDENTIALITY:
  Data exposed:
    - Domain credentials (all users, DA hash): YES / NO
    - Application user database (emails, hashes): YES / NO
    - Source code / intellectual property: YES / NO
    - Customer PII from sable-store: YES / NO
    - Private keys / certificates: YES / NO
  Confidentiality impact: High / Medium / Low

Impact on INTEGRITY:
  Can the attacker modify data?
    - sable-web application data (via DA + DB access): YES / NO
    - Active Directory objects (via DA): YES / NO
    - IoT device configuration: YES / NO
    - sable-store files (write access): YES / NO
  Integrity impact: High / Medium / Low

Impact on AVAILABILITY:
  Can the attacker disrupt services?
    - sable-web service: YES / NO
    - sable-svc port 9000 (binary crash): YES / NO
    - Domain controller (via DA): YES / NO
    - IoT device: YES / NO
  Availability impact: High / Medium / Low

Overall scenario CVSS (environmental):
  Maximum finding CVSS: _________ (Critical/High/Medium)

Estimated blast radius (real-world framing):
  If this were a real breach, the attacker could:
  1. Steal ________________________________________________
  2. Impersonate ___________________________________________
  3. Disrupt _______________________________________________
  4. Sell __________________________________________________
```

---

## 4 — Credential Register — Final

```
CREDENTIAL REGISTER — FINAL STATE

# Format: TYPE | HOST | ACCOUNT | CREDENTIAL | SOURCE
#-----------------------------------------------------------------
WEB_USER     sable-web       testuser       Test1234!           registered
WEB_JWT      sable-web       admin          <token>             JWT bypass
DB_PASS      sable-web       sable_app      <password>          .env file
SSH_KEY      sable-web       root           recon/pivot_key     deployed
DOMAIN_PASS  SABLE.LOCAL     sable_app      <password>          DB reuse
DOMAIN_PASS  SABLE.LOCAL     <krb_user>     <password>          Kerberoast
DOMAIN_NT    SABLE.LOCAL     Administrator  <NT_hash>           DCSync
DOMAIN_NT    SABLE.LOCAL     krbtgt         <NT_hash>           DCSync
IOT_PASS     sable-iot       root/admin     <password>          firmware
STORE_ACCESS sable-store     Administrator  <DA_password>       SMB DA
```

---

## 5 — Engagement Status Check

```
48-HOUR ENGAGEMENT — STATUS AT HOUR ~30

TARGETS:
  sable-web  (10.0.1.10): Exploited — foothold / root / user _________
  sable-svc  (10.0.1.20): Exploited — shell via binary exploit
  sable-dc   (10.0.1.30): Exploited — Domain Admin via _______________
  sable-iot  (10.0.1.40): Exploited — ________________________________
  sable-store(10.0.1.50): Accessed — data recovered ___________________

FINDINGS: _______ total
  Critical: _______
  High:     _______
  Medium:   _______
  Low:      _______

OBJECTIVES COMPLETE:
  [ ] Obtain domain admin in SABLE.LOCAL
  [ ] Extract secret data from sable-store
  [ ] Binary RCE on sable-svc
  [ ] IoT shell on sable-iot
  [ ] Web exploitation chain on sable-web

OPTIONAL BONUS OBJECTIVES:
  [ ] Persistence survives password reset (Golden Ticket)
  [ ] Extract and crack sable-store backup passwords
  [ ] Find a vulnerability not listed in the briefing hints

TIME REMAINING: _______ hours (target: ≤ 18h for reporting phase)
```

---

## Navigation

← Previous: [Day 719 — Phase 5: sable-store Access](DAY-0719-Phase5-SableStore-Access.md)
→ Next: [Day 721 — Phase 5: Persistence and C2](DAY-0721-Phase5-Persistence-C2.md)
