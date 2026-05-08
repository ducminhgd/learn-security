---
title: "Writing a Security Advisory — Full Format, CVE, PoC, Remediation"
tags: [vulnerability-research, security-advisory, CVE, disclosure, report-writing,
  advisory-format, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 659
prerequisites:
  - Day 658 — Responsible Disclosure Deep Dive
related_topics:
  - Static Analysis with Semgrep/CodeQL (Day 660)
  - Ghost Level Operations (Day 701+)
---

# Day 659 — Writing a Security Advisory: Full Format, CVE, PoC, Remediation

> "Anyone can find a bug. Writing the advisory is where you demonstrate
> whether you actually understand it. A bad advisory gets triaged as
> informational. A good advisory gets a CVE, a fix, and credit. The
> difference is not the severity of the bug — it is the quality of the
> argument you make for why it matters."
>
> — Ghost

---

## Goals

Learn the structure of a professional security advisory. Understand how to
write a clear impact statement, a reproducible PoC, a credible CVSS
justification, and an actionable remediation. Produce a complete advisory
for a vulnerability found in a lab exercise.

**Prerequisites:** Day 658.
**Estimated study time:** 3 hours.

---

## Advisory Structure — The Full Format

```python
#!/usr/bin/env python3
"""
Security advisory structure — what every section must contain and why.
"""
from __future__ import annotations

ADVISORY_STRUCTURE = {
    "header": {
        "title":         "Short, precise — CVE ID + product + class. Not 'SQL injection found'.",
        "cve_id":        "CVE-YYYY-NNNNN — request via NVD, MITRE, or GitHub Security Advisories",
        "advisory_id":   "Your own internal ID (e.g. RESEARCHER-2025-001)",
        "cvss_v3_score": "e.g. 9.8 Critical",
        "cvss_vector":   "e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "date_reported": "When vendor was first notified",
        "date_published":"When advisory was published (after fix or deadline)",
        "author":        "Researcher name / organisation",
        "vendor_ack":    "Whether vendor acknowledged and provided credit",
    },
    "summary": {
        "purpose": "One paragraph. Describe: what the bug is, where it is, what it enables.",
        "must_include": [
            "Product name and version range (what is affected)",
            "Vulnerability class (e.g. heap buffer overflow, SQL injection)",
            "Attack vector (local, adjacent, network)",
            "Authentication required (none / low / high privilege)",
            "Worst-case impact (RCE, credential theft, DoS)",
        ],
        "must_NOT_include": [
            "Vague language ('may allow an attacker to')",
            "Unconfirmed impact ('might be exploitable')",
            "Excessive hedging ('under certain conditions')",
        ],
    },
    "affected_versions": {
        "format": "Exact version range. Inclusive bounds.",
        "examples": [
            "libfoo <= 2.3.1 (all versions prior to 2.3.2)",
            "product >= 4.0, <= 4.6.3",
            "commit range: abc123 through def456 (exclusive)",
        ],
        "important": "Test the fix commit — confirm the patched version is NOT affected.",
    },
    "vulnerability_details": {
        "root_cause":    "Exact code location, CWE, and why the code is wrong",
        "trigger":       "Exact input value or sequence that activates the bug",
        "code_excerpt":  "The vulnerable code, before the fix (annotated)",
        "data_flow":     "How attacker-controlled input reaches the vulnerable operation",
        "constraints":   "Any constraints on exploitation (auth required? file upload? etc.)",
    },
    "impact": {
        "primary":   "What can the attacker do? Be specific. 'Execute arbitrary code' not 'cause harm'",
        "secondary": "What data is accessible? What systems are reachable from there?",
        "scope":     "Single system or lateral movement possible?",
        "real_world_scenario": "A paragraph describing a realistic attack chain",
    },
    "proof_of_concept": {
        "requirements": [
            "Must be reproducible by the vendor's triage team",
            "Minimum steps — no noise, no unrelated setup",
            "Clearly labelled expected output (what proves the bug triggered)",
            "For crash PoC: include ASan output or stack trace",
            "For RCE PoC: show command execution or shell interaction",
        ],
        "disclosure_timing": "Full PoC: publish after patch. Partial PoC (crash only): may publish with advisory",
    },
    "remediation": {
        "primary_fix":  "Update to version X.Y.Z — always the first recommendation",
        "workaround":   "If patch not yet available: specific config change or component disable",
        "validation":   "How to confirm the fix: re-run the PoC command, confirm no crash",
        "root_cause_fix": "Describe what the correct fix should look like (helps vendor)",
    },
    "timeline": {
        "required_entries": [
            "YYYY-MM-DD: Vulnerability discovered",
            "YYYY-MM-DD: Vendor notified (include PGP hash or email timestamp if possible)",
            "YYYY-MM-DD: Vendor acknowledged",
            "YYYY-MM-DD: Patch released / Fix committed",
            "YYYY-MM-DD: Advisory published",
            "YYYY-MM-DD: CVE assigned (if applicable)",
        ],
        "purpose": "Demonstrates good faith; protects researcher if legal questions arise",
    },
    "credits": {
        "researcher":    "Your name (or handle) — decide before publishing",
        "vendor_credit": "Name any vendor engineers who helped coordinate",
        "references":    "CVE, patch commit, vendor bulletin, related CVEs",
    },
}

print("[*] ADVISORY STRUCTURE SUMMARY")
for section, content in ADVISORY_STRUCTURE.items():
    print(f"\n  [{section.upper()}]")
    if isinstance(content, dict) and "purpose" in content:
        print(f"    Purpose: {content['purpose']}")
    if isinstance(content, dict) and "must_include" in content:
        print("    Must include:")
        for item in content["must_include"][:3]:
            print(f"      → {item}")
```

---

## Stage 1 — Writing the CVSS Score

CVSS v3.1 is the language of severity. Get it wrong and your advisory loses
credibility. Every vector string must be justified in the advisory text.

```python
#!/usr/bin/env python3
"""
CVSS v3.1 scoring guide — common metric combinations and their justifications.
"""
from __future__ import annotations

CVSS_METRICS = {
    "AV": {
        "name": "Attack Vector",
        "N": "Network — attacker reaches via the network (e.g. web app, network service)",
        "A": "Adjacent — same network segment (e.g. LAN, Bluetooth, WiFi)",
        "L": "Local — attacker must have local access (e.g. logged-in user)",
        "P": "Physical — attacker must have physical access to device",
    },
    "AC": {
        "name": "Attack Complexity",
        "L": "Low — no special conditions; attack succeeds reliably",
        "H": "High — requires specific configuration, race condition, or non-default setup",
    },
    "PR": {
        "name": "Privileges Required",
        "N": "None — unauthenticated attacker",
        "L": "Low — regular user account",
        "H": "High — admin/root account required",
    },
    "UI": {
        "name": "User Interaction",
        "N": "None — no user action needed (server-side bug)",
        "R": "Required — victim must click, open a file, visit a page",
    },
    "S": {
        "name": "Scope",
        "U": "Unchanged — impact confined to vulnerable component",
        "C": "Changed — attacker can impact OTHER components (e.g. container escape)",
    },
    "C_I_A": {
        "name": "Confidentiality / Integrity / Availability",
        "H": "High — total loss; attacker reads all data / writes anything / full crash",
        "L": "Low — limited access; some data / partial integrity loss / partial crash",
        "N": "None — no impact on this metric",
    },
}

# Common real-world CVSS combinations:
COMMON_PATTERNS = [
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score":  "9.8 Critical",
        "type":   "Unauthenticated RCE (e.g. remote heap overflow)",
        "example_cve": "CVE-2021-44228 (Log4Shell)",
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "score":  "8.8 High",
        "type":   "Authenticated RCE (e.g. SQLi with RCE, requires login)",
        "example_cve": "CVE-2021-3156 (sudo heap overflow)",
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "score":  "6.1 Medium",
        "type":   "Reflected XSS (victim must click malicious link)",
        "example_cve": "Typical reflected XSS in web app",
    },
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "score":  "7.5 High",
        "type":   "Unauthenticated DoS (e.g. null deref in network parser)",
        "example_cve": "CVE-2019-20907 (Python tarfile infinite loop)",
    },
    {
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "score":  "7.8 High",
        "type":   "Local privilege escalation (requires local user)",
        "example_cve": "CVE-2021-4034 (pkexec local privesc)",
    },
]

print("[*] COMMON CVSS PATTERNS")
for p in COMMON_PATTERNS:
    print(f"\n  Type:    {p['type']}")
    print(f"  Vector:  {p['vector']}")
    print(f"  Score:   {p['score']}")
    print(f"  Example: {p['example_cve']}")

print("\n[!] CVSS COMMON MISTAKES:")
mistakes = [
    "Using AV:N when the attacker must be authenticated AND on the same segment (use AV:A)",
    "Using PR:N for 'guest' accounts — if a real account is needed, use PR:L",
    "Using C:H/I:H/A:H for a crash PoC without confirmed write primitive (use A:H, C:N, I:N)",
    "Ignoring S:C when a container escape lets attacker reach the host",
    "Setting AC:L for race conditions (race conditions are AC:H)",
]
for m in mistakes:
    print(f"  ✗ {m}")
```

---

## Stage 2 — Complete Advisory Template

```markdown
# Security Advisory: [CVE-YYYY-NNNNN] — [Product] [Vulnerability Class]

**Advisory ID:**    RESEARCHER-YYYY-NNN
**CVE ID:**         CVE-YYYY-NNNNN
**CVSS v3.1:**      X.X [Critical|High|Medium|Low]
**Vector:**         CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
**Discovered:**     YYYY-MM-DD
**Published:**      YYYY-MM-DD
**Author:**         [Your Name]

---

## Summary

A [vulnerability class] in [Product] versions [X.Y.Z through A.B.C] allows
[attacker type] to [impact]. An attacker who [prerequisite condition] can
[specific attack action], resulting in [concrete outcome].

## Affected Products

| Product | Affected Versions | Fixed Version |
|---|---|---|
| [Product Name] | <= X.Y.Z | X.Y.W |

## Vulnerability Details

**CWE:** CWE-NNN — [CWE Name]

**Root cause:** The function `vulnerable_func()` in `src/parser.c` (line NNN)
passes attacker-controlled input directly to `memcpy()` without first checking
that the source length does not exceed the destination buffer size.

**Vulnerable code (before fix):**

```c
// src/parser.c, line 142
// header[] is 256 bytes; len comes from attacker-controlled input field
memcpy(header, data, len);   // VULNERABLE: len not bounded
```

**Triggering condition:** The `len` field in the [format] header at offset [N]
is a 4-byte unsigned integer. When set to any value >= 256, the memcpy writes
past the end of the 256-byte `header` stack buffer.

**Data flow:**
1. Attacker sends crafted [format] file with header.len = 0xFFFFFFFF
2. `parse_header()` reads `len` directly from input
3. `memcpy(header, data, len)` copies 4,294,967,295 bytes → stack smash

## Impact

An unauthenticated remote attacker can send a crafted [format] file to any
service using [Product] as a parsing library. This causes a stack buffer
overflow, overwriting the saved return address. On systems without stack
canaries or with a weak ASLR implementation, this may be leveraged for
arbitrary code execution.

**Realistic attack scenario:** [Product] is embedded in many mail server
attachment parsers. A crafted attachment delivered via email triggers the
vulnerability in the parsing daemon without user interaction, potentially
allowing full server compromise.

## Proof of Concept

**Requirements:** Linux x86-64, vulnerable [Product] version [X.Y.Z], gcc.

**Build vulnerable version:**

```bash
git clone https://github.com/[project]/[product].git
cd [product]
git checkout [vulnerable_commit]
CFLAGS="-g -fsanitize=address" ./configure && make -j$(nproc)
```

**Generate PoC input:**

```python
#!/usr/bin/env python3
import struct

with open("poc.bin", "wb") as f:
    f.write(b"MAGIC")                  # File magic
    f.write(b"\x01\x00")              # Version
    f.write(struct.pack("<I", 0x200))  # len = 512 (overflows 256-byte buffer)
    f.write(b"A" * 512)               # Overflow payload

print("PoC written to poc.bin")
```

**Run PoC:**

```bash
python3 poc_gen.py
./vulnerable_binary poc.bin 2>&1 | head -20
```

**Expected output:**

```
=================================================================
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
WRITE of size 512 at 0x7fff... thread T0
    #0 0x... in parse_header src/parser.c:142
    #1 0x... in process_file src/main.c:87
    ...
```

## Remediation

**Recommended:** Update to [Product] version [X.Y.W] or later.

**Patch:** [link to fixing commit]

**Workaround (if patch unavailable):** Reject input files larger than [N] bytes
at the application layer before passing to [Product].

**Correct fix:** Add a bounds check before `memcpy()`:

```c
if (len >= sizeof(header)) {
    return PARSE_ERROR_OVERFLOW;
}
memcpy(header, data, len);
```

## Timeline

| Date | Event |
|---|---|
| YYYY-MM-DD | Vulnerability discovered during fuzzing campaign |
| YYYY-MM-DD | Initial notification sent to security@[vendor].com (PGP encrypted) |
| YYYY-MM-DD | Vendor acknowledged receipt |
| YYYY-MM-DD | Vendor confirmed vulnerability, CVE requested |
| YYYY-MM-DD | CVE-YYYY-NNNNN assigned |
| YYYY-MM-DD | Fix committed: [commit hash] |
| YYYY-MM-DD | Patched version [X.Y.W] released |
| YYYY-MM-DD | Advisory published |

## Credits

Discovered by [Researcher Name]. The [Vendor] security team responded
promptly and coordinated disclosure professionally.

## References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
- Fix commit: https://github.com/[project]/commit/[hash]
- Vendor bulletin: [URL]
- CWE-NNN: https://cwe.mitre.org/data/definitions/NNN.html
```

---

## Stage 3 — Writing Effective Impact Statements

The impact section separates a $500 report from a $10,000 report. Most
researchers write "can execute arbitrary code" and stop. Ghost's students
write what that means.

```python
#!/usr/bin/env python3
"""
Impact statement templates — how to articulate real-world consequences.
"""
from __future__ import annotations

IMPACT_TEMPLATES = {
    "RCE_unauthenticated": """
An unauthenticated remote attacker who can send [input type] to [service] can
execute arbitrary code as the [user] operating system account. In typical
deployments, [service] runs as [privilege level]. From this position, an
attacker can:

1. Install persistent backdoors (e.g. cron job, SSH key injection)
2. Access credentials stored in memory or configuration files
3. Pivot to internal systems reachable from [service] host
4. Exfiltrate [data type] processed by [service]

The attack requires no authentication and no user interaction. It can be
automated and exploited at scale against all unpatched deployments.
""",
    "SQLi_auth_bypass": """
An unauthenticated attacker can bypass authentication to the [application]
admin panel by submitting a crafted [username/password] field. Once
authenticated as an administrative user, the attacker can:

1. Access all user accounts and associated data (PII, [data types])
2. Modify application configuration
3. Leverage admin functionality to achieve further compromise (e.g. [specific
   admin feature] that permits file upload → RCE)

All [Product] deployments with a publicly accessible login endpoint are
affected. No special knowledge of the target system is required.
""",
    "DoS_network": """
An unauthenticated attacker who can send [input type] to port [N] can trigger
a NULL pointer dereference in [function()], causing the [service] process to
crash. The crash is 100% reproducible. In most deployments:

1. [Service] does not auto-restart by default — manual intervention required
2. The crash is triggerable in under 1 second with a 16-byte packet
3. This is exploitable as a denial-of-service against any public [service]

An attacker could maintain a persistent denial of service by repeatedly
triggering the crash with a script, effectively taking any unpatched [service]
offline indefinitely.
""",
    "IDOR_sensitive_data": """
An authenticated attacker with a standard user account can read the profile
data of any other user by modifying the `user_id` parameter from their own
ID to any other ID. No IDOR is present on write operations.

Data accessible per user record: [list the fields]. Across [N] users (per
vendor's stated user count), this allows mass enumeration of [data type].

This represents a direct violation of GDPR Article 5(1)(f) (integrity and
confidentiality) for EU users and may constitute a reportable data breach
if exploited.
""",
}

print("[*] IMPACT STATEMENT TEMPLATES")
for vuln_type, template in IMPACT_TEMPLATES.items():
    print(f"\n  [{vuln_type.upper()}]")
    first_line = template.strip().split("\n")[0]
    print(f"  {first_line[:100]}...")
```

---

## Stage 4 — Pre-Publication Checklist

```python
#!/usr/bin/env python3
"""
Advisory quality gate — check this before sending to vendor or publishing.
"""
from __future__ import annotations

PRE_PUBLISH_CHECKLIST = {
    "accuracy": [
        "Vulnerability is reproducible on a fresh environment",
        "Affected version range is confirmed (tested oldest and patched version)",
        "CVSS vector is justified by the actual exploit conditions",
        "CWE is correct for the root cause (not just the symptom)",
    ],
    "completeness": [
        "Summary states product, class, vector, and worst-case impact",
        "Timeline documents every vendor interaction with dates",
        "PoC includes exact commands, not just a description",
        "Remediation section includes the fix version AND a workaround",
        "Credits section correctly attributes the discovery",
    ],
    "safety": [
        "PoC does NOT include weaponised exploit (RIP chain, shellcode) until after patch",
        "No third-party PII or customer data included in advisory examples",
        "Advisory does not reveal details of vendor's internal systems",
        "Vendor has been given the full coordinated-disclosure window",
    ],
    "legal": [
        "All research was performed in an authorised environment",
        "No systems beyond the scope of testing were accessed",
        "No data was downloaded beyond what was necessary to confirm the bug",
        "Disclosure timeline is documented for legal reference",
    ],
    "professional": [
        "No inflammatory language ('dangerous incompetent vendor', etc.)",
        "No speculation about exploitation in the wild without evidence",
        "References link to official sources (NVD, vendor bulletin, commit)",
        "Grammar and spelling reviewed — this is a professional document",
    ],
}

print("[*] ADVISORY PRE-PUBLICATION CHECKLIST")
all_pass = True
for category, items in PRE_PUBLISH_CHECKLIST.items():
    print(f"\n  [{category.upper()}]")
    for item in items:
        # Simulate all-pass in teaching context:
        status = "✓"
        print(f"    {status} {item}")

print("\n[*] All checks passed — advisory is ready for publication")
```

---

## Key Takeaways

1. **The impact statement is the advisory.** Triage engineers read the Summary
   and Impact first. If those sections do not clearly describe what an attacker
   can do and why it matters, the rest of the advisory will not be read carefully.
   Write the impact before you write anything else.
2. **The timeline is your legal protection.** A documented disclosure timeline
   showing when you notified the vendor, when they responded, and when you
   published proves good faith if a vendor or prosecutor later claims you acted
   irresponsibly. Every step gets a date.
3. **CVSS is an argument, not a calculation.** Each metric in the CVSS vector
   corresponds to a real property of the vulnerability. Every metric choice should
   be defensible against a sceptical triage engineer. "AV:N because the vulnerable
   service listens on TCP/443" is a justification. "AV:N because it's on the
   internet" is not.
4. **Publish the minimal PoC first.** A crash PoC (demonstrates the bug exists)
   is appropriate to publish alongside the advisory. A weaponised PoC (gives an
   attacker a working exploit) should wait until the patch is widely deployed —
   typically 7–14 days after the patched version is available. This distinction
   protects users while still giving defenders what they need to detect exploitation.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q659.1, Q659.2 …).

---

## Navigation

← Previous: [Day 658 — Responsible Disclosure Deep Dive](DAY-0658-Responsible-Disclosure-Deep-Dive.md)
→ Next: [Day 660 — Static Analysis with Semgrep and CodeQL](DAY-0660-Static-Analysis-Semgrep-CodeQL.md)
