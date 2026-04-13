---
title: "Email, People and LinkedIn OSINT — Harvesting, Metadata, Breach Data"
tags: [osint, email-harvesting, linkedin, people-recon, document-metadata, exiftool, FOCA,
       theHarvester, hunter-io, breach-data, T1591, T1596]
module: 02-Recon-01
day: 55
related_topics:
  - Domain DNS and Certificate Transparency (Day 054)
  - GitHub Code Recon and Secret Hunting (Day 056)
  - Social Media and Job Posting Intel (Day 058)
  - MITRE ATT&CK T1591 (Gather Victim Org Information)
  - MITRE ATT&CK T1597 (Search Closed Sources)
---

# Day 055 — Email, People and LinkedIn OSINT

## Goals

By the end of this lesson you will be able to:

1. Harvest email addresses for a target organisation using theHarvester and Hunter.io.
2. Infer an organisation's email format from a small sample of known addresses.
3. Conduct targeted LinkedIn OSINT without triggering profile view notifications.
4. Extract author metadata from PDF and Office documents using `exiftool`.
5. Check for breach exposure of harvested email addresses via HaveIBeenPwned API.
6. Explain how people recon escalates to credential attacks (Day 057+).

---

## Prerequisites

- [Day 054 — Domain DNS and Certificate Transparency](DAY-0054-Domain-DNS-and-Certificate-Transparency.md)

---

## Main Content

### 1. Why People Are the Attack Surface

Every technical control can be bypassed given enough time. The fastest path
into most organisations is through the people who already have access.

**What people recon enables:**
- **Phishing:** Targeted emails to specific individuals, impersonating colleagues
- **Credential stuffing:** Email addresses + breach passwords = real account access
- **Password spraying:** Email list + one common password = compromise 1–5% of accounts
- **Social engineering:** Call the helpdesk, impersonate a known employee
- **Spearphishing:** Reference the target's manager, project, or colleague to add
  credibility

In bug bounty, people recon is used differently — not to attack people, but to
understand the organisation's structure, technology choices, and potential misconfigurations
that stem from personnel decisions.

---

### 2. Email Harvesting

#### theHarvester

theHarvester queries search engines, LinkedIn, and public databases to find email
addresses, subdomains, and employee names associated with a domain.

```bash
# Install (Kali: pre-installed)
pip install theHarvester  # or: apt install theharvester

# Basic query — Google source only
theHarvester -d acmecorp.com -b google -l 200

# Query multiple sources
theHarvester -d acmecorp.com -b google,bing,duckduckgo,crtsh,securitytrails

# All available sources
theHarvester -d acmecorp.com -b all -l 500

# Save to HTML report
theHarvester -d acmecorp.com -b google -f acmecorp_harvest.html

# Key output sections:
# [*] Emails found:
#     john.smith@acmecorp.com
#     j.smith@acmecorp.com
#     security@acmecorp.com
#
# [*] Hosts found:
#     api.acmecorp.com:203.0.113.45
#     mail.acmecorp.com:203.0.113.20
```

**theHarvester data sources (useful ones):**

| Source | Type | Notes |
|---|---|---|
| `google` | Search engine | Email addresses in indexed pages |
| `bing` | Search engine | Sometimes finds different results |
| `duckduckgo` | Search engine | Privacy-respecting, different index |
| `linkedin` | Social network | Names and roles (no scraping) |
| `crtsh` | CT logs | Subdomains |
| `securitytrails` | DNS/passive DNS | Subdomains and historical data |
| `shodan` | Internet scanning | Open services |
| `virustotal` | Threat intel | Subdomains |
| `hunter` | Email | Requires Hunter.io API key |

---

#### Hunter.io

Hunter.io specialises in email discovery. It indexes publicly available email
addresses and infers email format patterns from them.

```bash
# Install the Python library
pip install hunter

# Or use the API directly
HUNTER_KEY="your_api_key"

# Find all emails for a domain
curl -s "https://api.hunter.io/v2/domain-search?domain=acmecorp.com&api_key=$HUNTER_KEY" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Email format: {data[\"data\"][\"pattern\"]}')
print(f'Total emails: {data[\"data\"][\"total\"]}')
for e in data['data']['emails']:
    print(f'  {e[\"value\"]} — {e.get(\"first_name\",\"\")} {e.get(\"last_name\",\"\")} '
          f'({e.get(\"position\",\"\")})')
"

# Verify a specific email address exists
curl -s "https://api.hunter.io/v2/email-verifier?email=john.smith@acmecorp.com&api_key=$HUNTER_KEY"
```

**Email format inference:**

Once you have 3–5 confirmed email addresses, you can often infer the pattern:
- `john.smith@acmecorp.com` → format: `{first}.{last}`
- `jsmith@acmecorp.com` → format: `{first_initial}{last}`
- `j.smith@acmecorp.com` → format: `{first_initial}.{last}`

Then build a wordlist from LinkedIn employee names (Section 3).

---

#### phonebook.cz

A specialised tool that searches for email addresses across breach data,
Pastebin, and public sources. No API key required for basic use.

```bash
curl -s "https://phonebook.cz/" # Use via web browser
# Search: "acmecorp.com" in the email search
```

---

### 3. LinkedIn OSINT

LinkedIn is the most valuable people intelligence source for corporate targets.
The challenge is gathering intel without revealing your identity.

#### What LinkedIn Reveals

- Full name and role of every employee willing to be listed
- Reporting structure (who reports to whom)
- Technology skills and endorsements (reveals internal tech stack)
- Job duration (long-tenured sysadmins know where bodies are buried)
- Former employees (may retain access or have insider knowledge)
- Recent hires in security = recent breach? or known gap?

#### Doing It Without Leaving Footprints

```
1. LinkedIn Private Mode:
   Settings → Visibility → Profile viewing options → Private mode

   In private mode, you appear as "LinkedIn Member" in profile viewers.
   You lose the ability to see WHO viewed your profile — trade-off.

2. Google dorking instead of direct LinkedIn search:
   site:linkedin.com/in "acmecorp" "senior engineer"
   site:linkedin.com/in "acmecorp" "devops" OR "infrastructure"
   site:linkedin.com/in "acmecorp" "security" "manager"

   This queries Google's cache of LinkedIn profiles — does NOT record your
   LinkedIn profile view.

3. Wayback Machine for deleted profiles:
   https://web.archive.org/web/*/linkedin.com/in/target-person
```

#### Extracting Intelligence from LinkedIn Profiles

For each employee found, record:

```
Name:         John Smith
Title:        Senior Platform Engineer
Company:      AcmeCorp (since 2019)
Technologies: AWS, Terraform, Kubernetes, PostgreSQL, GitLab
Education:    CS degree from State University
Connections:  420
Recent post:  "Excited to be at KubeCon next week"

Intel value:
  - AWS/Kubernetes/Terraform → cloud infrastructure tech stack confirmed
  - PostgreSQL → database technology
  - GitLab → CI/CD platform (not GitHub)
  - KubeCon post → target will be away from desk; reduced IR capacity
```

#### Building an Org Chart

From LinkedIn searches, reconstruct the reporting structure:

```
AcmeCorp
├── CEO: Mark Chen
├── CTO: Sarah Williams
│   ├── VP Engineering: David Park
│   │   ├── Engineering Manager (Backend): Alice Torres
│   │   └── Engineering Manager (Platform): John Smith ← our sysadmin
│   └── VP Security: James Lee
│       └── Security Engineer: Michael Brown ← knows where the vulns are
└── CFO: Jennifer Wu
```

This org chart is pure OSINT. It tells you exactly who to phish (if authorised),
whose credentials are most valuable (VP Security), and who manages the infrastructure.

---

### 4. Document Metadata — Exiftool and FOCA

Documents published by an organisation leak metadata: author names, internal
usernames, software versions, file paths, and sometimes geolocation data.

#### Finding Documents

```bash
# Google dork for documents
site:acmecorp.com filetype:pdf
site:acmecorp.com filetype:docx OR filetype:xlsx OR filetype:pptx
site:acmecorp.com filetype:doc "internal" OR "confidential"
```

#### Extracting Metadata with exiftool

```bash
# Install
apt install libimage-exiftool-perl  # Debian/Ubuntu
brew install exiftool               # macOS

# Analyse a single file
exiftool document.pdf

# Key fields to look for:
exiftool document.pdf | grep -iE "author|creator|producer|company|last.modified.by|software"

# Example output from a leaked PDF:
# Author                          : j.smith
# Creator                         : Microsoft Word 2016
# Producer                        : Acrobat PDFMaker 18 for Word
# Company                         : AcmeCorp Internal
# Last Modified By                : jsmith@ACMECORP-DESKTOP
#                                   ↑ Internal hostname reveals domain name format

# Bulk analysis of downloaded files
exiftool *.pdf | grep -A 20 "======" | grep -iE "author|company|creator"
```

**Intel extracted:**
- `j.smith` → email format candidate: `j.smith@acmecorp.com`
- `jsmith@ACMECORP-DESKTOP` → Active Directory domain name is `ACMECORP`
- Internal hostname format for network recon
- Software versions for vulnerability research

#### FOCA (Fingerprinting Organisations with Collected Archives)

FOCA is a Windows-based tool that automates document metadata extraction and
analysis. It:
1. Google dorks for documents on a target domain
2. Downloads them automatically
3. Extracts and correlates metadata
4. Builds a user list, server list, and email list

```
Available at: https://github.com/ElevenPaths/FOCA
Platform: Windows only
Alternative: Run via WINE or in a Windows VM
```

---

### 5. Breach Data — HaveIBeenPwned

Once you have a list of email addresses, check which have been exposed in
known data breaches. Breach exposure means:

1. Passwords from old breaches may still be in use (password reuse is ~30–60%)
2. Historical passwords reveal password patterns (e.g., `Company1!`, `Company2021!`)
3. Email addresses confirm the email format

```bash
# HaveIBeenPwned API v3 (requires paid API key for bulk lookups)
HIBP_KEY="your_api_key"

check_email() {
    local email="$1"
    response=$(curl -s -H "hibp-api-key: $HIBP_KEY" \
        -H "user-agent: recon-research" \
        "https://haveibeenpwned.com/api/v3/breachedaccount/$email")
    if [ "$response" != "" ]; then
        echo "[BREACHED] $email"
        echo "$response" | python3 -c "
import json, sys
breaches = json.load(sys.stdin)
for b in breaches:
    print(f'  - {b[\"Name\"]} ({b[\"BreachDate\"]}): {b[\"DataClasses\"]}')
"
    else
        echo "[CLEAN] $email"
    fi
    sleep 1.6  # Rate limit: max 1 request per 1.5 seconds
}

# Check a list of emails
while IFS= read -r email; do
    check_email "$email"
done < email_list.txt
```

**Ethics note:** Use HIBP only to understand the exposure risk of a target's
employees for your report — not to obtain or use actual breach credentials.
The relevant bug bounty finding is "X% of employees have been exposed in known
breaches" — not "here are their passwords."

---

### 6. Building the People Intelligence Product

After running all techniques above, consolidate into a people intel document:

```markdown
## People Intelligence — AcmeCorp

### Email Format
Pattern: {first}.{last}@acmecorp.com
Confidence: High (confirmed from 8 known addresses)
Alternate: {f}{last}@acmecorp.com (observed in 2 cases — may be legacy)

### Key Personnel
| Name | Role | Email | Breach Exposure | Tech Skills |
|---|---|---|---|---|
| Sarah Williams | CTO | s.williams@acmecorp.com | YES (LinkedIn, 2021) | AWS, Go, Kubernetes |
| James Lee | VP Security | j.lee@acmecorp.com | NO | SIEM, Splunk |
| John Smith | Platform Eng | j.smith@acmecorp.com | YES (Adobe, 2013) | AWS, Terraform |

### Document Metadata Findings
- 14 PDFs downloaded from acmecorp.com/resources/
- Active Directory domain: ACMECORP (from 3 document hostnames)
- Internal username format: {f}{last} (matches j.smith, mwilson pattern)
- Office version: Microsoft Office 2019 (from Word documents)

### Breach Summary
- 5/12 email addresses found in HIBP
- Most common breach: LinkedIn (2021) — passwords in scope
- Recommendation: Password spray with LinkedIn-era common patterns
  (FOR AUTHORISED ENGAGEMENT ONLY)
```

---

## Key Takeaways

1. **People are the attack surface that never patches.** A server can be updated;
   a human using `Company2021!` as their password cannot be forced to change
   behaviour without policy enforcement.
2. **Email format is a multiplier.** Knowing the email format + LinkedIn employee
   list = a full credential target list for spraying or phishing. One format inference
   from 5 known addresses creates 500 potential targets.
3. **Document metadata is often overlooked.** IT teams harden web apps; they
   rarely scrub metadata from PDFs posted to the company website. Internal hostnames
   and usernames from documents are consistently useful.
4. **Breach data closes the loop.** Passive recon + breach exposure means you can
   assess the concrete risk of credential-based compromise without sending a single
   packet to the target.
5. **LinkedIn OSINT without a LinkedIn login (via Google dorks) leaves no
   footprint.** Use this technique before ever touching LinkedIn directly.

---

## Exercises

### Exercise 1 — Email Harvesting

For `hackerone.com`:

1. Run `theHarvester -d hackerone.com -b google,bing -l 200`.
2. How many unique email addresses did you find?
3. What email format does HackerOne appear to use?
4. Are any of those emails in HIBP? (Use the web interface for individual checks)

---

### Exercise 2 — Document Metadata

1. Download any publicly available PDF from a company's website (e.g., an annual
   report, a white paper).
2. Run `exiftool filename.pdf`.
3. List every piece of intelligence you can extract from the metadata.
4. Which findings would be useful for a phishing engagement? Which for network recon?

---

### Exercise 3 — LinkedIn Org Chart

For a company of your choice:

1. Using Google dorks only (`site:linkedin.com/in`), find 5 employees.
2. Build a partial org chart from their titles and connections.
3. Identify which role would be the most valuable target for a social engineering
   engagement and explain why.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 054 — Domain, DNS and Certificate Transparency](DAY-0054-Domain-DNS-and-Certificate-Transparency.md)*
*Next: [Day 056 — GitHub Code Recon and Secret Hunting](DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md)*
