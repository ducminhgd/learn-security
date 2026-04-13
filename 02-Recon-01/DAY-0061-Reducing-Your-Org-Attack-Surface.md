---
title: "Reducing Your Org Attack Surface — Blue Team Hardening for Passive Recon Exposure"
tags: [defensive, blue-team, attack-surface, hardening, DNS, WHOIS-privacy, github-secret-scanning,
       CT-monitoring, DMARC, data-minimisation, recon-detection]
module: 02-Recon-01
day: 61
related_topics:
  - Passive Recon Lab (Day 060)
  - Subdomain Takeover and Dangling DNS (Day 062)
  - Detecting Recon (Day 073 — 02-Recon-02)
  - The Ghost Method: Harden Stage
---

# Day 061 — Reducing Your Org Attack Surface

## Goals

By the end of this lesson you will be able to:

1. Apply the Ghost Method's Harden stage to passive recon exposure.
2. Google dork your own organisation and identify what attackers would find.
3. Implement DNS hardening controls: DNSSEC, CAA records, SPF/DKIM/DMARC.
4. Configure GitHub organisation controls to reduce secret exposure.
5. Set up Certificate Transparency monitoring for proactive subdomain discovery.
6. Produce an actionable hardening checklist for a security team to execute.

---

## Prerequisites

- [Day 060 — Passive Recon Lab](DAY-0060-Passive-Recon-Lab.md)

---

## Main Content

> "The best time to run passive recon on your own organisation is before
> the attacker does. The second best time is right now."
>
> — Ghost

### 1. Audit Your Own Exposure

Before hardening, understand what is already out there. Run the same techniques
against your own organisation that you practiced in Days 051–060.

#### The Self-Dork Checklist

Run every one of these against `site:yourcompany.com`:

```bash
ORG="yourcompany.com"

# Open directories
# site:$ORG intitle:"index of"

# Exposed files
# site:$ORG filetype:env OR filetype:sql OR filetype:log OR filetype:bak

# Configuration files
# site:$ORG filetype:xml intext:"password" OR filetype:json intext:"api_key"

# Login portals you did not know about
# site:$ORG inurl:admin OR inurl:login OR inurl:dashboard OR inurl:signin

# Error pages revealing technology
# site:$ORG intext:"stack trace" OR intext:"SQL syntax"

# Subdomains Google has indexed
# site:*.$ORG -site:www.$ORG
```

For each result: categorise as (a) expected and acceptable, (b) unexpected but
acceptable, or (c) unexpected and concerning. Category (c) items are your
remediation backlog.

---

### 2. DNS Hardening

#### DNSSEC — Prevent DNS Spoofing

DNSSEC adds cryptographic signatures to DNS responses, preventing cache poisoning.

```bash
# Check current DNSSEC status
dig DS yourcompany.com +short
dig DNSKEY yourcompany.com +short

# If no output: DNSSEC is not configured.

# Implementation: Enable in your DNS registrar / DNS provider dashboard.
# Route53: Hosted zone → Enable DNSSEC
# Cloudflare: DNS → DNSSEC tab → Enable
# GoDaddy: DNS Management → DNSSEC → Activate
```

DNSSEC does not protect against subdomain takeover (Day 062) — it protects
against external cache poisoning attacks.

---

#### CAA Records — Restrict Certificate Issuance

CAA (Certification Authority Authorisation) records restrict which CAs can issue
certificates for your domain. Without CAA records, any CA can issue a certificate
for your domain.

```bash
# Current CAA record
dig CAA yourcompany.com +short

# Correct CAA configuration (add via your DNS provider):
# Allow only Let's Encrypt and DigiCert:
yourcompany.com.  CAA  0 issue "letsencrypt.org"
yourcompany.com.  CAA  0 issue "digicert.com"
yourcompany.com.  CAA  0 issuewild "letsencrypt.org"
yourcompany.com.  CAA  0 iodef "mailto:security@yourcompany.com"

# The iodef field sends violation notifications to your security team.
```

Without CAA, an attacker with control of your DNS (or through a misconfigured
CA's domain validation process) could issue a certificate for your domain.

---

#### SPF, DKIM, and DMARC — Prevent Email Spoofing

An email attacker impersonating `yourcompany.com` in a phishing campaign is
possible when these three are not configured correctly.

```bash
# Check current state
dig TXT yourcompany.com +short | grep -E "v=spf1|dmarc|dkim"
dig TXT _dmarc.yourcompany.com +short

# Ideal configuration:

# SPF — list all authorised sending sources, reject all others
yourcompany.com.  TXT  "v=spf1 include:_spf.google.com ip4:203.0.113.5 -all"
# -all means: REJECT mail from senders not in this list
# ~all (softfail) means: MARK but do not reject — weak protection

# DMARC — enforce SPF and DKIM alignment, report violations
_dmarc.yourcompany.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@yourcompany.com; ruf=mailto:dmarc-forensic@yourcompany.com; fo=1"
# p=reject: actual enforcement — do not use p=none in production
# p=none: monitoring only — does NOT prevent spoofing

# DKIM: Configure in your email provider (Google Workspace, O365)
# and publish the public key as a TXT record:
selector1._domainkey.yourcompany.com.  TXT  "v=DKIM1; k=rsa; p=MIG..."
```

**Common mistake:** Setting `p=none` in DMARC and thinking you are protected.
`p=none` means "monitor but allow." An attacker can still spoof your domain.
The correct setting is `p=reject`.

---

### 3. WHOIS Privacy

WHOIS data exposed personal registrant information publicly until GDPR (2018)
and CCPA drove widespread adoption of privacy services.

```bash
# Check current WHOIS exposure
whois yourcompany.com | grep -iE "registrant|tech|admin" | head -20

# If personal data is visible:
# 1. Enable registrar privacy service (GoDaddy, Namecheap, Google Domains all offer this)
# 2. This replaces personal contact info with the registrar's privacy service contact
# 3. Name servers remain visible — this is unavoidable and acceptable

# What attackers still get even with WHOIS privacy:
#   - Registrar name
#   - Name servers (authoritative DNS)
#   - Creation / update / expiry dates
#   - DNSSEC status
# → These are acceptable. Personal email and physical address are not.
```

---

### 4. GitHub Organisation Hardening

#### Organisation Settings

```
Settings → Security → Push protection:    ENABLE
Settings → Security → Secret scanning:    ENABLE
Settings → Security → Code scanning:      ENABLE (with CodeQL)
Settings → Member privileges:
  Base permissions:      None (not Read)
  Fork creation:         Disabled
  Private fork creation: Disabled
Settings → Code security and analysis:
  Dependency graph:      Enabled
  Dependabot alerts:     Enabled
  Dependabot security updates: Enabled
```

#### Branch Protection

```
Protect main / master branches:
  ✓ Require pull request reviews before merging
  ✓ Require status checks to pass before merging
  ✓ Require signed commits (GPG)
  ✓ Do not allow force pushes
  ✓ Do not allow deletions
```

#### Secret Scanning

GitHub's built-in secret scanning detects 200+ secret types automatically.
When it detects a secret:
1. It notifies the repository owner
2. It can automatically revoke secrets for supported providers (GitHub tokens,
   AWS keys, etc.)
3. Push protection can block the commit before it enters the repository

```bash
# Also run gitleaks as a CI check
# .github/workflows/secret-scan.yml:
name: Secret Scanning
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Auditing Historical Commits

Even with push protection enabled, secrets from before the policy was enforced
may remain in history:

```bash
# Audit your own organisation's repos
trufflehog github --org=yourcompany --only-verified

# For found secrets:
# 1. REVOKE the secret immediately at the provider
# 2. Remove from history with git-filter-repo (not git filter-branch)
pip install git-filter-repo
git filter-repo --path-glob '*.env' --invert-paths  # Remove .env from ALL history
git push --force --all  # Requires all team members to re-clone
```

---

### 5. Certificate Transparency Monitoring

CT logs are public — which means your new certificates are visible to attackers
immediately. Turn this into a defensive advantage by monitoring CT logs for
unexpected certificate issuance.

**Why this matters:** An attacker who successfully takes over a subdomain may
issue a certificate for it. A CT alert for `attacker.yourcompany.com` will tell
you before they can use it.

#### Free CT Monitoring Options

**1. Facebook CT Monitor (free):**

```
URL: https://developers.facebook.com/tools/ct/
Add: yourcompany.com and *.yourcompany.com
→ Receive email alerts for new certificate issuance
```

**2. certstream (real-time CT stream):**

```bash
pip install certstream

# Monitor live CT log stream for your domain
python3 - <<'EOF'
import certstream

def callback(message, context):
    if message["message_type"] == "certificate_update":
        domains = message["data"]["leaf_cert"]["all_domains"]
        for domain in domains:
            if "yourcompany.com" in domain:
                print(f"[CT Alert] New cert: {domain}")
                print(f"  Issued by: {message['data']['leaf_cert']['issuer']['O']}")

certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
EOF
```

**3. Sectigo Certificate Transparency Monitor:**
```
https://crt.sh/alerts
→ Email alerts for new certificates matching a domain pattern
```

---

### 6. Sensitive Information Removal

#### What Should NOT Be Publicly Indexed

Audit these and remove or restrict access:

| Item | How to remove | Priority |
|---|---|---|
| `.env` files accessible via HTTP | Block in nginx/apache config | Critical |
| Exposed backup files (`*.bak`, `*.sql`, `*.old`) | Remove from public web root | Critical |
| Directory listing enabled | `Options -Indexes` in Apache; `autoindex off` in nginx | High |
| Error pages with stack traces | Configure production error handlers | High |
| Internal API documentation accessible publicly | Move behind auth | High |
| Old subdomain with forgotten content | Remove DNS record | Medium |
| Employee photos with embedded GPS metadata | Strip metadata before publishing | Low |

#### nginx Configuration for Hardening

```nginx
server {
    # Disable server version disclosure
    server_tokens off;

    # Block access to sensitive file types
    location ~* \.(env|sql|bak|log|conf|config|ini|old|orig|backup)$ {
        deny all;
        return 404;
    }

    # Disable directory listing
    autoindex off;

    # Block hidden files (dot-files)
    location ~ /\. {
        deny all;
        return 404;
    }

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

---

### 7. Job Posting Hygiene

Job postings are an unavoidable intelligence source — you cannot hire without
advertising. But you can reduce what you reveal.

**Principles:**
- Do NOT include specific version numbers: "Python 3.10" not just "Python"
  is fine; "PostgreSQL 14.3 on AWS RDS r6g.xlarge" is more than needed.
- Do NOT mention specific internal tools: "our internal deployment system" vs
  "GitHub Actions and ArgoCD running on EKS 1.27"
- Generalise infrastructure: "AWS" not "AWS us-east-1 with EKS and RDS"
- Never reference specific CVE classes you are solving: "We recently had a
  security incident and need someone to fix X" tells attackers where to look

---

## Hardening Checklist

Produce this checklist for your (or a hypothetical) organisation and rate
current state as: ✅ Done, ⚠️ Partial, ❌ Not done, ℹ️ N/A.

```markdown
## Passive Recon Hardening Checklist

### DNS
[ ] DNSSEC enabled and validated
[ ] CAA records restrict certificate issuance to known CAs
[ ] SPF record with -all (hard fail)
[ ] DKIM configured and published
[ ] DMARC at p=reject (not p=none)
[ ] No zone transfer possible from authoritative nameservers
[ ] WHOIS registrant privacy enabled

### Web Server
[ ] Server version not disclosed (Server: header removed/generic)
[ ] Directory listing disabled
[ ] Sensitive file types blocked (.env, .sql, .bak, .log)
[ ] Security headers present (HSTS, X-Frame-Options, CSP)
[ ] robots.txt does not expose internal paths beyond /admin

### GitHub / Source Control
[ ] Secret scanning enabled on all repos
[ ] Push protection enabled
[ ] Historical commits scanned for secrets
[ ] Found secrets revoked and removed from history
[ ] Base organisation permissions set to None
[ ] Branch protection enabled on main/master

### Certificate Transparency
[ ] CT monitoring configured (email alerts for new certs)
[ ] Recent CT log results audited for unexpected issuance

### Cloud Storage
[ ] All S3/Blob/GCP buckets reviewed for public access
[ ] Bucket ACLs set to deny public access by default
[ ] AWS S3 Block Public Access enabled at account level
[ ] No public bucket listing (even for CDN assets)
[ ] Firebase security rules prevent unauthenticated read

### People / HR
[ ] WHOIS privacy enabled for all registered domains
[ ] Company-published documents metadata-stripped
[ ] Security awareness training includes OSINT risks
[ ] Offboarding includes API key and access token revocation

### Monitoring
[ ] Google Alert configured for company name + "breach"
[ ] CT log monitoring active
[ ] GitHub secret scanning alerts routed to security team
[ ] DMARC reports reviewed regularly
```

---

## Key Takeaways

1. **Run passive recon against yourself before the attacker does.** A 4-hour
   self-audit using the same techniques from Days 051–060 will reveal more
   actionable findings than most external audits.
2. **DMARC at `p=reject` is the one configuration change that prevents the
   most email-based attacks.** Most organisations run `p=none` and think they
   are protected. They are not.
3. **CT log monitoring converts a passive-recon advantage into a defensive
   alert.** New certificates for unexpected subdomains are an early warning
   of takeover or shadow IT.
4. **Git history is your organisation's biggest secret exposure.** Secret
   scanning running today does not help with a key committed in 2019 that is
   still in history. You need to audit history, not just current state.
5. **The most effective hardening is reducing what exists**, not adding controls
   to protect what should not be there. Remove old subdomains, revoke unused
   API keys, delete abandoned repositories.

---

## Exercises

### Exercise 1 — Self-Dork

Run the six Google dork categories from Section 1 against a domain you own
or control (e.g., a personal project domain or a practice domain).

Document every finding and categorise it as: acceptable, unexpected-acceptable,
or concerning.

---

### Exercise 2 — DNS Hardening Audit

For `yourcompany.com` (use any public company for practice):

1. Check DNSSEC status: `dig DS target.com +short`
2. Check CAA records: `dig CAA target.com +short`
3. Check DMARC: `dig TXT _dmarc.target.com +short`
4. Is SPF set to `-all` or `~all`?
5. Rate the DNS hardening: Strong / Moderate / Weak / None. Justify.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 060 — Passive Recon Lab](DAY-0060-Passive-Recon-Lab.md)*
*Next: [Day 062 — Subdomain Takeover and Dangling DNS](DAY-0062-Subdomain-Takeover-and-Dangling-DNS.md)*
