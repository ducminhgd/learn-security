---
title: "Subdomain Takeover and Dangling DNS — CNAME Hijack, NS Takeover, Detection"
tags: [recon, subdomain-takeover, dangling-dns, CNAME, NS-takeover, subjack, nuclei,
       can-i-take-over-xyz, bug-bounty, T1584, detection, hardening]
module: 02-Recon-01
day: 62
related_topics:
  - Reducing Your Org Attack Surface (Day 061)
  - Domain DNS and Certificate Transparency (Day 054)
  - Active Recon (02-Recon-02)
  - MITRE ATT&CK T1584.001 (Compromise Infrastructure: Domains)
---

# Day 062 — Subdomain Takeover and Dangling DNS

## Goals

By the end of this lesson you will be able to:

1. Explain precisely how a CNAME-based subdomain takeover occurs.
2. Distinguish between CNAME takeover, NS takeover, and A record-based takeover.
3. Use `subjack` and `nuclei` to scan for subdomain takeover candidates.
4. Reproduce a CNAME takeover proof-of-concept against a controlled lab target.
5. Explain the business impact of subdomain takeover (STS header bypass, cookie
   stealing, phishing credibility).
6. Implement detection and remediation for dangling DNS records.

---

## Prerequisites

- [Day 054 — Domain, DNS and Certificate Transparency](DAY-0054-Domain-DNS-and-Certificate-Transparency.md)
- [Day 061 — Reducing Your Org Attack Surface](DAY-0061-Reducing-Your-Org-Attack-Surface.md)

---

## Main Content

### 1. What Is Subdomain Takeover?

A subdomain takeover occurs when:

1. An organisation has a DNS record (typically CNAME) pointing to a third-party
   service.
2. That third-party service no longer exists (deprovisioned, plan cancelled,
   service shut down).
3. The DNS record is never cleaned up — it becomes "dangling."
4. An attacker registers the resource at the third-party service.
5. The subdomain now points to content controlled by the attacker.

```
BEFORE (legitimate):
  marketing.acmecorp.com  CNAME  acmecorp.github.io
  acmecorp.github.io      → GitHub Pages serving acmecorp's content

ORGANISATION REMOVES GITHUB PAGES BUT FORGETS TO REMOVE DNS RECORD:
  marketing.acmecorp.com  CNAME  acmecorp.github.io
  acmecorp.github.io      → GitHub: "There is no GitHub Pages site here."
  ↑ DANGLING CNAME — the DNS record has nowhere to go.

ATTACKER CREATES GitHub account "acmecorp" and publishes a GitHub Pages site:
  marketing.acmecorp.com  CNAME  acmecorp.github.io
  acmecorp.github.io      → ATTACKER'S GitHub Pages content
  ↑ SUBDOMAIN TAKEOVER — attacker controls marketing.acmecorp.com
```

---

### 2. The Ghost Method Applied

#### Recon (Stage 1)

Understand how CNAME chains work and where dangling records hide.

```bash
# A CNAME chain:
dig CNAME subdomain.target.com +short
# → third-party-service.io

dig A third-party-service.io +short
# → 203.0.113.50  (if resolves → probably not dangling)
# → NXDOMAIN     (if does not resolve → DANGLING — potential takeover)
```

#### Exploit (Stage 2)

Register the resource at the third-party provider and serve content.

**Lab example with GitHub Pages:**

```bash
# Scenario: staging.target.com CNAME staging-target.github.io
# GitHub account "staging-target" does not exist.

# Step 1: Create GitHub account "staging-target"
# Step 2: Create a repository named staging-target.github.io
# Step 3: Enable GitHub Pages for the repository
# Step 4: Add a CNAME file containing "staging.target.com"
# Step 5: Verify:
curl https://staging.target.com
# → Attacker's content served under target.com domain
```

#### Detect (Stage 3)

Build detection for dangling CNAME chains in your DNS.

#### Harden (Stage 4)

Remove dangling records before an attacker can register the target resource.

---

### 3. Services Vulnerable to CNAME Takeover

The authoritative list is maintained at:
**https://github.com/EdOverflow/can-i-take-over-xyz**

This repository tracks which third-party services are vulnerable to subdomain
takeover and what fingerprint to look for.

| Service | Fingerprint (page response when dangling) | Takeover possible? |
|---|---|---|
| GitHub Pages | `There isn't a GitHub Pages site here.` | Yes |
| AWS S3 (US East) | `NoSuchBucket` | Yes |
| Heroku | `No such app` | Yes |
| Fastly | `Fastly error: unknown domain` | Yes |
| Azure App Service | `404 Web Site not found` | Yes |
| Shopify | `Sorry, this shop is currently unavailable.` | Yes |
| Pantheon | `The gods are wise, but do not know of the domain...` | Yes |
| Zendesk | `Help Center Closed` | Yes |
| Tumblr | `There's nothing here.` | Yes |
| Surge.sh | `project not found` | Yes |
| Vercel | `The deployment you are looking for cannot be found` | Yes |
| Netlify | `Not Found - Request ID:...` | Yes |
| Cloudflare | Cannot be taken over (Cloudflare controls endpoint) | No |
| AWS CloudFront | Requires AWS account — complex but possible | Yes (limited) |

---

### 4. NS Takeover — Higher Impact

A **nameserver takeover** is more serious than a CNAME takeover. It occurs when:

1. A subdomain has its own `NS` (nameserver) records pointing to a third-party
   DNS provider.
2. The organisation stops using that DNS provider but does not remove the NS records.
3. An attacker registers an account with that DNS provider and claims the zone.
4. The attacker now controls ALL DNS records for that subdomain.

```bash
# Example dangling NS:
dig NS internal.acmecorp.com +short
# → ns1.movedprovider.io
# → ns2.movedprovider.io

# Check if movedprovider.io is still a valid DNS provider:
dig A movedprovider.io +short
# → NXDOMAIN — provider has shut down

# Attacker registers with movedprovider.io (if still active) or a similar
# provider and creates the zone for internal.acmecorp.com:
# Result: attacker controls ALL DNS for internal.acmecorp.com
# - Can issue TLS certificates (with DNS-01 ACME challenge)
# - Can intercept email sent to *@internal.acmecorp.com
# - Can redirect any host to attacker-controlled infrastructure
```

NS takeovers are rated **Critical** in bug bounty programmes because they give
complete control over a subdomain's entire DNS zone.

---

### 5. Why Subdomain Takeover Matters — Impact

The business impact depends on what the subdomain is:

```
Scenario 1: marketing.acmecorp.com taken over
  → Attacker serves phishing page under trusted acmecorp.com domain
  → Users see valid HTTPS certificate + acmecorp.com in URL bar
  → Phishing credibility: High
  Severity: Medium-High

Scenario 2: staging-api.acmecorp.com taken over
  → Staging cookies set to .acmecorp.com are readable by attacker's staging subdomain
  → If staging site shares cookie domain with production → cookie theft possible
  Severity: High (if cookies are shared)

Scenario 3: auth.acmecorp.com taken over (auth endpoint)
  → Attacker controls login page URL
  → OAuth redirect_uri whitelists *.acmecorp.com → OAuth tokens go to attacker
  Severity: Critical

Scenario 4: Any subdomain taken over — HSTS bypass
  → HSTS (Strict-Transport-Security) with includeSubDomains flag means all
    subdomains are expected to be HTTPS-only
  → If HSTS includeSubDomains is set, attacker can still serve HTTP from
    the taken-over subdomain, causing HSTS preload confusion
  → Less common impact, but notable
```

**HSTS preload and subdomains:**

If `acmecorp.com` has `HSTS: max-age=...; includeSubDomains; preload`, a taken-over
subdomain that cannot get a valid certificate is broken for users. A subdomain
that can get a certificate (via the same CNAME registration) can steal cookies
set with `Domain=.acmecorp.com` and `Secure` flag.

---

### 6. Tools — subjack

subjack checks a list of subdomains for CNAME-based takeover vulnerability.

```bash
# Install
go install github.com/haccer/subjack@latest

# Create fingerprints file (or use built-in)
# The -t flag sets timeout, -ssl verifies SSL, -o saves output

# Scan a list of subdomains
subjack -w subdomains/all_subdomains.txt -t 100 -timeout 30 -ssl \
    -o subdomains/takeover_candidates.txt -v

# Output example:
# [Vulnerable] staging.acmecorp.com - GitHub
# [Not Vulnerable] www.acmecorp.com - Cloudflare
# [Edge Case] dev.acmecorp.com - AWS S3 (exists but different account)
```

---

### 7. Tools — nuclei Takeover Templates

nuclei has a dedicated set of templates for subdomain takeover detection.

```bash
# Install nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Scan for takeovers
nuclei -l subdomains/all_subdomains.txt -t takeovers/ -o nuclei_takeovers.txt

# Scan specific subdomain
nuclei -target staging.acmecorp.com -t takeovers/ -v

# Example output:
# [subdomain-takeover:github-io] [http] [high] https://staging.acmecorp.com
```

nuclei's takeover templates also check for NS-based takeovers.

---

### 8. Detecting Subdomain Takeovers — Defensive

From the blue team side, you want to know when a dangling CNAME is introduced —
before an attacker acts on it.

#### Automated Monitoring Script

```python
#!/usr/bin/env python3
"""
monitor_dns.py — Monitor for dangling CNAME records
Run as a cron job: 0 6 * * * /usr/bin/python3 /opt/monitor_dns.py
"""
import dns.resolver
import requests
import json
import os
from datetime import datetime

DOMAIN = "acmecorp.com"
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")

# Fingerprints from can-i-take-over-xyz
VULNERABLE_FINGERPRINTS = [
    "There isn't a GitHub Pages site here",
    "NoSuchBucket",
    "No such app",
    "Fastly error: unknown domain",
    "project not found",
    "Sorry, this shop is currently unavailable",
    "Help Center Closed",
    "The deployment you are looking for cannot be found",
    "404 Web Site not found",
]


def get_cname(subdomain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None


def check_fingerprint(url: str) -> str | None:
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        for fp in VULNERABLE_FINGERPRINTS:
            if fp.lower() in resp.text.lower():
                return fp
    except requests.RequestException:
        pass
    return None


def alert(subdomain: str, cname: str, fingerprint: str) -> None:
    msg = (f":warning: *Subdomain Takeover Candidate*\n"
           f"Subdomain: `{subdomain}`\n"
           f"CNAME: `{cname}`\n"
           f"Fingerprint: `{fingerprint}`\n"
           f"Time: {datetime.now().isoformat()}")
    print(msg)
    if SLACK_WEBHOOK:
        requests.post(SLACK_WEBHOOK, json={"text": msg})


def main():
    # Load subdomain list (maintain this from your subdomain enumeration)
    with open(f"/opt/recon/{DOMAIN}/subdomains/all_subdomains.txt") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    for subdomain in subdomains:
        cname = get_cname(subdomain)
        if not cname:
            continue  # NXDOMAIN or A record — not a CNAME issue
        fingerprint = check_fingerprint(f"https://{subdomain}")
        if not fingerprint:
            fingerprint = check_fingerprint(f"http://{subdomain}")
        if fingerprint:
            alert(subdomain, cname, fingerprint)


if __name__ == "__main__":
    main()
```

---

### 9. Real-World Cases

#### Starbucks (2021)

A security researcher found that `retailer.starbucks.com` had a dangling CNAME
pointing to an Azure App Service endpoint that had been deprovisioned.
The researcher registered the endpoint and demonstrated full content control.
**Paid: $4,000 (High severity)**

#### Microsoft (2021)

Multiple Microsoft subdomains pointed to Azure services that had been
deprovisioned. Researchers found NS-level takeovers on some subdomains,
allowing DNS record creation.
**Paid: Up to $8,000 (Critical)**

#### Uber (2017)

`assets.uber.com` pointed to an S3 bucket that no longer existed.
The bucket name was globally registerable. Researcher demonstrated full
content control including serving JavaScript under the `uber.com` domain.
**This is why companies now pay $5,000+ for subdomain takeovers.**

---

### 10. Hardening — Remediation Workflow

When a dangling record is discovered:

```
1. VERIFY: Confirm the CNAME target does not resolve to legitimate content.
   dig CNAME subdomain.company.com +short
   curl -L https://subdomain.company.com

2. PRIORITISE: Is this subdomain in a cookie domain? Used for OAuth? Has traffic?
   High value → treat as P1. Low value → still fix immediately.

3. REMOVE the DNS record:
   Option A (preferred): Delete the CNAME entirely if the subdomain is not needed.
   Option B: Point to a controlled endpoint (e.g., a 410 Gone page on your own server)

4. VERIFY the third-party resource:
   If the third-party service is still in use, ensure the resource is claimed:
   - GitHub Pages: The repository must exist and have Pages enabled
   - Heroku: The app must exist and have the custom domain added
   - S3: The bucket must exist and respond with content or a proper 403

5. AUDIT: Find all other CNAME records and verify they are live.
   Tools: dnsx, dig, custom monitoring script above

6. MONITOR: Set up the monitoring script to alert on new dangling records.
```

---

## Key Takeaways

1. **Subdomain takeover is a passive-recon finding that converts to a real
   exploit in minutes.** The detection is pure DNS analysis; the exploit is
   registering a free resource. This makes it a favourite of fast-moving
   bug hunters.
2. **NS takeovers are Critical severity.** CNAME takeovers are typically
   High. The difference is control scope — NS gives you the entire subdomain
   DNS zone.
3. **The `can-i-take-over-xyz` repository is your reference.** Before testing
   any CNAME target, look up the fingerprint and whether takeover has been
   confirmed possible.
4. **Impact is context-dependent.** A taken-over marketing subdomain is
   Medium. A taken-over auth subdomain where OAuth whitelist is `*.company.com`
   is Critical. Always assess impact, not just vulnerability.
5. **The fix is always the same:** Remove the dangling DNS record. No patch,
   no config change — just delete the record or ensure the resource it points
   to is under your control.

---

## Exercises

### Exercise 1 — CNAME Chain Analysis

For each of the following, trace the full CNAME chain and determine if any
part of the chain resolves to NXDOMAIN or a takeover fingerprint:

1. `blog.company.com CNAME blog-company.ghost.io`
2. `cdn.company.com CNAME company.azureedge.net`
3. `shop.company.com CNAME company.myshopify.com`

Use: `dig CNAME [target] +short` then `curl -s https://[cname-target] | head -20`

---

### Exercise 2 — subjack Scan

Using the subdomain list from your Day 060 lab:

1. Run `subjack -w all_subdomains.txt -ssl -v -o takeover_results.txt`.
2. How many candidates were found?
3. For each candidate: check `can-i-take-over-xyz` to confirm if takeover
   is possible for that service.

---

### Exercise 3 — Reproduce a Takeover (Controlled Lab)

1. Create a personal domain (or use a free subdomain service).
2. Add a DNS record: `test.yourdomain.com CNAME testrepo.github.io`
3. Do NOT create the GitHub Pages site at `testrepo.github.io`.
4. Run `subjack` against `test.yourdomain.com` — does it detect the vulnerability?
5. Create a GitHub account with username `testrepo` and enable GitHub Pages.
6. Add a `CNAME` file to the repo containing `test.yourdomain.com`.
7. Visit `https://test.yourdomain.com` — you now control the subdomain.
8. Clean up: delete the GitHub repo and the DNS record.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 061 — Reducing Your Org Attack Surface](DAY-0061-Reducing-Your-Org-Attack-Surface.md)*
*Next: [Day 063 — nmap from First Principles](../02-Recon-02/DAY-0063-nmap-from-First-Principles.md)*
