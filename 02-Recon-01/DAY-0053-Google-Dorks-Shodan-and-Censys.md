---
title: "Google Dorks, Shodan and Censys — Search Engine Recon"
tags: [recon, osint, google-dorks, shodan, censys, GHDB, passive-recon, T1593, T1596]
module: 02-Recon-01
day: 53
related_topics:
  - Passive vs Active Recon and OpSec (Day 052)
  - Domain DNS and Certificate Transparency (Day 054)
  - MITRE ATT&CK T1593 (Search Open Websites/Domains)
  - MITRE ATT&CK T1596.005 (Scan Databases)
---

# Day 053 — Google Dorks, Shodan and Censys

## Goals

By the end of this lesson you will be able to:

1. Construct effective Google dork queries using at least 8 operators.
2. Find exposed files, login portals, and configuration data using GHDB categories.
3. Search Shodan for specific organisation infrastructure and interpret banner results.
4. Use Censys to enumerate certificates and hosts for a target domain.
5. Automate a multi-engine dork sweep for a target domain.

---

## Prerequisites

- [Day 052 — Passive vs Active Recon and OpSec](DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)
- An account on shodan.io (free tier sufficient for today)
- An account on search.censys.io (free tier sufficient)

---

## Main Content

### 1. Google Dorking — Operators Reference

Google's search operators were designed for power users. Attackers repurposed them
for reconnaissance. The technique has been publicly documented since 2004 when
Johnny Long published "Google Hacking for Penetration Testers."

The core insight: **Google has already indexed your target's exposed content.
You just need to ask the right questions.**

#### Primary Operators

| Operator | Syntax | What it does |
|---|---|---|
| `site:` | `site:target.com` | Restrict results to this domain |
| `filetype:` | `filetype:pdf` | Restrict to specific file extension |
| `inurl:` | `inurl:admin` | URL must contain this string |
| `intitle:` | `intitle:"index of"` | Page title must contain this string |
| `intext:` | `intext:"password"` | Page body must contain this string |
| `cache:` | `cache:target.com` | Google's cached version of a page |
| `related:` | `related:target.com` | Sites similar to this one |
| `link:` | `link:target.com` | Pages that link to this domain |
| `ext:` | `ext:bak` | Alias for filetype (not official but works) |
| `-` | `-site:www.target.com` | Exclude results matching this |
| `"` | `"exact phrase"` | Exact phrase match |
| `OR` / `|` | `pdf OR doc` | Boolean OR |
| `..` | `2020..2023` | Numeric range |

#### High-Value Dork Templates

**Exposed files and directories:**

```
site:target.com intitle:"index of"
site:target.com intitle:"index of" "parent directory"
site:target.com filetype:env
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:xml intext:"password"
site:target.com filetype:json intext:"api_key" OR intext:"secret"
site:target.com ext:bak OR ext:old OR ext:backup
```

**Login portals and admin panels:**

```
site:target.com inurl:login OR inurl:signin OR inurl:admin
site:target.com inurl:wp-admin
site:target.com inurl:phpmyadmin
site:target.com intitle:"Admin Panel"
site:target.com inurl:/admin/login
```

**Configuration and credential exposure:**

```
site:target.com intext:"DB_PASSWORD"
site:target.com intext:"AWS_SECRET_ACCESS_KEY"
site:target.com filetype:properties intext:"password"
site:target.com filetype:conf intext:"password"
site:target.com intext:"Authorization: Bearer"
```

**Subdomain discovery via Google:**

```
site:*.target.com -site:www.target.com
site:*.target.com -site:www.target.com -site:mail.target.com
```

**Technology fingerprinting:**

```
site:target.com intitle:"GitLab"
site:target.com intitle:"Jenkins"
site:target.com inurl:"/wp-content/"
site:target.com intext:"Powered by WordPress"
```

**Error pages (often leak stack traces):**

```
site:target.com intext:"syntax error" OR intext:"stack trace"
site:target.com intext:"Warning: mysql_" OR intext:"ORA-"
site:target.com intext:"PDOException"
site:target.com intitle:"500 Internal Server Error"
```

---

### 2. Google Hacking Database (GHDB)

The GHDB (maintained by Offensive Security at exploit-db.com/google-hacking-database)
is a curated collection of dorks organised by category. Study this database — every
entry represents a class of misconfiguration that real attackers search for.

Top GHDB categories for recon:

| Category | What it finds |
|---|---|
| Files Containing Passwords | Exposed credential files |
| Files Containing Usernames | Username enumeration |
| Sensitive Directories | Backup dirs, logs, config dirs |
| Vulnerable Servers | Default pages, known-vulnerable versions |
| Web Server Detection | Specific server software fingerprinting |
| Error Messages | Stack traces, DB errors, framework version leakage |
| Pages Containing Login Portals | Admin panels, VPN portals |
| Network or Vulnerability Data | Network device configs, SNMP data |

**Workflow:** Before starting a target, run 10–20 relevant GHDB dorks against
`site:target.com`. Document every result that looks interesting.

---

### 3. Bing Operators

Bing indexes different content than Google — especially images and older cached
pages. Use it as a secondary source.

| Operator | What it does |
|---|---|
| `site:` | Same as Google |
| `filetype:` | Same as Google |
| `inbody:` | Bing's equivalent of `intext:` |
| `intitle:` | Same as Google |
| `ip:` | Find pages hosted on a specific IP address |
| `contains:` | Link contains a specific file type |

The `ip:` operator is unique to Bing and useful for finding all domains hosted
on a shared IP (virtual hosting discovery):

```
ip:104.21.50.32
```

---

### 4. Shodan — The Search Engine for Internet-Connected Devices

Shodan crawls the internet continuously, collecting banners from open ports on
every routable IP address. Where Google indexes web pages, Shodan indexes
**running services**.

When you search Shodan for a target, you see what Shodan's scanners collected —
no packets reach the target.

#### Account Setup

```bash
# Install Shodan CLI
pip install shodan

# Initialise with your API key (from shodan.io account)
shodan init YOUR_API_KEY

# Upgrade account to get more features (free academic access available)
# https://developer.shodan.io/api/requirements
```

#### Core Search Operators

| Filter | Syntax | Example |
|---|---|---|
| Organisation | `org:"Target Corp"` | `org:"Cloudflare"` |
| Hostname | `hostname:target.com` | `hostname:.target.com` |
| IP range | `net:192.168.1.0/24` | `net:203.0.113.0/24` |
| Port | `port:8080` | `port:27017` |
| Product | `product:"Apache httpd"` | `product:"nginx"` |
| OS | `os:"Windows Server 2016"` | `os:"Linux"` |
| Country | `country:US` | `country:VN` |
| City | `city:"Hanoi"` | |
| ASN | `asn:AS15169` | `asn:AS13335` (Cloudflare) |
| SSL/TLS CN | `ssl.cert.subject.cn:target.com` | |
| HTTP title | `http.title:"Admin Panel"` | |
| HTTP headers | `http.component:"WordPress"` | |
| Before/After date | `before:2024-01-01` | |

#### High-Value Shodan Searches

```
# Find all hosts belonging to an organisation
org:"AcmeCorp" port:443

# Find exposed databases
org:"AcmeCorp" port:5432 product:"PostgreSQL"
org:"AcmeCorp" port:27017 product:"MongoDB"
org:"AcmeCorp" port:6379 product:"Redis"

# Find exposed admin interfaces
org:"AcmeCorp" http.title:"Admin"
org:"AcmeCorp" http.title:"Dashboard" port:8080

# Find devices with default credentials (Shodan has vuln data)
org:"AcmeCorp" has_vuln:true

# Find old/vulnerable TLS
ssl.version:sslv2 org:"AcmeCorp"
ssl.cert.expired:true org:"AcmeCorp"

# Find exposed development/staging environments
hostname:"staging" org:"AcmeCorp"
hostname:"dev" ssl.cert.subject.cn:*.target.com
```

#### Reading a Shodan Banner

```json
{
  "ip_str": "203.0.113.45",
  "port": 443,
  "transport": "tcp",
  "product": "nginx",
  "version": "1.14.0",
  "os": null,
  "hostnames": ["api.target.com"],
  "org": "Target Corp",
  "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\nX-Powered-By: PHP/7.2.24\r\n...",
  "ssl": {
    "cert": {
      "subject": {"CN": "api.target.com"},
      "issued": "2023-06-01T00:00:00",
      "expires": "2024-06-01T00:00:00",
      "expired": false
    }
  },
  "vulns": {
    "CVE-2019-11043": {
      "cvss": 9.8,
      "summary": "In PHP versions 7.1.x, a remote code execution flaw..."
    }
  }
}
```

Key fields to extract:
- **ip_str:** Add to your target IP list
- **product + version:** Technology fingerprint
- **hostnames:** Virtual host names at this IP
- **data (banner):** Raw service response — look for version strings, headers
- **vulns:** Shodan's automatic CVE matching (verify before reporting)
- **ssl.cert:** Certificate info — CN and SAN fields reveal subdomains

---

### 5. Censys — Certificate and Host Intelligence

Censys scans the internet similarly to Shodan but focuses on TLS certificates
and provides richer certificate data. Its certificate search is one of the best
free tools for subdomain discovery.

#### Censys Search v2 — Certificate Search

```
# All certificates issued to target.com (includes all SANs)
parsed.names: target.com

# Wildcards
parsed.names: *.target.com

# All certs where target.com appears anywhere in the subject
parsed.subject_dn: target.com

# Recently issued certificates
parsed.names: target.com AND parsed.validity.end: [2024-01-01 TO *]
```

#### Censys Host Search

```
# All hosts with target.com in their cert
services.tls.certificates.leaf_data.names: target.com

# Specific service on a host
services.port: 8443 AND services.tls.certificates.leaf_data.names: target.com

# Open databases
services.port: 5432 AND services.tls.certificates.leaf_data.names: target.com
```

#### Censys CLI

```bash
# Install
pip install censys

# Configure
censys config  # Enter API credentials from search.censys.io

# Search certificates
censys search "parsed.names: target.com" --index certificates

# Search hosts
censys search "services.tls.certificates.leaf_data.names: target.com" --index hosts
```

---

### 6. Putting It Together — Automated Dork Sweep

A Python script that runs a structured set of dorks and outputs findings:

> **Note:** Automated Google queries will trigger CAPTCHA quickly. Use a real
> browser for Google dorking; use the Shodan API for automation.

```python
#!/usr/bin/env python3
"""
recon_shodan.py — Shodan passive recon sweep for a target org/domain
Usage: python3 recon_shodan.py --org "AcmeCorp" --domain acmecorp.com
"""
import shodan
import argparse
import json
from datetime import datetime

API_KEY = "YOUR_SHODAN_API_KEY"

def sweep(org: str, domain: str) -> dict:
    api = shodan.Shodan(API_KEY)
    results = {"org": org, "domain": domain, "hosts": [], "timestamp": str(datetime.now())}

    queries = [
        f'org:"{org}"',
        f'hostname:{domain}',
        f'ssl.cert.subject.cn:{domain}',
        f'ssl.cert.subject.cn:*.{domain}',
    ]

    seen_ips = set()
    for query in queries:
        try:
            search = api.search(query, limit=100)
            for match in search["matches"]:
                ip = match.get("ip_str")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    entry = {
                        "ip": ip,
                        "port": match.get("port"),
                        "hostnames": match.get("hostnames", []),
                        "product": match.get("product"),
                        "version": match.get("version"),
                        "vulns": list(match.get("vulns", {}).keys()),
                        "ssl_cn": (match.get("ssl", {})
                                   .get("cert", {})
                                   .get("subject", {})
                                   .get("cn")),
                    }
                    results["hosts"].append(entry)
                    print(f"  [{ip}:{match.get('port')}] "
                          f"{match.get('product','')} {match.get('version','')} "
                          f"— hostnames: {match.get('hostnames')} "
                          f"— CVEs: {list(match.get('vulns', {}).keys())}")
        except shodan.APIError as e:
            print(f"Shodan error on query '{query}': {e}")

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output", default="shodan_results.json")
    args = parser.parse_args()

    print(f"[*] Shodan sweep: org='{args.org}' domain='{args.domain}'")
    data = sweep(args.org, args.domain)

    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n[+] Found {len(data['hosts'])} unique hosts. Saved to {args.output}")
    vuln_hosts = [h for h in data["hosts"] if h["vulns"]]
    if vuln_hosts:
        print(f"[!] {len(vuln_hosts)} hosts with known CVEs — investigate:")
        for h in vuln_hosts:
            print(f"    {h['ip']}:{h['port']} — {h['vulns']}")
```

---

## Key Takeaways

1. **Google has already done the crawling.** Everything indexed about your target is
   available for free — you just need to know the operators.
2. **The GHDB is a reconnaissance cheat sheet.** Every dork category maps to a class
   of exposure. Study it before your first engagement.
3. **Shodan sees what Google doesn't.** Port 27017 (MongoDB), port 6379 (Redis),
   port 5432 (PostgreSQL) — services that are never linked from web pages but are
   completely exposed on the internet.
4. **Censys specialises in certificates.** If you want every subdomain in scope,
   start with Censys certificate search before any DNS enumeration.
5. **Always verify before reporting.** Shodan's CVE matching is automated and
   produces false positives. Check the CVE against the actual version before
   including it in a report.

---

## Exercises

### Exercise 1 — Google Dork Practice

Using a target domain assigned by your instructor (or a well-known public company
that runs a bug bounty, e.g., `hackerone.com`):

1. Find all subdomains Google has indexed: `site:*.hackerone.com`.
2. Find any exposed directories: `site:hackerone.com intitle:"index of"`.
3. Find any login portals: `site:hackerone.com inurl:login OR inurl:admin`.
4. Search the GHDB for any dork in the "Sensitive Directories" category and apply
   it to your target.

Document each query and its result count. Mark any result that warrants further
investigation.

---

### Exercise 2 — Shodan Organisation Search

1. Search Shodan for `org:"Cloudflare"` (public company, safe for practice).
2. Find all hosts on port 443. How many results?
3. Find all hosts with `product:"nginx"`.
4. Find any hosts with `has_vuln:true`.
5. Read one full banner and extract: IP, port, product, version, hostname, any CVEs.

---

### Exercise 3 — Censys Certificate Sweep

1. Go to `search.censys.io` and search: `parsed.names: hackerone.com`.
2. How many certificates are returned?
3. Extract all unique SANs (Subject Alternative Names) from the first 10 results.
4. Are any of these SANs not listed as in-scope on HackerOne's programme?
5. What does this tell you about how companies discover their own shadow IT?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 052 — Passive vs Active Recon and OpSec](DAY-0052-Passive-vs-Active-Recon-and-OpSec.md)*
*Next: [Day 054 — Domain, DNS and Certificate Transparency](DAY-0054-Domain-DNS-and-Certificate-Transparency.md)*
