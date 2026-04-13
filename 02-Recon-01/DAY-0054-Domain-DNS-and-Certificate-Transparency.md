---
title: "Domain, DNS and Certificate Transparency — WHOIS, Subdomain Enumeration, CT Logs"
tags: [recon, dns, whois, subdomain-enumeration, certificate-transparency, amass, subfinder,
       crt.sh, passive-dns, T1590, T1596]
module: 02-Recon-01
day: 54
related_topics:
  - DNS Deep Dive (Day 003)
  - Google Dorks, Shodan and Censys (Day 053)
  - MITRE ATT&CK T1590.001 (Domain Properties)
  - MITRE ATT&CK T1590.002 (DNS)
  - MITRE ATT&CK T1596.003 (Digital Certificates)
---

# Day 054 — Domain, DNS and Certificate Transparency

## Goals

By the end of this lesson you will be able to:

1. Extract registrant information, registration history, and nameservers from WHOIS.
2. Enumerate all DNS record types for a target domain and interpret each.
3. Attempt and interpret a zone transfer (AXFR) and explain why it still succeeds
   on misconfigured servers.
4. Run `subfinder` and `amass` in passive mode to enumerate subdomains.
5. Query Certificate Transparency logs via crt.sh API to extract subdomains from
   TLS certificate SANs.
6. Use passive DNS databases to find historical records that are no longer live.

---

## Prerequisites

- [Day 003 — UDP, ICMP and DNS Deep Dive](../01-Foundation-01/DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md)
- [Day 053 — Google Dorks, Shodan and Censys](DAY-0053-Google-Dorks-Shodan-and-Censys.md)

---

## Main Content

### 1. WHOIS — Who Owns the Target

WHOIS is a query protocol (and the data it returns) that tells you who registered
a domain, when, and with which registrar. This is often the first thing an
attacker looks up.

#### What WHOIS Reveals

```
Domain Name: ACMECORP.COM
Registry Domain ID: 12345678_DOMAIN_COM-VRSN
Registrar: GoDaddy.com, LLC
Registrar WHOIS Server: whois.godaddy.com
Creation Date: 2005-03-14T00:00:00Z
Updated Date: 2023-09-01T00:00:00Z
Registry Expiry Date: 2025-03-14T00:00:00Z
Registrant Organization: Acme Corporation
Registrant Country: US
Name Server: NS1.ACMECORP.COM
Name Server: NS2.ACMECORP.COM
DNSSEC: unsigned
```

**Attacker interest:**
- **Registrant details:** Email/org used to register — cross-reference for
  email harvesting (Day 055)
- **Name servers:** The authoritative DNS servers — targets for zone transfer
  attempts
- **DNSSEC: unsigned:** No DNS response validation — zone transfer or DNS
  spoofing is more viable
- **Expiry date:** Domains expiring soon = potential domain registration hijack
- **Creation date:** New domains in a large org may be acquired companies with
  separate security postures

#### WHOIS Tools

```bash
# Standard WHOIS query
whois acmecorp.com

# Using viewdns.info for historical WHOIS data
# (historical registrant changes reveal corporate changes)
curl "https://viewdns.info/whois/?domain=acmecorp.com"

# DomainTools (paid) — best historical data
# SecurityTrails (freemium) — historical + current in one API
```

#### WHOIS Privacy / GDPR Redaction

Since GDPR (2018), most EU registrars redact personal registrant data. US
registrars followed with similar privacy services. What you will often see:

```
Registrant Organization: [REDACTED FOR PRIVACY]
Registrant Email: Please query the RDDS service...
```

**Still useful even when redacted:**
- Registrar name (useful for registrar-specific attacks)
- Name servers (always present — critical for DNS enumeration)
- Creation/update/expiry dates
- DNSSEC status

---

### 2. DNS Record Enumeration

DNS is a gold mine. Every record type reveals something about the target's
infrastructure.

#### Record Types and Attacker Value

```bash
# Resolve all record types in one command
dig acmecorp.com ANY +noall +answer 2>/dev/null

# Or enumerate individually for reliability:

# A record — IPv4 address(es) of the root domain
dig A acmecorp.com +short

# AAAA record — IPv6 address
dig AAAA acmecorp.com +short

# MX records — mail server(s) — reveals email provider (GSuite, O365, on-prem)
dig MX acmecorp.com +short

# NS records — authoritative nameservers
dig NS acmecorp.com +short

# TXT records — SPF, DKIM, DMARC, domain verification tokens (leak cloud services)
dig TXT acmecorp.com +short

# SOA record — primary nameserver + contact email
dig SOA acmecorp.com +short

# CNAME record — canonical name (aliases)
dig CNAME www.acmecorp.com +short
```

#### What Each Record Tells an Attacker

| Record | What you learn |
|---|---|
| `A` | IP address — start of network-level recon |
| `AAAA` | IPv6 address — often less firewalled than IPv4 |
| `MX` | Email provider: `google.com` = GSuite, `protection.outlook.com` = O365 |
| `NS` | Hosting provider, or self-hosted DNS (higher value target) |
| `TXT` | SPF records reveal all authorised mail infrastructure; `MS=...` = Microsoft Azure tenant; `google-site-verification=` = GCP/GSuite; third-party service verifications |
| `SOA` | Administrative contact email in older records |
| `CNAME` | Aliases — check for dangling CNAMEs (Day 062) |

**TXT record goldmine example:**

```
acmecorp.com.  TXT  "v=spf1 include:_spf.google.com include:amazonses.com
                     ip4:203.0.113.5 ~all"
acmecorp.com.  TXT  "MS=ms12345678"
acmecorp.com.  TXT  "google-site-verification=abc123def456..."
acmecorp.com.  TXT  "atlassian-domain-verification=..."
acmecorp.com.  TXT  "stripe-verification=..."
acmecorp.com.  TXT  "_dmarc=v=DMARC1; p=none; rua=mailto:dmarc@acmecorp.com"
```

From this single TXT record set, you learn: Google Workspace, Amazon SES,
a static IP mail server at 203.0.113.5, Microsoft 365 (Azure AD tenant),
Google Search Console, Atlassian (Jira/Confluence), Stripe payment integration,
and that DMARC is in monitoring mode only (`p=none` = email spoofing possible).

---

### 3. Zone Transfer (AXFR) — Misconfiguration Still Exists

A DNS zone transfer is a replication mechanism — secondary DNS servers use it to
copy the complete zone from the primary. It is intended for internal server
replication only. When misconfigured, it exposes the entire DNS zone publicly.

```bash
# Step 1: Find authoritative nameservers
dig NS acmecorp.com +short
# Output:
# ns1.acmecorp.com.
# ns2.acmecorp.com.

# Step 2: Attempt zone transfer against each nameserver
dig AXFR acmecorp.com @ns1.acmecorp.com
dig AXFR acmecorp.com @ns2.acmecorp.com

# Successful output reveals ALL DNS records:
# acmecorp.com.          SOA   ns1.acmecorp.com. admin.acmecorp.com. ...
# acmecorp.com.          A     203.0.113.10
# www.acmecorp.com.      A     203.0.113.10
# mail.acmecorp.com.     A     203.0.113.20
# dev.acmecorp.com.      A     10.0.1.5
# internal.acmecorp.com. A     10.0.1.100
# staging.acmecorp.com.  CNAME staging-env-1234.aws.example.com.
# ...
```

**Modern reality:** Most public DNS servers correctly refuse AXFR. However:
- Legacy on-premise DNS servers (BIND 8/9 with old configs) still expose this
- Internal DNS servers exposed to the internet
- Some smaller organisations and self-managed DNS

AXFR attempts against well-configured servers fail silently or return
`Transfer failed.` — this is expected. Log the attempt in your notes and
move on to passive methods.

**Real-world case:** In 2019, multiple government and corporate DNS zones were
exposed via AXFR, revealing internal network topology that facilitated
subsequent targeted intrusions.

---

### 4. Certificate Transparency Logs

When a CA (Certificate Authority) issues a TLS certificate, it must log it to
public Certificate Transparency (CT) logs (RFC 6962). These logs are immutable
and publicly queryable.

**Attacker value:** Every certificate issued for any subdomain of `*.target.com`
is in the CT logs — including internal staging, development, and forgotten systems.

#### crt.sh API

crt.sh is the simplest public CT log frontend:

```bash
# Query via browser
https://crt.sh/?q=%.acmecorp.com

# Query via API (JSON)
curl -s "https://crt.sh/?q=%.acmecorp.com&output=json" | \
    python3 -c "
import json, sys
certs = json.load(sys.stdin)
names = set()
for c in certs:
    for name in c.get('name_value', '').split('\n'):
        name = name.strip().lstrip('*.')
        if name:
            names.add(name)
for name in sorted(names):
    print(name)
" | grep -v '^$'
```

**Example output:**
```
acmecorp.com
api.acmecorp.com
app.acmecorp.com
dev-api.acmecorp.com
internal.acmecorp.com
mail.acmecorp.com
old-staging.acmecorp.com
payments.acmecorp.com
staging.acmecorp.com
vpn.acmecorp.com
www.acmecorp.com
```

`internal.acmecorp.com` — that is interesting. An internal service with a
TLS certificate means it had a public hostname at some point. Worth investigating.

---

### 5. Subdomain Enumeration — subfinder and amass

#### subfinder

subfinder queries dozens of passive sources (Shodan, VirusTotal, Censys, crt.sh,
HackerTarget, and more) and aggregates subdomain results.

```bash
# Install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic usage
subfinder -d acmecorp.com -silent

# Save to file
subfinder -d acmecorp.com -o subdomains.txt -silent

# Use all sources (requires API keys configured in ~/.config/subfinder/provider-config.yaml)
subfinder -d acmecorp.com -all -o subdomains_all.txt

# Multiple domains
subfinder -dL domains.txt -o subdomains.txt
```

**API key configuration** (`~/.config/subfinder/provider-config.yaml`):

```yaml
# Most high-value sources require free API keys
shodan:
  - YOUR_SHODAN_KEY
virustotal:
  - YOUR_VT_KEY
censys:
  - YOUR_CENSYS_APP_ID:YOUR_CENSYS_SECRET
github:
  - YOUR_GITHUB_TOKEN
securitytrails:
  - YOUR_ST_KEY
```

Even with zero API keys configured, subfinder finds significant results through
free sources. With all keys configured, results improve by ~40%.

---

#### amass (passive mode)

amass is more thorough than subfinder but slower. Always use `-passive` flag
during passive recon phase.

```bash
# Install
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive enumeration only (no active DNS queries to target)
amass enum -passive -d acmecorp.com -o amass_results.txt

# With specific sources only
amass enum -passive -d acmecorp.com -src

# Combine amass + subfinder + crt.sh into one deduplicated list
cat amass_results.txt subdomains.txt <(curl -s "https://crt.sh/?q=%.acmecorp.com&output=json" \
    | python3 -c "
import json,sys
[print(n.strip().lstrip('*.')) for c in json.load(sys.stdin)
 for n in c.get('name_value','').split('\n') if n.strip()]
") | sort -u | grep -E '\.acmecorp\.com$' > all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < all_subdomains.txt)"
```

---

### 6. Passive DNS — Historical Records

Passive DNS databases collect DNS resolutions as they are observed across the
internet. They reveal:
- Subdomains that no longer resolve (but might still have live infrastructure)
- Historical IP addresses (useful for tracking migrations)
- Subdomains that were briefly live (dev environments)

#### Sources

| Service | URL | Notes |
|---|---|---|
| VirusTotal | `https://www.virustotal.com/gui/domain/target.com/relations` | Free; good passive DNS |
| SecurityTrails | `https://securitytrails.com/domain/target.com/dns` | Freemium; best historical data |
| CIRCL Passive DNS | `https://www.circl.lu/services/passive-dns/` | Free API |
| Robtex | `https://www.robtex.com/dns-lookup/target.com` | Free |

```bash
# VirusTotal API for passive DNS (free API key required)
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_KEY&domain=acmecorp.com" \
    | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('Subdomains from VirusTotal:')
for sub in data.get('subdomains', []):
    print(' ', sub)
"
```

---

### 7. BGP and ASN Data — Discovering IP Ranges

Every organisation that owns IP space has an ASN (Autonomous System Number).
Finding the ASN reveals all IP ranges owned by the target — including ranges
not obviously associated with the domain.

```bash
# Find ASN from IP (BGPView API)
curl -s "https://api.bgpview.io/ip/203.0.113.10" | python3 -m json.tool

# Find all IP prefixes for an ASN
curl -s "https://api.bgpview.io/asn/15169/prefixes" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data['data']['ipv4_prefixes']:
    print(p['prefix'], p.get('description',''))
"

# Search for ASN by org name
curl -s "https://api.bgpview.io/search?query_term=acmecorp" | python3 -m json.tool
```

Also use: Hurricane Electric BGP Toolkit at `https://bgp.he.net/`

---

## Key Takeaways

1. **TXT records are a goldmine.** SPF, DKIM, and verification tokens in TXT records
   reveal every third-party SaaS the target uses. Map each one to a potential
   attack surface.
2. **Certificate Transparency is passive and comprehensive.** Every subdomain that
   ever had a TLS certificate is in the CT logs. For modern organisations, this is
   the most complete subdomain list available.
3. **Zone transfers still work.** Not often — but when they do, you get the complete
   DNS zone in seconds. Always attempt AXFR before moving to slower enumeration methods.
4. **Combine three sources for best coverage:** subfinder (API aggregation) +
   amass passive (broader source set) + crt.sh (CT logs). Union the results.
5. **Passive DNS shows history.** A subdomain that resolved 18 months ago may still
   have live infrastructure with an IP that does not resolve through current DNS.
   Check historical records.

---

## Exercises

### Exercise 1 — Full DNS Enumeration

For the domain `bugcrowd.com` (active bug bounty programme, safe for research):

1. Run `whois bugcrowd.com`. What registrar? What nameservers? DNSSEC enabled?
2. Enumerate all DNS record types (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`).
3. From the TXT records, list every third-party service you can identify.
4. Attempt an AXFR zone transfer against each nameserver. What is the result?
5. Query crt.sh for `%.bugcrowd.com`. How many unique subdomains do you find?
6. Run `subfinder -d bugcrowd.com -silent`. Does it find anything crt.sh missed?

---

### Exercise 2 — Subdomain Pipeline

Write a bash one-liner that:
1. Takes a domain as an argument (`$1`)
2. Runs subfinder, amass (passive), and crt.sh in parallel
3. Combines and deduplicates results
4. Outputs a sorted list of unique subdomains

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 053 — Google Dorks, Shodan and Censys](DAY-0053-Google-Dorks-Shodan-and-Censys.md)*
*Next: [Day 055 — Email, People and LinkedIn OSINT](DAY-0055-Email-People-and-LinkedIn-OSINT.md)*
