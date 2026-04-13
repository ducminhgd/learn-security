---
title: "Passive Recon Lab — Full Passive Profile on a Designated Target"
tags: [recon, osint, lab, passive-recon, attack-surface, hands-on, methodology,
       subfinder, shodan, github, crt.sh, s3scanner]
module: 02-Recon-01
day: 60
related_topics:
  - Attack Surface Mapping (Day 059)
  - Reducing Your Org Attack Surface (Day 061)
  - Passive vs Active Recon and OpSec (Day 052)
---

# Day 060 — Passive Recon Lab

## Goals

This is a **pure lab day**. No new theory. You apply everything from Days
051–059 against a designated target.

By the end of this lab you will have demonstrated ability to:

1. Execute a complete passive reconnaissance workflow from scratch.
2. Produce a professional attack surface document (ASDoc).
3. Prioritise targets within the attack surface for subsequent active recon.
4. Document findings with source attribution and confidence ratings.
5. Identify at least 3 gaps that require active recon to resolve.

> "Give me 20 hours of passive recon and I will spend 2 hours exploiting.
> Give me 2 hours of passive recon and I will waste 20 hours chasing
> dead ends."
>
> — Ghost

---

## Prerequisites

- [Day 051–059] All OSINT and Passive Recon content
- All tools installed and API keys configured:
  - `subfinder` with provider API keys
  - `amass` (passive mode)
  - `gitleaks` and `truffleHog`
  - `s3scanner`
  - Shodan CLI (`pip install shodan && shodan init YOUR_KEY`)
  - `exiftool`
  - `theHarvester`

---

## Target Selection

### Option A — Designated Lab Target (Recommended)

Use a bug bounty programme explicitly designed for learning:

1. **HackTheBox Bug Bounty Lab** — practice targets in controlled environment
2. **HackerOne's publicly disclosed programme** — use a live programme and only
   do passive recon (no active testing)
3. **Instructor-assigned target** — your trainer assigns a programme

**Recommended live programme for passive recon practice:**

HackerOne's public programme `https://hackerone.com/security` — HackerOne's
own scope. Studying a security-focused company's public footprint is
instructive.

---

### Option B — Build Your Own Lab Target

If you want a fully controlled environment, deploy this lab target:

```bash
# Lab target: a fake company "VaultPay" with multiple recon artifacts
# designed to be found. Run everything on localhost with custom /etc/hosts.

cat >> /etc/hosts << 'EOF'
127.0.0.1 vaultpay.local
127.0.0.1 api.vaultpay.local
127.0.0.1 staging.vaultpay.local
127.0.0.1 dev.vaultpay.local
EOF

# Docker compose for the lab environment
cat > /tmp/vaultpay-lab/docker-compose.yml << 'EOF'
version: "3.9"
services:
  web:
    image: nginx:1.18
    ports: ["80:80", "443:443"]
    volumes:
      - ./web:/usr/share/nginx/html

  api:
    image: python:3.9-slim
    command: python3 -m http.server 8080
    ports: ["8080:8080"]

  staging:
    image: nginx:1.14  # older version — intentionally vulnerable
    ports: ["8081:80"]

  minio:  # S3-compatible storage
    image: minio/minio
    command: server /data --console-address ":9001"
    ports: ["9000:9000", "9001:9001"]
    environment:
      MINIO_ROOT_USER: vaultpay-public
      MINIO_ROOT_PASSWORD: vaultpay123
EOF

# Note: For full passive recon simulation, use a real bug bounty target
# in read-only (passive) mode. The Docker lab is for tool practice only.
```

---

## Lab Workflow

Work through each phase in order. Document every finding immediately.
Do not move to the next phase without completing the current one.

### Phase 0 — Setup (15 minutes)

```bash
# Create target directory structure
TARGET="acmecorp.com"  # Replace with your chosen target
mkdir -p ~/recon/$TARGET/{dns,subdomains,cloud,people,code,screenshots}
cd ~/recon/$TARGET

# Start a log file
echo "=== Passive Recon Log: $TARGET ===" > recon.log
echo "Started: $(date)" >> recon.log
echo "Researcher: $(whoami)" >> recon.log
```

---

### Phase 1 — Domain and DNS (30 minutes)

```bash
TARGET="acmecorp.com"

# 1a. WHOIS
echo "[*] WHOIS lookup"
whois $TARGET > dns/whois.txt 2>&1
grep -iE "registrar|creation|expiry|name.server|dnssec" dns/whois.txt

# 1b. DNS records
echo "[*] DNS record enumeration"
for type in A AAAA MX NS TXT SOA; do
    echo "=== $type ===" >> dns/dns_records.txt
    dig $type $TARGET +short >> dns/dns_records.txt 2>&1
done
cat dns/dns_records.txt

# 1c. Zone transfer attempt
echo "[*] Zone transfer attempts"
NS=$(dig NS $TARGET +short | tr -d '.')
for ns in $NS; do
    echo "Trying AXFR against $ns..."
    dig AXFR $TARGET @$ns 2>&1 | tee -a dns/axfr_attempts.txt
done

# 1d. TXT record analysis — extract services
grep -oP '"[^"]*"' dns/dns_records.txt | sort -u > dns/txt_services.txt
echo "[*] Services in TXT records:"
cat dns/txt_services.txt
```

**Checkpoint:** You should have:
- [ ] Registrar and nameserver information
- [ ] Full DNS record set (A, AAAA, MX, NS, TXT, SOA)
- [ ] List of third-party services from TXT records
- [ ] Zone transfer result (pass or fail — both are recorded)

---

### Phase 2 — Subdomain Enumeration (45 minutes)

```bash
TARGET="acmecorp.com"

# 2a. Certificate Transparency (crt.sh)
echo "[*] Certificate Transparency logs"
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
    python3 -c "
import json, sys
certs = json.load(sys.stdin)
names = set()
for c in certs:
    for name in c.get('name_value', '').split('\n'):
        name = name.strip().lstrip('*.')
        if name and name.endswith('.$1'):
            names.add(name)
for name in sorted(names):
    print(name)
" > subdomains/crtsh.txt 2>/dev/null || \
    curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
    python3 -c "
import json,sys
[print(n.strip().lstrip('*.'))
 for c in json.load(sys.stdin)
 for n in c.get('name_value','').split('\n') if n.strip()]
" | sort -u > subdomains/crtsh.txt

echo "crt.sh found: $(wc -l < subdomains/crtsh.txt) entries"

# 2b. subfinder
echo "[*] subfinder passive enumeration"
subfinder -d $TARGET -silent -o subdomains/subfinder.txt 2>/dev/null
echo "subfinder found: $(wc -l < subdomains/subfinder.txt) entries"

# 2c. amass passive
echo "[*] amass passive enumeration (this takes a few minutes)"
amass enum -passive -d $TARGET -o subdomains/amass.txt 2>/dev/null
echo "amass found: $(wc -l < subdomains/amass.txt) entries"

# 2d. Deduplicate and combine
cat subdomains/crtsh.txt subdomains/subfinder.txt subdomains/amass.txt \
    | sort -u \
    | grep -E "\.${TARGET}$" \
    > subdomains/all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < subdomains/all_subdomains.txt)"

# 2e. Quick passive DNS check — which ones have A records?
# Note: This sends DNS queries to public resolvers, not target nameservers
echo "[*] Checking which subdomains resolve (passive DNS verification)"
cat subdomains/all_subdomains.txt | while read subdomain; do
    ip=$(dig +short A "$subdomain" @8.8.8.8 2>/dev/null | head -1)
    if [ -n "$ip" ]; then
        echo "$subdomain => $ip" | tee -a subdomains/resolved.txt
    fi
done
echo "[+] Resolved: $(wc -l < subdomains/resolved.txt)"
```

**Checkpoint:**
- [ ] Total subdomain count (all sources combined)
- [ ] Number that actively resolve
- [ ] Any interesting subdomains (staging, dev, admin, vpn, api)?

---

### Phase 3 — Search Engine and Shodan (30 minutes)

```bash
TARGET="acmecorp.com"

# 3a. Shodan org + hostname search
echo "[*] Shodan enumeration"
shodan search "hostname:${TARGET}" --fields ip_str,port,hostnames,product,version \
    > cloud/shodan_hostname.txt 2>/dev/null
shodan search "ssl.cert.subject.cn:${TARGET}" \
    --fields ip_str,port,hostnames,product,version \
    > cloud/shodan_ssl.txt 2>/dev/null

# 3b. Google dorks — run these manually in the browser (automated = CAPTCHA)
echo "[*] Google dorks to run manually:"
cat << 'EOF'
Copy and run each of these in Google:

1. site:*.${TARGET} (subdomain discovery)
2. site:${TARGET} intitle:"index of" (exposed directories)
3. site:${TARGET} filetype:env OR filetype:sql OR filetype:log
4. site:${TARGET} inurl:admin OR inurl:login OR inurl:dashboard
5. site:${TARGET} intext:"password" OR intext:"api_key"
6. site:${TARGET} intitle:"500 Internal Server Error"
EOF

# Record Google dork results manually in:
touch cloud/google_dorks.md
echo "# Google Dork Results — $TARGET" > cloud/google_dorks.md
echo "Run dorks manually. Record results below." >> cloud/google_dorks.md
```

---

### Phase 4 — Cloud Asset Discovery (30 minutes)

```bash
TARGET="acmecorp.com"
COMPANY=$(echo $TARGET | cut -d. -f1)  # "acmecorp"

# 4a. Generate bucket name candidates
python3 - <<EOF > cloud/bucket_candidates.txt
company = "$COMPANY"
envs = ["prod", "production", "staging", "dev", "development", "test", "qa", "uat"]
purposes = ["assets", "backups", "backup", "logs", "data", "static", "cdn",
            "uploads", "files", "media", "internal", "public", "reports", "archive"]
names = set([company])
for e in envs:
    names.add(f"{company}-{e}")
    names.add(f"{e}-{company}")
for p in purposes:
    names.add(f"{company}-{p}")
for e in envs:
    for p in purposes:
        names.add(f"{company}-{e}-{p}")
print('\n'.join(sorted(names)))
EOF

echo "Generated $(wc -l < cloud/bucket_candidates.txt) bucket candidates"

# 4b. S3 bucket scan
echo "[*] S3 bucket enumeration"
s3scanner scan --bucket-file cloud/bucket_candidates.txt --threads 10 \
    2>/dev/null > cloud/s3_results.txt
grep -v "not_exist" cloud/s3_results.txt | tee cloud/s3_interesting.txt

# 4c. Manual GrayhatWarfare search (browser-based)
echo "[*] Check GrayhatWarfare: https://grayhatwarfare.com/buckets?keywords=${COMPANY}"
echo "Record any open bucket findings in cloud/grayhatwarfare.md"
```

---

### Phase 5 — People and Email (30 minutes)

```bash
TARGET="acmecorp.com"

# 5a. theHarvester
echo "[*] Email and subdomain harvesting"
theHarvester -d $TARGET -b google,bing,crtsh -l 200 \
    -f people/theharvester_report.html 2>/dev/null | \
    tee people/theharvester_raw.txt

grep -E "@${TARGET}" people/theharvester_raw.txt | \
    sort -u > people/emails.txt
echo "[+] Emails found: $(wc -l < people/emails.txt)"

# 5b. Hunter.io API (if key available)
HUNTER_KEY="${HUNTER_IO_API_KEY:-}"
if [ -n "$HUNTER_KEY" ]; then
    echo "[*] Hunter.io domain search"
    curl -s "https://api.hunter.io/v2/domain-search?domain=${TARGET}&api_key=${HUNTER_KEY}" \
        | python3 -c "
import json,sys
d = json.load(sys.stdin)['data']
print(f'Email pattern: {d[\"pattern\"]}')
print(f'Total: {d[\"total\"]}')
for e in d['emails'][:20]:
    print(f'  {e[\"value\"]} — {e.get(\"first_name\",\"\")} {e.get(\"last_name\",\"\")} ({e.get(\"position\",\"\")})')
" | tee people/hunter_io.txt
fi

# 5c. LinkedIn dorks (run manually)
echo "[*] LinkedIn dorks to run in Google:"
echo "  site:linkedin.com/in \"${COMPANY}\" engineer"
echo "  site:linkedin.com/in \"${COMPANY}\" security"
echo "  site:linkedin.com/in \"${COMPANY}\" devops OR infrastructure"
echo "Record findings in people/linkedin.md"
touch people/linkedin.md
```

---

### Phase 6 — Code Repository Recon (30 minutes)

```bash
TARGET="acmecorp.com"
COMPANY=$(echo $TARGET | cut -d. -f1)

# 6a. GitHub organisation discovery
echo "[*] GitHub recon"
echo "Check manually: https://github.com/${COMPANY}"
echo "Also try: https://github.com/${COMPANY}-eng"
echo "Also try: https://github.com/search?q=${COMPANY}&type=organizations"
touch code/github_repos.md

# 6b. Clone and scan all public repos with gitleaks
# Replace with actual org name after discovery
ORG="${COMPANY}"  # Adjust after finding the real org name
echo "[*] If public repos found, scan with gitleaks:"
echo "  git clone https://github.com/${ORG}/REPO /tmp/${ORG}_REPO"
echo "  gitleaks detect --source /tmp/${ORG}_REPO --report-format json --report-path code/leaks_REPO.json"

# 6c. truffleHog scan (if org name confirmed)
echo "[*] truffleHog org scan command (run after confirming org name):"
echo "  trufflehog github --org=${ORG} --json > code/trufflehog.json"

# 6d. Wayback URL collection
echo "[*] Wayback URLs"
echo "${TARGET}" | waybackurls 2>/dev/null | \
    grep -E "\.(env|sql|bak|log|config|xml|json|php)$" | \
    sort -u > code/wayback_interesting.txt
echo "Interesting wayback URLs: $(wc -l < code/wayback_interesting.txt)"
```

---

### Phase 7 — Document Metadata (15 minutes)

```bash
TARGET="acmecorp.com"
mkdir -p people/documents

# 7a. Find and download documents
echo "[*] Searching for downloadable documents"
echo "Run in browser: site:${TARGET} filetype:pdf OR filetype:docx"
echo "Download up to 10 documents to people/documents/"

# 7b. Extract metadata from downloaded documents
if ls people/documents/*.pdf 2>/dev/null; then
    echo "[*] Extracting PDF metadata"
    exiftool people/documents/*.pdf | \
        grep -iE "author|creator|company|last.modified|producer" \
        > people/document_metadata.txt
    cat people/document_metadata.txt
fi
```

---

### Phase 8 — Compile the ASDoc (45 minutes)

Using the template from Day 059, create your completed ASDoc:

```bash
cp ~/recon/templates/asdoc_template.md ~/recon/$TARGET/ASDOC.md
```

Fill in every section. Prioritise targets. Identify gaps.

---

## Validation Checklist

Before submitting your lab work, verify:

**Phase 1 — DNS:**
- [ ] WHOIS recorded (registrar, nameservers, DNSSEC status)
- [ ] All 7 DNS record types queried
- [ ] AXFR attempted and result recorded
- [ ] Third-party services extracted from TXT records

**Phase 2 — Subdomains:**
- [ ] crt.sh, subfinder, and amass all run
- [ ] Results deduplicated and combined
- [ ] Resolved subdomains separated from unresolved
- [ ] Interesting subdomains noted (staging, dev, admin, vpn)

**Phase 3 — Search:**
- [ ] Shodan search run (hostname + SSL cert)
- [ ] Google dorks run (at least 6 dork categories)

**Phase 4 — Cloud:**
- [ ] S3 bucket wordlist generated from target name
- [ ] s3scanner run against wordlist
- [ ] GrayhatWarfare checked

**Phase 5 — People:**
- [ ] theHarvester run (3+ sources)
- [ ] Email format inferred from found addresses
- [ ] LinkedIn dorks run manually

**Phase 6 — Code:**
- [ ] GitHub org identified (or absence noted)
- [ ] Public repos scanned with gitleaks
- [ ] Wayback URLs collected and filtered

**Phase 7 — Metadata:**
- [ ] Documents downloaded and metadata extracted

**Phase 8 — ASDoc:**
- [ ] All 9 ASDoc sections completed
- [ ] Priority scores calculated for top 5 targets
- [ ] Active recon gaps documented

---

## Lab Debrief Questions

Answer these after completing the lab:

1. What was the most surprising finding in your passive recon?
2. Which source provided the most unique intelligence: CT logs, Shodan, or
   GitHub?
3. Did you find any potential security issues? Describe without exploiting.
4. How long did the complete passive recon take? Is this efficient?
5. What would an attacker do first with the intelligence you collected?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 059 — Attack Surface Mapping](DAY-0059-Attack-Surface-Mapping.md)*
*Next: [Day 061 — Reducing Your Org Attack Surface](DAY-0061-Reducing-Your-Org-Attack-Surface.md)*
