---
title: "Cloud Practice — Bug Bounty Cloud Recon"
tags: [cloud-practice, bug-bounty, cloud-recon, S3-enumeration, SSRF,
       asset-discovery, HackerOne, Bugcrowd, methodology, passive-recon]
module: 04-BroadSurface-02
day: 205
related_topics:
  - Cloud Bug Bounty Strategy (Day 193)
  - S3 Misconfiguration Lab (Day 185)
  - SSRF to AWS Metadata Lab (Day 184)
  - Bug Bounty Reporting (Days 161–165)
---

# Day 205 — Cloud Practice: Bug Bounty Cloud Recon

> "Bug bounty hunting in the cloud is 80% recon and 20% exploitation. If you
> know exactly where all the exposed assets are before you test, the actual
> testing is mechanical. Most hunters skip the recon and jump straight to
> testing random endpoints. They miss the tfstate bucket sitting in plain sight.
> They miss the SSRF parameter that was in a JavaScript file three years ago.
> They miss the S3 bucket that was misconfigured in the same week the product
> launched. Do the recon. All of it."
>
> — Ghost

---

## Goals

By the end of today's practice session you will be able to:

1. Apply the complete cloud recon methodology to map a target's cloud footprint.
2. Discover S3 buckets through passive sources without touching the target.
3. Identify SSRF entry points through systematic endpoint analysis.
4. Map a target's AWS, Azure, or GCP usage from DNS, headers, and certificates.
5. Prioritise findings by impact before starting any active testing.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| Cloud Bug Bounty Strategy | Day 193 |
| Bug Bounty Reporting | Days 161–165 |
| SSRF to AWS Metadata Lab | Day 184 |
| S3 Misconfiguration Lab | Day 185 |

---

## Part 1 — Choose a Target (10 min)

Select a bug bounty programme for today's recon exercise. Use:
- HackerOne (`hackerone.com/directory/programs`) — filter by "Cloud" or look
  for programmes with `*.amazonaws.com` in scope
- Bugcrowd (`bugcrowd.com/programs`) — filter by public programmes
- Intigriti (`intigriti.com/programs`)

**Scope criteria to look for:**
- `*.amazonaws.com` in scope
- Cloud infrastructure explicitly mentioned
- SaaS companies with developer tools (high chance of AWS backend)

**What to look for in scope exclusions:**
- "AWS infrastructure" excluded → skip
- "Only production domains" in scope → S3 subdomains may be borderline
- "$10,000+ critical" payout → cloud escalation chains are worth pursuing

> Do not test without reading the programme policy. Do not submit anything you
> are not authorised to find. Today's exercise is recon only — no testing.

---

## Part 2 — Cloud Provider Fingerprinting (20 min)

```bash
TARGET="target-company.com"   # Replace with chosen target

# Step 1: DNS-based cloud fingerprinting
dig $TARGET A CNAME | grep -E 'amazonaws|azure|googleapis|cloudfront'
dig $TARGET MX | grep -E 'google|microsoft|amazonses'
dig $TARGET TXT | grep -E 'v=spf1|amazon|google|microsoft'

# Step 2: HTTP response headers
curl -sI https://$TARGET | grep -iE 'server:|x-amz|x-ms-|x-goog|via:|cf-ray|x-cache'
# x-amz-* → Amazon
# x-ms-* → Microsoft/Azure
# x-goog-* → Google Cloud
# cf-ray → CloudFlare (but backend may still be AWS)
# Via: 1.1 cloudfront.net → AWS CloudFront

# Step 3: TLS certificate SAN enumeration
openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -text 2>/dev/null | \
  grep -oP 'DNS:\K[^\s,]+' | sort -u | head -30

# Step 4: ASN lookup — is the IP in a cloud provider ASN?
IP=$(dig +short $TARGET | tail -1)
curl -s "https://ipinfo.io/$IP" | jq '{org: .org, hostname: .hostname}'
# "org": "AS16509 Amazon.com, Inc." → AWS
# "org": "AS8075 Microsoft Corporation" → Azure
# "org": "AS15169 Google LLC" → GCP

# Step 5: SSL certificate transparency — find all subdomains
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  python3 -c "
import sys, json
try:
    certs = json.load(sys.stdin)
    names = {c['name_value'] for c in certs}
    for n in sorted(names):
        print(n)
except:
    print('Error parsing crt.sh response')
" | grep -v '\*\.' | head -50
```

---

## Part 3 — S3 Bucket Discovery (45 min)

### 3.1 — Passive Source Mining

```bash
# Source 1: Wayback Machine CDX API
curl -s "https://web.archive.org/cdx/search/cdx?\
url=*.s3.amazonaws.com&output=json&fl=original&limit=5000&collapse=urlkey" \
  2>/dev/null | \
  python3 -c "
import sys, json, re
try:
    entries = json.load(sys.stdin)
    buckets = set()
    for e in entries:
        if isinstance(e, list) and len(e) > 0:
            m = re.search(r'https?://([a-z0-9.-]+)\.s3', e[0])
            if m:
                buckets.add(m.group(1))
    for b in sorted(buckets):
        print(b)
except:
    pass
" | grep "$TARGET\|targetcorp\|$(echo $TARGET | cut -d. -f1)"

# Source 2: GitHub code search (requires gh CLI)
COMPANY=$(echo $TARGET | cut -d. -f1)
gh search code "s3.amazonaws.com $COMPANY" \
  --json path,textMatches --limit 100 2>/dev/null | \
  python3 -c "
import sys, json, re
try:
    results = json.load(sys.stdin)
    buckets = set()
    for r in results:
        for m in r.get('textMatches', []):
            fragment = m.get('fragment', '')
            found = re.findall(r'([a-z0-9.-]+)\.s3\.amazonaws\.com', fragment)
            buckets.update(found)
    for b in sorted(buckets):
        print(b)
except:
    pass
"

# Source 3: JavaScript files from the target
for jsfile in $(curl -s https://$TARGET 2>/dev/null | \
  grep -oP 'src="\K[^"]+\.js' | head -20); do
  url="https://$TARGET/$jsfile"
  curl -s "$url" 2>/dev/null | \
    grep -oP '[a-z0-9-]+\.s3\.amazonaws\.com' | sort -u
done

# Source 4: CommonCrawl (slower but comprehensive)
# curl -s "http://index.commoncrawl.org/CC-MAIN-2025-10-index?url=*.s3.amazonaws.com&output=json&limit=100"

# Collect all discovered bucket names
sort -u /tmp/discovered-buckets.txt 2>/dev/null
```

### 3.2 — Target-Specific Wordlist Generation

```python
# bucket_wordlist.py
import sys, itertools

COMPANY = sys.argv[1] if len(sys.argv) > 1 else "targetcorp"

# Extract meaningful name variants
company_variants = [
    COMPANY,
    COMPANY.replace("-", ""),
    COMPANY.replace(".", "-"),
    COMPANY.split(".")[0] if "." in COMPANY else COMPANY,
]

environments = ["", "prod", "production", "staging", "stg", "dev",
                "development", "test", "qa", "uat", "sandbox", "demo",
                "beta", "alpha", "preview"]

services = ["", "api", "app", "web", "mobile", "backend", "frontend",
            "data", "analytics", "ml", "ai", "logs", "log", "backup",
            "backups", "assets", "static", "media", "uploads", "files",
            "images", "docs", "documents", "archive", "exports", "reports",
            "terraform", "tf", "tfstate", "infra", "infrastructure",
            "config", "configs", "secrets", "creds", "keys", "internal",
            "private", "public", "shared", "common", "core", "base"]

regions = ["", "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
separators = ["-", ".", ""]

names = set()
for company in company_variants:
    for env in environments:
        for svc in services:
            for sep in separators:
                parts = [p for p in [company, env, svc] if p]
                if 2 <= len(parts) <= 3:
                    names.add(sep.join(parts))

# Filter by S3 name constraints
names = {n for n in names if 3 <= len(n) <= 63
         and n[0].isalnum() and n[-1].isalnum()
         and "--" not in n and ".." not in n}

with open("wordlist.txt", "w") as f:
    f.write("\n".join(sorted(names)))

print(f"Generated {len(names)} bucket name candidates", file=sys.stderr)
```

```bash
python3 bucket_wordlist.py targetcorp
wc -l wordlist.txt
```

### 3.3 — Fast Async Bucket Check

```python
# check_buckets.py
import asyncio, aiohttp, sys, time

async def check_bucket(session: aiohttp.ClientSession, name: str,
                       results: dict) -> None:
    url = f"https://{name}.s3.amazonaws.com/"
    try:
        async with session.head(url, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=5)) as r:
            if r.status == 200:
                results["public"].append(name)
                print(f"[PUBLIC]  {name}")
            elif r.status == 403:
                results["exists"].append(name)
                print(f"[EXISTS]  {name}")
            # 404 = does not exist — skip
    except Exception:
        pass

async def main() -> None:
    wordlist = sys.argv[1] if len(sys.argv) > 1 else "wordlist.txt"
    with open(wordlist) as f:
        names = [line.strip() for line in f if line.strip()]

    results = {"public": [], "exists": []}
    connector = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Process in batches to avoid overwhelming the target
        batch_size = 50
        for i in range(0, len(names), batch_size):
            batch = names[i:i + batch_size]
            await asyncio.gather(*[check_bucket(session, n, results)
                                   for n in batch])
            await asyncio.sleep(0.5)   # Polite delay between batches

    print(f"\n=== Summary ===")
    print(f"Public buckets: {len(results['public'])}")
    print(f"Existing (private) buckets: {len(results['exists'])}")
    if results["public"]:
        print("\n[!] PUBLIC BUCKETS (high priority):")
        for b in results["public"]:
            print(f"  - {b}")

asyncio.run(main())
```

```bash
python3 check_buckets.py wordlist.txt 2>&1 | tee bucket-results.txt
```

---

## Part 4 — SSRF Entry Point Mapping (30 min)

```bash
# Map all potential SSRF vectors on the target
# These are parameter names that typically cause server-side HTTP requests

# Step 1: Collect all URLs with parameters from passive sources
gau $TARGET 2>/dev/null | grep '?' | \
  grep -iE '[?&](url|callback|redirect|endpoint|webhook|fetch|target|dest|destination|uri|imageurl|src|source|link|next|return|return_url|continue|jump|goto|image|icon|thumb|proxy|remote|open|site|page|host|feed|rss|atom|load|ref|referer|referrer)=' \
  | sort -u | head -100

# Step 2: Spider the target for forms and AJAX endpoints
# Use waybackurls for passive enumeration only (no active requests)
waybackurls $TARGET 2>/dev/null | \
  grep -iE '/(fetch|render|preview|download|webhook|redirect|proxy|load)' | \
  sort -u | head -50

# Step 3: Search source code for URL-fetching patterns
# (GitHub search for the company's open-source code)
gh search code "requests.get site:github.com/targetcorp" --limit 20 2>/dev/null
gh search code "urllib.request site:github.com/targetcorp" --limit 20 2>/dev/null
gh search code "curl -s site:github.com/targetcorp" --limit 20 2>/dev/null

# Step 4: Document SSRF candidates
cat > ssrf-candidates.txt << 'EOF'
# Format: URL | Parameter | Note
https://app.target.com/api/screenshot?url= | url | Screenshot service
https://app.target.com/webhook | callbackUrl | Webhook configuration
https://app.target.com/import?source= | source | Data import endpoint
EOF
```

---

## Part 5 — Prioritise and Plan (15 min)

```
Impact Matrix for Cloud Findings (use this to prioritise testing time):

Finding                          | Effort | Payout Range | Priority
---------------------------------|--------|--------------|--------
SSRF → IMDS → admin escalation   | Med    | $10k–$50k    | 1st
Public S3 with PII               | Low    | $5k–$25k     | 2nd
Terraform state public           | Low    | $3k–$20k     | 2nd
Lambda env var exposure          | Med    | $1k–$10k     | 3rd
IAM privesc via misconfigured SA  | High   | $5k–$30k     | 3rd
Cross-account role open to all   | Med    | $5k–$15k     | 4th

Test order:
1. Check every discovered S3 bucket (low effort, high yield)
2. Test every SSRF candidate for IMDS access
3. Enumerate Lambda functions (if you have any valid credentials)
4. Check IAM trust policies (if you have any valid credentials)
```

Write your personalised test plan for the chosen programme:
- List of S3 buckets to test (from Part 3)
- SSRF endpoints to test (from Part 4)
- Estimated time per item
- Estimated payout if successful

---

## Key Takeaways

1. **Passive S3 discovery often outperforms wordlist brute-forcing.** Wayback
   Machine, GitHub code search, and certificate transparency logs collectively
   surface buckets that no wordlist would contain — because they were named
   after internal codenames or random IDs.
2. **SSRF entry points are predictable by parameter name.** Any parameter named
   `url`, `callback`, `webhook`, `fetch`, `redirect`, `imageUrl`, or similar
   deserves SSRF testing. Collect these before testing — do not enumerate
   randomly.
3. **Cloud fingerprinting from DNS and headers is zero-risk recon.** No requests
   reach the target application. This is always in scope and always reveals
   the cloud provider, CDN, email provider, and subdomain structure.
4. **Terraform state files are passive gold.** They do not require SSRF or
   credentials to find — just a public S3 bucket. Always include `terraform`,
   `tfstate`, `tf`, and `infra` in every S3 wordlist for every target.
5. **Map everything before testing anything.** A 2-hour recon session that
   surfaces 10 buckets and 5 SSRF candidates is worth more than 2 hours of
   random endpoint testing. The recon determines the test plan.

---

## Exercises

1. Complete the full recon methodology against your chosen bug bounty programme.
   Document every finding in a structured note (one section per recon technique).
   Do not test — document only.
2. Write a shell script that automates the full cloud recon pipeline for any
   domain: (a) DNS fingerprinting, (b) certificate SANs, (c) ASN lookup, (d)
   passive S3 bucket discovery from Wayback, (e) SSRF parameter enumeration
   from GAU. Output a structured report.
3. Research: what is the difference between `s3.amazonaws.com/bucket` (path-style)
   and `bucket.s3.amazonaws.com` (virtual-hosted-style)? Which one is easier to
   discover via passive recon? Does one bypass some security controls?
4. Build a personal cloud bug bounty scope tracker: a Markdown or CSV file that
   lists programmes with significant cloud attack surface, their payout ranges,
   known cloud provider, and your current status on each.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q205.1, Q205.2 …).
> Follow-up questions use hierarchical numbering (Q205.1.1, Q205.1.2 …).

---

## Navigation

← Previous: [Day 204 — Cloud Practice: CloudTrail Evasion and Hunting](DAY-0204-Cloud-Practice-CloudTrail-Evasion.md)
→ Next: [Day 206 — Cloud Practice: HTB Cloud Challenges](DAY-0206-Cloud-Practice-HTB-Challenges.md)
