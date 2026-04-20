---
title: "Bug Bounty Recon Methodology — End-to-End from Scope to Enumerated Targets"
tags: [bug-bounty, methodology, recon, scope-to-targets, decision-framework,
       attack-surface-document, target-prioritisation, workflow, T1595, T1590]
module: 02-Recon-02
day: 72
related_topics:
  - Bug Bounty Scope Analysis (Day 071)
  - Recon Automation Pipeline (Day 070)
  - Attack Surface Mapping (Day 059)
  - Passive Recon Lab (Day 060)
  - Detecting Recon (Day 073)
---

# Day 072 — Bug Bounty Recon Methodology

## Goals

By the end of this lesson you will be able to:

1. Execute a complete recon workflow from scope analysis to a prioritised target list.
2. Make principled decisions about where to spend time after recon.
3. Produce a structured attack surface document that drives exploitation.
4. Distinguish between a recon workflow optimised for speed vs one optimised
   for thoroughness.
5. Know when recon is done and when to start testing.

---

## Prerequisites

- [Day 059 — Attack Surface Mapping](../02-Recon-01/DAY-0059-Attack-Surface-Mapping.md)
- [Day 070 — Recon Automation Pipeline](DAY-0070-Recon-Automation-Pipeline.md)
- [Day 071 — Bug Bounty Scope Analysis](DAY-0071-Bug-Bounty-Scope-Analysis.md)

---

## Main Content

> "Recon is the difference between hunting and guessing. You can guess forever.
> Hunting has a beginning, a method, and an end. Know when to stop reconning
> and start attacking."
>
> — Ghost

### 1. The Full Recon Lifecycle

```
Phase 0: Scope Analysis (15–30 min)
  ↓ Understand what is in scope, what is prohibited
Phase 1: Passive Recon (30–60 min)
  ↓ No traffic to target; harvest from public sources
Phase 2: Active Recon (45–90 min)
  ↓ Direct interaction with target; enumerate services and content
Phase 3: Analysis and Prioritisation (30 min)
  ↓ Aggregate findings; rank attack surface by value
Phase 4: Document (15 min)
  ↓ Attack surface document → input for exploitation phase
```

Total: 2–4 hours for a medium-sized programme.
This is the investment before you write a single exploit payload.

---

### 2. Phase 0 — Scope Analysis

*(Covered in detail in Day 071)*

**Output:** Confirmed in-scope list and programme rules.

```bash
# Create scope files
cat > in_scope.txt << 'EOF'
*.target.com
EOF

cat > out_of_scope.txt << 'EOF'
blog.target.com
careers.target.com
mail.target.com
EOF

# Verify: does this programme allow port scanning?
# Y/N: ____
# Does it allow automated scanning?
# Y/N (and rate limit): ____
# Safe harbour present?
# Y/N: ____
```

---

### 3. Phase 1 — Passive Recon

Run these techniques against your scope without sending any traffic to the target.
Everything goes to public sources.

```bash
# 1.1 Subdomain enumeration (passive only)
subfinder -d target.com -all -silent | tee passive/subs_subfinder.txt

# 1.2 Certificate Transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
seen = set()
for e in data:
    for name in e.get('name_value','').split('\n'):
        name = name.strip().lstrip('*.')
        if name and name not in seen:
            seen.add(name)
            print(name)
" | tee passive/subs_crtsh.txt

# 1.3 GitHub recon
# Check: github.com/search?q=target.com
# Look for: API keys, credentials, internal paths, infrastructure details

# 1.4 Job postings
# Check LinkedIn, Indeed, Glassdoor for "target.com" job postings
# Note: tech stack from requirements, infrastructure hints from descriptions

# 1.5 Wayback Machine
waybackurls target.com | tee passive/wayback_urls.txt
cat passive/wayback_urls.txt | grep -iE "\.(env|sql|bak|log|xml|json|conf)$" > \
    passive/wayback_interesting.txt

# 1.6 Google dorks
# site:target.com filetype:env OR filetype:sql OR filetype:bak
# site:target.com intext:"api_key" OR intext:"password"

# 1.7 Shodan (if you have API access)
shodan search "hostname:target.com" --fields ip_str,port,org,product | \
    tee passive/shodan.txt

# Merge subdomains
cat passive/subs_*.txt | sort -u > passive/all_subs.txt
```

**Passive recon output:**

```
passive/
├── all_subs.txt          — all discovered subdomains
├── wayback_urls.txt      — historical URLs
├── wayback_interesting.txt — interesting historical files
├── shodan.txt            — externally visible services
└── notes.md              — manual findings from GitHub, job postings
```

---

### 4. Phase 2 — Active Recon

Now we interact with the target. Only do this after confirming active recon
is allowed in the programme's rules of engagement.

```bash
mkdir -p active/{dns,ports,web,js,params}

# 2.1 DNS resolution — filter to live subdomains
cat passive/all_subs.txt | \
    dnsx -silent -a -resp-only | sort -u > active/dns/ips.txt

cat passive/all_subs.txt | \
    dnsx -silent -a | awk '{print $1}' | sort -u > active/dns/resolved_subs.txt

# Apply out-of-scope filter
grep -vFf out_of_scope.txt active/dns/resolved_subs.txt > active/dns/in_scope_subs.txt

# 2.2 HTTP probing
cat active/dns/in_scope_subs.txt | \
    httpx -silent -status-code -title -tech-detect -server \
    -rate-limit 100 -threads 50 \
    -json -o active/web/httpx.json

cat active/web/httpx.json | python3 -c "
import json, sys
for line in sys.stdin:
    try: print(json.loads(line)['url'])
    except: pass
" | sort -u > active/web/live_urls.txt

# 2.3 Port scanning (if allowed)
cat active/dns/ips.txt | while read ip; do
    sudo nmap -sS -sV -p 22,80,443,3306,5432,8080,8443,8000,3000,6379,9200,27017 \
         --open --min-rate 200 -oG - "$ip" 2>/dev/null
done | grep "open" | tee active/ports/interesting_ports.txt

# 2.4 Directory fuzzing on key targets
# (Run against highest-value targets only — not all 200+ subdomains)
HIGH_VALUE_TARGETS=$(cat active/web/httpx.json | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        title = e.get('title','').lower()
        url = e.get('url','')
        # Prioritise: admin, login, API, dashboard
        if any(kw in title for kw in ['admin','login','dashboard','api','portal']):
            print(url)
        elif any(kw in url.lower() for kw in ['/api/','/admin','/v1/','/v2/']):
            print(url)
    except:
        pass
" | head -20)

echo "$HIGH_VALUE_TARGETS" | while read url; do
    domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||' | tr ':' '_')
    ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
         -u "${url}/FUZZ" \
         -mc 200,301,302,403 -fc 404 \
         -rate 50 \
         -o "active/web/ffuf_${domain}.json" -of json -silent
done

# 2.5 JS analysis on main targets
echo "$HIGH_VALUE_TARGETS" | while read url; do
    domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||' | tr ':' '_')
    python3 /opt/LinkFinder/linkfinder.py -i "$url" -d -o cli 2>/dev/null | \
        tee -a active/js/endpoints_${domain}.txt
done

# 2.6 nuclei scanning
nuclei -l active/web/live_urls.txt \
    -t exposures/ -t takeovers/ -t misconfiguration/ \
    -severity medium,high,critical \
    -rate-limit 50 \
    -json -o active/web/nuclei.json -silent 2>/dev/null
```

---

### 5. Phase 3 — Analysis and Prioritisation

This is the brain work. You have data. Now you need to make decisions.

#### 5.1 Target Prioritisation Framework

Rank targets by a combination of:

```
Attack surface value = f(entry_point_type, uniqueness, functionality_richness)

Entry point type (highest to lowest value):
  1. Authentication endpoints (login, password reset, OAuth)
  2. API endpoints handling user data
  3. Admin panels
  4. File upload functionality
  5. Search / filter functionality
  6. Third-party integrations (webhooks, OAuth providers)
  7. Static pages / marketing sites

Uniqueness:
  HIGH:   Custom-built functionality unique to this target
  MEDIUM: Off-the-shelf CMS/framework (well-known bugs exist)
  LOW:    Standard landing page with no functionality

Functionality richness:
  HIGH:   Many input fields, complex workflows, user roles
  MEDIUM: Some interactivity
  LOW:    Informational only
```

#### 5.2 Priority Tiers

```
P0 — Test immediately (most likely bugs, highest payout):
  - Admin panels accessible without authentication
  - nuclei high/critical findings (after manual confirmation)
  - Exposed secrets in JS or config files
  - Non-standard ports with dangerous services (Redis, MySQL, Elasticsearch)
  - Subdomain takeover candidates

P1 — Test next (high-value features):
  - Authentication flows (login, password reset, account creation)
  - API endpoints handling PII or financial data
  - File upload functionality
  - OAuth/SSO integration points

P2 — Test after P0 and P1 (medium-value features):
  - Search and filter functionality
  - User account settings
  - Admin functionality (once you reach admin)
  - API versioning (test old versions)

P3 — Test if time permits:
  - Static pages
  - Public-facing informational endpoints
  - Rate limiting analysis
  - CORS configuration review
```

---

### 6. Attack Surface Document

The final deliverable of recon is a structured document you use during
exploitation. It should be concise and actionable.

```markdown
# Attack Surface Document — target.com

**Date:** 2026-04-17
**Scope:** *.target.com (excl: blog, careers, mail)
**Programme:** HackerOne — Public
**Reward range:** $100–$10,000

---

## Summary Stats

- Subdomains discovered: 143
- Live web services: 67
- Interesting ports: 8 (see below)
- nuclei findings: 3 High, 12 Medium (all need manual verification)

---

## P0 — Immediate Priority

| Asset | Finding | Notes |
|-------|---------|-------|
| api.target.com:6379 | Redis port open, no auth | nuclei confirmed; unauthenticated |
| dev.target.com | nuclei: Spring Boot actuator /env exposed | Exposes env vars |
| staging.target.com | nuclei: takeover candidate (Azure) | Confirm with subjack |
| js analysis: app.js | Hardcoded API key: AIzaSy... | Google Maps API key — test scope |

---

## P1 — Authentication Surfaces

| URL | Method | Notes |
|-----|--------|-------|
| https://app.target.com/login | POST | Standard login; test brute-force, injection |
| https://app.target.com/password-reset | POST | Test token predictability, host-header |
| https://app.target.com/oauth/authorize | GET | OAuth flow; test redirect_uri bypass |
| https://api.target.com/v1/auth/register | POST | Account creation; test mass assignment |

---

## P1 — API Surfaces

| URL | Auth required? | Notes |
|-----|----------------|-------|
| https://api.target.com/v1/users | Yes (inferred) | Test BOLA |
| https://api.target.com/v1/orders | Yes (inferred) | Test IDOR on order ID |
| https://api.target.com/v2/admin | 403 currently | Try auth bypass techniques |
| https://api.target.com/internal/config | 404 (from wayback) | Might return 200 with token |

---

## P2 — Additional Surfaces

*(File upload, search endpoints, admin functionality, etc.)*

---

## Technology Stack

| Component | Version | Known CVEs |
|-----------|---------|-----------|
| nginx | 1.24.0 | None critical |
| Node.js | 18.x | None critical |
| React | 18.2.0 | None critical |
| JWT library | jsonwebtoken 8.5.1 | CVE-2022-23529 (check config) |

---

## Notes / Questions

- Does `api.target.com/v2/admin` accept the same JWT as /v1/? Test auth boundary.
- The Redis instance on api.target.com:6379 — is it also accessible from app servers?
  If yes, SSRF to Redis could give RCE.
- The password reset page did not implement rate limiting in a quick test.
  Verify and document for reporting.
```

---

### 7. Decision: When to Stop Reconning

Signs you have done enough recon:

```
✓ All subdomains are resolved and categorised
✓ All live web services are fingerprinted
✓ Full port scan on at least the top-value targets
✓ JS files analysed for key endpoints and secrets
✓ nuclei has run and findings are triaged
✓ Attack surface document is written and prioritised
✓ You have at least 5–10 things to test in your P0/P1 list

Signs you need more recon:
✗ Attack surface document has fewer than 5 interesting targets
  → Expand subdomain discovery, try different tools
✗ All nuclei findings are false positives
  → Run manual checks on specific technique areas
✗ No non-standard ports found
  → Consider a full port scan (0-65535) on the main target IPs
```

---

### 8. Speed vs Thoroughness Trade-Off

```
Bug bounty is competitive. Other researchers are on the same targets.

Speed-optimised workflow (use when racing for first finds):
  Phase 0: 5 min (know the programme well already)
  Phase 1: 15 min (subfinder + waybackurls only)
  Phase 2: 20 min (httpx + quick nuclei scan)
  Phase 3: 10 min (look for instant P0s)
  Total: 50 min before first test
  Trade-off: miss some attack surface; find the low-hanging fruit first

Thoroughness-optimised workflow (use for deep research):
  Phase 0: 30 min (full policy analysis)
  Phase 1: 60 min (all passive sources, manual GitHub analysis)
  Phase 2: 120 min (full port scan, recursive fuzzing, JS analysis)
  Phase 3: 45 min (full attack surface document)
  Total: 4–5 hours before first test
  Trade-off: find harder bugs; miss the race on obvious ones

Recommendation: Speed-optimised first run → spot the obvious.
Then thoroughness-optimised second run → find what others missed.
```

---

## Key Takeaways

1. **Recon is a structured process, not a list of tools to run.** Each phase
   has a purpose and produces input for the next phase. Random tool execution
   produces random results.
2. **The attack surface document is the recon deliverable.** Without it, you
   have data. With it, you have a plan.
3. **Prioritisation saves time and money.** Testing every endpoint equally is
   wrong. Spend 80% of your exploitation time on P0 and P1 targets.
4. **Know when to stop reconning.** More recon is not always better. Past a
   certain point, you are discovering diminishing returns. The goal is to find
   bugs, not to discover every subdomain in existence.
5. **The methodology must be repeatable.** Every time you return to a programme,
   run the same pipeline again. New infrastructure appears constantly. The P0
   finding from a new subdomain that appeared last week is yours if you recon
   regularly.

---

## Exercises

### Exercise 1 — End-to-End Methodology Run

Pick a public bug bounty programme (or use a lab target):

1. Complete Phases 0–3 fully.
2. Produce an attack surface document.
3. Identify your top 3 P0 targets.
4. Time each phase. Where did you spend the most time?

---

### Exercise 2 — Prioritisation Reasoning

Given the following findings from recon:

1. `admin.target.com` — returns 403, WordPress admin panel detected
2. `api.target.com/v1/users` — returns 200 with a JSON array of user objects (no auth)
3. `static.target.com` — HTML landing page only, no functionality
4. `dev.target.com` — Spring Boot `/actuator/env` exposed, shows DB password
5. `old.target.com` — running Apache 2.2.15 (2010), out of maintenance

Rank these P0–P3 and justify each ranking.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 071 — Bug Bounty Scope Analysis](DAY-0071-Bug-Bounty-Scope-Analysis.md)*
*Next: [Day 073 — Detecting Recon](DAY-0073-Detecting-Recon.md)*
