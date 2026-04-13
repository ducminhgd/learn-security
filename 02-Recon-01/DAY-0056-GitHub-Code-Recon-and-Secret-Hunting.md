---
title: "GitHub Code Recon and Secret Hunting — Dorking, truffleHog, gitleaks"
tags: [recon, github, secret-hunting, trufflehog, gitleaks, gitdorker, exposed-credentials,
       api-keys, T1593, commit-history, wayback]
module: 02-Recon-01
day: 56
related_topics:
  - Email People and LinkedIn OSINT (Day 055)
  - Cloud Asset and Bucket Discovery (Day 057)
  - MITRE ATT&CK T1593.003 (Code Repositories)
---

# Day 056 — GitHub Code Recon and Secret Hunting

## Goals

By the end of this lesson you will be able to:

1. Use GitHub search operators to find an organisation's repositories and code.
2. Identify high-value dorks for locating exposed secrets in public code.
3. Run `gitleaks` against a repository to find secrets in commit history.
4. Run `truffleHog v3` against a GitHub organisation and interpret results.
5. Use the Wayback Machine to find deleted code and pages.
6. Explain why Git commit history is a persistent data store — not an undo button.

---

## Prerequisites

- [Day 055 — Email, People and LinkedIn OSINT](DAY-0055-Email-People-and-LinkedIn-OSINT.md)

---

## Main Content

### 1. Why Code Repositories Are the Best Passive Recon Source

Source code is the specification of a system. When it is public, the attacker
has the blueprint.

**What public repositories reveal:**

```
┌──────────────────────────────────────────────────────────────────┐
│ WHAT DEVS COMMIT                  │ ATTACKER VALUE               │
├───────────────────────────────────┼──────────────────────────────┤
│ API keys and secrets              │ Direct account compromise    │
│ Database connection strings       │ Direct DB access             │
│ Internal URLs and hostnames       │ Expand attack surface        │
│ Infrastructure-as-code (Terraform)│ Cloud architecture map       │
│ CI/CD pipeline config             │ Build system attack surface  │
│ Hardcoded credentials             │ Credential reuse attacks     │
│ Commented-out debug code          │ Logic flaws, hidden features │
│ TODO: "fix this auth bypass"      │ Confirmed vulnerabilities    │
│ Error messages and stack traces   │ Technology fingerprinting    │
│ Third-party integrations          │ Supply chain attack surface  │
└──────────────────────────────────────────────────────────────────┘
```

**Real-world context:** The 2022 GitHub token exposure study by GitGuardian found
that 10 million secrets were exposed in public GitHub commits in a single year.
This is not a rare edge case — it is the norm.

---

### 2. GitHub Search Operators

GitHub has a powerful code search engine. Attackers use it to find secrets across
all public repositories.

#### Organisation and Repository Discovery

```
# Find all public repos for an organisation
org:acmecorp

# Find all repos owned by a user
user:jsmith-acmecorp

# Repositories containing specific terms
org:acmecorp "internal api"

# Repos with specific filenames
org:acmecorp filename:.env
org:acmecorp filename:credentials.json
org:acmecorp filename:id_rsa
```

#### Code Search for Secrets

```
# API keys and tokens
org:acmecorp "api_key"
org:acmecorp "AWS_SECRET_ACCESS_KEY"
org:acmecorp "AKIA" extension:env        # AWS Access Key ID prefix
org:acmecorp "sk-" extension:py          # OpenAI/Stripe key prefix

# Database credentials
org:acmecorp "DB_PASSWORD" extension:env
org:acmecorp "postgresql://" extension:py
org:acmecorp "mongodb+srv://"
org:acmecorp "mysql://" "password"

# Private keys
org:acmecorp "BEGIN RSA PRIVATE KEY"
org:acmecorp "BEGIN OPENSSH PRIVATE KEY"
org:acmecorp "BEGIN PGP PRIVATE KEY BLOCK"

# JWT secrets
org:acmecorp "JWT_SECRET"
org:acmecorp "SECRET_KEY" extension:env

# Internal URLs and hostnames
org:acmecorp "internal.acmecorp.com"
org:acmecorp "10.0." extension:tf        # Internal IPs in Terraform
org:acmecorp "192.168." extension:yaml

# Infrastructure config
org:acmecorp filename:terraform.tfvars
org:acmecorp filename:.env.production
org:acmecorp filename:config.prod.json
```

#### GitHub Advanced Search

GitHub's web search at `github.com/search` supports:

| Qualifier | Example | Purpose |
|---|---|---|
| `org:` | `org:acmecorp` | Repos in this org |
| `user:` | `user:jsmith` | Repos by this user |
| `filename:` | `filename:.env` | Specific filename |
| `extension:` | `extension:yaml` | File extension |
| `path:` | `path:config/` | File in this path |
| `language:` | `language:python` | Language filter |
| `pushed:` | `pushed:>2024-01-01` | Recently updated |
| `stars:` | `stars:>100` | Popular repos |
| `is:public` | `is:public` | Public only |

---

### 3. GitDorker — Automated GitHub Dorking

GitDorker automates running hundreds of dorks against a GitHub organisation
using the GitHub API.

```bash
# Install
git clone https://github.com/obheda12/GitDorker.git
cd GitDorker
pip install -r requirements.txt

# Run against a target org (requires GitHub personal access token)
python3 GitDorker.py -tf TOKENS.txt -q acmecorp.com -d dorks/medium_dorks.txt

# Run with org-specific search
python3 GitDorker.py -tf TOKENS.txt -q "org:acmecorp" -d dorks/large_dorks.txt

# Note: GitHub rate limits unauthenticated requests to 10/min.
# With a token: 30 search requests/min.
# TOKENS.txt = one GitHub personal access token per line (rotate to avoid limits)
```

---

### 4. Understanding Git Commit History

This is the most important concept in this lesson:

> **A commit is forever.** Deleting a file from a repository does not remove it
> from history. The data exists in every clone of the repository, in GitHub's
> servers, in CI/CD caches, and in Wayback Machine snapshots.

**The wrong mental model developers have:**

```
Dev commits .env with API key → realises mistake → deletes .env → pushes again
Dev thinks: "It's gone now."

Reality:
  git log --all --full-history -- .env
  git show <commit-hash>:.env
  → API key is right there, in full.
```

**How attackers exploit this:**

```bash
# Search git history for secrets in any cloned repo
git log --all --oneline | head -20     # List all commits

# Search for a string across all commits
git log -p --all -S "password" | grep "^+"

# Find when a file was deleted
git log --all --full-history -- ".env"

# Restore a deleted file from a specific commit
git show <commit-hash>:.env

# Find all changes to a config file ever
git log --follow -p -- config/database.yml
```

---

### 5. gitleaks — Secret Scanning

gitleaks scans a repository (including full history) for secrets using regex
rules and entropy analysis.

```bash
# Install
go install github.com/gitleaks/gitleaks/v8@latest
# or: brew install gitleaks

# Scan a local repository (full history)
cd /path/to/repo
gitleaks detect --source . --report-format json --report-path leaks.json

# Scan a specific Git revision
gitleaks detect --source . --log-opts="HEAD~50..HEAD"

# Scan a remote GitHub repo (without cloning)
gitleaks detect --source . --repo-url https://github.com/acmecorp/backend

# Clone and scan in one step
git clone --depth=0 https://github.com/acmecorp/backend /tmp/acmecorp-backend
cd /tmp/acmecorp-backend
gitleaks detect --source . --report-format json --report-path leaks.json

# Read the results
cat leaks.json | python3 -c "
import json, sys
leaks = json.load(sys.stdin)
for leak in leaks:
    print(f'[LEAK] Rule: {leak[\"RuleID\"]}')
    print(f'       File: {leak[\"File\"]}:{leak[\"StartLine\"]}')
    print(f'       Commit: {leak[\"Commit\"]}')
    print(f'       Secret: {leak[\"Secret\"][:40]}...' if len(leak['Secret']) > 40
          else f'       Secret: {leak[\"Secret\"]}')
    print()
"
```

**gitleaks rule categories** (from its built-in ruleset):

| Rule | What it detects |
|---|---|
| `aws-access-token` | AWS Access Key IDs (`AKIA...`) |
| `aws-secret-key` | AWS Secret Access Keys |
| `github-pat` | GitHub personal access tokens |
| `stripe-api-key` | Stripe secret keys (`sk_live_...`) |
| `twilio-api-key` | Twilio auth tokens |
| `private-key` | PEM private keys |
| `generic-api-key` | High-entropy strings near "key", "secret", "token" |
| `password-in-url` | Passwords embedded in connection strings |

---

### 6. truffleHog v3 — Deep Secret Scanning

truffleHog (v3 rewrite) uses both regex and Shannon entropy to find secrets.
It has verified detectors for 700+ secret types.

```bash
# Install
pip install trufflehog
# or: go install github.com/trufflesecurity/trufflehog/v3@latest

# Scan a GitHub org (all public repos)
trufflehog github --org=acmecorp

# Scan a specific repo
trufflehog git https://github.com/acmecorp/backend

# Scan with verified secrets only (reduces false positives)
trufflehog github --org=acmecorp --only-verified

# Scan since a specific date
trufflehog git https://github.com/acmecorp/backend --since-commit HEAD~100

# JSON output
trufflehog github --org=acmecorp --json
```

**The `--only-verified` flag** is important: truffleHog actively calls the
API provider to check if a found token is still valid. This is active behaviour —
but it pings the API service, not the target directly. For passive recon mode,
use without `--only-verified` and manually verify findings.

---

### 7. What to Do With a Found Secret

When you find a secret in a public repository:

**In a bug bounty context:**

```
1. DO NOT use the secret to access any production system.
2. DO document: repo URL, commit hash, filename, line number.
3. DO assess the secret type: AWS key? GitHub token? Database password?
4. DO check if the secret is still active (use provider-specific validation).
   For AWS: aws sts get-caller-identity --no-verify-ssl  ← test key
   For GitHub: curl -H "Authorization: token <TOKEN>" https://api.github.com/user
5. REPORT it according to the programme's disclosure policy.
   Severity: High to Critical depending on the system it accesses.
6. DO NOT wait — leaked keys should be reported the same day.
```

**Severity examples:**

| Secret Found | Impact | Typical Severity |
|---|---|---|
| AWS key with AdministratorAccess | Full cloud takeover | Critical |
| Database connection string (production) | Full data access | Critical |
| GitHub token with write access | Repo poisoning, CI/CD access | High |
| Stripe live key | Financial fraud capability | Critical |
| Internal API key (limited scope) | Limited data exposure | Medium-High |
| Expired key | None | Informational |

---

### 8. Wayback Machine — Deleted Content

The Internet Archive (archive.org) crawls and snapshots the web continuously.
Content removed from a site may persist in the archive for years.

```bash
# Check if a URL has archived versions
curl -s "http://archive.org/wayback/available?url=acmecorp.com/.env"

# Get all snapshots of a URL
curl -s "http://web.archive.org/cdx/search/cdx?url=acmecorp.com/.env&output=json"

# Using waybackurls tool — find all archived URLs for a domain
go install github.com/tomnomnom/waybackurls@latest
echo "acmecorp.com" | waybackurls | tee wayback_urls.txt

# Filter for interesting file types
cat wayback_urls.txt | grep -E "\.(env|sql|bak|log|config|xml|json|php|asp)$"

# Filter for potentially sensitive paths
cat wayback_urls.txt | grep -E "(admin|backup|config|credentials|password|secret|token)"
```

**High-value archived content:**

```
acmecorp.com/.env                     ← Often present in early deployment mistakes
acmecorp.com/backup.sql               ← Database dumps
acmecorp.com/wp-config.php.bak        ← WordPress config backups
acmecorp.com/config/production.json   ← App configuration
acmecorp.com/admin/                   ← Previously public admin panels
```

---

## Key Takeaways

1. **Git history is a permanent record.** When a developer says "I deleted the
   secret," what they mean is "I made it harder to find." It is still in the
   history. Teach this to every developer you work with.
2. **The `org:` GitHub operator is your best friend.** One search with the right
   dork across an entire organisation's repos is faster than reading every file.
3. **gitleaks + truffleHog are complementary.** Run both. gitleaks is faster for
   single repos; truffleHog covers more secret types and can scan entire GitHub orgs.
4. **Verify before escalating.** A regex match on "password" is not a finding.
   A confirmed active AWS key with AdministratorAccess is a Critical finding.
   Know the difference.
5. **Wayback Machine recovers what was never meant to survive.** Files deleted in
   panic after a security incident often persist in archives for years. Always check.

---

## Exercises

### Exercise 1 — GitHub Dork Practice

Search GitHub for:

1. Repositories in the `torvalds` user namespace containing `.env` files.
2. Any public repository with `"BEGIN RSA PRIVATE KEY"` in Python files.
3. The string `"AWS_SECRET_ACCESS_KEY"` in YAML files.
4. Any repository containing `"mongodb+srv://"` in JavaScript files.

For each result: note the repository, file, and whether the secret appears active
or revoked (expired format, obvious placeholder value, etc.).

---

### Exercise 2 — gitleaks on a Test Repository

1. Clone `https://github.com/trufflesecurity/test_keys` (a public test repo
   containing fake keys for scanner testing).
2. Run `gitleaks detect --source . --report-format json --report-path leaks.json`.
3. How many findings? What types?
4. Run `trufflehog git https://github.com/trufflesecurity/test_keys`. Compare results.

---

### Exercise 3 — Wayback Archaeology

1. Run `echo "bugcrowd.com" | waybackurls`.
2. Filter for `.env`, `.sql`, `.bak`, `.json` files.
3. Check if any archived URLs still return content (visit the Wayback Machine URL).
4. What is the oldest archived version of `bugcrowd.com`?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 055 — Email, People and LinkedIn OSINT](DAY-0055-Email-People-and-LinkedIn-OSINT.md)*
*Next: [Day 057 — Cloud Asset and Bucket Discovery](DAY-0057-Cloud-Asset-and-Bucket-Discovery.md)*
