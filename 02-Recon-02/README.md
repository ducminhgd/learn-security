# 02-Recon-02 — Active Recon and Bug Bounty Scope (Days 063–075)

**Track:** Reconnaissance  
**Module:** Active Recon and Bug Bounty Scope  
**Days:** 063–075  
**Competency Gate:** Day 075 — Recon Ready

---

## Module Overview

This module covers all active recon techniques used in professional bug bounty
hunting and penetration testing. You will learn to enumerate services, discover
hidden web content, extract intelligence from JavaScript, and understand how
scope boundaries work in a real programme.

Active recon means your packets reach the target. Everything you do here leaves
a trace. Operate with that knowledge.

---

## Lessons

| Day | File | Topic |
|-----|------|-------|
| 063 | [DAY-0063-nmap-from-First-Principles.md](DAY-0063-nmap-from-First-Principles.md) | SYN scan, connect scan, UDP scan — packet-level detail |
| 064 | [DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md) | -sV, -O, NSE scripts, fragmentation, decoys, timing |
| 065 | [DAY-0065-Directory-and-Endpoint-Fuzzing.md](DAY-0065-Directory-and-Endpoint-Fuzzing.md) | ffuf, dirsearch, feroxbuster — wordlists, recursion, filters |
| 066 | [DAY-0066-Parameter-Discovery-and-JS-Analysis.md](DAY-0066-Parameter-Discovery-and-JS-Analysis.md) | arjun, paramspider, LinkFinder, JS file endpoint mining |
| 067 | [DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md](DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md) | Wappalyzer, whatweb, header analysis, error page analysis |
| 068 | [DAY-0068-Masscan-and-Fast-Network-Scanning.md](DAY-0068-Masscan-and-Fast-Network-Scanning.md) | masscan internals, rate limiting, combining with nmap |
| 069 | [DAY-0069-Active-Recon-Lab.md](DAY-0069-Active-Recon-Lab.md) | Lab: full active recon on a lab target |
| 070 | [DAY-0070-Recon-Automation-Pipeline.md](DAY-0070-Recon-Automation-Pipeline.md) | amass → httpx → nuclei → report pipeline |
| 071 | [DAY-0071-Bug-Bounty-Scope-Analysis.md](DAY-0071-Bug-Bounty-Scope-Analysis.md) | Programme policies, in/out-of-scope, wildcards, safe harbour |
| 072 | [DAY-0072-Bug-Bounty-Recon-Methodology.md](DAY-0072-Bug-Bounty-Recon-Methodology.md) | End-to-end methodology from scope to enumerated targets |
| 073 | [DAY-0073-Detecting-Recon.md](DAY-0073-Detecting-Recon.md) | Honeypots, canary tokens, log analysis for crawlers |
| 074 | [DAY-0074-Recon-Review-and-Preparation.md](DAY-0074-Recon-Review-and-Preparation.md) | Review all recon techniques; prepare attack surface doc |
| 075 | [DAY-0075-Recon-Competency-Gate.md](DAY-0075-Recon-Competency-Gate.md) | **GATE: Recon Ready** — submit attack surface document |

---

## Tools Covered

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service detection, NSE scripts |
| masscan | Fast stateless port scanning at scale |
| ffuf | Web content / directory / parameter fuzzing |
| dirsearch | Directory fuzzing with built-in extension handling |
| feroxbuster | Recursive directory fuzzing |
| arjun | Hidden parameter discovery |
| paramspider | Historical URL parameter harvesting |
| LinkFinder | JavaScript endpoint extraction |
| Wappalyzer / whatweb | Technology stack fingerprinting |
| httpx | HTTP probing and bulk fingerprinting |
| subfinder / amass | Subdomain enumeration |
| nuclei | Template-based vulnerability scanning |
| subjack | Subdomain takeover detection |
| canarytokens.org | Honeypot tripwire deployment |

---

## Competency Gate — Day 075

To complete this module, you must pass the Day 075 gate:

- Submit a complete attack surface document for an authorised target
- Complete a live demo covering all active recon phases
- Pass an oral knowledge check (4/5 random questions)

See [DAY-0075-Recon-Competency-Gate.md](DAY-0075-Recon-Competency-Gate.md)
for full gate requirements.

---

*Previous module: [02-Recon-01](../02-Recon-01/README.md)*  
*Next module: [03-WebExploit-01](../03-WebExploit-01/) — Injection Attacks*
