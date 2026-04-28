---
title: "Ghost's Training Programme — Year 1: Bug Bounty Hunter | Year 2: Deep Hacker"
tags: [syllabus, curriculum, roadmap, bug-bounty, hacking]
updated: 2026-04-28
---

# Ghost's 2-Year Cybersecurity Training Programme

> "You cannot defend what you do not understand. You cannot understand what you have not
> broken. So we break things first — in here, where it is safe — and then we build things
> that are harder to break out there."
>
> — Ghost

---

## Programme Overview

| Property | Value |
|---|---|
| Duration | 2 years (730 days) |
| Daily commitment | 1 structured lesson per day (denser in Year 1) |
| Year 1 goal | Bug bounty hunter — find and earn from real vulnerabilities by Day 365 |
| Year 2 goal | Deep dive — binary exploitation, reversing, red team ops, vuln research |
| Methodology | The Ghost Method: Recon → Exploit → Detect → Harden |
| Assessment | Competency-based gates, not time-based certificates |
| Tools philosophy | Understand the technique first; the tool is just automation |

---

## Competency Gates

| Gate | Criteria | Target |
|---|---|---|
| **Foundation Complete** | Explain + demo any foundation topic; use Burp Suite fluently | Day 50 |
| **Recon Ready** | Build a full attack surface profile; identify scope + gaps | Day 75 |
| **Web Exploitation Ready** | Exploit all OWASP Top 10 + API Top 10 in lab; write real report | Day 165 |
| **Bug Bounty Hunter** | Accepted report on a real public bug bounty program | Day 365 |
| **Binary Exploitation Ready** | Write a working ROP chain for a 64-bit ELF with ASLR | Day 430 |
| **Reverse Engineering Ready** | Reverse a real-world crackme + analyse a packed binary | Day 490 |
| **Ghost Level** | Find + exploit an unknown vuln in a lab target within 48 hours | Day 730 |

---

## Year 1 — "Bug Bounty Hunter" (Days 1–365)

Goal: Become a functional, earning bug bounty hunter. Year 1 is dense. The
foundation is compressed so you reach real hacking faster. Every module ends with
a hands-on lab. No lab = no completion.

---

### 01-Foundation — Foundation Track (Days 1–50)

Goal: Build the mental model of how systems work before touching an exploit.

---

#### 01-Foundation-01 — Network Fundamentals (Days 1–8)

**Lab:** Wireshark — capture and dissect HTTP, TLS, and DNS traffic end-to-end

| Day | File | Topic |
|---|---|---|
| 001 | `01-Foundation-01/DAY-0001-OSI-Model-and-TCP-IP-Stack.md` | OSI layers, TCP/IP model, encapsulation, attacker perspective |
| 002 | `01-Foundation-01/DAY-0002-IP-Subnetting-and-TCP-State-Machine.md` | IPv4/IPv6, CIDR, TCP three-way handshake, flags, state machine |
| 003 | `01-Foundation-01/DAY-0003-UDP-ICMP-and-DNS-Deep-Dive.md` | UDP header, ICMP types, DNS resolution chain, record types |
| 004 | `01-Foundation-01/DAY-0004-DNS-Attacks-and-HTTP-Fundamentals.md` | DNS poisoning, exfil, subdomain takeover; HTTP methods + headers |
| 005 | `01-Foundation-01/DAY-0005-HTTP-Cookies-Sessions-and-TLS.md` | Cookie flags, session tokens, TLS 1.3 handshake, cert chain |
| 006 | `01-Foundation-01/DAY-0006-TLS-Attacks-HTTP2-and-Proxies.md` | TLS weaknesses, HTTP/2 + QUIC, proxies, CDN bypass |
| 007 | `01-Foundation-01/DAY-0007-Wireshark-Lab-Network-Analysis.md` | Capture filters, display filters, dissect HTTP + TLS + DNS |
| 008 | `01-Foundation-01/DAY-0008-ARP-Routing-NAT-and-Network-Check.md` | ARP, Layer 2, routing, NAT, IPv6 ND + foundation self-check |

---

#### 01-Foundation-02 — Linux for Hackers (Days 9–16)

**Lab:** Find a hidden file and escalate to root on a live box

| Day | File | Topic |
|---|---|---|
| 009 | `01-Foundation-02/DAY-0009-Linux-Filesystem-Permissions-and-Users.md` | FHS, file permissions, setuid/setgid, /etc/passwd, /etc/shadow |
| 010 | `01-Foundation-02/DAY-0010-Linux-Processes-Networking-and-Bash.md` | ps, /proc, signals, ip/ss/lsof, bash one-liners, piping |
| 011 | `01-Foundation-02/DAY-0011-Cron-Env-Variables-and-Capabilities.md` | crontab, PATH hijacking, LD_PRELOAD, capabilities, getcap |
| 012 | `01-Foundation-02/DAY-0012-SUID-Sudo-and-Package-Trust.md` | SUID/SGID exploitation, sudo -l, GTFOBins, package signing |
| 013 | `01-Foundation-02/DAY-0013-Logs-Named-Pipes-and-Sockets.md` | /var/log, journald, mkfifo, Unix sockets, attacker artefacts |
| 014 | `01-Foundation-02/DAY-0014-Linux-Lab-Enumeration-and-Hidden-Files.md` | Lab: enumerate a live box, find hidden files, read shadows |
| 015 | `01-Foundation-02/DAY-0015-Linux-Lab-Privilege-Escalation.md` | Lab: escalate from user to root using at least 2 paths |
| 016 | `01-Foundation-02/DAY-0016-Linux-Hardening-and-Forensic-Artefacts.md` | Harden escalation paths; bash_history, .ssh, /tmp — attacker traces |

---

#### 01-Foundation-03 — Web Architecture Deep Dive (Days 17–28)

**Lab:** Intercept and modify requests with Burp Suite; discover hidden endpoints

| Day | File | Topic |
|---|---|---|
| 017 | `01-Foundation-03/DAY-0017-Web-Architecture-Full-Stack.md` | Browser → DNS → TLS → server → app → DB; full stack view |
| 018 | `01-Foundation-03/DAY-0018-HTTP-Headers-and-Security-Headers.md` | Security headers, info-leaking headers, header injection |
| 019 | `01-Foundation-03/DAY-0019-Same-Origin-Policy-and-CORS.md` | SOP rules, CORS headers, pre-flight, misconfiguration risks |
| 020 | `01-Foundation-03/DAY-0020-REST-APIs-JSON-and-GraphQL.md` | REST conventions, JSON, GraphQL queries + introspection surface |
| 021 | `01-Foundation-03/DAY-0021-WebSockets-and-Client-Side-Storage.md` | WebSocket upgrade, auth bypass patterns, localStorage, IndexedDB |
| 022 | `01-Foundation-03/DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md` | Proxy config, CA cert, scope, intercept, Repeater, Intruder |
| 023 | `01-Foundation-03/DAY-0023-Burp-Lab-Episode-1.md` | Lab: intercept login, modify parameters, replay request |
| 024 | `01-Foundation-03/DAY-0024-Burp-Lab-Episode-2.md` | Lab: fuzz hidden parameters, discover unlinked endpoints |
| 025 | `01-Foundation-03/DAY-0025-CSP-and-Web-Cache-Behaviour.md` | CSP directives, bypass techniques, cache keys, CPDoS |
| 026 | `01-Foundation-03/DAY-0026-Load-Balancers-Proxies-Host-Headers.md` | CDN bypass, X-Forwarded-For, host header attacks |
| 027 | `01-Foundation-03/DAY-0027-Web-Architecture-Hardening-and-Review.md` | Harden: headers, CSP, CORS, cookies; tie to OWASP Top 10 |
| 028 | `01-Foundation-03/DAY-0028-Web-Architecture-Competency-Check.md` | Self-assessment + live Burp demo |

---

#### 01-Foundation-04 — Cryptography Essentials (Days 29–38)

**Lab:** Break a weak cipher and forge a MAC against a length-extension vulnerable API

| Day | File | Topic |
|---|---|---|
| 029 | `01-Foundation-04/DAY-0029-Symmetric-Encryption-and-ECB-Weakness.md` | AES modes (ECB, CBC, CTR, GCM), ECB penguin, block pattern leakage |
| 030 | `01-Foundation-04/DAY-0030-Hashing-Collisions-and-Length-Extension.md` | SHA family, collision properties, SHA-1 length extension attack |
| 031 | `01-Foundation-04/DAY-0031-MACs-HMACs-and-Forgery-Lab.md` | HMAC construction, MAC-then-Encrypt flaw, lab: forge a MAC |
| 032 | `01-Foundation-04/DAY-0032-Asymmetric-Encryption-and-RSA-Attacks.md` | RSA + ECC key pairs; small exponent, textbook RSA, common modulus |
| 033 | `01-Foundation-04/DAY-0033-TLS-Handshake-PKI-and-Cert-Chains.md` | TLS 1.3 step-by-step, root CA, intermediate CA, OCSP, pinning |
| 034 | `01-Foundation-04/DAY-0034-Password-Hashing-and-Cracking.md` | bcrypt, Argon2, scrypt, hashcat basics, rainbow tables |
| 035 | `01-Foundation-04/DAY-0035-Randomness-and-PRNG-Attacks.md` | Weak PRNG, seed guessing, math/rand vs crypto/rand |
| 036 | `01-Foundation-04/DAY-0036-Breaking-Weak-Cipher-Lab.md` | Lab: break Vigenère / single-byte XOR; frequency analysis |
| 037 | `01-Foundation-04/DAY-0037-Crypto-in-the-Wild-CVE-Review.md` | Real CVEs from cryptographic failures (Heartbleed, ROBOT, DROWN) |
| 038 | `01-Foundation-04/DAY-0038-Crypto-Competency-Check.md` | Self-assessment + lab submission |

---

#### 01-Foundation-05 — Authentication and Authorisation (Days 39–50)

**Lab:** Exploit broken session management; forge a JWT; steal an OAuth token

| Day | File | Topic |
|---|---|---|
| 039 | `01-Foundation-05/DAY-0039-Auth-vs-Authz-and-Password-Storage.md` | Auth vs authz distinction, password hashing, salting, cracking |
| 040 | `01-Foundation-05/DAY-0040-Session-Management-and-Broken-Session-Lab.md` | Session entropy, fixation, hijacking; lab: predict + hijack session |
| 041 | `01-Foundation-05/DAY-0041-MFA-and-MFA-Bypass.md` | TOTP, FIDO2, SMS OTP weaknesses, SIM swap, OTP interception |
| 042 | `01-Foundation-05/DAY-0042-JWT-Structure-and-JWT-Attack-Lab.md` | JWT anatomy, alg:none, RS256→HS256, lab: forge JWT + gain access |
| 043 | `01-Foundation-05/DAY-0043-OAuth-2-Flow-and-OAuth-Attacks.md` | Authorization Code flow, redirect_uri bypass, CSRF on OAuth |
| 044 | `01-Foundation-05/DAY-0044-OpenID-Connect-SAML-and-SSO-Attacks.md` | OIDC ID token, SAML assertion, XML signature wrapping |
| 045 | `01-Foundation-05/DAY-0045-API-Keys-RBAC-and-Broken-Access-Control.md` | API key hygiene, RBAC vs ABAC, IDOR lab, forced browsing |
| 046 | `01-Foundation-05/DAY-0046-Password-Reset-Flaws-and-Account-Takeover.md` | Token predictability, host-header injection, race conditions |
| 047 | `01-Foundation-05/DAY-0047-Auth-Detection-Logging-and-Hardening.md` | Detect brute force, session anomalies; harden every flaw covered |
| 048 | `01-Foundation-05/DAY-0048-Foundation-Complete-Review.md` | Full F-01–F-05 review; tie every concept to an attack |
| 049 | `01-Foundation-05/DAY-0049-Foundation-CTF-Day.md` | Solo mini-CTF covering all foundation topics |
| 050 | `01-Foundation-05/DAY-0050-Foundation-Competency-Gate.md` | **GATE: Foundation Complete** — oral exam + live demo |

---

### 02-Recon — Reconnaissance Track (Days 51–75)

Goal: Know the target better than the target knows itself before sending a single packet.

---

#### 02-Recon-01 — OSINT and Passive Recon (Days 51–62)

**Lab:** Build a complete attack surface profile from public sources only

| Day | File | Topic |
|---|---|---|
| 051 | `02-Recon-01/DAY-0051-Recon-Mindset-and-Kill-Chain.md` | Recon in the kill chain, MITRE ATT&CK T1590–T1598, bug bounty scope |
| 052 | `02-Recon-01/DAY-0052-Passive-vs-Active-Recon-and-OpSec.md` | Legal line, operational security, what leaves footprints |
| 053 | `02-Recon-01/DAY-0053-Google-Dorks-Shodan-and-Censys.md` | Google operators, Bing, Shodan filters, Censys queries |
| 054 | `02-Recon-01/DAY-0054-Domain-DNS-and-Certificate-Transparency.md` | whois, amass, subfinder, zone transfers, crt.sh |
| 055 | `02-Recon-01/DAY-0055-Email-People-and-LinkedIn-OSINT.md` | Hunter.io, theHarvester, LinkedIn OSINT, metadata in documents |
| 056 | `02-Recon-01/DAY-0056-GitHub-Code-Recon-and-Secret-Hunting.md` | truffleHog, gitleaks, commit history, exposed credentials |
| 057 | `02-Recon-01/DAY-0057-Cloud-Asset-and-Bucket-Discovery.md` | S3 brute force, Azure blob, GCP bucket enumeration |
| 058 | `02-Recon-01/DAY-0058-Social-Media-and-Job-Posting-Intel.md` | Technology stack from job ads, org chart from LinkedIn |
| 059 | `02-Recon-01/DAY-0059-Attack-Surface-Mapping.md` | Aggregate recon into an attack surface document |
| 060 | `02-Recon-01/DAY-0060-Passive-Recon-Lab.md` | Lab: full passive profile on a designated lab target |
| 061 | `02-Recon-01/DAY-0061-Reducing-Your-Org-Attack-Surface.md` | Harden stage: remove sensitive info from public sources |
| 062 | `02-Recon-01/DAY-0062-Subdomain-Takeover-and-Dangling-DNS.md` | CNAME to dead service, NS takeover, real-world examples |

---

#### 02-Recon-02 — Active Recon and Bug Bounty Scope (Days 63–75)

**Lab:** Active recon pipeline — nmap scan + subdomain fuzz + JS analysis

| Day | File | Topic |
|---|---|---|
| 063 | `02-Recon-02/DAY-0063-nmap-from-First-Principles.md` | SYN scan, connect scan, UDP scan — packet-level detail |
| 064 | `02-Recon-02/DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md` | -sV, -O, NSE scripts, fragmentation, decoys, timing |
| 065 | `02-Recon-02/DAY-0065-Directory-and-Endpoint-Fuzzing.md` | ffuf, dirsearch, feroxbuster — wordlists, recursion, filters |
| 066 | `02-Recon-02/DAY-0066-Parameter-Discovery-and-JS-Analysis.md` | arjun, paramspider, LinkFinder, JS file endpoint mining |
| 067 | `02-Recon-02/DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md` | Wappalyzer, whatweb, header analysis, error page analysis |
| 068 | `02-Recon-02/DAY-0068-Masscan-and-Fast-Network-Scanning.md` | masscan internals, rate limiting, combining with nmap |
| 069 | `02-Recon-02/DAY-0069-Active-Recon-Lab.md` | Lab: full active recon on a lab target — scope to enumeration |
| 070 | `02-Recon-02/DAY-0070-Recon-Automation-Pipeline.md` | Bash + Python pipeline: amass → httpx → nuclei → report |
| 071 | `02-Recon-02/DAY-0071-Bug-Bounty-Scope-Analysis.md` | Reading program policies, in-scope vs out-of-scope, wildcards |
| 072 | `02-Recon-02/DAY-0072-Bug-Bounty-Recon-Methodology.md` | End-to-end methodology from scope to enumerated targets |
| 073 | `02-Recon-02/DAY-0073-Detecting-Recon.md` | Honeypots, canary tokens, log analysis for crawlers |
| 074 | `02-Recon-02/DAY-0074-Recon-Review-and-Preparation.md` | Review all recon techniques; prepare attack surface doc |
| 075 | `02-Recon-02/DAY-0075-Recon-Competency-Gate.md` | **GATE: Recon Ready** — submit attack surface document |

---

### 03-WebExploit — Web Exploitation Track (Days 76–165)

Goal: Exploit every major web vulnerability class. Produce professional-quality reports.
This is the core of bug bounty. Master this and you are earning.

---

#### 03-WebExploit-01 — Injection Attacks (Days 76–89)

**Lab:** Exploit SQLi end-to-end on DVWA + exploit SSTI to RCE on a custom app

| Day | File | Topic |
|---|---|---|
| 076 | `03-WebExploit-01/DAY-0076-SQL-Injection-Fundamentals.md` | Error-based, UNION-based, blind, time-based SQLi |
| 077 | `03-WebExploit-01/DAY-0077-SQLi-Lab-Manual-Exploitation.md` | Lab: manual SQLi — login bypass + UNION data extraction |
| 078 | `03-WebExploit-01/DAY-0078-Blind-SQLi-and-sqlmap.md` | Boolean-blind, time-blind, out-of-band; sqlmap flags |
| 079 | `03-WebExploit-01/DAY-0079-SQLi-Post-Exploitation.md` | File read/write, xp_cmdshell, stacked queries, DB fingerprint |
| 080 | `03-WebExploit-01/DAY-0080-Second-Order-SQLi.md` | Stored + second-order injection, stored procedure abuse |
| 081 | `03-WebExploit-01/DAY-0081-Command-Injection.md` | OS command injection, blind injection, filter bypass |
| 082 | `03-WebExploit-01/DAY-0082-Command-Injection-Lab.md` | Lab: exploit command injection to get a reverse shell |
| 083 | `03-WebExploit-01/DAY-0083-SSTI-Server-Side-Template-Injection.md` | Jinja2, Twig, FreeMarker detection + RCE payloads |
| 084 | `03-WebExploit-01/DAY-0084-SSTI-Lab-Jinja2-to-RCE.md` | Lab: SSTI to RCE in a Python Flask application |
| 085 | `03-WebExploit-01/DAY-0085-XXE-XML-External-Entities.md` | Entity expansion, file read, SSRF via XXE, blind XXE |
| 086 | `03-WebExploit-01/DAY-0086-XXE-Lab.md` | Lab: extract /etc/passwd + internal port scan via XXE |
| 087 | `03-WebExploit-01/DAY-0087-Injection-Review-and-CWE-Mapping.md` | Map all injection classes to CWE + ATT&CK; CVSS scoring |
| 088 | `03-WebExploit-01/DAY-0088-Injection-Detection-and-Hardening.md` | WAF rules, parameterised queries, input validation patterns |
| 089 | `03-WebExploit-01/DAY-0089-Injection-Competency-Check.md` | Self-assessment + lab submission |

---

#### 03-WebExploit-02 — XSS and CSRF (Days 90–100)

**Lab:** Reflected XSS to account takeover; stored XSS to worm; CSRF payment bypass

| Day | File | Topic |
|---|---|---|
| 090 | `03-WebExploit-02/DAY-0090-XSS-Fundamentals.md` | Reflected, stored, DOM-based XSS — context and encoding rules |
| 091 | `03-WebExploit-02/DAY-0091-XSS-Lab-Reflected-Cookie-Theft.md` | Lab: reflected XSS, steal HttpOnly bypass, session hijack |
| 092 | `03-WebExploit-02/DAY-0092-XSS-Lab-Stored-and-Persistent.md` | Lab: stored XSS, persistent payload, worm via XSS |
| 093 | `03-WebExploit-02/DAY-0093-DOM-XSS-and-Dangerous-Sinks.md` | innerHTML, document.write, eval, postMessage — dangerous sinks |
| 094 | `03-WebExploit-02/DAY-0094-XSS-Filter-Bypass-Techniques.md` | Encoding, polyglots, context-dependent bypass, WAF evasion |
| 095 | `03-WebExploit-02/DAY-0095-XSS-to-Account-Takeover-Chains.md` | Cookie theft, CSRF via XSS, key logging, BeEF hooks |
| 096 | `03-WebExploit-02/DAY-0096-CSRF-Fundamentals-and-SameSite.md` | CSRF conditions, token bypass, SameSite=None risk |
| 097 | `03-WebExploit-02/DAY-0097-CSRF-Lab.md` | Lab: craft + deliver CSRF payload, change email, bypass token |
| 098 | `03-WebExploit-02/DAY-0098-CSP-Deep-Dive-and-Bypass.md` | CSP directives, unsafe-inline bypass, JSONP, base-uri abuse |
| 099 | `03-WebExploit-02/DAY-0099-XSS-CSRF-for-Bug-Bounty.md` | Real impact framing, chaining for ATO, report structure |
| 100 | `03-WebExploit-02/DAY-0100-Milestone-100-Days-Check.md` | **Milestone Day 100** — review, gaps, re-lab anything missed |

---

#### 03-WebExploit-03 — Access Control and IDOR (Days 101–112)

**Lab:** IDOR to exfiltrate all user records; horizontal + vertical privilege escalation

| Day | File | Topic |
|---|---|---|
| 101 | `03-WebExploit-03/DAY-0101-IDOR-Fundamentals.md` | IDOR/BOLA — direct object reference, UUID prediction |
| 102 | `03-WebExploit-03/DAY-0102-IDOR-Lab.md` | Lab: access another user's data; change another user's password |
| 103 | `03-WebExploit-03/DAY-0103-Forced-Browsing-and-Missing-Auth.md` | Unprotected admin pages, missing function-level checks |
| 104 | `03-WebExploit-03/DAY-0104-Mass-Assignment-and-JSON-Injection.md` | Property injection, role elevation via mass assignment |
| 105 | `03-WebExploit-03/DAY-0105-Privilege-Escalation-in-Web-Apps.md` | Horizontal vs vertical escalation, parameter tampering |
| 106 | `03-WebExploit-03/DAY-0106-Privilege-Escalation-Lab.md` | Lab: escalate from user → moderator → admin |
| 107 | `03-WebExploit-03/DAY-0107-Advanced-IDOR-Techniques.md` | Chained IDOR, indirect reference through relationships |
| 108 | `03-WebExploit-03/DAY-0108-BOLA-in-APIs.md` | Object-level auth in REST + GraphQL APIs |
| 109 | `03-WebExploit-03/DAY-0109-Access-Control-for-Bug-Bounty.md` | Finding high-value access control bugs; impact amplification |
| 110 | `03-WebExploit-03/DAY-0110-Access-Control-Detection-and-Hardening.md` | Authorisation middleware, test matrices, detection rules |
| 111 | `03-WebExploit-03/DAY-0111-Access-Control-Review.md` | Review + CWE/ATT&CK mapping |
| 112 | `03-WebExploit-03/DAY-0112-Access-Control-Competency-Check.md` | Self-assessment + lab submission |

---

#### 03-WebExploit-04 — SSRF, Path Traversal and File Attacks (Days 113–125)

**Lab:** SSRF to AWS metadata credential extraction; LFI to RCE via log poisoning

| Day | File | Topic |
|---|---|---|
| 113 | `03-WebExploit-04/DAY-0113-SSRF-Fundamentals.md` | SSRF reaching internal services + cloud metadata endpoints |
| 114 | `03-WebExploit-04/DAY-0114-SSRF-Lab-Internal-and-AWS-Metadata.md` | Lab: SSRF to read IMDSv1 credentials from AWS |
| 115 | `03-WebExploit-04/DAY-0115-Blind-SSRF-and-OOB-Techniques.md` | Out-of-band SSRF, DNS callbacks, Burp Collaborator |
| 116 | `03-WebExploit-04/DAY-0116-SSRF-Filter-Bypass-Techniques.md` | URL encoding, DNS rebinding, IPv6, alternative IP formats |
| 117 | `03-WebExploit-04/DAY-0117-Path-Traversal-and-LFI.md` | ../../../etc/passwd, null bytes, PHP wrappers, filter bypass |
| 118 | `03-WebExploit-04/DAY-0118-LFI-to-RCE.md` | Log poisoning, /proc/self/environ, phpinfo, session files |
| 119 | `03-WebExploit-04/DAY-0119-File-Upload-Vulnerabilities.md` | MIME bypass, extension bypass, webshell upload, polyglots |
| 120 | `03-WebExploit-04/DAY-0120-File-Upload-Lab.md` | Lab: bypass upload filter, achieve RCE via webshell |
| 121 | `03-WebExploit-04/DAY-0121-SSRF-LFI-Upload-for-Bug-Bounty.md` | Impact framing, cloud + internal network, report examples |
| 122 | `03-WebExploit-04/DAY-0122-Server-Side-Attack-Detection.md` | WAF signatures, SSRF logs, file access anomalies |
| 123 | `03-WebExploit-04/DAY-0123-Server-Side-Attack-Hardening.md` | Allowlists, path canonicalisation, upload sandboxing |
| 124 | `03-WebExploit-04/DAY-0124-Server-Side-Review.md` | Review all server-side classes |
| 125 | `03-WebExploit-04/DAY-0125-Server-Side-Competency-Check.md` | Self-assessment + lab submission |

---

#### 03-WebExploit-05 — Advanced Web Techniques (Days 126–145)

**Lab:** HTTP request smuggling + web cache poisoning + race condition chain

| Day | File | Topic |
|---|---|---|
| 126 | `03-WebExploit-05/DAY-0126-HTTP-Request-Smuggling-CL-TE.md` | CL.TE, TE.CL, TE.TE desync attacks, front-end/back-end split |
| 127 | `03-WebExploit-05/DAY-0127-HTTP-Smuggling-Lab.md` | Lab: smuggle a request to poison the request queue |
| 128 | `03-WebExploit-05/DAY-0128-Web-Cache-Poisoning.md` | Cache keys, unkeyed headers, cache deception vs poisoning |
| 129 | `03-WebExploit-05/DAY-0129-Web-Cache-Poisoning-Lab.md` | Lab: poison a cache with XSS payload |
| 130 | `03-WebExploit-05/DAY-0130-Business-Logic-Flaws.md` | State machine abuse, workflow bypass, negative quantities |
| 131 | `03-WebExploit-05/DAY-0131-Race-Conditions.md` | TOCTOU, race window, limit-override, coupon abuse |
| 132 | `03-WebExploit-05/DAY-0132-Race-Condition-Lab.md` | Lab: exploit a race condition to claim a discount twice |
| 133 | `03-WebExploit-05/DAY-0133-Open-Redirect-and-CRLF-Injection.md` | Open redirect chains, CRLF header injection, log injection |
| 134 | `03-WebExploit-05/DAY-0134-Clickjacking-and-UI-Redressing.md` | iframe overlay, framebusting bypass, dragjacking |
| 135 | `03-WebExploit-05/DAY-0135-CORS-Misconfiguration-Exploitation.md` | null origin, regex bypass, credentials flag, ATO via CORS |
| 136 | `03-WebExploit-05/DAY-0136-Host-Header-Attacks.md` | Virtual host routing, password reset poisoning via host header |
| 137 | `03-WebExploit-05/DAY-0137-WebSocket-Attacks.md` | Cross-site WebSocket hijacking, input injection via WS |
| 138 | `03-WebExploit-05/DAY-0138-OAuth-JWT-Advanced-Attacks.md` | kid injection, embedded JWK, x5u, PKCE bypass |
| 139 | `03-WebExploit-05/DAY-0139-Chaining-Vulnerabilities.md` | Multi-vuln chains for maximum impact, attack trees |
| 140 | `03-WebExploit-05/DAY-0140-Advanced-Web-Lab.md` | Lab: multi-vuln chain — SSRF + CORS + auth bypass |
| 141 | `03-WebExploit-05/DAY-0141-Advanced-Web-Bug-Bounty.md` | High-severity techniques, impact amplification strategies |
| 142 | `03-WebExploit-05/DAY-0142-Advanced-Web-Detection.md` | Detecting smuggling, cache poisoning, race conditions |
| 143 | `03-WebExploit-05/DAY-0143-Advanced-Web-Hardening.md` | Consistent CL/TE handling, cache controls, concurrency locks |
| 144 | `03-WebExploit-05/DAY-0144-Advanced-Web-Review.md` | Review all advanced techniques |
| 145 | `03-WebExploit-05/DAY-0145-Advanced-Web-Competency-Check.md` | Self-assessment + lab submission |

---

#### 03-WebExploit-06 — API Security (Days 146–160)

**Lab:** Enumerate and exploit a REST + GraphQL API; find BOLA + mass assignment

| Day | File | Topic |
|---|---|---|
| 146 | `03-WebExploit-06/DAY-0146-OWASP-API-Top-10.md` | All 10 categories with real examples and CVEs |
| 147 | `03-WebExploit-06/DAY-0147-API-Enumeration.md` | Swagger, OpenAPI, Postman, JS endpoint mining, JSParser |
| 148 | `03-WebExploit-06/DAY-0148-BOLA-and-BFLA.md` | Object-level vs function-level auth; finding in APIs |
| 149 | `03-WebExploit-06/DAY-0149-Mass-Assignment-and-API-Injection.md` | JSON property injection, role elevation, NoSQL injection |
| 150 | `03-WebExploit-06/DAY-0150-GraphQL-Attack-Lab.md` | Lab: introspect GraphQL, find hidden fields, exploit auth |
| 151 | `03-WebExploit-06/DAY-0151-REST-API-Lab-Episode-1.md` | Lab: enumerate + BOLA data extraction |
| 152 | `03-WebExploit-06/DAY-0152-REST-API-Lab-Episode-2.md` | Lab: mass assignment → admin escalation |
| 153 | `03-WebExploit-06/DAY-0153-API-Rate-Limiting-and-DoS.md` | Algorithmic complexity, resource exhaustion, batch abuse |
| 154 | `03-WebExploit-06/DAY-0154-Webhook-and-API-Versioning-Attacks.md` | Webhook SSRF, signature bypass, deprecated version abuse |
| 155 | `03-WebExploit-06/DAY-0155-Mobile-API-Analysis.md` | Intercepting mobile app traffic, certificate pinning bypass |
| 156 | `03-WebExploit-06/DAY-0156-API-Security-Bug-Bounty.md` | API bug bounty programmes, finding hidden APIs in prod |
| 157 | `03-WebExploit-06/DAY-0157-API-Detection-and-Hardening.md` | Schema validation, rate limiting, anomaly detection rules |
| 158 | `03-WebExploit-06/DAY-0158-API-Security-Review.md` | Review all API attack classes |
| 159 | `03-WebExploit-06/DAY-0159-API-Competency-Check.md` | Self-assessment + lab submission |
| 160 | `03-WebExploit-06/DAY-0160-Web-Exploitation-Gate-Prep.md` | Gate preparation: consolidate all web findings |

---

#### 03-WebExploit-07 — Bug Bounty Reporting (Days 161–165)

**Lab:** Write three professional finding reports at different severity levels

| Day | File | Topic |
|---|---|---|
| 161 | `03-WebExploit-07/DAY-0161-Report-Structure-and-Format.md` | Title, severity, impact, steps to reproduce, remediation |
| 162 | `03-WebExploit-07/DAY-0162-CVSS-Scoring-and-Risk-Rating.md` | CVSS 3.1 vector string, bug bounty triage alignment |
| 163 | `03-WebExploit-07/DAY-0163-PoC-Writing-and-Impact-Analysis.md` | Reproducible PoC, business impact framing, screenshots |
| 164 | `03-WebExploit-07/DAY-0164-Handling-Duplicates-and-Triage.md` | Triage process, duplicate bugs, escalation paths |
| 165 | `03-WebExploit-07/DAY-0165-Web-Exploitation-Competency-Gate.md` | **GATE: Web Exploitation Ready** — report review |

---

### 04-BroadSurface — Broader Attack Surface (Days 166–260)

Goal: Expand beyond web — auth attacks, cloud, mobile, infrastructure, privilege escalation.

---

#### 04-BroadSurface-01 — Authentication Attacks (Days 166–185)

**Lab:** Credential spray a rate-limited system; forge JWT with kid injection

| Day | File | Topic |
|---|---|---|
| 166 | `04-BroadSurface-01/DAY-0166-Credential-Stuffing-and-Spraying.md` | Breach DBs, combo lists, low-and-slow spraying, AD lockout |
| 167 | `04-BroadSurface-01/DAY-0167-Rate-Limiting-Bypass.md` | IP rotation, user-agent cycling, distributed brute force |
| 168 | `04-BroadSurface-01/DAY-0168-Credential-Attack-Lab.md` | Lab: spray lab login with rate limiting + IP blocking active |
| 169 | `04-BroadSurface-01/DAY-0169-JWT-Advanced-Attacks.md` | alg confusion, kid path traversal, JWK injection, x5u |
| 170 | `04-BroadSurface-01/DAY-0170-JWT-Advanced-Lab.md` | Lab: kid injection → RCE via JWT |
| 171 | `04-BroadSurface-01/DAY-0171-OAuth-Abuse-Deep-Dive.md` | Implicit flow token steal, PKCE downgrade, open redirect |
| 172 | `04-BroadSurface-01/DAY-0172-OAuth-Attack-Lab.md` | Lab: steal OAuth token via open redirect chain |
| 173 | `04-BroadSurface-01/DAY-0173-SAML-Attacks.md` | Signature wrapping, XXE in SAML, comment injection |
| 174 | `04-BroadSurface-01/DAY-0174-Account-Takeover-Chains.md` | Chain password reset + CSRF + IDOR → full ATO |
| 175 | `04-BroadSurface-01/DAY-0175-Kerberoasting-and-Pass-the-Hash-Intro.md` | SPN enum, TGS offline crack, NTLM relay basics |
| 176 | `04-BroadSurface-01/DAY-0176-Auth-Attack-Detection.md` | Failed login patterns, token anomalies, Sigma rules |
| 177 | `04-BroadSurface-01/DAY-0177-Auth-Hardening.md` | MFA enforcement, lockout policy, token binding |
| 178 | `04-BroadSurface-01/DAY-0178-Auth-Attacks-Review.md` | Review all auth attack classes |
| 179 | `04-BroadSurface-01/DAY-0179-Auth-Attacks-Practice.md` | Practice day: HTB + lab boxes focused on auth |
| 180 | `04-BroadSurface-01/DAY-0180-Auth-Attacks-Competency-Check.md` | Self-assessment + lab submission |

---

#### 04-BroadSurface-02 — Cloud Security (Days 181–210)

**Lab:** Full AWS attack chain — SSRF to metadata, role assumption, privilege escalation

| Day | File | Topic |
|---|---|---|
| 181 | `04-BroadSurface-02/DAY-0181-Cloud-Threat-Model.md` | Shared responsibility, cloud-specific attack surface |
| 182 | `04-BroadSurface-02/DAY-0182-AWS-IAM-Fundamentals.md` | Users, roles, policies, trust relationships, ARNs |
| 183 | `04-BroadSurface-02/DAY-0183-IAM-Misconfiguration-Attacks.md` | Overly permissive roles, inline policies, role chaining |
| 184 | `04-BroadSurface-02/DAY-0184-SSRF-to-AWS-Metadata-Lab.md` | Lab: IMDSv1 extraction → assume role → escalate |
| 185 | `04-BroadSurface-02/DAY-0185-S3-Misconfiguration-Lab.md` | Lab: enumerate + extract data from misconfigured S3 |
| 186 | `04-BroadSurface-02/DAY-0186-AWS-Enumeration-with-Pacu.md` | Pacu framework, permission enumeration, service recon |
| 187 | `04-BroadSurface-02/DAY-0187-Lambda-and-Serverless-Attacks.md` | Env variable theft, event injection, function abuse |
| 188 | `04-BroadSurface-02/DAY-0188-Container-and-ECS-Attacks.md` | Metadata from containers, ECS task role, privileged escape |
| 189 | `04-BroadSurface-02/DAY-0189-Azure-for-Attackers.md` | AAD, managed identity, storage blob misconfiguration |
| 190 | `04-BroadSurface-02/DAY-0190-GCP-for-Attackers.md` | Service accounts, metadata API, GCS bucket misconfiguration |
| 191 | `04-BroadSurface-02/DAY-0191-Cloud-Persistence-Techniques.md` | Backdoor IAM, cross-account roles, Lambda backdoor |
| 192 | `04-BroadSurface-02/DAY-0192-Cloud-Full-Attack-Lab.md` | Lab: full kill chain AWS — SSRF → creds → escalate → persist |
| 193 | `04-BroadSurface-02/DAY-0193-Cloud-Bug-Bounty-Strategy.md` | Cloud-focused programmes, IMDSv2, bucket brute-forcing |
| 194 | `04-BroadSurface-02/DAY-0194-Detecting-Cloud-Attacks.md` | CloudTrail, GuardDuty, alert on metadata queries |
| 195 | `04-BroadSurface-02/DAY-0195-Cloud-Hardening.md` | IMDSv2, SCPs, resource-based policies, least privilege |
| 196 | `04-BroadSurface-02/DAY-0196-Cloud-Security-Review.md` | Review all cloud attack classes |
| 197 | `04-BroadSurface-02/DAY-0197-Cloud-Practice-IAM-PrivEsc.md` | Practice: IAM privilege escalation drills |
| 198 | `04-BroadSurface-02/DAY-0198-Cloud-Practice-S3-Attacks.md` | Practice: S3 misconfiguration attack surface |
| 199 | `04-BroadSurface-02/DAY-0199-Cloud-Practice-Lambda-Serverless.md` | Practice: Lambda + serverless attack patterns |
| 200 | `04-BroadSurface-02/DAY-0200-Milestone-200-Days-Cloud-Review.md` | Milestone 200 — cloud module retrospective |
| 201 | `04-BroadSurface-02/DAY-0201-Cloud-Practice-Azure.md` | Practice: Azure AD + managed identity attacks |
| 202 | `04-BroadSurface-02/DAY-0202-Cloud-Practice-GCP.md` | Practice: GCP service accounts + metadata API |
| 203 | `04-BroadSurface-02/DAY-0203-Cloud-Practice-Persistence-Detection.md` | Practice: detect and hunt cloud persistence |
| 204 | `04-BroadSurface-02/DAY-0204-Cloud-Practice-CloudTrail-Evasion.md` | Practice: CloudTrail evasion techniques |
| 205 | `04-BroadSurface-02/DAY-0205-Cloud-Practice-Bug-Bounty-Recon.md` | Practice: cloud bug bounty recon methodology |
| 206 | `04-BroadSurface-02/DAY-0206-Cloud-Practice-Container-Kubernetes.md` | Practice: container escape + Kubernetes RBAC exploitation |
| 207 | `04-BroadSurface-02/DAY-0207-Cloud-Practice-Kill-Chain-Speed-Run.md` | Practice: full kill chain timed speed run |
| 208 | `04-BroadSurface-02/DAY-0208-Cloud-Practice-Mock-Bug-Bounty.md` | Practice: mock bug bounty cloud engagement |
| 209 | `04-BroadSurface-02/DAY-0209-Cloud-Practice-Report-Writing.md` | Practice: cloud finding report writing sprint |
| 210 | `04-BroadSurface-02/DAY-0210-Cloud-Competency-Check.md` | Self-assessment + lab submission |

---

#### 04-BroadSurface-03 — Mobile Security (Days 211–230)

**Lab:** Full Android APK assessment — static + dynamic + certificate pinning bypass

| Day | File | Topic |
|---|---|---|
| 211 | `04-BroadSurface-03/DAY-0211-Mobile-Security-Overview.md` | Android vs iOS architecture, attack surface comparison |
| 212 | `04-BroadSurface-03/DAY-0212-Android-Static-Analysis.md` | Jadx, apktool, manifest inspection, hardcoded secrets |
| 213 | `04-BroadSurface-03/DAY-0213-Android-Static-Analysis-Lab.md` | Lab: reverse APK, find API keys + vulnerable endpoints |
| 214 | `04-BroadSurface-03/DAY-0214-Android-Dynamic-Analysis-Frida.md` | Frida basics, hooking functions, runtime patching |
| 215 | `04-BroadSurface-03/DAY-0215-Certificate-Pinning-Bypass.md` | Frida bypass, objection, ProxyDroid, custom trust manager |
| 216 | `04-BroadSurface-03/DAY-0216-Android-Insecure-Storage.md` | SharedPreferences, SQLite, external storage, key material |
| 217 | `04-BroadSurface-03/DAY-0217-Android-WebView-and-Intent-Attacks.md` | WebView JS bridge, deep link hijacking, intent redirection |
| 218 | `04-BroadSurface-03/DAY-0218-iOS-App-Security-Overview.md` | Keychain, binary protections, jailbreak detection bypass |
| 219 | `04-BroadSurface-03/DAY-0219-Mobile-API-Attack-Surface.md` | Intercepting mobile APIs, hidden endpoints, version abuse |
| 220 | `04-BroadSurface-03/DAY-0220-Mobile-Bug-Bounty-Methodology.md` | Mobile-focused programmes, scope analysis, payout patterns |
| 221 | `04-BroadSurface-03/DAY-0221-Mobile-Full-Assessment-Lab.md` | Lab: complete Android assessment from APK to RCE |
| 222 | `04-BroadSurface-03/DAY-0222-Mobile-Detection-and-Hardening.md` | Certificate pinning, root detection, obfuscation, ProGuard |
| 223 | `04-BroadSurface-03/DAY-0223-Mobile-Practice-Day-1.md` | Practice: HTB mobile static analysis sprint |
| 224 | `04-BroadSurface-03/DAY-0224-Mobile-Practice-Day-2.md` | Practice: Frida scripting and dynamic analysis |
| 225 | `04-BroadSurface-03/DAY-0225-Mobile-Practice-Day-3.md` | Practice: mobile API enumeration and IDOR testing |
| 226 | `04-BroadSurface-03/DAY-0226-Mobile-Practice-Day-4.md` | Practice: WebView and Intent attack patterns |
| 227 | `04-BroadSurface-03/DAY-0227-Mobile-Practice-Day-5.md` | Practice: iOS app analysis and jailbreak bypass |
| 228 | `04-BroadSurface-03/DAY-0228-Mobile-Practice-Day-6.md` | Practice: live bug bounty recon on a mobile programme |
| 229 | `04-BroadSurface-03/DAY-0229-Mobile-Practice-Day-7.md` | Practice: module review, write-up, gate preparation |
| 230 | `04-BroadSurface-03/DAY-0230-Mobile-Competency-Check.md` | Self-assessment + lab submission |

---

#### 04-BroadSurface-04 — Network Exploitation and Privilege Escalation (Days 231–260)

**Lab:** MITM on a lab network; escalate Linux + Windows from low-priv to SYSTEM

| Day | File | Topic |
|---|---|---|
| 231 | `04-BroadSurface-04/DAY-0231-MITM-ARP-Spoofing-Lab.md` | ARP poison + DNS spoof; capture credentials from lab subnet |
| 232 | `04-BroadSurface-04/DAY-0232-SMB-Relay-and-LLMNR-Poisoning.md` | Responder, NTLMv2 relay, ntlmrelayx |
| 233 | `04-BroadSurface-04/DAY-0233-Network-Credential-Extraction.md` | Extract creds from PCAP: FTP, Telnet, HTTP Basic, NTLM |
| 234 | `04-BroadSurface-04/DAY-0234-Linux-PrivEsc-Enumeration.md` | LinPEAS, manual checklist, what to look for first |
| 235 | `04-BroadSurface-04/DAY-0235-Linux-PrivEsc-Lab-1-SUID-Sudo.md` | Lab: SUID binary + sudo misconfiguration escalation |
| 236 | `04-BroadSurface-04/DAY-0236-Linux-PrivEsc-Lab-2-Cron-and-Writable.md` | Lab: cron job + writable files escalation paths |
| 237 | `04-BroadSurface-04/DAY-0237-Kernel-Exploits-Linux.md` | DirtyCow, overlayfs, kernel version fingerprinting |
| 238 | `04-BroadSurface-04/DAY-0238-Windows-PrivEsc-Enumeration.md` | WinPEAS, PowerShell enumeration |
| 239 | `04-BroadSurface-04/DAY-0239-Windows-PrivEsc-Lab.md` | Lab: token impersonation + unquoted service path |
| 240 | `04-BroadSurface-04/DAY-0240-Container-Escape.md` | Privileged container, Docker socket, host mount escape |
| 241 | `04-BroadSurface-04/DAY-0241-Post-Exploitation-Basics.md` | Credential harvesting, persistence, lateral movement intro |
| 242 | `04-BroadSurface-04/DAY-0242-C2-Concepts-and-Sliver-Lab.md` | C2 architecture, beaconing, Sliver — deploy + beacon |
| 243 | `04-BroadSurface-04/DAY-0243-Living-off-the-Land.md` | LOLBins/LOLBAS, native tools for attacker purposes |
| 244 | `04-BroadSurface-04/DAY-0244-Infrastructure-Detection-and-Hardening.md` | DHCP snooping, dynamic ARP inspection, 802.1X, EDR basics |
| 245–259 | `04-BroadSurface-04/DAY-XXXX-Infrastructure-Practice-Days.md` | Practice: mixed HTB boxes, privesc challenges |
| 260 | `04-BroadSurface-04/DAY-0260-BroadSurface-Competency-Check.md` | Self-assessment + lab submission |

---

### 05-BugBountyOps — Bug Bounty Operations (Days 261–365)

Goal: Operate as a professional bug bounty hunter. Find real bugs. Get paid.

---

#### 05-BugBountyOps-01 — Platforms, Strategy and Automation (Days 261–290)

**Lab:** Build a personal recon + vulnerability pipeline; submit on a live programme

| Day | File | Topic |
|---|---|---|
| 261 | `05-BugBountyOps-01/DAY-0261-Bug-Bounty-Platforms-Overview.md` | HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, Synack |
| 262 | `05-BugBountyOps-01/DAY-0262-Reading-Program-Policies-and-Scope.md` | Scope tables, wildcard vs explicit, OOS traps, safe harbour |
| 263 | `05-BugBountyOps-01/DAY-0263-Choosing-the-Right-Program.md` | VDP vs paid, private vs public, signal-to-noise ratio |
| 264 | `05-BugBountyOps-01/DAY-0264-Nuclei-Templates-and-Automation.md` | Nuclei setup, writing custom templates, CI integration |
| 265 | `05-BugBountyOps-01/DAY-0265-Recon-Pipeline-Automation.md` | amass → httpx → nuclei → notify pipeline |
| 266 | `05-BugBountyOps-01/DAY-0266-Burp-Extensions-for-Bug-Bounty.md` | Active Scan++, Autorize, Param Miner, J2EEScan |
| 267 | `05-BugBountyOps-01/DAY-0267-ffuf-and-Custom-Wordlists.md` | Custom wordlists, SecLists, ffuf modes, filter tuning |
| 268 | `05-BugBountyOps-01/DAY-0268-Tracking-Findings-and-Notes.md` | Obsidian, Notion, bug tracking; when to stop on a target |
| 269 | `05-BugBountyOps-01/DAY-0269-Responsible-Disclosure-Process.md` | Disclosure timeline, triage expectations, escalation |
| 270 | `05-BugBountyOps-01/DAY-0270-Bug-Bounty-Legal-and-Ethics.md` | CFAA, Computer Misuse Act, safe harbour, OOS actions |
| 271 | `05-BugBountyOps-01/DAY-0271-Studying-Public-Disclosures.md` | HackerOne Hacktivity, Bugcrowd dislosures — pattern analysis |
| 272 | `05-BugBountyOps-01/DAY-0272-Portfolio-and-Reputation-Building.md` | Write-ups, CVE credits, conference talks, hall of fame |
| 273 | `05-BugBountyOps-01/DAY-0273-Earnings-Optimisation.md` | High-reward target selection, P1 vs P5, severity negotiation |
| 274 | `05-BugBountyOps-01/DAY-0274-Community-and-Resources.md` | Twitter/X, Discord, HackerOne community, good blogs |
| 275 | `05-BugBountyOps-01/DAY-0275-Bug-Bounty-Methodology-Synthesis.md` | End-to-end personal methodology document |
| 276–289 | `05-BugBountyOps-01/DAY-XXXX-Live-Programme-Practice.md` | Practice days: apply methodology on real live programmes |
| 290 | `05-BugBountyOps-01/DAY-0290-BugBountyOps-1-Check.md` | Self-assessment |

---

#### 05-BugBountyOps-02 — CTF and Skill Sharpening (Days 291–330)

**Lab:** Complete 10 HackTheBox + TryHackMe machines covering all skill areas

| Day | File | Topic |
|---|---|---|
| 291–295 | `05-BugBountyOps-02/DAY-XXXX-HTB-Web-Series.md` | HackTheBox web machines x5 |
| 296–300 | `05-BugBountyOps-02/DAY-XXXX-HTB-Linux-Series.md` | HackTheBox Linux machines x5 |
| 301–305 | `05-BugBountyOps-02/DAY-XXXX-HTB-API-Series.md` | API-focused challenges x5 |
| 306–310 | `05-BugBountyOps-02/DAY-XXXX-HTB-Cloud-Series.md` | Cloud security labs x5 |
| 311–315 | `05-BugBountyOps-02/DAY-XXXX-CTF-Web-Competition.md` | Web CTF competition practice |
| 316–325 | `05-BugBountyOps-02/DAY-XXXX-Weak-Area-Reinforce.md` | Identify weak spots from the last 290 days; re-lab them |
| 326–330 | `05-BugBountyOps-02/DAY-XXXX-Write-Up-Sprint.md` | Write 5 public write-ups for completed challenges |

---

#### 05-BugBountyOps-03 — Real Programme Submissions (Days 331–360)

**Lab:** Submit at least 3 real vulnerability reports; target at least 1 acceptance

| Day | File | Topic |
|---|---|---|
| 331–340 | `05-BugBountyOps-03/DAY-XXXX-First-Programme-Sprint.md` | Dedicated 10-day sprint on a chosen programme |
| 341–350 | `05-BugBountyOps-03/DAY-XXXX-Second-Programme-Sprint.md` | Switch programme; apply all recon + exploit learnings |
| 351–355 | `05-BugBountyOps-03/DAY-XXXX-Report-Review-and-Resubmit.md` | Review triage feedback; iterate on reports |
| 356–360 | `05-BugBountyOps-03/DAY-XXXX-Year-1-Review-and-Retrospective.md` | What worked; gap analysis; Year 2 readiness check |

---

#### Year 1 Gate (Days 361–365)

| Day | File | Topic |
|---|---|---|
| 361–364 | `05-BugBountyOps-03/DAY-XXXX-Gate-Preparation.md` | Prepare gate evidence: reports, write-ups, lab demos |
| 365 | `05-BugBountyOps-03/DAY-0365-Bug-Bounty-Hunter-Gate.md` | **GATE: Bug Bounty Hunter** — accepted report required |

---

## Year 2 — "Deep Dive" (Days 366–730)

Goal: Go deeper. Binary exploitation, reverse engineering, advanced red team,
cryptographic attacks, malware analysis, and the zero-day mindset.

---

### 06-BinaryExploit — Binary Exploitation (Days 366–430)

**Lab:** Write a ROP chain for a 64-bit ELF with ASLR; exploit a heap UAF

| Day | File | Topic |
|---|---|---|
| 366 | `06-BinaryExploit-01/DAY-0366-Memory-Layout-of-a-Process.md` | Stack, heap, BSS, text segment, registers, calling conventions |
| 367 | `06-BinaryExploit-01/DAY-0367-x86-x64-Assembly-Basics.md` | Registers, stack frames, calling conventions, System V ABI |
| 368 | `06-BinaryExploit-01/DAY-0368-GDB-and-PWNDBG.md` | Breakpoints, examine memory, disassemble, info registers |
| 369 | `06-BinaryExploit-01/DAY-0369-Stack-Buffer-Overflow-Theory.md` | EIP/RIP overwrite, controlling program flow, offset finding |
| 370 | `06-BinaryExploit-01/DAY-0370-Stack-Overflow-Lab-32bit.md` | Lab: crash + control EIP on a 32-bit ELF, inject shellcode |
| 371 | `06-BinaryExploit-01/DAY-0371-Shellcode-Writing.md` | Syscall table, execve shellcode, bad char avoidance, null-free |
| 372 | `06-BinaryExploit-01/DAY-0372-Exploit-Mitigations.md` | ASLR, NX/DEP, stack canaries, PIE, RELRO — what each does |
| 373 | `06-BinaryExploit-01/DAY-0373-Return-Oriented-Programming.md` | ROP concepts, gadget chains, ret2libc, ret2plt |
| 374 | `06-BinaryExploit-01/DAY-0374-ROP-Lab-NX-Bypass.md` | Lab: ret2libc on binary with NX enabled |
| 375 | `06-BinaryExploit-01/DAY-0375-64bit-Stack-Overflow-Lab.md` | Lab: ROP chain on 64-bit ELF with ASLR |
| 376 | `06-BinaryExploit-01/DAY-0376-ASLR-Bypass-Techniques.md` | Information leaks, partial overwrites, brute force |
| 377 | `06-BinaryExploit-01/DAY-0377-Format-String-Vulnerabilities.md` | %x, %n, arbitrary read + write, GOT overwrite |
| 378 | `06-BinaryExploit-01/DAY-0378-Format-String-Lab.md` | Lab: exploit format string to overwrite a GOT entry |
| 379 | `06-BinaryExploit-01/DAY-0379-pwntools-Mastery.md` | pwntools API, tubes, cyclic, shellcraft, ROP module |
| 380 | `06-BinaryExploit-01/DAY-0380-pwntools-Lab.md` | Lab: automate all previous stack exploits with pwntools |
| 381–390 | `06-BinaryExploit-01/DAY-XXXX-Stack-Practice-Labs.md` | Practice: pwn.college stack challenges |
| 391 | `06-BinaryExploit-02/DAY-0391-Heap-Internals.md` | glibc malloc/free, chunk structure, bins, tcache |
| 392 | `06-BinaryExploit-02/DAY-0392-Heap-Overflow.md` | Heap overflow into next chunk, tcache poisoning |
| 393 | `06-BinaryExploit-02/DAY-0393-Use-After-Free.md` | UAF fundamentals, dangling pointer exploitation |
| 394 | `06-BinaryExploit-02/DAY-0394-UAF-Lab.md` | Lab: exploit a heap UAF CTF binary |
| 395 | `06-BinaryExploit-02/DAY-0395-Double-Free-and-Tcache-Poisoning.md` | Double free, tcache dup, arbitrary write primitive |
| 396 | `06-BinaryExploit-02/DAY-0396-Heap-Exploitation-Lab.md` | Lab: tcache poisoning to arbitrary write → shell |
| 397–410 | `06-BinaryExploit-02/DAY-XXXX-Heap-Practice-Labs.md` | Practice: pwn.college heap + CTF heap challenges |
| 411–420 | `06-BinaryExploit-02/DAY-XXXX-Kernel-Exploitation-Intro.md` | Kernel bug classes, LPE via kernel, ret2usr, SMEP/SMAP |
| 421–429 | `06-BinaryExploit-02/DAY-XXXX-Binary-Exploit-CTF-Sprint.md` | CTF binary exploitation sprint |
| 430 | `06-BinaryExploit-02/DAY-0430-Binary-Exploit-Competency-Gate.md` | **GATE: Binary Exploitation Ready** |

---

### 07-ReverseEngineering — Reverse Engineering (Days 431–490)

**Lab:** Reverse a real crackme; analyse a packed malware sample

| Day | File | Topic |
|---|---|---|
| 431 | `07-RE-01/DAY-0431-RE-Mindset-and-Toolchain.md` | Static vs dynamic, Ghidra vs IDA, workflow |
| 432 | `07-RE-01/DAY-0432-Ghidra-Fundamentals.md` | Decompiler, function analysis, rename, cross-references |
| 433 | `07-RE-01/DAY-0433-Ghidra-Lab-Crackme-1.md` | Lab: reverse a simple crackme — find the password |
| 434 | `07-RE-01/DAY-0434-x64-Assembly-for-Reverse-Engineers.md` | Reading disassembly, recognising patterns, structs, loops |
| 435 | `07-RE-01/DAY-0435-Ghidra-Lab-Crackme-2.md` | Lab: multi-stage crackme with anti-debug |
| 436 | `07-RE-01/DAY-0436-Dynamic-Analysis-with-GDB-and-PWNDBG.md` | Breakpoints, watchpoints, tracing execution |
| 437 | `07-RE-01/DAY-0437-Frida-for-Reverse-Engineering.md` | Frida JS API, hooking functions, tracing returns |
| 438 | `07-RE-01/DAY-0438-Windows-PE-Format.md` | PE headers, sections, imports, exports, TLS callbacks |
| 439 | `07-RE-01/DAY-0439-ELF-Format-Deep-Dive.md` | ELF header, sections, PLT/GOT, dynamic linking |
| 440 | `07-RE-01/DAY-0440-Identifying-Algorithms-in-Binaries.md` | Crypto constants, compression signatures, protocol parsers |
| 441–450 | `07-RE-01/DAY-XXXX-RE-Practice-Labs.md` | Practice: reverse.engineering crackmes, flare-on |
| 451 | `07-RE-02/DAY-0451-Packers-and-Obfuscation.md` | UPX, custom packers, section entropy, unpacking stubs |
| 452 | `07-RE-02/DAY-0452-Unpacking-Lab.md` | Lab: manually unpack a UPX-compressed binary |
| 453 | `07-RE-02/DAY-0453-Anti-Debugging-Techniques.md` | IsDebuggerPresent, timing checks, NtQueryInfo bypass |
| 454 | `07-RE-02/DAY-0454-Obfuscation-and-Deobfuscation.md` | Control flow flattening, string encryption, VM protection |
| 455 | `07-RE-02/DAY-0455-Deobfuscation-Lab.md` | Lab: deobfuscate a script-based payload |
| 456 | `07-RE-02/DAY-0456-Patch-Diffing.md` | BinDiff, diaphora — finding bugs from security patches |
| 457 | `07-RE-02/DAY-0457-CVE-Reproduction-from-Patch-Diff.md` | Lab: reproduce a CVE starting from the patch alone |
| 458–480 | `07-RE-02/DAY-XXXX-RE-Advanced-Practice.md` | Flare-on + advanced CTF reversing challenges |
| 481–489 | `07-RE-02/DAY-XXXX-RE-CTF-Sprint.md` | CTF reversing sprint |
| 490 | `07-RE-02/DAY-0490-RE-Competency-Gate.md` | **GATE: Reverse Engineering Ready** |

---

### 08-RedTeamOps — Red Team Operations (Days 491–560)

**Lab:** Full kill-chain multi-stage engagement against a lab environment

| Day | File | Topic |
|---|---|---|
| 491 | `08-RedTeam-01/DAY-0491-Red-Team-vs-Pentest-Mindset.md` | Red team objectives, ROE, TTPs vs techniques |
| 492 | `08-RedTeam-01/DAY-0492-C2-Infrastructure-Design.md` | Redirectors, CDN fronting, malleable profiles, OpSec |
| 493 | `08-RedTeam-01/DAY-0493-C2-Lab-Cobalt-Strike-Sliver.md` | Lab: deploy C2 with redirectors, establish beacons |
| 494 | `08-RedTeam-01/DAY-0494-AV-and-EDR-Evasion-Concepts.md` | AMSI bypass, ETW patching, obfuscation, process injection |
| 495 | `08-RedTeam-01/DAY-0495-Evasion-Lab.md` | Lab: bypass Defender + Sysmon with a custom payload |
| 496 | `08-RedTeam-01/DAY-0496-Payload-Development.md` | C shellcode runner, reflective DLL, process hollowing |
| 497 | `08-RedTeam-01/DAY-0497-Post-Exploitation-Advanced.md` | Mimikatz, credential cache, DPAPI, remote registry |
| 498 | `08-RedTeam-01/DAY-0498-Lateral-Movement-Advanced.md` | WMI, DCOM, over-pass-the-hash, PTK |
| 499 | `08-RedTeam-01/DAY-0499-Domain-Dominance.md` | DCSync, Golden Ticket, Silver Ticket, skeleton key |
| 500 | `08-RedTeam-01/DAY-0500-Milestone-500-Days.md` | **Milestone Day 500** — review, gaps, re-lab |
| 501 | `08-RedTeam-02/DAY-0501-AD-Attack-Path-Analysis.md` | BloodHound, SharpHound, attack path visualisation |
| 502 | `08-RedTeam-02/DAY-0502-AD-Attack-Lab.md` | Lab: BloodHound → attack path → domain admin |
| 503 | `08-RedTeam-02/DAY-0503-Exchange-and-Email-Attacks.md` | Exchange exploitation, ProxyLogon, PrivExchange |
| 504 | `08-RedTeam-02/DAY-0504-Physical-and-Social-Engineering.md` | Pretexting, vishing, badge cloning, USB drops |
| 505 | `08-RedTeam-02/DAY-0505-Phishing-Campaign-Full-Lab.md` | Lab: GoPhish campaign with payload delivery |
| 506 | `08-RedTeam-02/DAY-0506-Full-Kill-Chain-Lab-Day-1.md` | Lab: recon → initial access → persistence |
| 507 | `08-RedTeam-02/DAY-0507-Full-Kill-Chain-Lab-Day-2.md` | Lab: lateral movement → domain admin → exfil |
| 508 | `08-RedTeam-03/DAY-0508-Purple-Team-Concepts.md` | Red + blue collaboration, ATT&CK emulation plans |
| 509 | `08-RedTeam-03/DAY-0509-Atomic-Red-Team-Lab.md` | Lab: run Atomic tests, detect with Sigma rules |
| 510 | `08-RedTeam-03/DAY-0510-Red-Team-Reporting.md` | Narrative report, executive summary, remediation priority |
| 511–550 | `08-RedTeam-03/DAY-XXXX-Red-Team-Practice.md` | AD practice labs, Offshore-style environments |
| 551–559 | `08-RedTeam-03/DAY-XXXX-Red-Team-CTF-Sprint.md` | Red team CTF sprint |
| 560 | `08-RedTeam-03/DAY-0560-Red-Team-Competency-Check.md` | Self-assessment + engagement report |

---

### 09-CryptoAttacks — Cryptographic Attacks (Days 561–610)

**Lab:** Exploit CBC padding oracle; length extension attack; ECDSA nonce reuse

| Day | File | Topic |
|---|---|---|
| 561 | `09-Crypto-01/DAY-0561-Padding-Oracle-Attack.md` | CBC padding oracle — mechanism and byte-by-byte decryption |
| 562 | `09-Crypto-01/DAY-0562-Padding-Oracle-Lab.md` | Lab: POODLE-style CBC oracle, extract plaintext |
| 563 | `09-Crypto-01/DAY-0563-Timing-Attacks.md` | Timing side-channel, constant-time comparisons, Python demo |
| 564 | `09-Crypto-01/DAY-0564-Length-Extension-Attack.md` | SHA-2 construction, extension attack, forging signed requests |
| 565 | `09-Crypto-01/DAY-0565-Length-Extension-Lab.md` | Lab: forge an HMAC via length extension |
| 566 | `09-Crypto-01/DAY-0566-ECB-Cut-and-Paste.md` | Block boundary manipulation, block oracle attacks |
| 567 | `09-Crypto-01/DAY-0567-RSA-Attack-Lab.md` | Lab: small public exponent, common modulus, broadcast attack |
| 568 | `09-Crypto-01/DAY-0568-Diffie-Hellman-Attacks.md` | Small subgroup, LOGJAM, invalid curve attacks |
| 569 | `09-Crypto-01/DAY-0569-ECDSA-Nonce-Reuse.md` | Nonce reuse → private key recovery, PS3 real case |
| 570 | `09-Crypto-01/DAY-0570-ECDSA-Lab.md` | Lab: recover private key from two sigs with same nonce |
| 571–590 | `09-Crypto-01/DAY-XXXX-Crypto-CTF-Practice.md` | Cryptopals challenges + crypto CTF sprint |
| 591–609 | `09-Crypto-02/DAY-XXXX-Advanced-Crypto-Topics.md` | Bleichenbacher, GCM nonce reuse, lattice attacks intro |
| 610 | `09-Crypto-02/DAY-0610-Crypto-Competency-Check.md` | Self-assessment + lab submission |

---

### 10-MalwareAndVulnResearch — Malware Analysis and Vulnerability Research (Days 611–700)

**Lab:** Analyse real malware; audit an open-source project and report findings

#### 10-MalwareAnalysis (Days 611–650)

| Day | File | Topic |
|---|---|---|
| 611 | `10-MalwareAnalysis-01/DAY-0611-Malware-Analysis-Setup.md` | FlareVM, REMnux, Cuckoo, isolated lab environment |
| 612 | `10-MalwareAnalysis-01/DAY-0612-Static-Analysis-Fundamentals.md` | PE analysis, string extraction, import analysis, YARA |
| 613 | `10-MalwareAnalysis-01/DAY-0613-Dynamic-Analysis-Fundamentals.md` | Process Monitor, Wireshark, Regshot, sandbox analysis |
| 614 | `10-MalwareAnalysis-01/DAY-0614-Malware-Sample-Lab-1.md` | Lab: analyse a real ransomware sample statically |
| 615 | `10-MalwareAnalysis-01/DAY-0615-Malware-Sample-Lab-2.md` | Lab: dynamic analysis — observe C2 comms, artefacts |
| 616 | `10-MalwareAnalysis-01/DAY-0616-Sandbox-Evasion-Techniques.md` | Timing, VM detection, user interaction, sleep calls |
| 617 | `10-MalwareAnalysis-01/DAY-0617-Unpacking-Malware.md` | OEP finding, dump + fix, manual unpacking |
| 618 | `10-MalwareAnalysis-01/DAY-0618-Rootkit-and-Kernel-Malware.md` | DKOM, hook-based rootkits, kernel drivers |
| 619 | `10-MalwareAnalysis-01/DAY-0619-Malware-Report-Writing.md` | Malware report structure, IOCs, MITRE ATT&CK mapping |
| 620–650 | `10-MalwareAnalysis-01/DAY-XXXX-Malware-Practice.md` | Analyse samples from MalwareBazaar; produce reports |

---

#### 10-VulnerabilityResearch (Days 651–700)

| Day | File | Topic |
|---|---|---|
| 651 | `10-VulnResearch-01/DAY-0651-Source-Code-Auditing.md` | Reading C/C++/Go source for vulnerabilities, grep patterns |
| 652 | `10-VulnResearch-01/DAY-0652-Code-Audit-Lab.md` | Lab: audit a small open-source project, find one bug |
| 653 | `10-VulnResearch-01/DAY-0653-Fuzzing-Fundamentals.md` | AFL++, libFuzzer — instrumentation, seed corpus, crash triage |
| 654 | `10-VulnResearch-01/DAY-0654-Fuzzing-Lab.md` | Lab: fuzz a parsing library, find a crash |
| 655 | `10-VulnResearch-01/DAY-0655-Coverage-Guided-Fuzzing.md` | Coverage feedback, persistent mode, structured input |
| 656 | `10-VulnResearch-01/DAY-0656-Patch-Diffing-and-CVE-Reproduction.md` | BinDiff patch analysis, root cause, exploit development |
| 657 | `10-VulnResearch-01/DAY-0657-CVE-Reproduction-Lab.md` | Lab: reproduce a CVE from patch diff to working PoC |
| 658 | `10-VulnResearch-01/DAY-0658-Responsible-Disclosure-Deep-Dive.md` | CVE process, coordinated disclosure, bug bounty vs CVE |
| 659 | `10-VulnResearch-01/DAY-0659-Writing-a-Security-Advisory.md` | Full advisory format, timeline, PoC, remediation |
| 660–700 | `10-VulnResearch-01/DAY-XXXX-Research-Sprint.md` | Audit + fuzz 2 open-source projects; produce findings |

---

### 11-GhostLevel — Ghost Level (Days 701–730)

**Lab:** 48-hour solo engagement on an unknown target

| Day | File | Topic |
|---|---|---|
| 701 | `11-GhostLevel/DAY-0701-Hardware-Security-UART-JTAG.md` | JTAG, UART, firmware extraction, side-channel intro |
| 702 | `11-GhostLevel/DAY-0702-Firmware-Analysis.md` | binwalk, squashfs, credential extraction, backdoors |
| 703 | `11-GhostLevel/DAY-0703-Mobile-Advanced-iOS-Jailbreak.md` | iOS binary protections, Frida on jailbroken device |
| 704 | `11-GhostLevel/DAY-0704-Zero-Day-Mindset.md` | What makes a zero-day, variant analysis, bug classes |
| 705 | `11-GhostLevel/DAY-0705-Year-2-Review-and-Synthesis.md` | Full review: binary → reversing → red team → research |
| 706 | `11-GhostLevel/DAY-0706-Ghost-Level-Preparation.md` | Prepare for the 48-hour challenge: tools, methodology |
| 707–728 | `11-GhostLevel/DAY-XXXX-Ghost-Level-48h-Engagement.md` | **48-hour solo engagement on an unknown lab target** |
| 729 | `11-GhostLevel/DAY-0729-Ghost-Level-Debrief.md` | Debrief: timeline, findings, what was missed and why |
| 730 | `11-GhostLevel/DAY-0730-Ghost-Level-Competency-Gate.md` | **GATE: Ghost Level** — findings report + live review |

---

## Directory Structure

```
learn-security/
├── SYLLABUS.md
├── 01-Foundation-01/     (Days   1–  8) Network Fundamentals
├── 01-Foundation-02/     (Days   9– 16) Linux for Hackers
├── 01-Foundation-03/     (Days  17– 28) Web Architecture
├── 01-Foundation-04/     (Days  29– 38) Cryptography Essentials
├── 01-Foundation-05/     (Days  39– 50) Auth and Authorisation
├── 02-Recon-01/          (Days  51– 62) OSINT and Passive Recon
├── 02-Recon-02/          (Days  63– 75) Active Recon and Bug Bounty Scope
├── 03-WebExploit-01/     (Days  76– 89) Injection Attacks
├── 03-WebExploit-02/     (Days  90–100) XSS and CSRF
├── 03-WebExploit-03/     (Days 101–112) Access Control and IDOR
├── 03-WebExploit-04/     (Days 113–125) SSRF, Path Traversal, File Attacks
├── 03-WebExploit-05/     (Days 126–145) Advanced Web Techniques
├── 03-WebExploit-06/     (Days 146–160) API Security
├── 03-WebExploit-07/     (Days 161–165) Bug Bounty Report Writing
├── 04-BroadSurface-01/   (Days 166–180) Authentication Attacks
├── 04-BroadSurface-02/   (Days 181–210) Cloud Security
├── 04-BroadSurface-03/   (Days 211–230) Mobile Security
├── 04-BroadSurface-04/   (Days 231–260) Network Exploitation and PrivEsc
├── 05-BugBountyOps-01/   (Days 261–290) Platforms, Strategy, Automation
├── 05-BugBountyOps-02/   (Days 291–330) CTF and Skill Sharpening
├── 05-BugBountyOps-03/   (Days 331–365) Real Programmes + Year 1 Gate
├── 06-BinaryExploit-01/  (Days 366–390) Stack Exploitation
├── 06-BinaryExploit-02/  (Days 391–430) Heap Exploitation + Kernel Intro
├── 07-RE-01/             (Days 431–450) Static Reverse Engineering
├── 07-RE-02/             (Days 451–490) Dynamic RE, Packers, Patch Diff
├── 08-RedTeam-01/        (Days 491–510) C2, Evasion, Post-Exploitation
├── 08-RedTeam-02/        (Days 511–535) AD Attacks, Kill Chain
├── 08-RedTeam-03/        (Days 536–560) Purple Team, Reporting
├── 09-Crypto-01/         (Days 561–590) Classical Crypto Attacks
├── 09-Crypto-02/         (Days 591–610) Advanced Cryptographic Attacks
├── 10-MalwareAnalysis-01/(Days 611–650) Malware Analysis
├── 10-VulnResearch-01/   (Days 651–700) Vulnerability Research
├── 11-GhostLevel/        (Days 701–730) Ghost Level Engagement
└── knowledge-base/       Reference material linked from lessons
```

---

> "Every system you learn to break is a system some defender worked hard to build.
> Respect that. Then break it anyway — so the next version is harder. That is the job."
>
> — Ghost
