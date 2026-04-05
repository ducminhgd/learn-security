---
title: "Ghost's 2-Year Cybersecurity Training Programme — Master Syllabus"
tags: [syllabus, curriculum, roadmap]
updated: 2026-04-05
---

# Ghost's 2-Year Cybersecurity Training Programme

> "You cannot defend what you do not understand. You cannot understand what you have not broken.
> So we break things first — in here, where it is safe — and then we build things that are harder
> to break out there."
>
> — Ghost

---

## Programme Overview

| Property         | Value                                                              |
|------------------|--------------------------------------------------------------------|
| Duration         | 2 years (730 days)                                                 |
| Daily commitment | 1 structured lesson per day                                        |
| Methodology      | The Ghost Method — Recon → Exploit → Detect → Harden              |
| Assessment       | Competency-based gates, not time-based certificates                |
| Tools philosophy | Understand the technique first; the tool is just automation        |

---

## Competency Gates

You do not advance past a gate by finishing lessons. You advance by demonstrating competency.

| Gate                  | Criteria                                                                           | Target date   |
|-----------------------|------------------------------------------------------------------------------------|---------------|
| **Foundation Complete** | Explain and demonstrate any F-01–F-06 concept live                               | Day 120       |
| **Red Cell Ready**      | Solo pentest a lab app end-to-end; write a professional finding report           | Day 360       |
| **Blue Cell Ready**     | Detect a simulated intrusion, write a Sigma/Suricata rule, produce IR timeline   | Day 540       |
| **Ghost Level**         | Find and exploit an unknown vulnerability in a lab target within 48 hours        | Day 730       |

---

## Year 1 — "Getting Off Zero + Going Red"

### 01-Foundation — Foundation Track (Days 1–120)

Goal: Build the mental model of how systems actually work before touching an exploit.
Every module ends with a hands-on lab. No lab = no completion.

---

#### 01-Foundation-01 — How the Internet Actually Works (Days 1–20)

**Lab:** Wireshark traffic capture and dissection

| Day  | File                                                     | Topic                                                  |
|------|----------------------------------------------------------|--------------------------------------------------------|
| 001  | `01-Foundation-01/DAY-0001-OSI-Model-and-Why-It-Matters.md`         | OSI model — layers, purpose, attacker perspective      |
| 002  | `01-Foundation-01/DAY-0002-IP-Addressing-and-Subnetting.md`         | IPv4/IPv6, CIDR, subnets, broadcast domains            |
| 003  | `01-Foundation-01/DAY-0003-TCP-Three-Way-Handshake.md`              | TCP state machine, SYN/ACK, RST, FIN — what a scanner sees |
| 004  | `01-Foundation-01/DAY-0004-UDP-and-ICMP.md`                         | UDP characteristics, ICMP types, ping sweeps           |
| 005  | `01-Foundation-01/DAY-0005-DNS-Deep-Dive.md`                        | Resolution chain, record types, zone transfers         |
| 006  | `01-Foundation-01/DAY-0006-DNS-as-an-Attack-Surface.md`             | DNS poisoning, DNS exfiltration, subdomain takeover    |
| 007  | `01-Foundation-01/DAY-0007-HTTP-from-First-Principles.md`           | Request/response cycle, methods, headers, status codes |
| 008  | `01-Foundation-01/DAY-0008-HTTP-Cookies-and-Sessions.md`            | Cookie attributes, session tokens, same-site           |
| 009  | `01-Foundation-01/DAY-0009-HTTPS-and-TLS-Handshake.md`             | TLS 1.2 vs 1.3, certificate chain, pinning             |
| 010  | `01-Foundation-01/DAY-0010-TLS-Attacks-and-Weaknesses.md`          | BEAST, POODLE, HSTS bypass, cert validation errors     |
| 011  | `01-Foundation-01/DAY-0011-HTTP2-and-HTTP3.md`                      | Multiplexing, header compression, QUIC, attack surface differences |
| 012  | `01-Foundation-01/DAY-0012-Proxies-and-CDNs.md`                     | Forward/reverse proxies, CDN bypass, X-Forwarded-For   |
| 013  | `01-Foundation-01/DAY-0013-Wireshark-Fundamentals.md`               | Capture filters, display filters, protocol dissectors  |
| 014  | `01-Foundation-01/DAY-0014-Wireshark-Lab-Episode-1.md`              | Lab: capture and dissect HTTP traffic                  |
| 015  | `01-Foundation-01/DAY-0015-Wireshark-Lab-Episode-2.md`              | Lab: capture and dissect TLS, identify certificates    |
| 016  | `01-Foundation-01/DAY-0016-Wireshark-Lab-Episode-3.md`              | Lab: capture DNS and reconstruct a full session         |
| 017  | `01-Foundation-01/DAY-0017-ARP-and-Layer-2.md`                      | ARP, MAC tables, VLAN basics, attacker perspective     |
| 018  | `01-Foundation-01/DAY-0018-Routing-and-NAT.md`                      | Routing tables, NAT traversal, source routing          |
| 019  | `01-Foundation-01/DAY-0019-Network-Protocols-Review.md`             | Review session: tie all protocols to attack scenarios  |
| 020  | `01-Foundation-01/DAY-0020-F01-Competency-Check.md`                 | Self-assessment + lab submission                       |

---

#### 01-Foundation-02 — Linux Fundamentals for Hackers (Days 21–40)

**Lab:** Find a hidden file, escalate to root on a live box

| Day  | File                                                          | Topic                                                       |
|------|---------------------------------------------------------------|-------------------------------------------------------------|
| 021  | `01-Foundation-02/DAY-0021-Linux-Filesystem-Hierarchy.md`                | FHS, mount points, where secrets live                       |
| 022  | `01-Foundation-02/DAY-0022-File-Permissions-and-ACLs.md`                 | rwx, octal, setuid, setgid, sticky bit                      |
| 023  | `01-Foundation-02/DAY-0023-Users-Groups-and-etc-passwd.md`               | /etc/passwd, /etc/shadow, /etc/group, UID 0                 |
| 024  | `01-Foundation-02/DAY-0024-Processes-and-proc.md`                        | ps, /proc, signals, process trees, parent–child             |
| 025  | `01-Foundation-02/DAY-0025-Linux-Networking-from-CLI.md`                 | ip, ss, netstat, lsof, /proc/net                            |
| 026  | `01-Foundation-02/DAY-0026-Bash-for-Hackers.md`                          | One-liners, piping, redirection, here-docs, cron            |
| 027  | `01-Foundation-02/DAY-0027-Cron-and-Scheduled-Tasks.md`                  | crontab syntax, /etc/cron.*, writable cron paths            |
| 028  | `01-Foundation-02/DAY-0028-Environment-Variables-and-PATH.md`            | PATH hijacking, LD_PRELOAD, env inspection                  |
| 029  | `01-Foundation-02/DAY-0029-Log-Files-and-Syslog.md`                      | /var/log hierarchy, journald, rsyslog, log rotation         |
| 030  | `01-Foundation-02/DAY-0030-Linux-Capabilities.md`                        | capabilities vs root, cap_net_raw, getcap/setcap            |
| 031  | `01-Foundation-02/DAY-0031-Sudo-and-Sudoers.md`                          | sudoers syntax, NOPASSWD, ALL=(ALL), sudo -l                |
| 032  | `01-Foundation-02/DAY-0032-SUID-and-SGID-Binaries.md`                   | find -perm, GTFOBins, real-world escalation paths           |
| 033  | `01-Foundation-02/DAY-0033-Named-Pipes-and-Sockets.md`                   | mkfifo, Unix domain sockets, inter-process attack surface   |
| 034  | `01-Foundation-02/DAY-0034-Package-Managers-and-Trust.md`                | apt/yum supply chain, package signing, mirror poisoning     |
| 035  | `01-Foundation-02/DAY-0035-Lab-Episode-1-Enumeration.md`                 | Lab: enumerate a live box from a low-priv shell             |
| 036  | `01-Foundation-02/DAY-0036-Lab-Episode-2-Hidden-File-Hunt.md`            | Lab: find hidden files across the filesystem                |
| 037  | `01-Foundation-02/DAY-0037-Lab-Episode-3-Privilege-Escalation.md`        | Lab: escalate from user to root using at least 2 paths      |
| 038  | `01-Foundation-02/DAY-0038-Linux-Hardening-Basics.md`                    | Harden stage: fix every escalation path found               |
| 039  | `01-Foundation-02/DAY-0039-Linux-Forensics-Artefacts.md`                 | bash_history, .ssh, /tmp, last, wtmp — what attackers leave |
| 040  | `01-Foundation-02/DAY-0040-F02-Competency-Check.md`                      | Self-assessment + lab submission                            |

---

#### 01-Foundation-03 — Networking for Attackers (Days 41–60)

**Lab:** nmap scan a lab network; interpret results with precision

| Day  | File                                                          | Topic                                                       |
|------|---------------------------------------------------------------|-------------------------------------------------------------|
| 041  | `01-Foundation-03/DAY-0041-Network-Scanning-Concepts.md`                 | Ping sweep, port scan, service detection — how each works   |
| 042  | `01-Foundation-03/DAY-0042-nmap-from-First-Principles.md`                | SYN scan, connect scan, UDP scan — packet-level detail      |
| 043  | `01-Foundation-03/DAY-0043-nmap-Service-and-OS-Detection.md`             | -sV, -O, version detection probes, fingerprint database     |
| 044  | `01-Foundation-03/DAY-0044-nmap-Scripting-Engine.md`                     | NSE categories, useful scripts, writing a basic NSE script  |
| 045  | `01-Foundation-03/DAY-0045-Firewall-Evasion-with-nmap.md`                | Fragmentation, decoys, timing, source port manipulation     |
| 046  | `01-Foundation-03/DAY-0046-Passive-Reconnaissance-with-Wireshark.md`     | Identify hosts, services, OS from captured traffic          |
| 047  | `01-Foundation-03/DAY-0047-ARP-Scanning-and-Discovery.md`                | arp-scan, arping, layer-2 discovery vs layer-3              |
| 048  | `01-Foundation-03/DAY-0048-Service-Banner-Grabbing.md`                   | nc, curl, openssl s_client — manual banner extraction       |
| 049  | `01-Foundation-03/DAY-0049-Masscan-and-Fast-Scanning.md`                 | masscan internals, rate limiting, comparison with nmap      |
| 050  | `01-Foundation-03/DAY-0050-Network-Topology-Mapping.md`                  | traceroute, TTL analysis, mapping a lab network             |
| 051  | `01-Foundation-03/DAY-0051-VPN-and-Tunnel-Protocols.md`                  | OpenVPN, WireGuard, SSH tunnels, attacker pivot channels    |
| 052  | `01-Foundation-03/DAY-0052-Proxychains-and-SOCKS.md`                     | proxychains config, SOCKS4/5, pivoting through a compromised host |
| 053  | `01-Foundation-03/DAY-0053-Network-Lab-Episode-1.md`                     | Lab: full nmap scan of a lab subnet, produce a service map  |
| 054  | `01-Foundation-03/DAY-0054-Network-Lab-Episode-2.md`                     | Lab: pivot from one network to another through a dual-homed host |
| 055  | `01-Foundation-03/DAY-0055-Interpreting-Scan-Results.md`                 | What each open port implies, common misconfigurations       |
| 056  | `01-Foundation-03/DAY-0056-Detecting-Port-Scans.md`                      | Snort/Suricata scan detection rules, baseline vs anomaly    |
| 057  | `01-Foundation-03/DAY-0057-Hardening-Network-Services.md`                | Minimal exposure, firewall rules, disable unused services   |
| 058  | `01-Foundation-03/DAY-0058-IPv6-for-Attackers.md`                        | Neighbour Discovery, SLAAC, dual-stack blind spots          |
| 059  | `01-Foundation-03/DAY-0059-Wireless-Networking-Basics.md`                | 802.11 frames, WPA2/3, rogue APs (conceptual)               |
| 060  | `01-Foundation-03/DAY-0060-F03-Competency-Check.md`                      | Self-assessment + lab submission                            |

---

#### 01-Foundation-04 — Cryptography Essentials (Days 61–80)

**Lab:** Break a weak cipher; forge a MAC with a known flaw

| Day  | File                                                          | Topic                                                       |
|------|---------------------------------------------------------------|-------------------------------------------------------------|
| 061  | `01-Foundation-04/DAY-0061-Why-Cryptography-Matters.md`                  | CIA triad through a crypto lens, attacker goals             |
| 062  | `01-Foundation-04/DAY-0062-Symmetric-Encryption.md`                      | Block vs stream ciphers, AES modes (ECB, CBC, CTR, GCM)    |
| 063  | `01-Foundation-04/DAY-0063-ECB-Mode-Weakness.md`                         | ECB penguin, block pattern leakage — hands-on break        |
| 064  | `01-Foundation-04/DAY-0064-CBC-Mode-and-Padding.md`                      | IV, padding schemes, why padding matters for attackers      |
| 065  | `01-Foundation-04/DAY-0065-Hashing-Algorithms.md`                        | MD5, SHA-1, SHA-256, SHA-3 — properties and weaknesses     |
| 066  | `01-Foundation-04/DAY-0066-Hash-Collisions-and-Length-Extension.md`      | MD5 collision demo, SHA length extension attack             |
| 067  | `01-Foundation-04/DAY-0067-MACs-and-HMACs.md`                            | HMAC construction, why MAC-then-Encrypt is broken          |
| 068  | `01-Foundation-04/DAY-0068-Forging-a-MAC-Lab.md`                         | Lab: forge a MAC against a length-extension vulnerable API  |
| 069  | `01-Foundation-04/DAY-0069-Asymmetric-Encryption.md`                     | RSA, ECC — key pairs, encryption, signing                   |
| 070  | `01-Foundation-04/DAY-0070-RSA-Common-Mistakes.md`                       | Small exponent, common modulus, textbook RSA attacks        |
| 071  | `01-Foundation-04/DAY-0071-Diffie-Hellman-Key-Exchange.md`               | DH handshake, forward secrecy, LOGJAM                      |
| 072  | `01-Foundation-04/DAY-0072-Digital-Signatures.md`                        | RSA-PSS, ECDSA, signature verification failures             |
| 073  | `01-Foundation-04/DAY-0073-TLS-Handshake-Deep-Dive.md`                   | TLS 1.3 step-by-step, cipher suites, certificate validation |
| 074  | `01-Foundation-04/DAY-0074-PKI-and-Certificate-Chains.md`                | Root CA, intermediate CA, cert pinning, OCSP               |
| 075  | `01-Foundation-04/DAY-0075-Password-Hashing.md`                          | bcrypt, Argon2, scrypt — why speed is your enemy here       |
| 076  | `01-Foundation-04/DAY-0076-Breaking-Weak-Cipher-Lab.md`                  | Lab: break a Vigenère / single-byte XOR cipher             |
| 077  | `01-Foundation-04/DAY-0077-Randomness-and-PRNG-Attacks.md`               | Weak PRNG, seed guessing, crypto/rand vs math/rand          |
| 078  | `01-Foundation-04/DAY-0078-Crypto-in-the-Wild.md`                        | Real CVEs from cryptographic failures (CVE catalog)        |
| 079  | `01-Foundation-04/DAY-0079-Cryptography-Hardening.md`                    | Harden stage: pick correct cipher suites, key lengths       |
| 080  | `01-Foundation-04/DAY-0080-F04-Competency-Check.md`                      | Self-assessment + lab submission                            |

---

#### 01-Foundation-05 — Web Architecture (Days 81–100)

**Lab:** Intercept and replay requests with Burp Suite

| Day  | File                                                          | Topic                                                       |
|------|---------------------------------------------------------------|-------------------------------------------------------------|
| 081  | `01-Foundation-05/DAY-0081-Web-Architecture-Overview.md`                 | Browser → DNS → TLS → Server → App → DB — full stack        |
| 082  | `01-Foundation-05/DAY-0082-HTTP-Headers-Deep-Dive.md`                    | Security headers, info-leaking headers, header injection    |
| 083  | `01-Foundation-05/DAY-0083-Cookies-SameSite-Secure-HttpOnly.md`          | Cookie flags, their security implications, defaults         |
| 084  | `01-Foundation-05/DAY-0084-Sessions-and-State-Management.md`             | Server sessions, client-side state, session fixation        |
| 085  | `01-Foundation-05/DAY-0085-Same-Origin-Policy.md`                        | SOP rules, what it prevents, what it does not               |
| 086  | `01-Foundation-05/DAY-0086-CORS-Configuration.md`                        | Pre-flight, CORS headers, misconfiguration risks            |
| 087  | `01-Foundation-05/DAY-0087-REST-APIs-and-JSON.md`                        | REST conventions, JSON parsing, content negotiation         |
| 088  | `01-Foundation-05/DAY-0088-GraphQL-Basics.md`                            | Queries, mutations, introspection — attacker surface        |
| 089  | `01-Foundation-05/DAY-0089-WebSockets.md`                                | Upgrade handshake, message format, auth bypass patterns     |
| 090  | `01-Foundation-05/DAY-0090-Burp-Suite-Setup-and-Proxy.md`                | Proxy config, CA cert install, scope, intercept mode        |
| 091  | `01-Foundation-05/DAY-0091-Burp-Repeater-and-Intruder.md`                | Replay, fuzzing positions, payload sets                     |
| 092  | `01-Foundation-05/DAY-0092-Burp-Lab-Episode-1.md`                        | Lab: intercept login, modify parameters, replay             |
| 093  | `01-Foundation-05/DAY-0093-Burp-Lab-Episode-2.md`                        | Lab: fuzz hidden parameters, discover unlinked endpoints    |
| 094  | `01-Foundation-05/DAY-0094-Content-Security-Policy.md`                   | CSP directives, bypass techniques, evaluation tools         |
| 095  | `01-Foundation-05/DAY-0095-Web-Caches-and-Cache-Poisoning.md`            | Cache keys, poisoning conditions, CPDoS                     |
| 096  | `01-Foundation-05/DAY-0096-Load-Balancers-and-Reverse-Proxies.md`        | IP leakage, header smuggling, host header attacks           |
| 097  | `01-Foundation-05/DAY-0097-Client-Side-Storage.md`                       | localStorage, sessionStorage, IndexedDB — attack surface    |
| 098  | `01-Foundation-05/DAY-0098-Web-Architecture-Hardening.md`                | Harden stage: headers, CSP, CORS, cookie flags              |
| 099  | `01-Foundation-05/DAY-0099-Web-Architecture-Review.md`                   | Review: tie all concepts to OWASP Top 10 categories         |
| 100  | `01-Foundation-05/DAY-0100-F05-Competency-Check.md`                      | Self-assessment + lab submission                            |

---

#### 01-Foundation-06 — Authentication and Authorisation (Days 101–120)

**Lab:** Exploit broken session management

| Day  | File                                                          | Topic                                                       |
|------|---------------------------------------------------------------|-------------------------------------------------------------|
| 101  | `01-Foundation-06/DAY-0101-Authentication-vs-Authorisation.md`           | Definitions, common confusion, attacker perspective         |
| 102  | `01-Foundation-06/DAY-0102-Password-Storage-and-Cracking.md`             | Hashing, salting, rainbow tables, hashcat basics            |
| 103  | `01-Foundation-06/DAY-0103-Session-Management-Fundamentals.md`           | Session ID entropy, fixation, hijacking                     |
| 104  | `01-Foundation-06/DAY-0104-Broken-Session-Lab.md`                        | Lab: exploit predictable session ID, hijack a session       |
| 105  | `01-Foundation-06/DAY-0105-Multi-Factor-Authentication.md`               | TOTP, FIDO2, SMS OTP — strength and weaknesses              |
| 106  | `01-Foundation-06/DAY-0106-MFA-Bypass-Techniques.md`                     | SIM swap, OTP interception, fallback exploitation           |
| 107  | `01-Foundation-06/DAY-0107-JSON-Web-Tokens.md`                           | JWT structure, alg:none, RS256→HS256 confusion, weak secret |
| 108  | `01-Foundation-06/DAY-0108-JWT-Attack-Lab.md`                            | Lab: forge a JWT with alg:none and weak secret              |
| 109  | `01-Foundation-06/DAY-0109-OAuth-2-Flow.md`                              | Authorization Code flow, Implicit, Client Credentials       |
| 110  | `01-Foundation-06/DAY-0110-OAuth-Attacks.md`                             | redirect_uri bypass, CSRF on OAuth, token leakage           |
| 111  | `01-Foundation-06/DAY-0111-OpenID-Connect.md`                            | OIDC on top of OAuth, ID token, nonce, replay attacks       |
| 112  | `01-Foundation-06/DAY-0112-API-Keys-and-Service-Auth.md`                 | API key storage, rotation, scope, leakage in repos          |
| 113  | `01-Foundation-06/DAY-0113-RBAC-and-ABAC.md`                             | Role-based vs attribute-based, privilege escalation paths   |
| 114  | `01-Foundation-06/DAY-0114-Broken-Access-Control-Lab.md`                 | Lab: IDOR, forced browsing, missing authorisation checks    |
| 115  | `01-Foundation-06/DAY-0115-SSO-and-SAML.md`                              | SAML assertions, XML signature wrapping attacks             |
| 116  | `01-Foundation-06/DAY-0116-Password-Reset-Flaws.md`                      | Token predictability, host header injection, race condition  |
| 117  | `01-Foundation-06/DAY-0117-Authentication-Hardening.md`                  | Harden stage: fix every auth flaw covered in the module     |
| 118  | `01-Foundation-06/DAY-0118-Auth-Detection-and-Logging.md`                | Detect brute force, session anomalies, token reuse          |
| 119  | `01-Foundation-06/DAY-0119-Foundation-Track-Review.md`                   | Full F-01–F-06 review, link all concepts together           |
| 120  | `01-Foundation-06/DAY-0120-Foundation-Competency-Gate.md`                | **GATE: Foundation Complete** — oral exam + live demo       |

---

### 02-RedCell — Offensive Track / Red Cell (Days 121–360)

Goal: Think like an attacker. Every module produces a professional-quality finding.

---

#### 02-RedCell-01 — Reconnaissance (Days 121–140)

**Lab:** Build a target profile from public sources only

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 121  | `02-RedCell-01/DAY-0121-Recon-Mindset-and-Kill-Chain.md`                   | Recon in the kill chain, MITRE ATT&CK T1590–T1598        |
| 122  | `02-RedCell-01/DAY-0122-Passive-vs-Active-Recon.md`                        | Legal line, operational security, what leaves footprints |
| 123  | `02-RedCell-01/DAY-0123-OSINT-Search-Operators.md`                         | Google dorks, Bing operators, Shodan, Censys             |
| 124  | `02-RedCell-01/DAY-0124-Domain-and-DNS-Recon.md`                           | whois, amass, subfinder, zone transfers, DNSSEC           |
| 125  | `02-RedCell-01/DAY-0125-Certificate-Transparency.md`                       | crt.sh, certspotter, domain discovery from TLS certs     |
| 126  | `02-RedCell-01/DAY-0126-Email-and-People-OSINT.md`                         | Hunter.io, theHarvester, LinkedIn OSINT techniques       |
| 127  | `02-RedCell-01/DAY-0127-GitHub-and-Code-Recon.md`                          | truffleHog, gitleaks, finding secrets in repos           |
| 128  | `02-RedCell-01/DAY-0128-Shodan-and-Censys-Deep-Dive.md`                    | Shodan filters, Censys queries, finding exposed services |
| 129  | `02-RedCell-01/DAY-0129-Web-Application-Fingerprinting.md`                 | Wappalyzer, whatweb, response header analysis            |
| 130  | `02-RedCell-01/DAY-0130-Cloud-Asset-Discovery.md`                          | S3 bucket brute force, Azure blob discovery, GCP assets  |
| 131  | `02-RedCell-01/DAY-0131-Social-Media-OSINT.md`                             | Twitter/X, LinkedIn, job postings as intel               |
| 132  | `02-RedCell-01/DAY-0132-Wireless-and-Physical-OSINT.md`                    | Wigle.net, Google Street View, physical reconnaissance   |
| 133  | `02-RedCell-01/DAY-0133-Attack-Surface-Mapping.md`                         | Aggregating recon into an attack surface document        |
| 134  | `02-RedCell-01/DAY-0134-Recon-Lab-Episode-1.md`                            | Lab: passive recon on a designated lab target            |
| 135  | `02-RedCell-01/DAY-0135-Recon-Lab-Episode-2.md`                            | Lab: active recon — enumerate subdomains, ports, stack   |
| 136  | `02-RedCell-01/DAY-0136-Recon-Lab-Episode-3.md`                            | Lab: build a full target profile document                |
| 137  | `02-RedCell-01/DAY-0137-Operational-Security-for-Red-Teams.md`             | Cover your tracks, VPS setup, traffic routing            |
| 138  | `02-RedCell-01/DAY-0138-Detecting-Recon.md`                                | Honeypots, canary tokens, log analysis for crawlers      |
| 139  | `02-RedCell-01/DAY-0139-Recon-Hardening.md`                                | Reduce org footprint, remove sensitive info from public  |
| 140  | `02-RedCell-01/DAY-0140-R01-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-02 — Web Exploitation (Days 141–175)

**Lab:** Exploit DVWA + custom vulnerable app; write a PoC finding report

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 141  | `02-RedCell-02/DAY-0141-Web-Exploitation-Overview.md`                      | OWASP Top 10, injection vs logic flaws, scope            |
| 142  | `02-RedCell-02/DAY-0142-SQL-Injection-Fundamentals.md`                     | Error-based, blind, time-based — how each works          |
| 143  | `02-RedCell-02/DAY-0143-SQL-Injection-Lab-Episode-1.md`                    | Lab: manual SQLi on login form                           |
| 144  | `02-RedCell-02/DAY-0144-SQL-Injection-Lab-Episode-2.md`                    | Lab: UNION-based data extraction                         |
| 145  | `02-RedCell-02/DAY-0145-Blind-SQL-Injection.md`                            | Boolean-blind, time-blind, out-of-band                  |
| 146  | `02-RedCell-02/DAY-0146-sqlmap-and-Automation.md`                          | sqlmap flags, tamper scripts, understanding the output   |
| 147  | `02-RedCell-02/DAY-0147-XSS-Fundamentals.md`                               | Reflected, stored, DOM-based — context and encoding      |
| 148  | `02-RedCell-02/DAY-0148-XSS-Lab-Episode-1.md`                              | Lab: reflected XSS, steal a cookie                       |
| 149  | `02-RedCell-02/DAY-0149-XSS-Lab-Episode-2.md`                              | Lab: stored XSS, persistent payload                      |
| 150  | `02-RedCell-02/DAY-0150-DOM-XSS-and-Sinks.md`                              | innerHTML, document.write, eval — dangerous sinks        |
| 151  | `02-RedCell-02/DAY-0151-CSRF-Fundamentals.md`                              | State-changing requests, CSRF token bypass, SameSite     |
| 152  | `02-RedCell-02/DAY-0152-CSRF-Lab.md`                                       | Lab: craft and deliver a CSRF payload                    |
| 153  | `02-RedCell-02/DAY-0153-SSRF-Fundamentals.md`                              | Reaching internal services, cloud metadata endpoints     |
| 154  | `02-RedCell-02/DAY-0154-SSRF-Lab.md`                                       | Lab: SSRF to read AWS metadata, internal service         |
| 155  | `02-RedCell-02/DAY-0155-XXE-XML-External-Entities.md`                      | Entity expansion, file read, SSRF via XXE                |
| 156  | `02-RedCell-02/DAY-0156-XXE-Lab.md`                                        | Lab: extract /etc/passwd via XXE                         |
| 157  | `02-RedCell-02/DAY-0157-IDOR-and-Broken-Object-Level.md`                   | Direct object reference, UUID prediction, mass assignment|
| 158  | `02-RedCell-02/DAY-0158-IDOR-Lab.md`                                       | Lab: access another user's data via IDOR                 |
| 159  | `02-RedCell-02/DAY-0159-Path-Traversal-and-LFI.md`                         | ../../../etc/passwd, null bytes, log poisoning for RCE   |
| 160  | `02-RedCell-02/DAY-0160-File-Upload-Vulnerabilities.md`                     | MIME type bypass, extension bypass, webshell upload      |
| 161  | `02-RedCell-02/DAY-0161-Command-Injection.md`                               | OS command injection, blind injection, SSRF chains       |
| 162  | `02-RedCell-02/DAY-0162-SSTI-Server-Side-Template-Injection.md`            | Jinja2, Twig, FreeMarker — detection and RCE             |
| 163  | `02-RedCell-02/DAY-0163-Web-Cache-Poisoning.md`                            | Cache key manipulation, poisoned response delivery       |
| 164  | `02-RedCell-02/DAY-0164-HTTP-Request-Smuggling.md`                         | CL.TE, TE.CL, TE.TE — desync attacks                    |
| 165  | `02-RedCell-02/DAY-0165-Business-Logic-Flaws.md`                           | Race conditions, negative quantities, workflow bypass    |
| 166  | `02-RedCell-02/DAY-0166-DVWA-Full-Exploitation-Lab.md`                     | Lab: exploit every DVWA vulnerability end-to-end         |
| 167  | `02-RedCell-02/DAY-0167-Custom-App-Lab-Episode-1.md`                       | Lab: custom app — recon and initial exploitation         |
| 168  | `02-RedCell-02/DAY-0168-Custom-App-Lab-Episode-2.md`                       | Lab: custom app — escalation and data extraction         |
| 169  | `02-RedCell-02/DAY-0169-Writing-a-Finding-Report.md`                       | CVSS, PoC format, risk rating, remediation guidance      |
| 170  | `02-RedCell-02/DAY-0170-Web-Vuln-Detection-Rules.md`                       | WAF rules, Suricata signatures for SQLi/XSS              |
| 171  | `02-RedCell-02/DAY-0171-Secure-Coding-for-Web.md`                          | Parameterised queries, output encoding, CSP              |
| 172  | `02-RedCell-02/DAY-0172-Web-App-Hardening.md`                              | Harden stage: fix all findings from the custom app lab   |
| 173  | `02-RedCell-02/DAY-0173-Web-Exploitation-Review.md`                        | Review: map all vulns to CWE and ATT&CK                  |
| 174  | `02-RedCell-02/DAY-0174-Finding-Report-Review.md`                          | Review and critique a sample finding report              |
| 175  | `02-RedCell-02/DAY-0175-R02-Competency-Check.md`                           | Self-assessment + finding report submission              |

---

#### 02-RedCell-03 — Authentication Attacks (Days 176–195)

**Lab:** Attack a realistic login system with rate limiting in place

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 176  | `02-RedCell-03/DAY-0176-Credential-Stuffing.md`                            | Breach databases, combo lists, automation, detection     |
| 177  | `02-RedCell-03/DAY-0177-Password-Spraying.md`                              | Low-and-slow, common passwords, AD lockout thresholds    |
| 178  | `02-RedCell-03/DAY-0178-Brute-Force-and-Rate-Limiting-Bypass.md`           | IP rotation, user-agent cycling, distributed attacks     |
| 179  | `02-RedCell-03/DAY-0179-Credential-Attack-Lab.md`                          | Lab: spray a lab login system with rate limiting active  |
| 180  | `02-RedCell-03/DAY-0180-JWT-Attacks-Deep-Dive.md`                          | alg confusion, kid injection, embedded JWK, x5u attack  |
| 181  | `02-RedCell-03/DAY-0181-JWT-Attack-Lab.md`                                 | Lab: exploit kid injection to achieve RCE via JWT        |
| 182  | `02-RedCell-03/DAY-0182-OAuth-Abuse.md`                                    | redirect_uri bypass, implicit flow token steal, PKCE     |
| 183  | `02-RedCell-03/DAY-0183-OAuth-Lab.md`                                      | Lab: steal OAuth token via open redirect                 |
| 184  | `02-RedCell-03/DAY-0184-SAML-Attacks.md`                                   | Signature wrapping, XXE in SAML, comment injection       |
| 185  | `02-RedCell-03/DAY-0185-Account-Takeover-Chains.md`                        | Chaining password reset + CSRF + IDOR                    |
| 186  | `02-RedCell-03/DAY-0186-Kerberoasting-Introduction.md`                     | SPN enumeration, TGS ticket, offline cracking            |
| 187  | `02-RedCell-03/DAY-0187-Pass-the-Hash-and-Pass-the-Ticket.md`             | NTLM relay, PtH, PtT — Windows auth attack chains       |
| 188  | `02-RedCell-03/DAY-0188-Auth-Attack-Detection.md`                          | Failed login patterns, token anomalies, Sigma rules      |
| 189  | `02-RedCell-03/DAY-0189-Auth-Hardening.md`                                 | MFA enforcement, lockout policy, token binding           |
| 190  | `02-RedCell-03/DAY-0190-R03-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-04 — API Security (Days 191–210)

**Lab:** Enumerate and exploit a REST and GraphQL API

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 191  | `02-RedCell-04/DAY-0191-OWASP-API-Top-10.md`                               | All 10 categories with examples                          |
| 192  | `02-RedCell-04/DAY-0192-API-Enumeration.md`                                | Swagger, OpenAPI, Postman collections, JS endpoint mining|
| 193  | `02-RedCell-04/DAY-0193-Broken-Object-Level-Auth.md`                       | BOLA/IDOR at API level — finding and exploiting          |
| 194  | `02-RedCell-04/DAY-0194-Broken-Function-Level-Auth.md`                     | Admin endpoints, HTTP method override, hidden routes     |
| 195  | `02-RedCell-04/DAY-0195-Mass-Assignment-Attack.md`                         | JSON property injection, role elevation                  |
| 196  | `02-RedCell-04/DAY-0196-GraphQL-Introspection-and-Attack.md`               | Schema dump, nested query DoS, batching attacks          |
| 197  | `02-RedCell-04/DAY-0197-GraphQL-Lab.md`                                    | Lab: introspect, find hidden fields, exploit auth        |
| 198  | `02-RedCell-04/DAY-0198-REST-API-Lab-Episode-1.md`                         | Lab: enumerate, find BOLA, extract data                  |
| 199  | `02-RedCell-04/DAY-0199-REST-API-Lab-Episode-2.md`                         | Lab: mass assignment, escalate to admin                  |
| 200  | `02-RedCell-04/DAY-0200-API-Rate-Limiting-and-DoS.md`                      | Algorithmic complexity attacks, resource exhaustion      |
| 201  | `02-RedCell-04/DAY-0201-API-Security-Headers.md`                           | Content-Type enforcement, CORS, auth headers             |
| 202  | `02-RedCell-04/DAY-0202-Webhook-Security.md`                               | SSRF via webhook, signature bypass, replay attacks       |
| 203  | `02-RedCell-04/DAY-0203-API-Detection-Rules.md`                            | Anomaly patterns, Sigma rules for API abuse              |
| 204  | `02-RedCell-04/DAY-0204-API-Hardening.md`                                  | Schema validation, least privilege, rate limiting        |
| 205  | `02-RedCell-04/DAY-0205-R04-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-05 — Network Exploitation (Days 206–225)

**Lab:** MITM on a lab network, extract credentials

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 206  | `02-RedCell-05/DAY-0206-MITM-Attack-Concepts.md`                           | ARP poisoning, DNS spoofing, SSL stripping               |
| 207  | `02-RedCell-05/DAY-0207-ARP-Spoofing-Lab.md`                               | Lab: ARP poison a lab subnet, intercept traffic          |
| 208  | `02-RedCell-05/DAY-0208-DNS-Poisoning.md`                                  | Cache poisoning, Kaminsky attack, mDNS poisoning         |
| 209  | `02-RedCell-05/DAY-0209-SSL-Stripping.md`                                  | Bettercap, sslstrip, HSTS bypass                         |
| 210  | `02-RedCell-05/DAY-0210-SMB-Relay-Attack.md`                               | LLMNR/NBT-NS poisoning, Responder, NTLMv2 relay          |
| 211  | `02-RedCell-05/DAY-0211-SMB-Relay-Lab.md`                                  | Lab: capture and relay NTLMv2 hashes                     |
| 212  | `02-RedCell-05/DAY-0212-VLAN-Hopping.md`                                   | Switch spoofing, double tagging attack                   |
| 213  | `02-RedCell-05/DAY-0213-DHCP-Attacks.md`                                   | DHCP starvation, rogue DHCP server, option 66/67         |
| 214  | `02-RedCell-05/DAY-0214-Network-Credential-Extraction.md`                  | Extract creds from PCAP: FTP, Telnet, HTTP Basic, NTLM   |
| 215  | `02-RedCell-05/DAY-0215-IPv6-MITM.md`                                      | SLAAC attack, fake router advertisement, MITM6           |
| 216  | `02-RedCell-05/DAY-0216-Wireless-Attack-Concepts.md`                       | Deauth, evil twin, WPA2 handshake capture                |
| 217  | `02-RedCell-05/DAY-0217-Network-MITM-Full-Lab.md`                          | Lab: full MITM — ARP + DNS + credential capture          |
| 218  | `02-RedCell-05/DAY-0218-Detecting-MITM-Attacks.md`                         | ARP watch, DHCP snooping, dynamic ARP inspection         |
| 219  | `02-RedCell-05/DAY-0219-Network-Hardening.md`                              | 802.1X, DNSSEC, HSTS preloading, SMB signing             |
| 220  | `02-RedCell-05/DAY-0220-R05-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-06 — Privilege Escalation (Days 221–245)

**Lab:** Escalate from www-data to root on a Linux box

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 221  | `02-RedCell-06/DAY-0221-Privilege-Escalation-Mindset.md`                   | Post-exploitation mindset, ATT&CK TA0004                 |
| 222  | `02-RedCell-06/DAY-0222-Linux-PrivEsc-Enumeration.md`                      | LinPEAS, manual checklist, what to look for              |
| 223  | `02-RedCell-06/DAY-0223-SUID-and-SGID-Exploitation.md`                     | GTFOBins, custom SUID exploitation                       |
| 224  | `02-RedCell-06/DAY-0224-Sudo-Misconfigurations.md`                         | ALL=(ALL), sudo -l, restricted shell bypass              |
| 225  | `02-RedCell-06/DAY-0225-Cron-Job-Exploitation.md`                          | Writable scripts, PATH injection, wildcard injection     |
| 226  | `02-RedCell-06/DAY-0226-Writable-Files-and-Weak-Permissions.md`            | /etc/passwd writable, shadow readable, config files      |
| 227  | `02-RedCell-06/DAY-0227-Kernel-Exploits-Linux.md`                          | Dirty Cow, overlayfs, kernel version fingerprinting      |
| 228  | `02-RedCell-06/DAY-0228-Linux-PrivEsc-Lab-Episode-1.md`                    | Lab: SUID and sudo escalation                            |
| 229  | `02-RedCell-06/DAY-0229-Linux-PrivEsc-Lab-Episode-2.md`                    | Lab: cron job and weak permission escalation             |
| 230  | `02-RedCell-06/DAY-0230-Windows-PrivEsc-Enumeration.md`                    | WinPEAS, PowerShell enumeration, what to look for        |
| 231  | `02-RedCell-06/DAY-0231-Token-Impersonation.md`                            | SeImpersonatePrivilege, Potato attacks, JuicyPotato      |
| 232  | `02-RedCell-06/DAY-0232-AlwaysInstallElevated.md`                          | Registry check, MSI package exploitation                 |
| 233  | `02-RedCell-06/DAY-0233-Unquoted-Service-Paths.md`                         | Service binary injection, space in path                  |
| 234  | `02-RedCell-06/DAY-0234-DLL-Hijacking.md`                                  | DLL search order, missing DLL, phantom DLL               |
| 235  | `02-RedCell-06/DAY-0235-Windows-PrivEsc-Lab.md`                            | Lab: escalate on a Windows box using at least 2 paths    |
| 236  | `02-RedCell-06/DAY-0236-Container-Escape-Basics.md`                        | Privileged container, Docker socket, host mount          |
| 237  | `02-RedCell-06/DAY-0237-Container-Escape-Lab.md`                           | Lab: escape from a privileged Docker container           |
| 238  | `02-RedCell-06/DAY-0238-PrivEsc-Detection.md`                              | Auditd rules, EDR process trees, file integrity          |
| 239  | `02-RedCell-06/DAY-0239-PrivEsc-Hardening.md`                              | Fix all paths: permissions, sudo, cron, capabilities     |
| 240  | `02-RedCell-06/DAY-0240-R06-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-07 — Post-Exploitation and Persistence (Days 241–265)

**Lab:** Establish persistence without triggering a basic EDR

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 241  | `02-RedCell-07/DAY-0241-Post-Exploitation-Mindset.md`                      | Objectives after access: pillage, pivot, persist         |
| 242  | `02-RedCell-07/DAY-0242-Internal-Enumeration.md`                           | Host discovery, service enumeration from inside the net  |
| 243  | `02-RedCell-07/DAY-0243-Credential-Harvesting.md`                          | Mimikatz, LSASS dump, credential files, env variables    |
| 244  | `02-RedCell-07/DAY-0244-Lateral-Movement-Techniques.md`                    | PsExec, WMI, WinRM, SSH, RDP — ATT&CK TA0008            |
| 245  | `02-RedCell-07/DAY-0245-Lateral-Movement-Lab.md`                           | Lab: pivot from host A to host B using harvested creds   |
| 246  | `02-RedCell-07/DAY-0246-Living-off-the-Land.md`                            | LOLBins, LOLBAS — native tools for attacker purposes     |
| 247  | `02-RedCell-07/DAY-0247-Linux-Persistence-Mechanisms.md`                   | Cron, .bashrc, systemd service, SSH key, SUID backdoor   |
| 248  | `02-RedCell-07/DAY-0248-Windows-Persistence-Mechanisms.md`                 | Registry run keys, scheduled tasks, WMI subscriptions    |
| 249  | `02-RedCell-07/DAY-0249-C2-Concepts-and-Architecture.md`                   | C2 channels, beaconing intervals, malleable profiles     |
| 250  | `02-RedCell-07/DAY-0250-C2-Lab-with-Sliver.md`                             | Lab: deploy Sliver C2, establish beacon, task execution  |
| 251  | `02-RedCell-07/DAY-0251-DNS-C2-and-Covert-Channels.md`                     | DNS beaconing, data exfiltration over DNS                |
| 252  | `02-RedCell-07/DAY-0252-Data-Exfiltration-Techniques.md`                   | HTTP exfil, DNS exfil, cloud storage, steganography       |
| 253  | `02-RedCell-07/DAY-0253-Persistence-without-EDR-Lab.md`                    | Lab: persist through a reboot without alerting basic EDR |
| 254  | `02-RedCell-07/DAY-0254-Covering-Tracks.md`                                | Log clearing, timestomping, hiding processes             |
| 255  | `02-RedCell-07/DAY-0255-Detecting-Post-Exploitation.md`                    | EDR telemetry, process anomalies, network beacon patterns|
| 256  | `02-RedCell-07/DAY-0256-Post-Exploitation-Hardening.md`                    | Credential vaulting, EDR tuning, lateral movement blocks |
| 257  | `02-RedCell-07/DAY-0257-R07-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-08 — Exploit Development Fundamentals (Days 258–290)

**Lab:** Write a working stack overflow exploit for a 32-bit ELF

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 258  | `02-RedCell-08/DAY-0258-Memory-Layout-of-a-Process.md`                     | Stack, heap, BSS, text segment, registers               |
| 259  | `02-RedCell-08/DAY-0259-x86-Assembly-Basics.md`                            | Registers, calling conventions, stack frames             |
| 260  | `02-RedCell-08/DAY-0260-GDB-and-PWNDBG.md`                                 | Breakpoints, examine memory, disassemble, info registers |
| 261  | `02-RedCell-08/DAY-0261-Stack-Buffer-Overflow-Theory.md`                   | EIP/RIP overwrite, controlling program flow              |
| 262  | `02-RedCell-08/DAY-0262-Stack-Overflow-Lab-Episode-1.md`                   | Lab: crash the binary, find the offset                   |
| 263  | `02-RedCell-08/DAY-0263-Stack-Overflow-Lab-Episode-2.md`                   | Lab: control EIP, redirect to shellcode                  |
| 264  | `02-RedCell-08/DAY-0264-Stack-Overflow-Lab-Episode-3.md`                   | Lab: working exploit with shellcode, get a shell         |
| 265  | `02-RedCell-08/DAY-0265-Shellcode-Writing-Basics.md`                       | Syscall numbers, execve shellcode, bad char avoidance    |
| 266  | `02-RedCell-08/DAY-0266-Exploit-Mitigations.md`                            | ASLR, NX/DEP, stack canaries, PIE — what each does       |
| 267  | `02-RedCell-08/DAY-0267-Bypassing-NX-with-ROP.md`                         | ROP concepts, gadget chains, ret2libc                    |
| 268  | `02-RedCell-08/DAY-0268-ROP-Lab.md`                                        | Lab: ret2libc on a binary with NX enabled               |
| 269  | `02-RedCell-08/DAY-0269-Bypassing-ASLR.md`                                 | Information leaks, brute force, partial overwrites       |
| 270  | `02-RedCell-08/DAY-0270-Format-String-Vulnerabilities.md`                  | %x, %n, arbitrary read and write                         |
| 271  | `02-RedCell-08/DAY-0271-Format-String-Lab.md`                              | Lab: exploit a format string to overwrite a GOT entry    |
| 272  | `02-RedCell-08/DAY-0272-pwntools-Introduction.md`                          | pwntools API, tubes, cyclic patterns, shellcraft         |
| 273  | `02-RedCell-08/DAY-0273-pwntools-Lab.md`                                   | Lab: rewrite all previous exploits using pwntools        |
| 274  | `02-RedCell-08/DAY-0274-Heap-Basics.md`                                    | malloc/free internals, chunk structure, bins             |
| 275  | `02-RedCell-08/DAY-0275-Heap-Overflow.md`                                  | Heap overflow into next chunk, tcache poisoning intro    |
| 276  | `02-RedCell-08/DAY-0276-Exploit-Development-Review.md`                     | Review all exploit types, mitigation bypass matrix       |
| 277  | `02-RedCell-08/DAY-0277-R08-Competency-Check.md`                           | Lab: write a full exploit for a given 32-bit ELF         |

---

#### 02-RedCell-09 — Cloud Exploitation (Days 278–305)

**Lab:** Extract credentials from a misconfigured AWS environment

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 278  | `02-RedCell-09/DAY-0278-Cloud-Threat-Model.md`                             | Shared responsibility, cloud attack surface              |
| 279  | `02-RedCell-09/DAY-0279-AWS-IAM-Fundamentals.md`                           | Users, roles, policies, trust relationships              |
| 280  | `02-RedCell-09/DAY-0280-IAM-Misconfiguration-Attacks.md`                   | Overly permissive roles, inline policies, role chaining  |
| 281  | `02-RedCell-09/DAY-0281-SSRF-to-AWS-Metadata.md`                           | IMDSv1 vs IMDSv2, credential extraction via SSRF        |
| 282  | `02-RedCell-09/DAY-0282-AWS-Metadata-Lab.md`                               | Lab: SSRF to metadata, assume role, escalate             |
| 283  | `02-RedCell-09/DAY-0283-S3-Bucket-Misconfiguration.md`                     | Public buckets, ACL vs bucket policy, listing objects    |
| 284  | `02-RedCell-09/DAY-0284-S3-Attack-Lab.md`                                  | Lab: discover and extract data from misconfigured S3     |
| 285  | `02-RedCell-09/DAY-0285-AWS-Enumeration-with-Pacu.md`                      | Pacu framework, permission enumeration, service recon    |
| 286  | `02-RedCell-09/DAY-0286-Lambda-and-Serverless-Attacks.md`                  | Environment variable theft, event injection, function abuse |
| 287  | `02-RedCell-09/DAY-0287-Container-and-ECS-Attacks.md`                      | Metadata from containers, ECS task role abuse            |
| 288  | `02-RedCell-09/DAY-0288-Azure-Fundamentals-for-Attackers.md`               | AAD, managed identity, storage blob misconfiguration     |
| 289  | `02-RedCell-09/DAY-0289-GCP-Fundamentals-for-Attackers.md`                 | Service accounts, metadata API, bucket misconfiguration  |
| 290  | `02-RedCell-09/DAY-0290-Cloud-Persistence.md`                              | Backdoor IAM users, cross-account roles, Lambda backdoor |
| 291  | `02-RedCell-09/DAY-0291-Cloud-Attack-Lab-Full.md`                          | Lab: full AWS attack chain — SSRF → creds → escalate     |
| 292  | `02-RedCell-09/DAY-0292-Detecting-Cloud-Attacks.md`                        | CloudTrail, GuardDuty, alert on metadata queries         |
| 293  | `02-RedCell-09/DAY-0293-Cloud-Hardening.md`                                | IMDSv2, SCPs, resource-based policies, least privilege   |
| 294  | `02-RedCell-09/DAY-0294-R09-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 02-RedCell-10 — Social Engineering and Phishing (Days 295–320)

**Lab:** Build a phishing campaign in a controlled simulation

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 295  | `02-RedCell-10/DAY-0295-Social-Engineering-Foundations.md`                 | Psychology of influence, Cialdini principles             |
| 296  | `02-RedCell-10/DAY-0296-Pretexting-and-Scenarios.md`                       | Building believable pretexts, target research            |
| 297  | `02-RedCell-10/DAY-0297-Phishing-Campaign-Architecture.md`                 | Infrastructure: domain, mail server, landing page        |
| 298  | `02-RedCell-10/DAY-0298-GoPhish-Setup-and-Campaign.md`                     | GoPhish installation, template design, tracking          |
| 299  | `02-RedCell-10/DAY-0299-Phishing-Lab-Episode-1.md`                         | Lab: deploy phishing infrastructure                      |
| 300  | `02-RedCell-10/DAY-0300-Phishing-Lab-Episode-2.md`                         | Lab: craft and deliver a phishing campaign               |
| 301  | `02-RedCell-10/DAY-0301-Payload-Delivery-Techniques.md`                    | Macro documents, HTA, ISO/LNK, HTML smuggling            |
| 302  | `02-RedCell-10/DAY-0302-Payload-Lab.md`                                    | Lab: craft a payload that bypasses basic AV              |
| 303  | `02-RedCell-10/DAY-0303-Vishing-and-Smishing.md`                           | Voice phishing techniques, SMS spoofing, SIM swap setup  |
| 304  | `02-RedCell-10/DAY-0304-Physical-Intrusion-Concepts.md`                    | Tailgating, badge cloning, USB drops                     |
| 305  | `02-RedCell-10/DAY-0305-Detecting-Phishing-Campaigns.md`                   | Email gateway rules, lookalike domain detection          |
| 306  | `02-RedCell-10/DAY-0306-Anti-Phishing-Hardening.md`                        | SPF/DKIM/DMARC, security awareness training              |
| 307  | `02-RedCell-10/DAY-0307-Red-Cell-Pentest-Report-Writing.md`                | Full pentest report structure, executive summary, PoC    |
| 308  | `02-RedCell-10/DAY-0308-R10-Competency-Check.md`                           | Self-assessment + phishing report submission             |

---

#### Red Cell Gate (Days 309–360)

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 309  | `R-GATE/DAY-0309-Red-Cell-Review-Episode-1.md`                    | Review R-01 to R-05                                      |
| 310  | `R-GATE/DAY-0310-Red-Cell-Review-Episode-2.md`                    | Review R-06 to R-10                                      |
| 311  | `R-GATE/DAY-0311-Red-Cell-CTF-Day-1.md`                           | Solo CTF — web + network challenges                      |
| 312  | `R-GATE/DAY-0312-Red-Cell-CTF-Day-2.md`                           | Solo CTF — exploit dev + cloud challenges                |
| 313  | `R-GATE/DAY-0313-Red-Cell-CTF-Debrief.md`                         | Debrief: what worked, what did not, what to revisit      |
| 314–360 | `R-GATE/DAY-031X-Solo-Pentest-Preparation.md` (×46 days)      | Solo pentest preparation: box practice, report drafts    |
| 360  | `R-GATE/DAY-0360-Red-Cell-Competency-Gate.md`                     | **GATE: Red Cell Ready** — solo pentest + report        |

---

## Year 2 — "Going Blue + Ghost Level"

### 03-BlueCell — Defensive Track / Blue Cell (Days 361–540)

Goal: See attacks from the defender's perspective. Detect everything you just did.

---

#### 03-BlueCell-01 — Security Monitoring Architecture (Days 361–380)

**Lab:** Stand up an Elastic stack; ingest and query logs

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 361  | `03-BlueCell-01/DAY-0361-SIEM-Concepts-and-Architecture.md`                 | Log aggregation, normalisation, correlation rules        |
| 362  | `03-BlueCell-01/DAY-0362-Elastic-Stack-Setup.md`                            | Elasticsearch, Kibana, Filebeat — Docker compose lab     |
| 363  | `03-BlueCell-01/DAY-0363-Log-Sources-and-Collection.md`                     | Syslog, Windows Event Log, auditd, application logs      |
| 364  | `03-BlueCell-01/DAY-0364-KQL-and-Kibana-Queries.md`                         | Kibana Query Language, Discover, dashboards              |
| 365  | `03-BlueCell-01/DAY-0365-Graylog-as-SIEM.md`                                | Graylog setup, streams, alert conditions                 |
| 366  | `03-BlueCell-01/DAY-0366-Log-Parsing-and-Normalisation.md`                  | Grok patterns, Logstash pipelines, field extraction      |
| 367  | `03-BlueCell-01/DAY-0367-Alerting-and-Correlation.md`                       | Elastic detection rules, threshold alerts, ML jobs       |
| 368  | `03-BlueCell-01/DAY-0368-SIEM-Lab-Episode-1.md`                             | Lab: ingest SSH, Apache, and Windows logs                |
| 369  | `03-BlueCell-01/DAY-0369-SIEM-Lab-Episode-2.md`                             | Lab: build a dashboard detecting failed SSH attempts     |
| 370  | `03-BlueCell-01/DAY-0370-SIEM-Lab-Episode-3.md`                             | Lab: write a correlation rule — brute force to success   |
| 371  | `03-BlueCell-01/DAY-0371-Log-Retention-and-Compliance.md`                   | Retention periods, log integrity, legal requirements     |
| 372  | `03-BlueCell-01/DAY-0372-Cloud-Logging-AWS-CloudTrail.md`                   | CloudTrail structure, GuardDuty, ingesting into SIEM     |
| 373  | `03-BlueCell-01/DAY-0373-Windows-Event-Logs-Deep-Dive.md`                   | Event IDs: 4624, 4625, 4648, 4688, 4698, 7045           |
| 374  | `03-BlueCell-01/DAY-0374-Linux-Auditd-Deep-Dive.md`                         | auditd rules, ausearch, aureport                         |
| 375  | `03-BlueCell-01/DAY-0375-B01-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 03-BlueCell-02 — Threat Hunting (Days 376–395)

**Lab:** Hunt for simulated lateral movement in a log dataset

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 376  | `03-BlueCell-02/DAY-0376-Threat-Hunting-Fundamentals.md`                    | Hypothesis-driven hunting, reactive vs proactive         |
| 377  | `03-BlueCell-02/DAY-0377-MITRE-ATT&CK-for-Defenders.md`                     | Using ATT&CK for hunt hypotheses                         |
| 378  | `03-BlueCell-02/DAY-0378-Sigma-Rules-Fundamentals.md`                       | Sigma syntax, conditions, backends                       |
| 379  | `03-BlueCell-02/DAY-0379-Writing-Sigma-Rules.md`                            | Write rules for techniques covered in Red Cell phase     |
| 380  | `03-BlueCell-02/DAY-0380-Hunting-Lateral-Movement.md`                       | SMB, PsExec, WMI, WinRM — what they look like in logs   |
| 381  | `03-BlueCell-02/DAY-0381-Lateral-Movement-Hunt-Lab.md`                      | Lab: hunt for lateral movement in a provided log dataset |
| 382  | `03-BlueCell-02/DAY-0382-Hunting-Persistence.md`                            | Registry, scheduled tasks, services — hunt hypotheses    |
| 383  | `03-BlueCell-02/DAY-0383-Hunting-C2-Beaconing.md`                           | Beacon interval analysis, DNS-based C2, HTTP jitter      |
| 384  | `03-BlueCell-02/DAY-0384-Hunting-Data-Exfiltration.md`                      | Large outbound transfers, DNS exfil, cloud uploads       |
| 385  | `03-BlueCell-02/DAY-0385-Zeek-for-Threat-Hunting.md`                        | Zeek logs, conn.log, dns.log, http.log, ssl.log          |
| 386  | `03-BlueCell-02/DAY-0386-Hunting-with-Zeek-Lab.md`                          | Lab: use Zeek logs to identify C2 and exfiltration       |
| 387  | `03-BlueCell-02/DAY-0387-Threat-Intelligence-Integration.md`                | IOC feeds, MISP, enrichment in SIEM alerts               |
| 388  | `03-BlueCell-02/DAY-0388-Building-a-Hunt-Report.md`                         | Hunt report format, TTP documentation, recommendations   |
| 389  | `03-BlueCell-02/DAY-0389-Hunt-Maturity-Model.md`                            | HMM levels, building a hunt programme from scratch       |
| 390  | `03-BlueCell-02/DAY-0390-B02-Competency-Check.md`                           | Self-assessment + lab submission                         |

---

#### 03-BlueCell-03 — Intrusion Detection (Days 391–410)

**Lab:** Write a Suricata rule detecting the R-02 web exploits

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 391  | `03-BlueCell-03/DAY-0391-IDS-IPS-Concepts.md`                               | Signature vs anomaly, inline vs passive, NFQ             |
| 392  | `03-BlueCell-03/DAY-0392-Suricata-Setup-and-Architecture.md`                | Suricata modes, YAML config, eve.json output             |
| 393  | `03-BlueCell-03/DAY-0393-Suricata-Rule-Syntax.md`                           | Rule header, options, keywords, fast.log vs eve.json     |
| 394  | `03-BlueCell-03/DAY-0394-Writing-Suricata-Rules-Web.md`                     | Rules for SQLi, XSS, SSRF based on R-02 labs             |
| 395  | `03-BlueCell-03/DAY-0395-Suricata-Rule-Lab-Episode-1.md`                    | Lab: detect SQLi against DVWA                            |
| 396  | `03-BlueCell-03/DAY-0396-Suricata-Rule-Lab-Episode-2.md`                    | Lab: detect XSS, SSRF, command injection                 |
| 397  | `03-BlueCell-03/DAY-0397-Network-Anomaly-Detection.md`                      | Baseline traffic, anomaly thresholds, ML-lite approaches |
| 398  | `03-BlueCell-03/DAY-0398-Zeek-Scripting-for-Detection.md`                   | Zeek scripting language, writing a detection script      |
| 399  | `03-BlueCell-03/DAY-0399-Snort-vs-Suricata-Comparison.md`                   | Rule compatibility, performance, use cases               |
| 400  | `03-BlueCell-03/DAY-0400-Tuning-IDS-Rules.md`                               | False positive reduction, threshold, suppress            |
| 401  | `03-BlueCell-03/DAY-0401-Evasion-of-IDS.md`                                 | Fragmentation, encoding, protocol anomalies              |
| 402  | `03-BlueCell-03/DAY-0402-IDS-in-Cloud-Environments.md`                      | VPC flow logs, cloud-native IDS, traffic mirroring       |
| 403  | `03-BlueCell-03/DAY-0403-B03-Competency-Check.md`                           | Self-assessment + rule set submission                    |

---

#### 03-BlueCell-04 — Endpoint Detection (Days 404–423)

**Lab:** Write a YARA rule detecting a given malware sample

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 404  | `03-BlueCell-04/DAY-0404-EDR-Concepts-and-Architecture.md`                  | Kernel callbacks, ETW, telemetry pipeline                |
| 405  | `03-BlueCell-04/DAY-0405-Process-Trees-and-Anomalies.md`                    | Parent–child relationships, LOLBin spawning, Sysmon      |
| 406  | `03-BlueCell-04/DAY-0406-Sysmon-Setup-and-Config.md`                        | Sysmon event IDs: 1, 3, 7, 8, 10, 11, 12, 13            |
| 407  | `03-BlueCell-04/DAY-0407-Sysmon-Lab.md`                                     | Lab: detect a reverse shell using Sysmon events          |
| 408  | `03-BlueCell-04/DAY-0408-YARA-Fundamentals.md`                              | YARA syntax, rule structure, string types, conditions    |
| 409  | `03-BlueCell-04/DAY-0409-YARA-Rule-Lab-Episode-1.md`                        | Lab: write a YARA rule matching strings in a sample      |
| 410  | `03-BlueCell-04/DAY-0410-YARA-Rule-Lab-Episode-2.md`                        | Lab: write a YARA rule using PE metadata and imports     |
| 411  | `03-BlueCell-04/DAY-0411-Memory-Forensics-Introduction.md`                  | Volatility3, process listing, network connections        |
| 412  | `03-BlueCell-04/DAY-0412-Memory-Forensics-Lab.md`                           | Lab: extract IOCs from a memory image                   |
| 413  | `03-BlueCell-04/DAY-0413-Fileless-Malware-Detection.md`                     | PowerShell in-memory, reflective DLL, hollow process     |
| 414  | `03-BlueCell-04/DAY-0414-EDR-Telemetry-Analysis.md`                         | Wazuh/Velociraptor as open-source EDR                    |
| 415  | `03-BlueCell-04/DAY-0415-Velociraptor-Lab.md`                               | Lab: hunt with Velociraptor across a lab fleet           |
| 416  | `03-BlueCell-04/DAY-0416-B04-Competency-Check.md`                           | Self-assessment + YARA rule submission                   |

---

#### 03-BlueCell-05 — Digital Forensics (Days 417–436)

**Lab:** Reconstruct an attack timeline from a compromised host image

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 417  | `03-BlueCell-05/DAY-0417-Digital-Forensics-Principles.md`                   | Chain of custody, evidence integrity, forensic soundness |
| 418  | `03-BlueCell-05/DAY-0418-Disk-Imaging.md`                                   | dd, FTK Imager, Guymager, write blockers                 |
| 419  | `03-BlueCell-05/DAY-0419-Filesystem-Analysis-Linux.md`                      | ext4 structure, inode, deleted file recovery, Autopsy    |
| 420  | `03-BlueCell-05/DAY-0420-Filesystem-Analysis-Windows.md`                    | NTFS, MFT, $LogFile, $UsnJrnl, recycle bin              |
| 421  | `03-BlueCell-05/DAY-0421-Windows-Registry-Forensics.md`                     | ShimCache, Amcache, UserAssist, MRU lists                |
| 422  | `03-BlueCell-05/DAY-0422-Timeline-Construction.md`                          | Plaso/log2timeline, supertimeline, event correlation     |
| 423  | `03-BlueCell-05/DAY-0423-Timeline-Lab.md`                                   | Lab: build a timeline from a compromised Windows image   |
| 424  | `03-BlueCell-05/DAY-0424-Log-Analysis-for-Forensics.md`                     | Windows Event Logs, IIS logs, firewall logs in forensics |
| 425  | `03-BlueCell-05/DAY-0425-Browser-and-Email-Forensics.md`                    | Chrome history, cached files, email headers, PST         |
| 426  | `03-BlueCell-05/DAY-0426-Network-Forensics.md`                              | PCAP analysis post-incident, extract files from capture  |
| 427  | `03-BlueCell-05/DAY-0427-Linux-Host-Forensics-Lab.md`                       | Lab: forensics on a compromised Linux host image         |
| 428  | `03-BlueCell-05/DAY-0428-Artefact-Recovery-Lab.md`                          | Lab: recover deleted malware and establish attack path   |
| 429  | `03-BlueCell-05/DAY-0429-Forensic-Report-Writing.md`                        | Structure, findings, chain of custody statement          |
| 430  | `03-BlueCell-05/DAY-0430-B05-Competency-Check.md`                           | Self-assessment + forensic report submission             |

---

#### 03-BlueCell-06 — Incident Response (Days 431–450)

**Lab:** Tabletop exercise — simulated breach

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 431  | `03-BlueCell-06/DAY-0431-IR-Lifecycle.md`                                   | NIST SP 800-61: Prepare, Identify, Contain, Eradicate    |
| 432  | `03-BlueCell-06/DAY-0432-IR-Playbooks.md`                                   | Playbook structure, decision trees, escalation paths     |
| 433  | `03-BlueCell-06/DAY-0433-Containment-Decisions.md`                          | Network isolation, account disabling, forensic hold      |
| 434  | `03-BlueCell-06/DAY-0434-Evidence-Preservation.md`                          | Volatile data, memory capture order, legal hold          |
| 435  | `03-BlueCell-06/DAY-0435-Eradication-and-Recovery.md`                       | Removing persistence, re-imaging, patch before restore   |
| 436  | `03-BlueCell-06/DAY-0436-Tabletop-Exercise-Ransomware.md`                   | Lab: ransomware tabletop — decisions under pressure      |
| 437  | `03-BlueCell-06/DAY-0437-Tabletop-Exercise-APT.md`                          | Lab: APT tabletop — long dwell time, stealthy exfil      |
| 438  | `03-BlueCell-06/DAY-0438-Post-Incident-Activity.md`                         | Lessons learned, root cause analysis, metrics            |
| 439  | `03-BlueCell-06/DAY-0439-Communication-During-IR.md`                        | Stakeholder comms, legal considerations, PR              |
| 440  | `03-BlueCell-06/DAY-0440-IR-Metrics-and-Maturity.md`                        | MTTD, MTTR, IR programme maturity models                 |
| 441  | `03-BlueCell-06/DAY-0441-B06-Competency-Check.md`                           | Tabletop exercise submission + debrief                   |

---

#### 03-BlueCell-07 — Malware Analysis (Days 442–465)

**Lab:** Analyse a real malware sample in a sandboxed VM

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 442  | `03-BlueCell-07/DAY-0442-Malware-Analysis-Lab-Setup.md`                     | FlareVM, REMnux, snapshot discipline, network isolation  |
| 443  | `03-BlueCell-07/DAY-0443-Static-Analysis-Basics.md`                         | file, strings, PE header, imports, exports               |
| 444  | `03-BlueCell-07/DAY-0444-Static-Analysis-Lab.md`                            | Lab: static analysis of a given PE sample                |
| 445  | `03-BlueCell-07/DAY-0445-Dynamic-Analysis-Basics.md`                        | Process Monitor, Wireshark, Regshot during execution     |
| 446  | `03-BlueCell-07/DAY-0446-Dynamic-Analysis-Lab.md`                           | Lab: detonate a sample, capture all behaviours           |
| 447  | `03-BlueCell-07/DAY-0447-Cuckoo-Sandbox.md`                                 | Cuckoo setup, report interpretation, limitations         |
| 448  | `03-BlueCell-07/DAY-0448-Disassembly-with-Ghidra.md`                        | Ghidra navigation, function analysis, renaming           |
| 449  | `03-BlueCell-07/DAY-0449-Ghidra-Lab.md`                                     | Lab: find the C2 URL hardcoded in a sample using Ghidra  |
| 450  | `03-BlueCell-07/DAY-0450-Obfuscation-and-Packers.md`                        | UPX, XOR obfuscation, string decryption, unpacking       |
| 451  | `03-BlueCell-07/DAY-0451-Unpacking-Lab.md`                                  | Lab: unpack a UPX binary, then analyse the unpacked code |
| 452  | `03-BlueCell-07/DAY-0452-Sandbox-Evasion-Techniques.md`                     | Sleep, user activity checks, VM detection tricks         |
| 453  | `03-BlueCell-07/DAY-0453-Ransomware-Analysis.md`                            | File encryption loop, key management, C2 check-in        |
| 454  | `03-BlueCell-07/DAY-0454-RAT-and-C2-Analysis.md`                            | RAT architecture, protocol analysis, beacon extraction   |
| 455  | `03-BlueCell-07/DAY-0455-Malware-Analysis-Report.md`                        | Report format: executive summary, IOCs, TTPs, YARA rule  |
| 456  | `03-BlueCell-07/DAY-0456-B07-Competency-Check.md`                           | Malware analysis report submission                       |

---

#### 03-BlueCell-08 — Secure Architecture Review (Days 457–476)

**Lab:** Threat model a real architecture diagram

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 457  | `03-BlueCell-08/DAY-0457-Threat-Modelling-Fundamentals.md`                  | STRIDE, PASTA, attack trees — when to use what           |
| 458  | `03-BlueCell-08/DAY-0458-STRIDE-in-Practice.md`                             | Apply STRIDE to a web application diagram                |
| 459  | `03-BlueCell-08/DAY-0459-Data-Flow-Diagrams.md`                             | DFD elements, trust boundaries, data classification      |
| 460  | `03-BlueCell-08/DAY-0460-Threat-Modelling-Lab-Episode-1.md`                 | Lab: threat model a 3-tier web application               |
| 461  | `03-BlueCell-08/DAY-0461-Threat-Modelling-Lab-Episode-2.md`                 | Lab: threat model a cloud-native microservices arch      |
| 462  | `03-BlueCell-08/DAY-0462-Security-Design-Review.md`                         | Reviewing architecture docs for missing controls         |
| 463  | `03-BlueCell-08/DAY-0463-Zero-Trust-Architecture.md`                        | ZTA principles, microsegmentation, identity-centric      |
| 464  | `03-BlueCell-08/DAY-0464-Security-Requirements.md`                          | Deriving security requirements from threats              |
| 465  | `03-BlueCell-08/DAY-0465-Supply-Chain-Security.md`                          | Dependency risks, SBOM, SolarWinds, log4shell lessons    |
| 466  | `03-BlueCell-08/DAY-0466-Secure-Architecture-Patterns.md`                   | Defence in depth, bulkhead, secrets management           |
| 467  | `03-BlueCell-08/DAY-0467-Cloud-Architecture-Review.md`                      | AWS Well-Architected security pillar, review checklist   |
| 468  | `03-BlueCell-08/DAY-0468-B08-Competency-Check.md`                           | Threat model report submission                           |

---

#### 03-BlueCell-09 — Deception and Honeypots (Days 469–485)

**Lab:** Deploy a honeynet; trigger alerts using attacker TTPs

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 469  | `03-BlueCell-09/DAY-0469-Deception-Theory.md`                               | Why deception works, attacker psychology                 |
| 470  | `03-BlueCell-09/DAY-0470-Honeypot-Types.md`                                 | Low-interaction vs high-interaction, production vs research|
| 471  | `03-BlueCell-09/DAY-0471-Canary-Tokens.md`                                  | canarytokens.org, token types, alert integration         |
| 472  | `03-BlueCell-09/DAY-0472-Canary-Token-Lab.md`                               | Lab: plant canary tokens, trigger and receive alerts     |
| 473  | `03-BlueCell-09/DAY-0473-OpenCanary-Setup.md`                               | Deploy OpenCanary, configure services, forward alerts    |
| 474  | `03-BlueCell-09/DAY-0474-Honeynet-Lab-Episode-1.md`                         | Lab: deploy a honeynet in Docker                         |
| 475  | `03-BlueCell-09/DAY-0475-Honeynet-Lab-Episode-2.md`                         | Lab: trigger alerts using R-02 through R-07 TTPs         |
| 476  | `03-BlueCell-09/DAY-0476-Honeytokens-in-Applications.md`                    | Fake credentials, fake API keys, fake S3 buckets         |
| 477  | `03-BlueCell-09/DAY-0477-Deception-Detection-Pipeline.md`                   | Alert routing, SIEM integration, automated response      |
| 478  | `03-BlueCell-09/DAY-0478-Anti-Deception-Techniques.md`                      | How attackers detect honeypots — improve your deception  |
| 479  | `03-BlueCell-09/DAY-0479-B09-Competency-Check.md`                           | Honeynet lab + alert report submission                   |

---

#### 03-BlueCell-10 — Purple Team Operations (Days 480–520)

**Lab:** Full kill-chain simulation with a paired red cell

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 480  | `03-BlueCell-10/DAY-0480-Purple-Team-Fundamentals.md`                       | Purple team vs red+blue separately, collaboration model  |
| 481  | `03-BlueCell-10/DAY-0481-ATT&CK-Emulation-Plans.md`                         | MITRE CTID emulation plans, APT29, APT3                  |
| 482  | `03-BlueCell-10/DAY-0482-Atomic-Red-Team.md`                                | Atomic tests, mapping to ATT&CK, running atomics         |
| 483  | `03-BlueCell-10/DAY-0483-Atomic-Red-Team-Lab.md`                            | Lab: execute atomics, verify detection coverage          |
| 484  | `03-BlueCell-10/DAY-0484-Caldera-Framework.md`                              | CALDERA setup, adversary profiles, run an operation      |
| 485  | `03-BlueCell-10/DAY-0485-Caldera-Lab.md`                                    | Lab: run a CALDERA operation, detect in SIEM             |
| 486  | `03-BlueCell-10/DAY-0486-Detection-Coverage-Mapping.md`                     | ATT&CK Navigator, coverage gaps, prioritisation          |
| 487  | `03-BlueCell-10/DAY-0487-Purple-Team-Exercise-Planning.md`                  | Scope, rules of engagement, success criteria             |
| 488  | `03-BlueCell-10/DAY-0488-Purple-Exercise-Episode-1.md`                      | Lab: kill-chain sim — initial access + lateral movement  |
| 489  | `03-BlueCell-10/DAY-0489-Purple-Exercise-Episode-2.md`                      | Lab: kill-chain sim — persistence + exfiltration         |
| 490  | `03-BlueCell-10/DAY-0490-Purple-Exercise-Debrief.md`                        | Debrief: detection gaps, rule improvements, coverage map |
| 491  | `03-BlueCell-10/DAY-0491-B10-Competency-Check.md`                           | Purple team report + ATT&CK Navigator map submission     |

---

#### Blue Cell Gate (Days 492–540)

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 492  | `B-GATE/DAY-0492-Blue-Cell-Review-Episode-1.md`                   | Review B-01 to B-05                                      |
| 493  | `B-GATE/DAY-0493-Blue-Cell-Review-Episode-2.md`                   | Review B-06 to B-10                                      |
| 494  | `B-GATE/DAY-0494-Full-Purple-Team-Simulation-Day-1.md`            | Full simulation: red attacks across the full kill chain  |
| 495  | `B-GATE/DAY-0495-Full-Purple-Team-Simulation-Day-2.md`            | Full simulation: blue detects, responds, produces report |
| 496–539 | `B-GATE/DAY-04XX-Blue-Cell-Preparation.md` (×44 days)         | Additional practice: threat hunting, rule writing, IR    |
| 540  | `B-GATE/DAY-0540-Blue-Cell-Competency-Gate.md`                    | **GATE: Blue Cell Ready** — live exercise + IR report   |

---

### 04-Advanced — Advanced Track / Ghost Level (Days 541–730)

Goal: Elite techniques. Find what others miss. Research-grade skills.

---

#### 04-Advanced-01 — Binary Exploitation Advanced (Days 541–565)

**Lab:** Exploit a heap UAF in a CTF binary

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 541  | `04-Advanced-01/DAY-0541-Heap-Internals-Deep-Dive.md`                       | ptmalloc2, tcache, fastbins, smallbins, unsorted bin     |
| 542  | `04-Advanced-01/DAY-0542-Heap-Overflow-Advanced.md`                         | Unlink exploit, chunk overlapping, tcache poisoning      |
| 543  | `04-Advanced-01/DAY-0543-Use-After-Free-Theory.md`                          | UAF mechanics, dangling pointers, object lifecycle       |
| 544  | `04-Advanced-01/DAY-0544-UAF-Lab-Episode-1.md`                              | Lab: trigger UAF, control freed memory                   |
| 545  | `04-Advanced-01/DAY-0545-UAF-Lab-Episode-2.md`                              | Lab: exploit UAF to achieve code execution               |
| 546  | `04-Advanced-01/DAY-0546-Tcache-Poisoning.md`                               | Tcache dup, safe-linking bypass, house of botcake        |
| 547  | `04-Advanced-01/DAY-0547-Heap-Exploitation-Lab.md`                          | Lab: full heap exploit on a CTF binary                   |
| 548  | `04-Advanced-01/DAY-0548-Kernel-Exploitation-Introduction.md`               | Ring 0 vs Ring 3, kernel modules, CTF kernel pwn setup   |
| 549  | `04-Advanced-01/DAY-0549-ret2usr-Attack.md`                                 | SMEP/SMAP, ret2usr vs kernel ROP                         |
| 550  | `04-Advanced-01/DAY-0550-Kernel-Exploit-Lab.md`                             | Lab: LPE via kernel module vulnerability in CTF VM       |
| 551  | `04-Advanced-01/DAY-0551-A01-Competency-Check.md`                           | Lab: exploit a heap UAF CTF binary from scratch          |

---

#### 04-Advanced-02 — Reverse Engineering (Days 552–575)

**Lab:** Reverse a crackme and a simple packer

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 552  | `04-Advanced-02/DAY-0552-Reverse-Engineering-Mindset.md`                    | Goal: understand behaviour without source code           |
| 553  | `04-Advanced-02/DAY-0553-Ghidra-Advanced.md`                                | Custom data types, struct overlay, P-Code analysis       |
| 554  | `04-Advanced-02/DAY-0554-IDA-Free-Basics.md`                                | IDA Pro Free, graph view, pseudocode, FLIRT signatures   |
| 555  | `04-Advanced-02/DAY-0555-GDB-and-PWNDBG-Advanced.md`                        | Scripting GDB with Python, conditional breakpoints       |
| 556  | `04-Advanced-02/DAY-0556-Crackme-Lab-Episode-1.md`                          | Lab: static reverse a Linux crackme, find the key       |
| 557  | `04-Advanced-02/DAY-0557-Crackme-Lab-Episode-2.md`                          | Lab: dynamic reverse a Windows crackme under x64dbg     |
| 558  | `04-Advanced-02/DAY-0558-Anti-Reversing-Techniques.md`                      | Anti-debug, anti-VM, junk code, opaque predicates        |
| 559  | `04-Advanced-02/DAY-0559-Defeating-Anti-Reversing.md`                       | Scripted de-obfuscation, NOP patching, ScyllaHide        |
| 560  | `04-Advanced-02/DAY-0560-Packer-Analysis.md`                                | Packer detection, OEP hunting, manual unpacking          |
| 561  | `04-Advanced-02/DAY-0561-Packer-Lab.md`                                     | Lab: unpack a custom packer, recover original binary     |
| 562  | `04-Advanced-02/DAY-0562-Protocol-Reversing.md`                             | Reversing a custom binary protocol from a sample         |
| 563  | `04-Advanced-02/DAY-0563-A02-Competency-Check.md`                           | Lab: crack a keygen crackme and document the algorithm   |

---

#### 04-Advanced-03 — Hardware and Embedded Security (Days 564–580)

**Lab:** Extract firmware via UART from a dev board

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 564  | `04-Advanced-03/DAY-0564-Embedded-Systems-Overview.md`                      | MCU vs SoC, firmware types, boot process                 |
| 565  | `04-Advanced-03/DAY-0565-UART-Interface.md`                                 | UART protocol, baud rate, finding TX/RX on a board       |
| 566  | `04-Advanced-03/DAY-0566-UART-Lab.md`                                       | Lab: connect to a dev board via UART, get a shell        |
| 567  | `04-Advanced-03/DAY-0567-JTAG-and-SWD.md`                                   | JTAG TAP, debug access, OpenOCD                          |
| 568  | `04-Advanced-03/DAY-0568-Firmware-Extraction-Methods.md`                    | UART, JTAG, SPI flash dump, binwalk analysis             |
| 569  | `04-Advanced-03/DAY-0569-Firmware-Analysis.md`                              | binwalk, firmware-mod-kit, squashfs extraction           |
| 570  | `04-Advanced-03/DAY-0570-Firmware-Analysis-Lab.md`                          | Lab: extract and analyse a router firmware image         |
| 571  | `04-Advanced-03/DAY-0571-Side-Channel-Introduction.md`                      | Power analysis, timing attacks, cache side-channels      |
| 572  | `04-Advanced-03/DAY-0572-Fault-Injection-Concepts.md`                       | Voltage glitching, clock glitching, bypass secure boot   |
| 573  | `04-Advanced-03/DAY-0573-Embedded-Hardening.md`                             | Secure boot, JTAG fusing, encrypted firmware             |
| 574  | `04-Advanced-03/DAY-0574-A03-Competency-Check.md`                           | Lab: extract and document firmware from a target board   |

---

#### 04-Advanced-04 — Mobile Security (Days 575–595)

**Lab:** Bypass certificate pinning on an Android app

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 575  | `04-Advanced-04/DAY-0575-Android-Security-Model.md`                         | App sandbox, permissions, SELinux, intent model          |
| 576  | `04-Advanced-04/DAY-0576-APK-Analysis-Static.md`                            | apktool, jadx, AndroidManifest.xml, exported components  |
| 577  | `04-Advanced-04/DAY-0577-APK-Analysis-Lab.md`                               | Lab: static analysis of a target APK, find hardcoded keys|
| 578  | `04-Advanced-04/DAY-0578-Dynamic-Analysis-Android.md`                       | Frida, objection, logcat, Burp with Android emulator     |
| 579  | `04-Advanced-04/DAY-0579-Certificate-Pinning.md`                            | Pinning implementations: OkHttp, TrustKit, custom        |
| 580  | `04-Advanced-04/DAY-0580-Certificate-Pinning-Bypass-Lab.md`                 | Lab: bypass pinning using Frida and objection             |
| 581  | `04-Advanced-04/DAY-0581-Android-Intent-Attacks.md`                         | Exported activity, deeplink abuse, intent injection      |
| 582  | `04-Advanced-04/DAY-0582-iOS-Security-Model.md`                             | App sandbox, entitlements, Secure Enclave, JB detection  |
| 583  | `04-Advanced-04/DAY-0583-iOS-App-Analysis.md`                               | class-dump, Hopper, Frida on iOS, SSL Kill Switch         |
| 584  | `04-Advanced-04/DAY-0584-Mobile-App-Hardening.md`                           | Root/JB detection, obfuscation, secure storage           |
| 585  | `04-Advanced-04/DAY-0585-A04-Competency-Check.md`                           | Lab: full Android app analysis + pinning bypass report   |

---

#### 04-Advanced-05 — Red Team Operations (Days 586–615)

**Lab:** Multi-stage engagement against a lab environment

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 586  | `04-Advanced-05/DAY-0586-Red-Team-vs-Pentest.md`                            | Objectives, rules of engagement, threat emulation        |
| 587  | `04-Advanced-05/DAY-0587-Red-Team-Infrastructure.md`                        | Redirectors, C2 resilience, domain fronting              |
| 588  | `04-Advanced-05/DAY-0588-C2-Framework-Deep-Dive.md`                         | Cobalt Strike concepts, Sliver, Havoc — malleable comms  |
| 589  | `04-Advanced-05/DAY-0589-EDR-Evasion-Techniques.md`                         | AMSI bypass, ETW patching, process injection variants    |
| 590  | `04-Advanced-05/DAY-0590-AV-Bypass-Techniques.md`                           | Signature evasion, entropy reduction, LLVM obfuscation   |
| 591  | `04-Advanced-05/DAY-0591-Evasion-Lab-Episode-1.md`                          | Lab: bypass Defender with a custom shellcode loader      |
| 592  | `04-Advanced-05/DAY-0592-Evasion-Lab-Episode-2.md`                          | Lab: bypass EDR with process injection technique         |
| 593  | `04-Advanced-05/DAY-0593-Full-Kill-Chain-Lab-Day-1.md`                      | Lab: initial access + establish C2                       |
| 594  | `04-Advanced-05/DAY-0594-Full-Kill-Chain-Lab-Day-2.md`                      | Lab: escalation + lateral movement                       |
| 595  | `04-Advanced-05/DAY-0595-Full-Kill-Chain-Lab-Day-3.md`                      | Lab: persistence + exfiltration without triggering EDR   |
| 596  | `04-Advanced-05/DAY-0596-Red-Team-Report-Writing.md`                        | Red team report structure, finding narratives, impact    |
| 597  | `04-Advanced-05/DAY-0597-A05-Competency-Check.md`                           | Red team report submission for the full kill-chain lab   |

---

#### 04-Advanced-06 — Vulnerability Research (Days 598–625)

**Lab:** Reproduce a real CVE from the patch diff alone

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 598  | `04-Advanced-06/DAY-0598-Vulnerability-Research-Process.md`                 | Target selection, code audit workflow, fuzzing pipeline  |
| 599  | `04-Advanced-06/DAY-0599-Source-Code-Auditing-Techniques.md`                | Grep for sinks, taint analysis, semantic analysis        |
| 600  | `04-Advanced-06/DAY-0600-Code-Audit-Lab-Episode-1.md`                       | Lab: audit a small C project, find a memory corruption   |
| 601  | `04-Advanced-06/DAY-0601-Code-Audit-Lab-Episode-2.md`                       | Lab: audit a Python web app, find injection flaws        |
| 602  | `04-Advanced-06/DAY-0602-Fuzzing-Fundamentals.md`                           | Mutation vs generation fuzzing, coverage-guided          |
| 603  | `04-Advanced-06/DAY-0603-AFL-and-LibFuzzer.md`                              | AFL++ setup, harness writing, corpus, crash triage       |
| 604  | `04-Advanced-06/DAY-0604-Fuzzing-Lab.md`                                    | Lab: fuzz a binary parser, find and triage crashes       |
| 605  | `04-Advanced-06/DAY-0605-Patch-Diffing.md`                                  | BinDiff, diaphora, patch diff to find fixed vuln         |
| 606  | `04-Advanced-06/DAY-0606-CVE-Reproduction-Lab.md`                           | Lab: reproduce a CVE from the patch diff — no writeup    |
| 607  | `04-Advanced-06/DAY-0607-Responsible-Disclosure.md`                         | Coordinated disclosure, CNA process, CVE assignment      |
| 608  | `04-Advanced-06/DAY-0608-Writing-a-Bug-Bounty-Report.md`                    | Report quality, CVSS scoring, PoC requirements           |
| 609  | `04-Advanced-06/DAY-0609-A06-Competency-Check.md`                           | Submit a CVE reproduction with full technical write-up   |

---

#### 04-Advanced-07 — Cryptographic Attacks (Days 610–630)

**Lab:** Exploit a CBC padding oracle and extract plaintext

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 610  | `04-Advanced-07/DAY-0610-Padding-Oracle-Theory.md`                          | CBC decryption, PKCS#7, oracle concept                   |
| 611  | `04-Advanced-07/DAY-0611-Padding-Oracle-Lab.md`                             | Lab: exploit a padding oracle, decrypt ciphertext        |
| 612  | `04-Advanced-07/DAY-0612-Timing-Attacks.md`                                 | String comparison timing, remote timing, cache timing    |
| 613  | `04-Advanced-07/DAY-0613-Timing-Attack-Lab.md`                              | Lab: remote timing attack on a MAC comparison            |
| 614  | `04-Advanced-07/DAY-0614-Length-Extension-Attack.md`                        | SHA-2 Merkle–Damgård extension, forging signatures       |
| 615  | `04-Advanced-07/DAY-0615-Length-Extension-Lab.md`                           | Lab: forge a HMAC-MD5 token via length extension         |
| 616  | `04-Advanced-07/DAY-0616-Elliptic-Curve-Weaknesses.md`                      | Invalid curve attacks, biased nonce ECDSA, Pohlig-Hellman|
| 617  | `04-Advanced-07/DAY-0617-ECDSA-Nonce-Reuse.md`                              | Nonce reuse → private key recovery                       |
| 618  | `04-Advanced-07/DAY-0618-ECDSA-Nonce-Lab.md`                                | Lab: recover private key from two signatures with same k |
| 619  | `04-Advanced-07/DAY-0619-RSA-Advanced-Attacks.md`                           | Wiener's attack, Coppersmith's theorem, partial key exp  |
| 620  | `04-Advanced-07/DAY-0620-Modern-Crypto-Pitfalls.md`                         | Galois/Counter Mode nonce reuse, AES-GCM forgery         |
| 621  | `04-Advanced-07/DAY-0621-A07-Competency-Check.md`                           | Lab: solve a multi-step crypto CTF challenge             |

---

#### 04-Advanced-08 — Zero-Day Mindset (Days 622–700)

**Lab:** Audit a small open-source project; report findings

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 622  | `04-Advanced-08/DAY-0622-Zero-Day-Mindset.md`                               | Attacker-researcher mindset, target selection framework  |
| 623  | `04-Advanced-08/DAY-0623-Automated-Fuzzing-Pipeline.md`                     | CI fuzzing, OSS-Fuzz, ClusterFuzz, crash deduplication   |
| 624  | `04-Advanced-08/DAY-0624-Source-Audit-Advanced.md`                          | Data flow analysis, CodeQL basics, Semgrep rules         |
| 625  | `04-Advanced-08/DAY-0625-CodeQL-Lab.md`                                     | Lab: write a CodeQL query to find SQL injection patterns |
| 626  | `04-Advanced-08/DAY-0626-Semgrep-Lab.md`                                    | Lab: write Semgrep rules for a Python codebase           |
| 627  | `04-Advanced-08/DAY-0627-Browser-Security-Research.md`                      | Renderer vs browser process, JIT bugs, IPC              |
| 628  | `04-Advanced-08/DAY-0628-Open-Source-Audit-Lab-Day-1.md`                    | Lab: select and begin auditing a real open-source project|
| 629  | `04-Advanced-08/DAY-0629-Open-Source-Audit-Lab-Day-2.md`                    | Lab: continue audit, document findings                   |
| 630  | `04-Advanced-08/DAY-0630-Open-Source-Audit-Lab-Day-3.md`                    | Lab: write up findings, draft disclosure report          |
| 631  | `04-Advanced-08/DAY-0631-Responsible-Disclosure-Practice.md`                | Draft and send a disclosure to the project maintainer    |
| 632–699 | `04-Advanced-08/DAY-06XX-Ghost-Level-Preparation.md` (×68 days)         | Independent research, CTF competitions, bug bounty       |
| 700  | `04-Advanced-08/DAY-0700-A08-Competency-Check.md`                           | Audit report submission + disclosure documentation       |

---

### Final Gate Preparation (Days 701–730)

| Day  | File                                                               | Topic                                                    |
|------|--------------------------------------------------------------------|----------------------------------------------------------|
| 701  | `FINAL/DAY-0701-Programme-Review-Episode-1.md`                    | Review Foundation and Red Cell                           |
| 702  | `FINAL/DAY-0702-Programme-Review-Episode-2.md`                    | Review Blue Cell and Advanced                            |
| 703  | `FINAL/DAY-0703-Ghost-Level-Prep-Day-1.md`                        | Unknown target warm-up — scoped lab                      |
| 704  | `FINAL/DAY-0704-Ghost-Level-Prep-Day-2.md`                        | Exploit development under time pressure                  |
| 705  | `FINAL/DAY-0705-Ghost-Level-Prep-Day-3.md`                        | Full recon + exploitation + reporting sprint             |
| 706–727 | `FINAL/DAY-07XX-Solo-Research-and-Practice.md` (×22 days)     | Student-directed deep dive into weakest area             |
| 728  | `FINAL/DAY-0728-Final-Review.md`                                  | Final review session with Ghost                          |
| 729  | `FINAL/DAY-0729-Ghost-Level-Gate-Briefing.md`                     | Rules, scope, target briefing for the 48-hour challenge  |
| 730  | `FINAL/DAY-0730-Ghost-Level-Competency-Gate.md`                   | **GATE: Ghost Level** — 48-hour solo unknown target     |

---

## Directory Structure

```
learn-security/
├── SYLLABUS.md
├── knowledge-base/               # Prerequisite knowledge articles
├── samples/                      # Code samples linked from lessons
├── F-01/                         # How the Internet Works
├── F-02/                         # Linux Fundamentals
├── F-03/                         # Networking for Attackers
├── F-04/                         # Cryptography Essentials
├── F-05/                         # Web Architecture
├── F-06/                         # Authentication and Authorisation
├── R-01/                         # Reconnaissance
├── R-02/                         # Web Exploitation
├── R-03/                         # Authentication Attacks
├── R-04/                         # API Security
├── R-05/                         # Network Exploitation
├── R-06/                         # Privilege Escalation
├── R-07/                         # Post-Exploitation
├── R-08/                         # Exploit Development
├── R-09/                         # Cloud Exploitation
├── R-10/                         # Social Engineering
├── R-GATE/                       # Red Cell Competency Gate
├── B-01/                         # Security Monitoring
├── B-02/                         # Threat Hunting
├── B-03/                         # Intrusion Detection
├── B-04/                         # Endpoint Detection
├── B-05/                         # Digital Forensics
├── B-06/                         # Incident Response
├── B-07/                         # Malware Analysis
├── B-08/                         # Secure Architecture Review
├── B-09/                         # Deception and Honeypots
├── B-10/                         # Purple Team Operations
├── B-GATE/                       # Blue Cell Competency Gate
├── A-01/                         # Binary Exploitation Advanced
├── A-02/                         # Reverse Engineering
├── A-03/                         # Hardware and Embedded
├── A-04/                         # Mobile Security
├── A-05/                         # Red Team Operations
├── A-06/                         # Vulnerability Research
├── A-07/                         # Cryptographic Attacks
├── A-08/                         # Zero-Day Mindset
└── FINAL/                        # Ghost Level Gate
```

---

## Quick Reference — Module to Day Mapping

| Track | Module | Days | Gate |
|-------|--------|------|------|
| Foundation | F-01 Internet | 1–20 | |
| Foundation | F-02 Linux | 21–40 | |
| Foundation | F-03 Networking | 41–60 | |
| Foundation | F-04 Cryptography | 61–80 | |
| Foundation | F-05 Web Architecture | 81–100 | |
| Foundation | F-06 Auth | 101–120 | **Day 120: Foundation Gate** |
| Red Cell | R-01 Recon | 121–140 | |
| Red Cell | R-02 Web Exploitation | 141–175 | |
| Red Cell | R-03 Auth Attacks | 176–190 | |
| Red Cell | R-04 API Security | 191–205 | |
| Red Cell | R-05 Network Exploitation | 206–220 | |
| Red Cell | R-06 Privilege Escalation | 221–240 | |
| Red Cell | R-07 Post-Exploitation | 241–257 | |
| Red Cell | R-08 Exploit Development | 258–277 | |
| Red Cell | R-09 Cloud Exploitation | 278–294 | |
| Red Cell | R-10 Social Engineering | 295–308 | |
| Red Cell Gate | — | 309–360 | **Day 360: Red Cell Gate** |
| Blue Cell | B-01 SIEM | 361–375 | |
| Blue Cell | B-02 Threat Hunting | 376–390 | |
| Blue Cell | B-03 Intrusion Detection | 391–403 | |
| Blue Cell | B-04 Endpoint Detection | 404–416 | |
| Blue Cell | B-05 Digital Forensics | 417–430 | |
| Blue Cell | B-06 Incident Response | 431–441 | |
| Blue Cell | B-07 Malware Analysis | 442–456 | |
| Blue Cell | B-08 Secure Architecture | 457–468 | |
| Blue Cell | B-09 Deception | 469–479 | |
| Blue Cell | B-10 Purple Team | 480–491 | |
| Blue Cell Gate | — | 492–540 | **Day 540: Blue Cell Gate** |
| Advanced | A-01 Heap/Kernel Exploitation | 541–551 | |
| Advanced | A-02 Reverse Engineering | 552–563 | |
| Advanced | A-03 Hardware/Embedded | 564–574 | |
| Advanced | A-04 Mobile Security | 575–585 | |
| Advanced | A-05 Red Team Operations | 586–597 | |
| Advanced | A-06 Vulnerability Research | 598–609 | |
| Advanced | A-07 Cryptographic Attacks | 610–621 | |
| Advanced | A-08 Zero-Day Mindset | 622–700 | |
| Final Gate | — | 701–730 | **Day 730: Ghost Level Gate** |

---

> "Every system you learn to break is a system some defender worked hard to build.
> Respect that. Then break it anyway — so the next version is harder.
> That is the job."
>
> — Ghost
