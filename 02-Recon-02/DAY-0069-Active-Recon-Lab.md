---
title: "Active Recon Lab — Full Active Recon Pipeline on a Lab Target"
tags: [lab, active-recon, nmap, masscan, ffuf, whatweb, JS-analysis, parameter-discovery,
       recon-pipeline, bug-bounty, hands-on, T1046, T1595]
module: 02-Recon-02
day: 69
related_topics:
  - nmap from First Principles (Day 063)
  - nmap Service Detection NSE and Evasion (Day 064)
  - Directory and Endpoint Fuzzing (Day 065)
  - Parameter Discovery and JS Analysis (Day 066)
  - Web App Fingerprinting and Tech Stack (Day 067)
  - Masscan and Fast Network Scanning (Day 068)
  - Passive Recon Lab (Day 060)
---

# Day 069 — Active Recon Lab

## Goals

By the end of this lab you will have:

1. Executed a complete active recon pipeline against a multi-service lab target.
2. Combined all tools from Days 063–068 into a coherent methodology.
3. Produced a structured enumeration document covering: open ports, services,
   web endpoints, parameters, tech stack, and identified attack surface.
4. Identified at least one non-obvious finding that passive recon alone would
   have missed.

---

## Prerequisites

- [Day 063 — nmap from First Principles](DAY-0063-nmap-from-First-Principles.md)
- [Day 064 — nmap Service Detection, NSE and Evasion](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md)
- [Day 065 — Directory and Endpoint Fuzzing](DAY-0065-Directory-and-Endpoint-Fuzzing.md)
- [Day 066 — Parameter Discovery and JS Analysis](DAY-0066-Parameter-Discovery-and-JS-Analysis.md)
- [Day 067 — Web App Fingerprinting and Tech Stack](DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md)
- [Day 068 — Masscan and Fast Network Scanning](DAY-0068-Masscan-and-Fast-Network-Scanning.md)

---

## Lab Environment

### Option A — Local Docker Lab (Recommended)

This docker-compose stack runs a multi-service target that is realistic and
controllable. Every finding you make is genuine.

```yaml
# docker-compose.yml
# Save as: ~/labs/active-recon-lab/docker-compose.yml

version: "3.8"

services:
  web:
    image: vulnerables/web-dvwa
    container_name: recon_web
    ports:
      - "80:80"
    networks:
      lab_net:
        ipv4_address: 172.20.0.10

  api:
    image: node:18-alpine
    container_name: recon_api
    working_dir: /app
    volumes:
      - ./api:/app
    command: sh -c "npm install && node server.js"
    ports:
      - "3000:3000"
    networks:
      lab_net:
        ipv4_address: 172.20.0.11

  db:
    image: mysql:8.0
    container_name: recon_db
    environment:
      MYSQL_ROOT_PASSWORD: "rootpass123"
      MYSQL_DATABASE: "appdb"
    ports:
      - "3306:3306"
    networks:
      lab_net:
        ipv4_address: 172.20.0.12

  admin:
    image: phpmyadmin/phpmyadmin
    container_name: recon_admin
    environment:
      PMA_HOST: recon_db
      PMA_PORT: 3306
    ports:
      - "8080:80"
    networks:
      lab_net:
        ipv4_address: 172.20.0.13

networks:
  lab_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

```bash
# Start the lab
cd ~/labs/active-recon-lab
mkdir -p api

# Create a minimal vulnerable Node.js API
cat > api/server.js << 'EOF'
const express = require('express');
const app = express();
app.use(express.json());

// Exposed "internal" endpoint not visible from the main site
app.get('/api/v1/users', (req, res) => {
  const users = [{id:1,name:"alice",role:"admin"},{id:2,name:"bob",role:"user"}];
  res.json(users);
});
app.get('/api/v2/debug', (req, res) => {
  res.json({status:"ok",env:process.env,version:"2.1.0-dev"});
});
app.get('/api/v1/flag', (req, res) => {
  if(req.query.token === 'supersecret') {
    res.json({flag:"FLAG{active_recon_parameter_discovery}"});
  } else {
    res.status(403).json({error:"forbidden"});
  }
});
app.listen(3000);
console.log("API running on :3000");
EOF

cat > api/package.json << 'EOF'
{"name":"api","version":"1.0.0","dependencies":{"express":"^4.18.0"}}
EOF

docker compose up -d
```

### Option B — HackTheBox / TryHackMe

Use a machine rated Easy on HackTheBox (e.g., **Lame**, **Blue**, **Legacy**)
or TryHackMe's "Active Recon" room as your target. The lab steps below apply
to either environment.

---

## Lab Instructions

### Phase 0 — Setup (15 minutes)

```bash
# Create output directory
TARGET="172.20.0.10"      # or your HTB machine IP
OUTDIR="~/labs/recon_lab_$(date +%Y%m%d)"
mkdir -p "$OUTDIR"/{nmap,masscan,ffuf,js,params,fingerprint}
cd "$OUTDIR"

# Define scope
echo "$TARGET" > scope.txt
echo "Scope confirmed: $TARGET"
echo "Lab start time: $(date)"
```

---

### Phase 1 — Network Scanning (20 minutes)

```bash
# 1.1 Fast masscan — all ports
echo "[*] Phase 1.1: masscan full port sweep"
sudo masscan "$TARGET" -p 0-65535 --rate 1000 \
     -oJ masscan/full_ports.json

# 1.2 Parse open ports
OPEN_PORTS=$(python3 -c "
import json
with open('masscan/full_ports.json') as f:
    data = json.load(f)
ports = set()
for e in data:
    for p in e.get('ports',[]):
        ports.add(str(p['port']))
print(','.join(sorted(ports, key=int)))
")
echo "[+] Open ports: $OPEN_PORTS"
echo "$OPEN_PORTS" > masscan/open_ports.txt

# 1.3 Deep nmap on open ports
echo "[*] Phase 1.3: nmap deep scan"
sudo nmap -sS -sV -sC \
     -p "$OPEN_PORTS" \
     --open \
     -oA nmap/deep_scan \
     "$TARGET"

# 1.4 Targeted NSE for web ports
WEB_PORTS=$(echo "$OPEN_PORTS" | tr ',' '\n' | \
            grep -E "^(80|443|8080|8443|8000|3000|5000)$" | \
            tr '\n' ',' | sed 's/,$//')
if [ -n "$WEB_PORTS" ]; then
    echo "[*] Phase 1.4: web NSE scripts on $WEB_PORTS"
    sudo nmap --script="http-title,http-methods,http-robots.txt,ssl-cert,http-waf-detect" \
         -p "$WEB_PORTS" \
         -oA nmap/web_scripts \
         "$TARGET"
fi
```

**Checkpoint questions after Phase 1:**

1. How many ports are open?
2. Are any unusual/non-standard ports open?
3. What services are running? Did nmap confirm the service or just guess?

---

### Phase 2 — Fingerprinting (15 minutes)

```bash
# 2.1 whatweb fingerprinting for each web port
echo "[*] Phase 2.1: whatweb fingerprinting"
for PORT in $(echo "$WEB_PORTS" | tr ',' '\n'); do
    PROTO="http"
    [ "$PORT" == "443" ] || [ "$PORT" == "8443" ] && PROTO="https"
    URL="${PROTO}://${TARGET}:${PORT}"
    echo "Fingerprinting $URL"
    whatweb -v -a 3 "$URL" >> fingerprint/whatweb_all.txt 2>&1
done

# 2.2 Header analysis
echo "[*] Phase 2.2: header analysis"
for PORT in $(echo "$WEB_PORTS" | tr ',' '\n'); do
    PROTO="http"
    [ "$PORT" == "443" ] || [ "$PORT" == "8443" ] && PROTO="https"
    echo "=== ${PROTO}://${TARGET}:${PORT} ===" >> fingerprint/headers.txt
    curl -sIL "${PROTO}://${TARGET}:${PORT}" >> fingerprint/headers.txt
    echo "" >> fingerprint/headers.txt
done

# 2.3 Error page probing
echo "[*] Phase 2.3: error page probing"
curl -s "http://${TARGET}/does_not_exist_xyz_12345" > fingerprint/404_page.html
curl -s "http://${TARGET}/api?id='" > fingerprint/sqli_error.html
```

**Checkpoint questions after Phase 2:**

1. What technology stack is running?
2. What version of each component is identified?
3. Are any versions known to be vulnerable? (Check searchsploit)

---

### Phase 3 — Content Discovery (25 minutes)

```bash
# 3.1 Quick directory fuzz on port 80
echo "[*] Phase 3.1: quick directory fuzz (port 80)"
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u "http://${TARGET}/FUZZ" \
     -mc 200,301,302,403 \
     -fc 404 \
     -o ffuf/port80_quick.json -of json \
     -rate 50

# 3.2 Medium fuzz with extensions
echo "[*] Phase 3.2: medium fuzz with PHP extensions"
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u "http://${TARGET}/FUZZ" \
     -e .php,.html,.txt,.bak,.xml,.json,.old \
     -mc 200,301,302,403 \
     -fc 404 \
     -o ffuf/port80_medium.json -of json \
     -rate 50

# 3.3 Fuzz other web ports discovered in Phase 1
for PORT in $(echo "$WEB_PORTS" | tr ',' '\n' | grep -v "^80$"); do
    PROTO="http"
    [ "$PORT" == "443" ] && PROTO="https"
    echo "[*] Fuzzing ${PROTO}://${TARGET}:${PORT}/"
    ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
         -u "${PROTO}://${TARGET}:${PORT}/FUZZ" \
         -mc 200,301,302,403 \
         -fc 404 \
         -o "ffuf/port${PORT}_quick.json" -of json \
         -rate 50
done

# 3.4 API path fuzzing (if API port found)
if echo "$WEB_PORTS" | grep -q "3000"; then
    echo "[*] Phase 3.4: API fuzzing on port 3000"
    ffuf -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
         -u "http://${TARGET}:3000/FUZZ" \
         -mc 200,201,400,401,403 \
         -fc 404 \
         -o ffuf/port3000_api.json -of json \
         -rate 50
fi
```

**Checkpoint questions after Phase 3:**

1. Which endpoints returned 200? Which returned 403 (forbidden but existing)?
2. Are there any backup files or configuration files exposed?
3. Did you find any admin panels or debug endpoints?

---

### Phase 4 — JS Analysis and Parameter Discovery (20 minutes)

```bash
# 4.1 Harvest JS files
echo "[*] Phase 4.1: JS file discovery"
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u "http://${TARGET}/FUZZ.js" \
     -mc 200 \
     -o js/js_files.json -of json \
     -rate 50

# Download discovered JS files
python3 - << 'EOF'
import json
with open('js/js_files.json') as f:
    data = json.load(f)
for r in data.get('results', []):
    print(r['url'])
EOF | while read url; do
    fname="js/$(basename $url)"
    curl -s "$url" -o "$fname"
    echo "Downloaded: $fname"
done

# 4.2 Beautify and extract endpoints
for jsfile in js/*.js; do
    [ -f "$jsfile" ] || continue
    echo "[*] LinkFinder: $jsfile"
    python3 /opt/LinkFinder/linkfinder.py -i "$jsfile" -o cli 2>/dev/null
done | sort -u > js/endpoints_extracted.txt

# 4.3 Parameter discovery
echo "[*] Phase 4.3: arjun parameter discovery"
# Run against each discovered endpoint
while IFS= read -r endpoint; do
    full_url="http://${TARGET}${endpoint}"
    arjun -u "$full_url" -oJ "params/arjun_$(echo $endpoint | tr / _).json" 2>/dev/null
done < <(grep "^/" js/endpoints_extracted.txt | head -20)

# 4.4 paramspider (historical URLs)
echo "[*] Phase 4.4: paramspider"
# paramspider -d "$TARGET" -o params/paramspider.txt 2>/dev/null
# (For a local lab IP, skip paramspider — it queries the internet)
```

---

### Phase 5 — Compile Findings (15 minutes)

```bash
# Generate enumeration report
cat > "${OUTDIR}/ENUMERATION_REPORT.md" << REPORT
# Active Recon Enumeration Report

**Target:** $TARGET
**Date:** $(date)
**Tester:** [Your name]

---

## Open Ports and Services

\`\`\`
$(grep "open" nmap/deep_scan.gnmap | awk '{print $2, $NF}')
\`\`\`

## Technology Stack

\`\`\`
$(grep -E "Server:|X-Powered-By:|MetaGenerator:|WordPress:|PHP:|nginx:" fingerprint/whatweb_all.txt | sort -u)
\`\`\`

## Web Endpoints (200/403)

\`\`\`
$(cat ffuf/*.json | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        data = json.loads(line)
        for r in data.get('results', []):
            print(r['status'], r['url'])
    except:
        pass
" | sort)
\`\`\`

## JS-Extracted Endpoints

\`\`\`
$(cat js/endpoints_extracted.txt)
\`\`\`

## Interesting Findings

*(Fill this in manually after reviewing above)*

1.
2.
3.

## Attack Surface Notes

*(What would you test first? Why?)*

REPORT

echo "[+] Report saved to ENUMERATION_REPORT.md"
```

---

## Debrief

After completing the lab, answer these questions before moving on:

### Technical Questions

1. **Port 3306 (MySQL) was open. What is the risk?** What would an attacker
   do with a directly accessible MySQL instance?

2. **phpMyAdmin was on port 8080.** What are the default credentials? What
   is the typical attack path if default credentials are not changed?

3. **The API on port 3000 had a `/api/v2/debug` endpoint.** What sensitive
   information did it expose? What is the CVSS score for this finding?

4. **The arjun scan found a `token` parameter on `/api/v1/flag`.** How would
   you approach finding the correct token value without knowing it in advance?

5. **You found `/api/v2/debug` exposing `process.env`.** What should you look
   for in that response that would escalate this to a Critical finding?

### Methodology Questions

6. **Put the phases in order of information dependency.** Why do you need
   Phase 1 before Phase 3? Why does Phase 4 depend on Phase 3?

7. **You found 12 open endpoints during fuzzing. How do you decide which to
   investigate first?** What criteria do you use?

8. **The lab took about 90 minutes.** In a real bug bounty context, how would
   you time-box each phase? What is the most valuable phase to maximise?

---

## Clean Up

```bash
# Stop and remove lab containers
cd ~/labs/active-recon-lab
docker compose down -v
docker system prune -f

echo "[*] Lab cleaned up"
```

---

## Key Takeaways

1. **Recon is sequential for a reason.** Each phase's output feeds the next.
   You cannot fuzz endpoints you have not found; you cannot find parameters
   on endpoints you have not fuzzed.
2. **The most valuable findings are often on non-standard ports.** phpMyAdmin
   on 8080, Redis on 6379, the Node API on 3000 — these are exposed attack
   surface that a generic scan misses.
3. **JS analysis regularly finds what no other technique does.** The `token`
   parameter on `/api/v1/flag` is not in any wordlist. It was only findable
   through code analysis.
4. **Documentation is part of the work.** An enumeration document produced
   during recon becomes your attack plan. Every finding with no context attached
   to it is wasted effort.
5. **Active recon creates log entries.** Every SYN packet, every HTTP request,
   every JS download is recorded somewhere. Know this. It matters when you are
   working on real programmes.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 068 — Masscan and Fast Network Scanning](DAY-0068-Masscan-and-Fast-Network-Scanning.md)*
*Next: [Day 070 — Recon Automation Pipeline](DAY-0070-Recon-Automation-Pipeline.md)*
