# Active Directory Attack Skill

Attack an Active Directory domain by routing from verified prerequisites: no credentials, a valid domain user, local administrator, or replication rights. Re-evaluate paths after each identity gain.

## When to Classify Here

Use this skill when the objective is a domain privilege boundary or an AD attack chain, rather than elevation on one host:

- "Assess <DOMAIN> from our current network access without credentials."
- "We have a domain user; prioritize Kerberoasting, BloodHound and AD-CS."
- "Use verified local admin on <TARGET> to assess a path into the domain."
- "Check whether this principal can DCSync and validate the authorized domain objective."

Keywords (specific to this workflow): Active Directory domain attack, domain attack chain, AS-REP prerequisite routing, domain-user Kerberoast, BloodHound path to DA, AD-CS enrollment path, replication-rights validation, local-admin to domain pivot.

### Disjoint from neighbouring skills

- vs. [local_privilege_escalation](local_privilege_escalation.md) (community): same-host Linux root or Windows SYSTEM from an existing shell belongs there. Stay here when directory identities, domain ACLs, Kerberos or certificate services define the objective.
- vs. `brute_force_credential_guess` (built-in): a standalone password attack belongs there. This skill routes domain-specific ticket acquisition and the associated offline analysis to the existing references; it does not introduce password spray as an automatic fallback.
- vs. `cve_exploit` (built-in): exploitation of a named CVE as the primary request belongs there. Directory misconfiguration and prerequisite-driven chain selection belong here.
- vs. `rce` (built-in): obtaining the initial execution foothold belongs there. Domain access may instead be provided by an already reachable network path; do not promise a pivot that does not exist.
- vs. capture/relay work: LLMNR poisoning, NTLM capture, coercion and NTLM relay are outside this workflow. Their feasibility depends on network placement, inbound reachability and protocol prerequisites (issue #46). Do not start a listener or treat a relay opportunity as a working path.

## Tools and Reference Routing

Use `query_graph` to reuse project recon, `kali_shell` for the documented sandbox AD utilities and `metasploit_console` only to inspect an existing foothold when relevant. Serialize console calls and keep target-session identity separate from sandbox identity.

| Verified prerequisite | Load existing reference | Sandbox utilities for that route |
|---|---|---|
| Reachable domain services; no credential | [AD Kill Chain](../skills/active_directory/ad_kill_chain.md), `/skill ad_kill_chain`, anonymous enumeration sections; [Kerberoasting](../skills/active_directory/kerberoasting.md), `/skill kerberoasting`, ASREPRoast section | NetExec (`nxc`), `impacket-GetNPUsers` |
| Valid domain credential | [Kerberoasting](../skills/active_directory/kerberoasting.md), credentialed branch | `impacket-GetUserSPNs` |
| Valid domain credential and collection permitted | [BloodHound Path to DA](../skills/active_directory/bloodhound_path_to_da.md), `/skill bloodhound_path_to_da` | `bloodhound-python`, `bhgraph` |
| Valid domain credential and reachable CA/directory | [AD-CS ESC](../skills/active_directory/ad_cs_esc.md), `/skill ad_cs_esc`, discovery and applicable non-relay certificate path | `certipy-ad` |
| Verified local admin on an in-scope host | [AD Kill Chain](../skills/active_directory/ad_kill_chain.md), local-admin credential-access section | Impacket `impacket-secretsdump`, NetExec (`nxc`) |
| Verified effective replication rights on the domain | [AD Kill Chain](../skills/active_directory/ad_kill_chain.md), DCSync section | `bhgraph` for candidate analysis; `impacket-secretsdump` for an authorized bounded proof |

These references hold the commands and technical recipes; load the selected section instead of duplicating or running the full chain. Repository links are reference locations, not paths on a target. Apply this workflow's boundaries when a reference discusses broader actions: capture/relay and persistence remain excluded here.

Rubeus and Mimikatz are not promised as prepackaged Windows binaries. This workflow uses the documented sandbox utilities above; it does not require uploading those Windows toolkits. A reference mentioning another utility does not establish its availability: check the current toolbox and installed image before using it.

## Workflow

### Phase 1: Establish Domain Context and Prerequisites (Informational)

1. **Reuse recon before probing.** Ask `query_graph` for the in-scope <DOMAIN>, DC candidates, domain service exposure and existing foothold evidence. Treat stored recon as a lead, not proof of current reachability. Confirm DNS/domain naming, time alignment for Kerberos, and the relevant service path from the actual sandbox or established foothold. An open SMB port alone does not prove the host is a DC.
2. **Inventory access accurately.** Record available identities as anonymous, username-only, authenticated domain user, verified local admin on a named host, or principal with verified domain privileges. A username without an authentication secret/ticket is still the no-credential branch. Distinguish local credentials from domain credentials and expired artifacts from usable authentication.
3. **Choose the initial route from the table.** Check service reachability and permission requirements for that route. If there is no domain network path, stop with the missing prerequisite. Do not silently create tunnels or assume the foothold and sandbox share reachability.
4. **Bound the operation.** Record allowed hosts/accounts, collection limits, acceptable authentication attempts and the operator's objective. Use a run-specific artifact directory; the person's sandbox and reference helper state can be shared across chats. Protect credential material and avoid overwriting another run's collection or owned-principal set.
5. **Perform only prerequisite discovery.** Anonymous discovery follows the relevant AD Kill Chain section with a bounded in-scope name set. Credentialed discovery selects the smallest useful collection; broad host/session enumeration is not the default. Distinguish denied access, unsupported collection and absent findings.

Once reachability, current identity and the selected route are established, **request transition to exploitation phase**. Wait for the phase gate before requesting roastable tickets, credential access or directory changes.

### Phase 2: Route by Current Access (Exploitation)

#### A. No credentials

Use the anonymous-enumeration sections of AD Kill Chain to identify domain context and a bounded candidate user set. If anonymous access is denied, record the limitation; do not launch a huge name sweep automatically.

Route to the ASREPRoast section of Kerberoasting only when candidate usernames and KDC reachability are established. Preauthentication must be disabled for the candidate account; a username or a KDC error alone is not proof of a usable AS-REP. Keep ticket acquisition and authorized offline analysis within that reference's procedure. If no credential results, report the blocked route rather than assuming success or falling through to spraying or relay.

#### B. Valid domain user

Validate the supplied credential once against the intended domain service, respecting the agreed authentication budget. Choose by evidence:

- SPN-bearing accounts and permitted ticket acquisition: route to Kerberoasting. A service ticket is evidence of roasting exposure, not proof of recovered credentials or elevated access.
- Unknown privilege path: route to BloodHound Path to DA. Begin with the smallest suitable collection; use `bhgraph` for local analysis. Collection is a snapshot, so confirm critical rights against the current directory before walking an edge.
- Reachable certificate services: route to AD-CS ESC discovery. Check actual enrollment rights, template/CA settings and certificate mapping prerequisites before selecting a certificate path. Enumeration flags alone do not prove impersonation. Exclude ESC8/ESC11 relay branches and any other branch requiring capture, coercion or relay, even if the reference documents them.

Prefer a verified, minimally invasive path to the operator's objective. Do not execute every route just because a credential is available. For an authorized directory or template modification, record original values and a restoration plan before acting.

#### C. Local administrator on a host

Confirm effective administrative access on that specific host, then route authorized credential access to AD Kill Chain's local-admin section. Limit access to the in-scope host and necessary material. Local admin on a member host does not grant domain replication rights; credential recovery can be blocked or yield only local accounts.

Validate any recovered domain credential within the authentication budget, then return to branch B and update path analysis. Do not sweep the domain with a recovered local password/hash. If only local elevation is needed, hand off to [local_privilege_escalation](local_privilege_escalation.md).

#### D. Replication rights confirmed

Use BloodHound output as a candidate list, then confirm the principal's effective replication permissions on the relevant domain naming context. Local admin, a graph edge or an untested credential is insufficient by itself.

When the domain objective and authorization include DCSync, route to the AD Kill Chain DCSync section and perform the smallest permitted replication proof. Notify the operator of the high-impact credential-access operation first. Stop at the agreed evidence threshold; a domain-wide dump or persistent ticket is not required to demonstrate a bounded finding.

### Phase 3: Verify and Re-route After Each Gain (Exploitation)

1. Validate the newly usable principal and its effective rights on the intended host/domain service. Distinguish obtained artifacts, successful authentication and demonstrated privilege.
2. Re-enumerate under the new identity. In the BloodHound reference, mark only validated principals as owned and recompute the path with `bhgraph`. Refresh relevant directory/CA rights when prior collection may be stale. Follow one newly verified edge at a time.
3. Record each hop: prerequisite, identity before/after, reference section used, current evidence and modifications. If an edge fails, mark it unverified and choose an evidence-backed alternative instead of retrying blindly.
4. Stop at the agreed objective, denied authorization, instability or exhausted viable routes. No path found means no path in the available evidence, not that the domain is secure.

### Phase 4: Safe Exit and Scope Limits

- Do not perform persistence, ticket forgery for continued access or account creation unless separately requested and authorized. Those optional reference sections are not automatic follow-ons.
- Nothing destructive without explicit operator confirmation. Restore run-created directory/template changes from recorded originals and report any failed restoration.
- Protect tickets, certificates and recovered secrets in the run's artifacts. Agree retention and cleanup with the operator; remove only this run's temporary artifacts and preserve the evidence needed for review.
- Capture/relay remains outside scope, including LLMNR/NTLM relay and relay-dependent AD-CS paths. Record the network dependency for issue #46 without claiming the sandbox can receive arbitrary callbacks or opening additional inbound ports.

## Reporting Guidelines

- Domain and host placeholders, verified network path, starting principal and prerequisite branch.
- Reference sections selected, collection scope and observed limitations.
- Candidate paths versus verified hops, before/after identities and re-enumeration results.
- Separate roastable ticket acquisition, credential recovery, authentication, local admin and domain replication proof.
- For AD-CS, the template/CA and effective rights plus demonstrated certificate authentication; for DCSync, the permission evidence and bounded proof location. Redact all secrets.
- Changes, restoration/cleanup status, blocked or excluded capture/relay paths and missing prerequisites.
- Remediation tied to verified evidence: service-account protection, preauthentication, directory/replication ACLs, local-admin separation and certificate enrollment/mapping policy as applicable.

## Important Notes

- The documented utilities are in `kali_shell`'s toolbox and the sandbox Dockerfile. Installed tooling does not guarantee network reach, target rights or success.
- No credential or target data belongs in shared examples. Use <TARGET>, <DOMAIN> and other placeholders in reports intended for sharing.
- Import and enable this Markdown skill per user in Agent Skills. Catalog discovery requires no agent rebuild; adding a file does not globally enable it or update previously imported copies.
