# Local Privilege Escalation Attack Skill

Escalate privileges on an existing Linux or Windows foothold. Confirm the session, enumerate that host, prioritize local misconfigurations, and verify identity after every change.

## When to Classify Here

Use this skill when code execution or an authenticated shell already exists and the objective is a stronger local identity on the same host:

- "We have a shell on <TARGET>; escalate the local user to root."
- "Use the existing Windows session to reach SYSTEM."
- "Enumerate local privilege escalation from this foothold."
- "After switching users, check what the new account can access locally."

Keywords (specific to this workflow): existing foothold, local privilege escalation, low-privilege shell to root, local user to SYSTEM, local token elevation, post-foothold enumeration, re-enumerate after identity change.

### Disjoint from neighbouring skills

- vs. `cve_exploit` (built-in): a request to validate or exploit a named CVE belongs there. Stay here for host-led vector selection; if a CVE becomes the selected vector, hand off the verified host context and prerequisites to that skill.
- vs. `brute_force_credential_guess` (built-in): password guessing, spraying, and cracking as the primary objective belong there. This workflow starts from an existing session and does not guess passwords to obtain one.
- vs. [active_directory_attack](active_directory_attack.md) (community): domain principals, Kerberos, directory ACLs and domain-wide attack paths belong there. A domain-joined host alone does not make a same-host escalation an AD attack. Hand off only when the objective crosses into domain privileges.
- vs. `rce` (built-in): obtaining initial execution belongs there. If there is no working foothold, report the missing prerequisite instead of treating sandbox execution as target execution.
- vs. application authorization skills: a web role change is not an OS identity change. Route application-only escalation to the relevant access-control skill.

## Tools and References

- `metasploit_console` to inspect and interact with existing Metasploit shell or Meterpreter sessions. Serialize console calls; preserve the original session.
- `kali_shell` for sandbox-side preparation and the documented transfer channel. It executes in the person's sandbox, not automatically on <TARGET>.
- `web_search` for a finding-specific GTFOBins or LOLBAS lookup after enumeration.
- [Linux Privesc](../skills/post_exploitation/linux_privesc.md), available as `/skill linux_privesc`, owns Linux enumeration commands, staging and vector recipes.
- [Windows Privesc](../skills/post_exploitation/windows_privesc.md), available as `/skill windows_privesc`, owns Windows enumeration commands, staging and vector recipes.

Load the matching reference when entering its branch. The links identify repository content; they are not paths on the target. Use the reference's relevant section rather than executing its entire playbook. This workflow controls selection, verification and stopping conditions.

## Workflow

### Phase 1: Confirm Foothold and Selective Enumeration (Informational)

1. **Bind the work to an existing session.** Inspect available sessions with `metasploit_console`, or use the already established shell channel. Record the session identifier, target host, transport, originating foothold and last successful interaction. Confirm that the host is in scope. If the session is stale, stop and report it; do not launch another exploit just to replace it.

2. **Record a baseline from the target.** Use the OS reference's triage section through that session. Capture OS/build, architecture, current user, effective identity, groups and privileges. On Windows include token integrity and elevation; on Linux include namespace/container context. Distinguish local and domain accounts. Never infer target identity from the user running `kali_shell`.

3. **Choose one OS branch and one useful enumerator.** Reuse the files already staged in the sandbox:

   | OS | Available sandbox files | Selection |
   |---|---|---|
   | Linux | `/opt/tools/linux/linpeas.sh`, `/opt/tools/linux/LinEnum.sh` | Start with the triage evidence and one auditor, limited to the suspected category; use the alternative only for a concrete information gap. |
   | Linux | `/opt/tools/linux/pspy64` | Observe scheduled privileged activity only if that hypothesis needs it; bound observation time and stop the observer afterward. |
   | Windows | `/opt/tools/windows/winPEASx64.exe`, `/opt/tools/windows/PowerUp.ps1`, `/opt/tools/windows/PrivescCheck.ps1` | Choose a compatible auditor for services, tasks, writable paths and token privileges. Do not run all three by default. |

   Follow the matching reference's staging instructions over the existing session or an authorized credentialed transfer. Check target architecture, destination permissions and execution restrictions first. These are sandbox assets, not files guaranteed to exist on the target. Do not bypass endpoint protection merely because an auditor is blocked.

4. **Build a short evidence-backed candidate list.** On Linux focus on delegated commands, SUID/SGID, capabilities, writable privileged service/task inputs and scheduled execution. On Windows focus on service/task permissions, executable search paths, token privileges and elevation context. For each candidate record the current principal's actual rights, the privileged consumer, required trigger and expected identity. An auditor highlight is a hypothesis, not proof.

5. **Rank before acting.** Prefer a confirmed, reversible misconfiguration over an exploit. Check effective permissions and real execution context before choosing it. Treat kernel/build matches as last-resort research leads; verify vendor backports and exploit prerequisites rather than trusting version strings.

When the foothold, baseline and a bounded candidate are documented, **request transition to exploitation phase**. Wait for the phase gate before performing identity-changing actions.

### Phase 2: Select and Exercise One Vector (Exploitation)

1. Choose the highest-confidence candidate with the smallest operational impact. Prefer delegated execution or existing token rights, then confirmed service/task/path misconfiguration. Consider a kernel exploit only after safer candidates are exhausted and its crash risk has been discussed with the operator.
2. Load only the corresponding vector section in the Linux or Windows reference. Verify all prerequisites on this host. Do not copy a generic payload blindly, download a new toolkit, create an account, or install a persistent privileged helper as a shortcut.
3. State the intended identity, trigger, affected files or service and rollback before changing anything. Obtain explicit confirmation before destructive actions, disruptive restarts or a potentially crashing exploit. If confirmation is missing, preserve the evidence and stop that branch.
4. Execute one bounded attempt through the target session. Retain exact commands and relevant output as evidence with secrets redacted. A successful exit code, changed prompt, service restart or new session alone does not demonstrate escalation.

### Phase 3: Verify Identity and Re-enumerate (Exploitation)

1. **Verify in the resulting execution context.** Repeat the reference's identity checks through the new or changed target session and compare with the baseline. On Linux verify effective UID, groups, capabilities and namespace. Root inside a container does not prove host root. On Windows verify the actual user/SID, token privileges and integrity; Administrators membership does not prove an elevated token or SYSTEM.
2. **Re-enumerate after every identity change**, including intermediate user changes that have not reached root or SYSTEM. Repeat OS-specific permission and local-resource checks as the new principal. Record newly available groups, delegated rights, services/tasks and accessible configuration before selecting another vector. Never reuse a previous user's access assumptions.
3. If the claimed identity did not change, mark the attempt unverified or failed and explain the evidence. Revisit the candidate list instead of repeatedly firing the same exploit.
4. Stop when the operator's local objective is verified. If re-enumeration reveals domain credentials or domain rights, request the appropriate scope and hand off to [active_directory_attack](active_directory_attack.md); local admin is not Domain Admin.

### Phase 4: Limits and Safe Exit

1. No persistence unless the operator explicitly requests it. Do not turn a verified local elevation into account creation, startup changes or a permanent access mechanism.
2. Restore modified settings and files from recorded originals. Remove only artifacts created by this run, stop its observers and retain the original foothold unless the operator asks to close it. Report cleanup failures and any changes that need an operator maintenance window.
3. Stop on target instability, lost session, scope ambiguity or an unmet safety prerequisite. Report partial coverage and the next prerequisite; do not substitute destructive proof or broad secret collection for an identity check.

## Reporting Guidelines

- Foothold/session identifier, host placeholder, OS/build, architecture and initial identity/context.
- Enumerator selected, relevant evidence and the ranked vector with its prerequisites.
- Exact bounded attempt, before/after identity evidence, and each intermediate identity's re-enumeration results.
- Privilege boundary actually crossed, distinguishing container root, elevated local admin, SYSTEM and domain rights.
- Failed hypotheses, blocked checks, coverage limitations and any handoff.
- Changes made, rollback/cleanup status and remediation for the verified misconfiguration or vulnerable component.

## Important Notes

- Keep proof minimal: demonstrate identity and effective access without dumping unrelated secrets or changing protected data.
- Use placeholders such as <TARGET> in shared examples; redact credentials and sensitive target output from the final report.
- Stage through the existing channel. The sandbox has one target-reachable inbound port, determined by its payload settings; this workflow creates no additional listener or tunnel.
- Import and enable this skill for the individual user in Agent Skills. Adding the Markdown file to the catalog requires no agent rebuild and does not enable it globally.
