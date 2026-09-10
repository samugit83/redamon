"""
RedAmon Unclassified Attack Skill Prompts

Generic exploitation guidance for attack skills that don't match
CVE exploit or brute force credential guess workflows.
Provides tool descriptions without workflow-specific instructions.
"""

UNCLASSIFIED_EXPLOIT_TOOLS = """
## Exploitation Workflow (Unclassified Attack Skill)

This attack skill does not have a specialized workflow. Use the tools
listed in the **Available Tools** table above to accomplish the exploitation objective.

### Approach

1. **Gather information** about the target using the available reconnaissance and query tools
2. **Identify the attack vector** based on the objective
3. **Execute the attack** using the most appropriate tools from the table above
4. **Verify the result** and document findings

### Skill routing -- switch as soon as the class is clear

The moment the live target reveals a concrete vulnerability class, emit
`action='switch_skill'` with the correct `to_skill` to load that class's
specialized workflow. The `to_skill` MUST be one of the enabled skill IDs -- a
descriptive synonym (e.g. `template_injection`, `ssti`, `lfi`, `deserialization`,
`command_injection`) is NOT a valid skill ID and will be REJECTED. If a switch is
rejected, do NOT abandon switching and stay unclassified -- map your class to the
enabled skill that HOUSES it and switch to that ID instead:

| Observed vulnerability class | Correct `to_skill` |
|------------------------------|--------------------|
| Server-side template injection (SSTI), template injection, expression-language injection (OGNL / SpEL / MVEL / EL), eval/exec code injection, OS command injection, insecure deserialization / gadget chains | `rce` |
| Local/remote file inclusion (LFI/RFI), directory/path traversal, arbitrary file read, archive-extraction (Zip/Tar Slip) | `path_traversal` |
| SQL injection, NoSQL injection, ORM injection | `sql_injection` |
| Reflected/stored/DOM cross-site scripting, JavaScript/HTML injection into a victim browser | `xss` |
| Server-side request forgery, webhook/URL-fetch abuse, cloud-metadata pivots, open redirect used to reach internal hosts | `ssrf` |
| XML external entity (XXE), XML injection, attacker-supplied DOCTYPE / ENTITY / DTD, XInclude, an XML parser processing untrusted XML (SOAP, `.wsdl`, XML upload such as SVG / DOCX) | `xxe` |
| Broken access control / authorization bypass, privilege escalation, IDOR / BOLA (object-level authz), mass-assignment or client-trusted role / privilege / entitlement fields, forced browsing to privileged functions, business-logic / multi-step auth flaws, JWT / cookie / session-token authorization tampering | `access_control` |
| Credential guessing / brute force / default credentials against a login | `brute_force_credential_guess` |
| A specific CVE or Metasploit-module target | `cve_exploit` |

Note in particular: **template injection of every kind (SSTI, and the
expression-language / eval / command-injection / deserialization family) is
housed in the `rce` skill** -- switch to `rce` to load the engine-fingerprint and
template-injection workflow. Only fall back to a `<term>-unclassified` skill if
the class genuinely matches none of the enabled skills above.

### Important Notes

- There is no mandatory step-by-step workflow for this attack skill
- Use your judgment to select the best tools for the specific attack technique
- Only use tools that are listed as available in the current phase
- If the attack requires a tool not available in this phase, request a phase transition
- Document all findings and evidence thoroughly
- If the attack technique ultimately maps to a CVE or brute force approach, proceed accordingly
"""
