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

### Important Notes

- There is no mandatory step-by-step workflow for this attack skill
- Use your judgment to select the best tools for the specific attack technique
- Only use tools that are listed as available in the current phase
- If the attack requires a tool not available in this phase, request a phase transition
- Document all findings and evidence thoroughly
- If the attack technique ultimately maps to a CVE or brute force approach, proceed accordingly
"""
