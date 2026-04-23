"""
RedAmon Attack Skill Classification Prompt

LLM-based classification of user intent to select the appropriate attack skill and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
Dynamically includes only ENABLED skills in the classification prompt.
"""

from project_settings import get_enabled_builtin_skills, get_enabled_user_skills, get_setting


# =============================================================================
# BUILT-IN SKILL SECTIONS (included when the skill is enabled)
# =============================================================================

_CVE_EXPLOIT_SECTION = """### cve_exploit — CVE (MSF)
- Exploit known CVE vulnerabilities directly against a service using Metasploit Framework (MSF) modules
- Keywords: CVE-XXXX, exploit, RCE, vulnerability, pwn, hack, metasploit
"""

_BRUTE_FORCE_SECTION = """### brute_force_credential_guess
- Password guessing / credential attacks using Hydra against login services (SSH, FTP, MySQL, RDP, SMB, etc.)
- Keywords: brute force, crack password, dictionary attack, wordlist, password spray, guess password, credential attack
"""

_PHISHING_SECTION = """### phishing_social_engineering
- Attack where a target user must execute, open, click, or install something (payload, document, link, one-liner)
- Includes: msfvenom payloads, document-based payloads, web delivery, email delivery, handler setup
- Key distinction: target user runs artifact on THEIR machine (vs cve_exploit which hits a service directly)
- Keywords: payload, reverse shell, msfvenom, payload delivery, phishing, document payload, handler
"""

_DOS_SECTION = """### denial_of_service
- Attacks that DISRUPT service availability rather than gaining access or stealing data
- Includes: DoS modules, flooding, slowloris, resource exhaustion, crash exploits
- Key distinction: goal is DISRUPTION/CRASH/UNAVAILABILITY — no shell, no credentials, no data theft
- Keywords: dos, denial of service, crash, disrupt, availability, slowloris, flood, exhaust, stress test, take down, knock offline, overwhelm
"""

_SQLI_SECTION = """### sql_injection — SQL Injection
- SQL injection testing against web applications using SQLMap and manual techniques
- Includes: error-based, union-based, blind boolean, blind time-based, out-of-band (OOB/DNS exfiltration)
- Key distinction: injecting SQL into application parameters to extract data or gain access
- Keywords: SQL injection, SQLi, sqlmap, database dump, union select, blind injection, WAF bypass, authentication bypass
"""

_XSS_SECTION = """### xss — Cross-Site Scripting (XSS)
- XSS testing against web applications using dalfox, kxss, Playwright DOM analysis, and manual context-aware payloads
- Includes: reflected XSS, stored XSS, DOM-based XSS, blind XSS via OOB callbacks, CSP bypass
- Key distinction: injecting JavaScript that executes in a victim's browser context (vs sql_injection which targets the DB, vs ssrf-unclassified which targets the backend)
- Keywords: XSS, cross-site scripting, reflected XSS, stored XSS, DOM XSS, blind XSS, dalfox, payload encoding, CSP bypass, innerHTML, event handler, script injection
"""

_UNCLASSIFIED_SECTION = """### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit the enabled attack skills above
- The agent has no specialized workflow for these — it will use available tools generically
- **Key distinction from phishing:** the attacker directly interacts with a SERVICE/APPLICATION, NOT generating a payload for a target user to execute
  - "Test for SSRF on the API" → unclassified (attacker sends crafted input to a web service)
  - "Generate a reverse shell payload" → phishing (attacker creates a file for a target user to execute)
- **Key distinction from sql_injection:** if the request is specifically about SQL injection, use the `sql_injection` skill instead
- **Key distinction from xss:** if the request is specifically about XSS, cross-site scripting, or JavaScript injection in a browser, use the `xss` skill instead
- You MUST create a short, descriptive snake_case term followed by "-unclassified"
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Example values: "ssrf-unclassified", "file_upload-unclassified", "directory_traversal-unclassified", "command_injection-unclassified"
- Keywords: directory traversal, path traversal, SSRF, file upload, command injection, LFI, RFI, deserialization, XXE, privilege escalation
- Example requests:
  - "Test for SSRF on the API" -> "ssrf-unclassified"
  - "Try to upload a web shell" -> "file_upload-unclassified"
  - "Attempt directory traversal" -> "directory_traversal-unclassified"
  - "Try command injection on the web form" -> "command_injection-unclassified"
"""

# Map of built-in skill ID -> (section text, classification priority letter)
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    'brute_force_credential_guess': (_BRUTE_FORCE_SECTION, 'b', 'brute_force_credential_guess'),
    'cve_exploit': (_CVE_EXPLOIT_SECTION, 'c', 'cve_exploit'),
    'denial_of_service': (_DOS_SECTION, 'd', 'denial_of_service'),
    'sql_injection': (_SQLI_SECTION, 'e', 'sql_injection'),
    'xss': (_XSS_SECTION, 'f', 'xss'),
}

# Classification instructions for built-in skills (no priority — best match wins)
_CLASSIFICATION_INSTRUCTIONS = {
    'phishing_social_engineering': """   - **phishing_social_engineering**:
      - Is the request asking to GENERATE, CREATE, or SET UP a payload, malicious file, document, backdoor, reverse shell, one-liner, or delivery server?
      - Will the output be something a target user must execute, open, click, or install on their machine?
      - Does it mention msfvenom, handler, multi/handler, web delivery, HTA server, encoding for AV evasion?
      - Does it mention sending something via email to a target person?""",
    'brute_force_credential_guess': """   - **brute_force_credential_guess**:
      - Does the request mention password guessing, brute force, credential attacks, wordlists, or dictionary attacks?
      - Does it target a login service (SSH, FTP, MySQL, etc.) with credential-based attack?""",
    'cve_exploit': """   - **cve_exploit**:
      - Does the request mention a specific CVE ID or Metasploit exploit module to use DIRECTLY against a service?
      - Does it describe exploiting a service vulnerability where NO target user interaction is needed?""",
    'denial_of_service': """   - **denial_of_service**:
      - Is the goal to DISRUPT, CRASH, or make a service UNAVAILABLE (not to gain access)?
      - Does it mention DoS, denial of service, flooding, slowloris, stress test, take down, exhaust resources?
      - Is the user NOT trying to get a shell, steal data, or obtain credentials?""",
    'sql_injection': """   - **sql_injection**:
      - Does the request mention SQL injection, SQLi, database dumping, or union/blind injection?
      - Does it target a web application parameter with SQL-specific attack intent?
      - Does it mention sqlmap, WAF bypass for SQL, authentication bypass via SQL, or OOB/DNS exfiltration?""",
    'xss': """   - **xss**:
      - Does the request mention XSS, cross-site scripting, JavaScript injection, or DOM sinks?
      - Does it target a web application input/parameter with the goal of executing JS in a victim browser?
      - Does it mention reflected/stored/DOM XSS, payload encoding, CSP bypass, blind XSS callbacks, or dalfox?""",
}


def build_classification_prompt(objective: str) -> str:
    """Build a dynamic classification prompt based on enabled skills.

    Only includes sections for enabled built-in skills and any enabled user skills.
    """
    enabled_builtins = get_enabled_builtin_skills()
    enabled_user_skills = get_enabled_user_skills()

    # RoE enforcement: exclude skills from classification when RoE prohibits them
    if get_setting('ROE_ENABLED', False):
        if not get_setting('ROE_ALLOW_DOS', False):
            enabled_builtins.discard('denial_of_service')
        if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
            enabled_builtins.discard('brute_force_credential_guess')
        if not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False):
            enabled_builtins.discard('phishing_social_engineering')

    # --- Header ---
    parts = [
        "You are classifying a penetration testing request to determine:\n"
        "1. The required PHASE (informational vs exploitation)\n"
        "2. The ATTACK SKILL TYPE (for exploitation requests only)\n"
    ]

    # --- Phase Types (always included) ---
    parts.append("""## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Generating payloads, reverse shells, or delivery mechanisms for target user execution
- Setting up handlers, listeners, or delivery servers
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"
  - "Try SQL injection on the web app"
  - "Generate a reverse shell payload"
  - "Create a malicious Word document"
  - "Set up a web delivery attack"
""")

    # --- Attack Skill Types ---
    parts.append("## Attack Skill Types (ONLY for exploitation phase)\n")

    # Built-in skills (only enabled ones)
    for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss']:
        if skill_id in enabled_builtins:
            section_text, _, _ = _BUILTIN_SKILL_MAP[skill_id]
            parts.append(section_text)

    # User skills — use description if available, otherwise first 500 chars of content
    for skill in enabled_user_skills:
        preview = skill.get('description') or skill['content'][:500]
        if not skill.get('description') and len(skill['content']) > 500:
            preview += "..."
        parts.append(f'### user_skill:{skill["id"]}\n'
                     f'- User-defined attack skill: **{skill["name"]}**\n'
                     f'- Skill description:\n{preview}\n')

    # Unclassified (always included)
    parts.append(_UNCLASSIFIED_SECTION)

    # --- User Request ---
    parts.append(f"## User Request\n{objective}\n")

    # --- Classification Instructions ---
    parts.append("## Instructions\nClassify the user's request:\n")
    parts.append("1. First determine the REQUIRED PHASE:\n"
                 '   - Is this a reconnaissance/information gathering request? -> "informational"\n'
                 '   - Is this an active attack/exploitation request? -> "exploitation"\n')

    parts.append("2. Determine the AGENT SKILL TYPE that **best matches** the request — regardless of phase. "
                 "Even informational requests have a skill type (e.g., 'scan for SQLi' → sql_injection, "
                 "'brute force SSH' → brute_force_credential_guess). Pick the one whose criteria fit most closely:\n")

    # Built-in skill classification criteria
    builtin_skill_ids = ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss']
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            parts.append(_CLASSIFICATION_INSTRUCTIONS[skill_id])

    # User skills classification criteria
    for skill in enabled_user_skills:
        parts.append(f'   - **user_skill:{skill["id"]}** ("{skill["name"]}"):\n'
                     f'      - Does the request match the workflow described in the "{skill["name"]}" skill?')

    # Unclassified
    parts.append("   - **<descriptive_term>-unclassified**:\n"
                 "      - Does the request describe a specific attack technique that doesn't match any of the above?\n"
                 "      - For general reconnaissance with no specific attack intent (e.g., 'show attack surface', "
                 "'what vulnerabilities exist'), use **recon-unclassified**")

    default_type = "cve_exploit" if "cve_exploit" in enabled_builtins else "recon-unclassified"
    parts.append(f'\n   If truly unclear (e.g., vague "hack the target"), default to "{default_type}".\n')

    parts.append("3. Extract TARGET HINTS from the request (best-effort, used for graph linking):\n"
                 '   - target_host: IP address or hostname mentioned (e.g., "10.0.0.5", "www.example.com"). null if none found.\n'
                 '   - target_port: port number mentioned (e.g., 8080, 443). null if none found.\n'
                 '   - target_cves: list of CVE IDs mentioned (e.g., ["CVE-2021-41773"]). Empty list if none found.\n')

    # --- Build valid attack_path_type values for JSON schema ---
    valid_types = []
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            valid_types.append(f'"{skill_id}"')
    for skill in enabled_user_skills:
        valid_types.append(f'"user_skill:{skill["id"]}"')
    valid_types.append('"<descriptive_term>-unclassified"')

    parts.append(f"""Output valid JSON matching this schema:

```json
{{{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": {' | '.join(valid_types)},
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null,
  "target_host": "10.0.0.5" | "www.example.com" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` MUST always be set — it identifies which agent skill workflow to use, regardless of phase
- For general recon with no specific attack technique, use "recon-unclassified"
- For unclassified attack techniques, use a descriptive term followed by "-unclassified" (e.g., "ssrf-unclassified", "file_upload-unclassified")
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
- `target_host`, `target_port`, `target_cves` are best-effort extraction — null/empty if not mentioned""")

    return "\n".join(parts)


# Keep backward-compatible constant for any code that still references it directly
# (uses all skills enabled as default)
ATTACK_PATH_CLASSIFICATION_PROMPT = None  # Use build_classification_prompt() instead
