# Security Policy

## Supported Versions

RedAmon follows a rolling-release model. Only the **latest version** on the `master` branch receives security updates.

| Version                       | Supported          |
| ----------------------------- | ------------------ |
| Latest release on `master`    | :white_check_mark: |
| Any older version             | :x:                |

If you are running an older version, please update to the latest release before reporting issues. See the [Updating to a New Version](README.md#updating-to-a-new-version) section.

## Reporting a Vulnerability

If you discover a security vulnerability in RedAmon, **please do not open a public GitHub issue**. Instead, report it privately:

1. **GitHub Private Vulnerability Reporting** — Go to the [Security Advisories](https://github.com/samugit83/redamon/security/advisories) page and click **"Report a vulnerability"**.
2. **Email** — Send a detailed report to the repository owner via their GitHub profile contact.

### What to Include

- A clear description of the vulnerability
- Steps to reproduce (affected component, Docker configuration, etc.)
- The potential impact (e.g., container escape, credential exposure, privilege escalation)
- Any suggested fix, if you have one

### What to Expect

- **Acknowledgement** within 72 hours of your report
- **Status update** within 7 days with an initial assessment
- If accepted, a fix will be prioritized and released as soon as possible
- Accepted reports are published as GitHub Security Advisories when the fixed release ships, crediting the reporter
- Whether a CVE is requested for an advisory is at the maintainers' discretion
- If declined, you will receive an explanation of why

### Scope

The following are **in scope** for security reports:

- Vulnerabilities in RedAmon's own code (webapp, recon orchestrator, agent, MCP servers)
- Docker container misconfigurations that could lead to host compromise
- Authentication/authorization bypasses in the web application
- Credential leaks (API keys, Neo4j/PostgreSQL passwords exposed unintentionally)
- Command injection or code execution in user-controlled inputs
- The plugin platform: the plugin runner's isolation (its networks, per-worker limits, clean environment), the Gateway's authorization of every plugin call, catalog and archive verification, and the core review and approval screens

The following are **out of scope**:

- Vulnerabilities in upstream tools (Metasploit, Nmap, Nuclei, Hydra, etc.) — report those to the respective projects
- Security issues in test/vulnerable environments (VulnBank, DVWA) — these are intentionally vulnerable
- Expected behavior of offensive security features when used as designed (e.g., the agent executing exploits against authorized targets)
- Vulnerabilities in a plugin's own code. Plugins are third-party code installed on demand from the separate [`redamon-plugins`](https://github.com/samugit83/redamon-plugins) repository: report a flaw in a plugin to that repository's maintainers, privately, in the same way as above. If a plugin can escape the runner, call the Gateway beyond the permissions an admin granted, or change agent behaviour without a person's approval, that is a platform vulnerability and in scope here

## Responsible Disclosure

We ask that you:

- Allow reasonable time for a fix before public disclosure
- Do not exploit the vulnerability beyond what is necessary to demonstrate it
- Do not access or modify other users' data

We are committed to working with the security community and will credit reporters in the release notes (unless you prefer to remain anonymous).

## Important Reminder

RedAmon is an offensive security tool intended for **authorized testing only**. See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer and acceptable use policy.
