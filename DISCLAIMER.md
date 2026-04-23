# Legal Disclaimer and Terms of Use

## IMPORTANT: READ BEFORE USING THIS SOFTWARE

### Purpose and Intended Use

RedAmon is an **educational and research tool** designed exclusively for:

- Authorized penetration testing engagements
- Security research and academic study
- Capture The Flag (CTF) competitions
- Testing on systems you own or have explicit written permission to test
- Learning about offensive security techniques in controlled environments

### Disclaimer of Liability

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.**

The authors and contributors of this project:

1. **DO NOT CONDONE** the use of this tool for any illegal or unauthorized activities
2. **ARE NOT RESPONSIBLE** for any misuse, damage, or illegal activities performed using this software
3. **PROVIDE NO WARRANTY** that this software is fit for any particular purpose
4. **ASSUME NO LIABILITY** for any direct, indirect, incidental, special, or consequential damages arising from the use or misuse of this software

### Legal Compliance

By using this software, you acknowledge and agree that:

1. **You will only use this tool on systems you own or have explicit, written authorization to test**
2. **You are solely responsible** for ensuring your use complies with all applicable local, state, national, and international laws
3. **Unauthorized access to computer systems is illegal** under laws including but not limited to:
   - Computer Fraud and Abuse Act (CFAA) - United States
   - Computer Misuse Act 1990 - United Kingdom
   - Directive 2013/40/EU - European Union
   - And similar laws in other jurisdictions
4. **Violations can result in severe civil and criminal penalties**, including fines and imprisonment

### User Responsibilities

Before using this software, you MUST:

- Obtain **written permission** from the system owner
- Ensure you have a **signed authorization document** or **penetration testing agreement**
- Operate within the **defined scope** of any authorized engagement
- Comply with all **rules of engagement** and applicable laws
- Maintain **confidentiality** of any findings
- **Document everything**: Keep logs of all testing activities for reporting and compliance
- Adhere to any **Non-Disclosure Agreements (NDAs)** when handling sensitive information

### Cloud and Third-Party Services

If the target system is hosted in a **cloud environment** (AWS, Azure, GCP, etc.):

- Verify that your testing is **within the cloud provider's acceptable use policy**
- Some providers require **advance notification** or have specific pentesting policies
- If you are unsure whether usage is lawful, **do not test until you have confirmed**

### Scanning Impact and Target Systems

Automated security scanning can have significant effects on target infrastructure. By using this tool, you acknowledge that:

- **Intrusion Detection Systems (IDS/IPS)**: Scanning activity will likely trigger security alerts on the target network. Coordinate with the target's **Security Operations Center (SOC)** or **Network Operations Center (NOC)** before testing to avoid incident response escalations
- **Service degradation**: High-rate port scanning, web crawling, and vulnerability scanning can degrade target system performance or cause service disruptions. Configure **rate limits** appropriately for each engagement
- **No built-in scan throttling limits**: This tool does not enforce maximum concurrent scans or global rate caps. It is the user's sole responsibility to configure scan intensity suitable for the target environment
- **Firewall and WAF triggers**: Scanning patterns may result in your IP being blocked or blacklisted by the target's Web Application Firewall (WAF) or network firewall
- **Legal implications of disruption**: Unintentional denial-of-service caused by aggressive scanning may constitute a criminal offense even with authorization, if the authorization did not explicitly permit high-volume testing

### Privacy and Data Protection

You must:

- Respect **data confidentiality** and **privacy laws** (GDPR, CCPA, etc.)
- Never exfiltrate, store, or share personal data discovered during testing
- Report any accidentally discovered personal data to the system owner immediately
- Delete any captured data after the engagement concludes

### External LLM Services and Data Disclosure

This project relies on **external Large Language Model (LLM) APIs** (e.g., OpenAI, Anthropic, or other third-party providers) to power its agentic capabilities. By using this tool, you acknowledge that:

- **Data is transmitted to third parties**: Prompts, reconnaissance results, target information, and tool outputs may be sent to external LLM provider servers for processing. This data leaves your local environment and is subject to the **privacy policies and data handling practices of the respective LLM provider**
- **No guarantee of privacy or confidentiality**: The authors of this project have **no control** over how external LLM providers store, process, log, or retain the data sent to their APIs. Sensitive information (e.g., target URLs, IP addresses, discovered vulnerabilities, credentials) may be logged or retained by these providers
- **Data leakage risk**: There is an inherent risk of data exposure when transmitting security-related information through third-party services. Users should be aware that this data could potentially be accessed by the LLM provider's employees, used for model training (depending on provider policies), or exposed in the event of a security breach at the provider
- **User responsibility**: It is your sole responsibility to review and accept the terms of service and privacy policies of any LLM provider you configure. Ensure that sending target and reconnaissance data to these services is compatible with your engagement's rules, NDAs, and applicable data protection laws
- **Mitigation**: Where possible, consider using **self-hosted or on-premise LLM solutions** to keep all data within your controlled environment. Avoid sending highly sensitive or classified information through external APIs

### External Services and Data Transmission

In addition to LLM providers, this project transmits data to several **external third-party services** during normal operation. By using this tool, you acknowledge that target-related information may be sent to:

- **Web Archives (via GAU)**: Domain names are sent to the **Wayback Machine** (Internet Archive), **Common Crawl**, **AlienVault OTX**, and **URLScan.io** for passive URL discovery. These services may log your queries
- **NIST National Vulnerability Database (NVD)**: CVE identifiers and vulnerability queries are sent to the NVD API for enrichment
- **Vulners**: Vulnerability queries may be sent to the Vulners API if configured
- **GitHub API**: When GitHub secret hunting is enabled, target organization names, repository names, commit history, and gist contents are queried through the GitHub API. Depending on the configured access token, this may include access to **private repositories**
- **Tavily Search API**: The AI agent sends web search queries (which may include target names, CVE IDs, and vulnerability details) to the Tavily search service for threat intelligence research
- **Wappalyzer / unpkg CDN**: Technology fingerprint databases are downloaded from the unpkg.com CDN
- **ProjectDiscovery**: Nuclei vulnerability templates are updated from ProjectDiscovery's servers

The authors have **no control** over how these third-party services handle, store, or retain data transmitted to them. It is your responsibility to review each service's privacy policy and ensure compliance with your engagement's rules, NDAs, and applicable data protection regulations.

### Data Persistence and Retention

This project stores reconnaissance and exploitation data in local databases. You should be aware that:

- **Neo4j Graph Database**: All discovered domains, subdomains, IP addresses, open ports, URLs, technologies, vulnerabilities, exploitation results, and GitHub secrets are stored persistently in a Neo4j graph database. **There is no automatic data retention or deletion policy** — data persists indefinitely unless manually deleted
- **PostgreSQL Database**: Project configurations, scan metadata, and user settings are stored in PostgreSQL
- **Sensitive data in scan results**: Nuclei vulnerability scan results may include `curl_command` fields that capture full HTTP request headers, which can contain **Authorization tokens, API keys, session cookies**, and other credentials from the target
- **GDPR and data protection compliance**: Under regulations such as GDPR, personal data must be kept **no longer than necessary** for its intended purpose. Users are responsible for implementing appropriate data retention policies and deleting project data after engagements conclude
- **Multi-project storage**: All projects share a single Neo4j database instance. While data is segregated by project context, users managing multiple engagements should be aware of this shared storage model
- **Recommendation**: Delete all project data (Neo4j nodes, PostgreSQL records, container logs) promptly after each engagement concludes and reporting is complete

### Credential and API Key Storage

This project stores user-provided API keys and credentials for integration with external services:

- **Plaintext storage**: API keys (GitHub Access Tokens, NVD API keys, Vulners API keys) and custom HTTP headers (which may contain Bearer tokens or other authentication credentials) are stored **without encryption at rest** in the PostgreSQL database
- **No built-in encryption**: The project does not implement field-level encryption for sensitive credentials. Securing the database (encryption at rest, access controls, network isolation) is the **user's sole responsibility**
- **GitHub token scope**: GitHub Personal Access Tokens configured for secret hunting may grant access to the target organization's **private repositories, gists, and full commit history**. Ensure the token's permissions are scoped appropriately for your engagement
- **API key rotation**: Users should regularly rotate all configured API keys and revoke them immediately after engagements conclude
- **Database backups**: If you create database backups, ensure they are encrypted and stored securely, as they will contain all plaintext credentials

### Responsible Disclosure

If you discover vulnerabilities:

- **Disclose responsibly** to vendors, system owners, or appropriate authorities
- Follow **coordinated disclosure** timelines (typically 90 days)
- Never publicly disclose vulnerabilities before the owner has had time to remediate
- Never use discovered vulnerabilities for personal gain or malicious purposes

### Recommended Testing Environments

For learning and practice, use **authorized sandbox environments** such as:

- Your own isolated lab network or virtual machines
- [Hack The Box](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [VulnHub](https://www.vulnhub.com/)
- [DVWA](https://dvwa.co.uk/) (Damn Vulnerable Web Application)
- The included `guinea_pigs/` test environments in this repository

**Never practice on production systems or networks you do not own.**

### Intentionally Vulnerable Test Environments

This repository includes intentionally vulnerable applications in the `guinea_pigs/` directory (e.g., Apache servers with known CVEs). These are provided **strictly for isolated lab testing**:

- **Isolated deployment only**: These vulnerable environments must **NEVER** be deployed on publicly accessible infrastructure, cloud instances with public IPs, or any network reachable from the internet
- **Fictitious credentials**: Any credentials bundled with test environments are entirely fictitious and intended solely for demonstration. Do **NOT** reuse these credentials in any real system
- **Known vulnerabilities by design**: These environments contain deliberately unpatched software with known exploits (e.g., CVE-2021-41773, CVE-2021-42013). Deploying them outside a controlled lab creates serious security risks
- **User assumes all risk**: The authors assume no liability for any consequences arising from the deployment, exposure, or misuse of these intentionally vulnerable environments

### Indemnification

You agree to **indemnify, defend, and hold harmless** the authors, contributors, and any affiliated parties from and against any claims, damages, losses, liabilities, costs, and expenses (including legal fees) arising from:

- Your use or misuse of this software
- Your violation of any laws or regulations
- Your violation of any third-party rights
- Any unauthorized or illegal activities conducted using this software

### Prohibited Uses

This software shall **NOT** be used for:

- Unauthorized access to any computer system or network
- Any activity that violates applicable laws or regulations
- Attacking systems without explicit written authorization
- Any malicious, harmful, or illegal purpose
- Circumventing security measures on systems you do not own
- Any activity that could cause harm to individuals or organizations

### Autonomous AI Agent — Unintended Effects

RedAmon's AI agent operates **autonomously**, making real-time decisions about which tools to invoke, which vulnerabilities to exploit, and how to chain attack steps — with minimal or no human intervention. By using this tool in autonomous mode (i.e., with approval gates disabled), you acknowledge and accept that:

- **Unpredictable behavior**: The AI agent may take actions that were not explicitly anticipated, including targeting services, ports, or endpoints outside the user's intended scope, depending on the information it discovers during operation
- **Collateral impact**: Autonomous exploitation, brute-force attacks, and post-exploitation activities can cause **service degradation, data corruption, account lockouts, or unintended denial-of-service** on target systems
- **Scope drift**: The agent's autonomous reasoning may lead it to explore attack paths that extend beyond the originally intended scope, especially when chaining multiple exploits or pivoting through networks
- **No guaranteed containment**: While Rules of Engagement (RoE) and the Target Guardrail provide constraints, they are best-effort safeguards — not absolute guarantees. The AI agent's behavior depends on the underlying LLM, which may not perfectly follow all restrictions in all circumstances
- **User assumes all risk**: The authors and contributors accept **no liability** for any damage, data loss, service disruption, or legal consequences arising from the autonomous operation of the AI agent. You are solely responsible for supervising the agent's actions and ensuring they remain within your authorized scope
- **Recommendation**: Keep **approval gates enabled** (the default) for exploitation and post-exploitation phases. Disabling them grants the agent full autonomy over offensive operations and significantly increases the risk of unintended consequences

### Exploitation Capabilities and Scope Boundaries

This tool integrates with **Metasploit Framework** and other exploitation tools capable of active exploitation, including reverse shells, Meterpreter sessions, and credential testing. Users must understand the following:

- **Authorization scope**: Your written authorization document should explicitly specify the **exact services, CVEs, IP ranges, and timeframes** permitted for exploitation. Do not exploit targets or vulnerabilities outside the defined scope
- **Session management**: Meterpreter and shell sessions establish persistent access to compromised systems. Users must ensure that sessions do not **exceed the authorized time window** and are properly terminated after testing
- **Reverse shell infrastructure**: Configuring reverse shell callbacks (LHOST/LPORT) exposes your infrastructure in the target's network logs. Users are responsible for securing their listener infrastructure
- **Brute force attacks**: THC Hydra credential guessing attacks (SSH, FTP, RDP, SMB, MySQL, HTTP, and 50+ protocols) have a 30-minute hard timeout but can generate significant traffic. Users must set appropriate **thread limits, timeouts, and wordlist sizes** in Hydra project settings to avoid excessive load on target systems
- **Audit trail**: Users should maintain **immutable, timestamped logs** of all exploitation activity for the duration required by their engagement contract and applicable regulations. This project does not enforce persistent audit logging — container logs are ephemeral by default
- **Post-exploitation boundaries**: Any post-exploitation activities (enumeration, lateral movement, data access) must remain within the explicitly authorized scope. Discovering access beyond scope does not constitute authorization to use it

### Educational Context

This project is released in the spirit of:

- **Security research advancement**
- **Educational knowledge sharing**
- **Improving defensive security capabilities**
- **Understanding attacker methodologies to build better defenses**

The techniques demonstrated are already publicly known and documented. This tool simply automates existing security testing methodologies that are freely available in tools like Metasploit, Nmap, and Nuclei.

### Third-Party Security Tools and Licenses

RedAmon integrates, bundles, or invokes the following third-party open-source tools. Each tool is governed by its own license and terms. **The authors of RedAmon do not own, maintain, or provide warranty for any of these tools.** Users must independently comply with each tool's license:

| Tool | Purpose | License |
|------|---------|---------|
| Naabu | Port scanning | AGPL-3.0 (ProjectDiscovery) |
| Nuclei | Vulnerability scanning (template-based) | AGPL-3.0 (ProjectDiscovery) |
| Katana | Web crawling and endpoint discovery | AGPL-3.0 (ProjectDiscovery) |
| HTTPx | HTTP probing and technology detection | AGPL-3.0 (ProjectDiscovery) |
| GAU (GetAllUrls) | Passive URL discovery from web archives | MIT |
| Kiterunner | API endpoint discovery | Open Source |
| Knockpy | Subdomain enumeration | Open Source |
| Wappalyzer | Technology fingerprinting | GPL-3.0 |
| Metasploit Framework | Exploitation and post-exploitation | BSL-2.0 (Rapid7) |
| GVM/OpenVAS | Network vulnerability assessment | AGPL-3.0 (Greenbone) |
| Nmap | Network scanning and service detection | GPL |
| Tor / Proxychains | Anonymous network routing (optional) | BSD / LGPL-2.1+ |
| Neo4j Community | Graph database for recon data | Neo4j Community License |
| PostgreSQL | Relational database | PostgreSQL License (BSD-like) |

- **No warranty on third-party behavior**: The authors make no guarantees about the accuracy, reliability, or safety of any third-party tool's output
- **License compliance**: Some tools use **AGPL-3.0** or **GPL** licenses, which impose specific obligations on distribution and modification. Users must review and comply with each license independently
- **AGPL-3.0 source code availability**: Several tools bundled in RedAmon's Docker images (including Nuclei, Naabu, Katana, HTTPx, Subfinder, Hydra, GVM/OpenVAS, and Kiterunner) are licensed under AGPL-3.0. The complete corresponding source code for all AGPL-licensed components is available at their respective upstream repositories. See **[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)** for the full list of tools, their licenses, and source code locations
- **Tool updates**: Third-party tools may update their templates, modules, or databases automatically (e.g., Nuclei templates, Metasploit modules). The authors are not responsible for changes introduced by upstream tool updates

### AI Regulation and EU AI Act

This project is a **non-commercial, open-source research project** intended to explore AI-driven security automation. Under the **EU AI Act (Regulation 2024/1689)**:

- **Open-Source Exemption (Article 2(12))**: This software is released under a free and open-source license (MIT) with no commercial purpose or monetization. Under Article 2(12) of the EU AI Act, AI components made available under free and open-source licenses are exempt from provider obligations, except for prohibited practices (Article 5) and transparency obligations (Article 50). This exemption does not apply if the software is monetized or deployed in a high-risk context as defined in Annex III
- **Scientific Research Exemption (Article 2(6))**: Additionally, AI systems developed and put into service for the sole purpose of scientific research and development are generally exempt from the heaviest regulatory requirements
- **Transparency (Article 50)**: This tool integrates third-party Large Language Models (LLMs) that autonomously generate security analysis, tool selection decisions, and attack strategies. All AI-generated outputs should be treated as machine-generated content. The AI agent's decisions are not human decisions — users must exercise independent judgment before acting on any AI-generated recommendation
- **Non-Commercial/Research Use**: This tool is not intended for commercial deployment or "High-Risk" use cases as defined by the EU AI Act
- **No Built-in Governance Framework**: This project does not include a built-in governance or compliance framework. Users are strongly encouraged to run this tool in **isolated, self-hosted environments** to ensure data sovereignty and compliance with local laws (e.g., GDPR, national cybersecurity regulations)
- **User-Managed Compliance**: If deploying in any capacity beyond personal research, the user is solely responsible for implementing appropriate governance, logging, and oversight mechanisms. Deployers who use this tool in a high-risk context (Annex III) assume full provider/deployer obligations under the EU AI Act
- **Liability Shift**: The authors of this open-source project bear no provider obligations under the EU AI Act. Any entity deploying this software commercially or in a regulated context assumes all applicable legal obligations as the provider or deployer under the Act

### Dual-Use Technology Notice

This software is a "dual-use" technology similar to:
- Kitchen knives (can cook or harm)
- Lockpicking tools (used by locksmiths and security researchers)
- Network scanners (used by IT administrators daily)

The authors release this tool for **defensive and educational purposes**. Like Metasploit, Nmap, Burp Suite, and other industry-standard tools, this software is intended for legitimate security professionals.

This software is publicly available open-source code. Users are responsible for ensuring compliance with applicable export control regulations (e.g., US EAR, EU Dual-Use Regulation 2021/821, Wassenaar Arrangement) in their jurisdiction.

### Acceptance of Terms

**By downloading, installing, or using this software, you acknowledge that you have read, understood, and agree to be bound by this disclaimer and all applicable terms.**

If you do not agree with these terms, **DO NOT USE THIS SOFTWARE**.

---

## Contact

For questions about authorized use or licensing, please open an issue on the repository.

---

*Last updated: February 2026*
