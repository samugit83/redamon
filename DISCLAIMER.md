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
   - Article 615-ter of the Codice Penale (unauthorized access to a computer system) - Italy
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

### Self-Hosted Deployment and Internet-Facing Instances

This repository includes deployment tooling and documentation (see the **`tooling/deploy/`** directory) for provisioning a RedAmon instance on a remote Linux server (EC2 or any VPS). This tooling is provided **strictly to help an operator self-host a single instance for their own authorized use.** By deploying RedAmon with it, you acknowledge and agree that:

- **Single-operator self-hosting only, not a service**: The deployment tooling is intended for standing up **your own private instance**. It is **NOT** a means to offer RedAmon as a hosted, multi-tenant, or "attack-as-a-service" offering to third parties. Operating RedAmon as a service through which others conduct security testing is outside the intended, supported, and licensed use of this tool, and may carry additional legal obligations and liability that you assume entirely
- **Deployment grants no authorization**: Standing up a RedAmon instance — publicly reachable or otherwise — **does not grant you authorization to scan, probe, or attack anything.** Every engagement still requires explicit, written authorization from the target's owner, exactly as described throughout this disclaimer
- **An exposed instance is itself a high-value target**: A deployed RedAmon instance stores API keys and custom HTTP headers **in plaintext** (see *Credential and API Key Storage*), along with reconnaissance data, exploitation results, discovered secrets, and reverse-shell/listener configuration. If compromised, an attacker gains not only this sensitive data but a pre-armed offensive toolkit. **Securing the deployed host is your sole responsibility**
- **Minimum hardening expectations**: If you expose the instance to the internet, you are responsible for, at minimum: a **strong, unique administrator credential** (never a default or weak password on a public origin), TLS on the single public origin, keeping all other services (agent API, databases, MCP servers, orchestrator, reverse-shell catcher) bound to loopback and not published, host firewalling, prompt patching, and access logging. The `tooling/deploy/` tooling aims to establish this baseline, but you must verify and maintain it
- **Safety defaults must remain enabled**: The deployment tooling does **not** disable RedAmon's safety controls, and you should not either. **Approval gates, Rules of Engagement (RoE), and the Target Guardrail must remain enabled** on any deployed instance. Disabling them on an internet-reachable, autonomous offensive system materially increases the risk of unintended, unauthorized, or out-of-scope actions (see *Autonomous AI Agent — Unintended Effects*)
- **You become the host operator**: Once deployed, you are the operator of the host and are responsible for its security, its lawful operation, its data retention, and compliance with the laws of the jurisdiction in which it is hosted and from which it is operated. Cloud providers' acceptable-use policies also apply to **your** instance, not only to targets
- **Non-commercial exemptions depend on how you deploy**: The open-source and research exemptions this project relies on (see *AI Regulation and EU AI Act*) depend on non-commercial, research-oriented use. Deploying RedAmon in a commercial, hosted, or otherwise regulated capacity shifts provider/deployer obligations onto you and may remove those exemptions
- **No warranty for RedAmon's own security defects; internet exposure is at your own risk**: RedAmon is provided "AS IS" with **no warranty of any kind** (see the *MIT License* and *Disclaimer of Liability*), and this expressly extends to **security defects, bugs, or vulnerabilities in RedAmon's own code** (webapp, agent, orchestrator, MCP servers, and bundled components). RedAmon is **designed local-only**; exposing an instance to the public internet is a deliberate choice you make, and you accept that such an instance may be compromised — including through undiscovered vulnerabilities in RedAmon itself — with any resulting damage, data loss, credential exposure, or downstream harm to you or to third parties being **your sole responsibility**. To the maximum extent permitted by applicable law, the authors and contributors accept **no liability** for any consequence arising from a defect in this software, whether the instance is run locally or exposed to the internet. This allocation of risk does not purport to exclude liability that cannot be excluded by law (e.g., liability for willful misconduct or gross negligence). If you discover such a vulnerability, report it privately and do not exploit it, per **[SECURITY.md](SECURITY.md)**

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
- The included `testing/guinea_pigs/` test environments in this repository

**Never practice on production systems or networks you do not own.**

### Intentionally Vulnerable Test Environments

This repository includes intentionally vulnerable applications in the `testing/guinea_pigs/` directory (e.g., Apache servers with known CVEs). These are provided **strictly for isolated lab testing**:

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

RedAmon integrates, bundles, or invokes numerous third-party open-source tools (port scanners, vulnerability scanners, exploitation frameworks, databases, and more). Each tool is governed by its own license and terms. **The authors of RedAmon do not own, maintain, or provide warranty for any of these tools.** Users must independently comply with each tool's license. The complete, authoritative list of bundled tools, their purposes, their licenses, and their upstream source-code locations is maintained in **[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)**.

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
- **No Built-in Governance Framework**: This project does not include a built-in governance or compliance framework. By default RedAmon is designed to run **local-only** (single host, single operator, not exposed to the public internet). Users are strongly encouraged to keep it in **isolated, self-hosted environments** to ensure data sovereignty and compliance with local laws (e.g., GDPR, national cybersecurity regulations). The optional deployment tooling in `tooling/deploy/` supports internet-facing self-hosting as a **deliberate, hardened exception** to this default — it is single-operator self-hosting behind a TLS reverse proxy and firewall, not a commercial or multi-tenant service (see *Self-Hosted Deployment and Internet-Facing Instances*)
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

*Last updated: July 2026*
