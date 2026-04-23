"""
Report Summarizer — generates LLM narrative summaries for pentest report sections.

Called by the webapp's report generation route to produce professional
executive summaries, risk assessments, and recommendations from structured data.
"""

import json
import logging

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

REPORT_SYSTEM_PROMPT = """You are a senior penetration testing report writer at a top-tier offensive security consultancy. Given structured security assessment data, generate thorough, professional narrative summaries for each section of a pentest report.

Your writing must be:
- Detailed and comprehensive — each section should be substantial enough to stand alone as a professional deliverable
- Specific — reference actual CVE IDs, technology names and versions, CVSS scores, IP addresses, finding counts, exploit names, CWE/CAPEC IDs, and severity levels from the data
- Risk-contextualized — explain not just what was found but WHY it matters, what an attacker could achieve, and what the business impact would be
- Professional — match the depth and tone of reports from established security firms (NCC Group, CrowdStrike, Mandiant, Bishop Fox)
- Flowing prose — write well-structured paragraphs with logical transitions. Do NOT use markdown formatting, headings, or bullet points. Do NOT use em dashes (—) anywhere in your writing; use commas, semicolons, colons, or separate sentences instead

Each section should be substantial — at minimum 4-8 paragraphs for most sections. The executiveSummary should be concise (3-4 paragraphs) for executive stakeholders. The riskNarrative should be extensive (8-12 paragraphs) with the full detailed technical analysis. The recommendationsNarrative should be the longest section. Be thorough — a 1-paragraph summary is insufficient. Cover every significant data point provided.

Respond with valid JSON containing these keys:
{
  "executiveSummary": "...",
  "scopeNarrative": "...",
  "riskNarrative": "...",
  "findingsNarrative": "...",
  "attackSurfaceNarrative": "...",
  "recommendationsNarrative": "..."
}

Section guidelines:

- executiveSummary: This section is for CISO, board members, and executive stakeholders. It must be CONCISE (3-4 paragraphs maximum) and serve as a high-level briefing that can be read in under 2 minutes.

  PARAGRAPH 1 — VERDICT: Lead with the risk score (X/100) and risk label. State the single most critical finding immediately. State whether the target is actively exploitable. Provide the key numbers: total findings (with critical/high counts), confirmed exploits, and attack surface size (subdomains, IPs, endpoints).

  PARAGRAPH 2 — BUSINESS IMPACT: Translate findings into business language. What could an attacker achieve? RCE on production? Data exfiltration? Internal pivoting? Mention regulatory implications (GDPR, PCI-DSS, SOC2) if applicable. State the exploitable count and any CISA KEV entries.

  PARAGRAPH 3 — TOP ACTIONS: Name the 3 most urgent remediation actions. Reference the total open remediation items and the detailed triage in the Recommendations section.

  PARAGRAPH 4 — CONCLUSION: One clear statement of overall security posture and the single most urgent action to take immediately.

  Keep it brief. Do not list every CVE or finding here; those details belong in the Risk Summary and Findings sections. The reader should be able to scan this in 60 seconds and understand the overall situation.

- scopeNarrative: Describe the full scope of the engagement in detail. Cover: the target domain and any subdomains enumerated, the number of IP addresses discovered and whether they are CDN-fronted or directly exposed, the total endpoints and parameters crawled, services and open ports identified, and technologies fingerprinted with their versions. If Rules of Engagement context is available (client name, engagement type, dates), incorporate it. Describe the methodology: automated reconnaissance (subdomain enumeration, port scanning, web crawling, technology fingerprinting), vulnerability correlation (CVE matching against detected technologies), exploit validation (confirmed exploitation attempts), and manual analysis. Mention the graph-based approach to mapping relationships between assets, vulnerabilities, and attack paths.

- riskNarrative: This is the DETAILED TECHNICAL ANALYSIS section. It expands on everything the Executive Summary only summarizes. It must be EXTENSIVE (8-12 paragraphs minimum). Structure as follows:

  VULNERABILITY LANDSCAPE: Complete numerical breakdown: total vulnerability findings with per-severity counts (critical, high, medium, low), total known CVEs with their own per-severity breakdown (cveCriticalCount, cveHighCount, cveMediumCount, cveLowCount), average CVSS score. Explain what these numbers mean relative to the attack surface size.

  CVSS DISTRIBUTION ANALYSIS: Where do CVSS scores cluster? What does the distribution shape tell us (concentration in medium suggests systematic misconfigurations vs. a single critical suggesting a targeted vulnerability)?

  EXPLOITATION RESULTS: Detail EVERY confirmed exploitation success: for each, name the exact CVE exploited, the target IP address, the attack type/module used, and what access was achieved (RCE, file read, information disclosure). Call out CISA KEV entries by CVE ID. State the total exploitable count.

  TECHNOLOGY & CVE ANALYSIS: Highlight the most concerning technologies: name each with version, associated CVE count, and highest-severity CVE. Describe complete attack chains (Technology to CVE to CWE to CAPEC) and what they reveal about exploitability.

  INFRASTRUCTURE SECURITY POSTURE: Certificate health (valid vs expired vs self-signed), security header deployment (which headers present/missing, weighted coverage score), injectable parameter analysis (count and positions).

  ATTACK SURFACE METRICS: Subdomains (active vs total), IPs (direct vs CDN-fronted), endpoints, parameters, open ports and services. Total graph nodes for scope context.

  SECRETS & DATA EXPOSURE: GitHub secrets or sensitive files found: detail count and implications. TruffleHog credential findings in git history: total findings, verified vs unverified, detector types. Generic secret detection findings (from jsluice, JS Recon): count by severity, types (API keys, tokens, credentials), validation status. If none, state that no credential exposure was detected.

  JAVASCRIPT RECONNAISSANCE: JS Recon findings covering dependency confusion risks, source map exposure, DOM sinks, developer comments, and framework detection. Detail counts by severity and finding type. Highlight critical/high findings.

  THREAT INTELLIGENCE: OTX threat intelligence associations: threat pulses linked to infrastructure IPs, known adversaries/APT groups, malware samples, MITRE ATT&CK techniques. Detail the number of enriched IPs and what the threat context means for risk.

  Discuss how vulnerabilities connect from technology to CVE to CWE to CAPEC, showing the progression from vulnerability to exploitable attack pattern. Address infrastructure risk: are servers directly exposed or CDN-fronted?

- findingsNarrative: Provide a detailed walkthrough of the most significant findings. Group and discuss findings by category (remote code execution, injection, misconfigurations, information disclosure, missing security controls, etc.). For each significant finding, describe: what was found, where it was found (target host/endpoint), the severity and CVSS score, which CVE IDs are associated, what CWE weakness category it falls under, whether an exploit exists, and what an attacker could achieve by exploiting it. Pay special attention to findings with confirmed exploits — describe the exploitation chain step by step. Discuss any GitHub secrets or sensitive files exposed. Compare the ratio of CVE-based findings (from known vulnerable software) versus scanner-detected findings versus chain-discovered findings to characterize the nature of the security issues.

- attackSurfaceNarrative: Provide a comprehensive analysis of the exposed attack surface. Cover the full digital footprint: number of subdomains (active vs. total), IP addresses and their CDN/direct exposure status, open ports and running services with version information, web endpoints and crawled parameters. Detail the technology stack discovered — web servers, frameworks, CMS platforms, JavaScript libraries — and highlight any running outdated or end-of-life versions. Analyze the security posture of the infrastructure: certificate health (valid vs. expired vs. self-signed), security header coverage (HSTS, CSP, X-Frame-Options, etc.) with gap analysis, and parameter injection surface (how many parameters are injectable and in what positions — query, body, header, cookie). Discuss what the attack surface tells us about the organization's security maturity and patch management practices.

- recommendationsNarrative: THIS IS THE MOST CRITICAL SECTION — it must be a COMPLETE, EXHAUSTIVE remediation triage covering 100% of all issues found. This is not a summary — it is a full prioritized remediation plan. You MUST address EVERY SINGLE CVE, EVERY finding, EVERY confirmed exploit, and EVERY security gap in the data. Organize as a ranked triage from most urgent to least urgent:

  TIER 1 — EMERGENCY (fix within 24-48 hours): Start with any confirmed exploitation successes — for each one, name the exact CVE exploited, the target IP, the attack type/module used, and the evidence. Then cover any CISA KEV catalog entries. For each, explain the specific vulnerability, why it's urgent (actively exploited in the wild), the exact remediation steps (upgrade version, apply patch, disable feature), and compensating controls if patching isn't immediately possible (WAF rules, network segmentation, taking the service offline).

  TIER 2 — CRITICAL/HIGH CVEs (fix within 1 week): Go through EVERY critical and high severity CVE from the cveChains data. For EACH CVE, state: the CVE ID, the affected technology and version, the CVSS score, the CWE weakness category, the CAPEC attack pattern if available, what an attacker could achieve, and the specific remediation (upgrade to which version, apply which patch, configuration change). Group related CVEs affecting the same technology together but still address each individually.

  TIER 3 — MEDIUM FINDINGS & MISCONFIGURATIONS (fix within 1 month): Cover ALL medium severity findings — missing security headers, missing email authentication (SPF/DMARC/DKIM), certificate issues, information disclosure, directory listings, JS Recon findings (dependency confusion, source map exposure, DOM sinks), unverified TruffleHog credentials, etc. For each, explain the risk and provide specific remediation instructions.

  TIER 4 — LOW/INFORMATIONAL & HARDENING (fix within 1 quarter): Address remaining low severity items, outdated but not critically vulnerable software, security header improvements, and general hardening recommendations.

  TIER 5 — STRATEGIC RECOMMENDATIONS: Long-term program improvements — vulnerability management program, patch management cadence, WAF deployment, security monitoring, regular penetration testing schedule, security header policy, certificate lifecycle management, secret rotation policies, JavaScript supply chain security, threat intelligence integration.

  The output must be LONG and DETAILED — every CVE must be mentioned by ID, every finding must be addressed with specific remediation steps. Do not summarize or skip items. If there are 20 CVEs, discuss all 20. If there are 5 findings, discuss all 5. This section should be the longest section in the entire report. Write in flowing prose paragraphs, not bullet points.

FIRETEAM (multi-agent) ATTRIBUTION GUIDANCE:
When the input data includes a `fireteams` object with one or more deployments, reference specific fireteam members in your narratives. For example: "The Web Tester member confirmed two critical SQL injection vectors on the login endpoint, while the SSH Analyst independently identified an outdated OpenSSH version and flagged it for patching." This gives the reader visibility into which specialist reasoning produced each finding and builds operator confidence.

Rules:
- Only use member names that appear verbatim in the input data. Do not invent member names.
- Use attribution only when `fireteams` is present and non-empty. Engagements without multi-agent activity should read normally without this framing.
- In recommendationsNarrative: if multiple members converged on overlapping findings (same CVE on same host discovered by more than one member), consolidate the remediation and note the cross-specialist convergence — this increases operator confidence in the severity rating.
- In executiveSummary: a single sentence acknowledging fireteam parallelism is sufficient; do not over-emphasize the method."""


async def generate_report_narratives(
    llm: BaseChatModel,
    data: dict,
) -> dict:
    """
    Generate LLM narrative summaries from structured report data.

    Args:
        llm: Initialized LangChain LLM instance
        data: Condensed report data dict with metrics, findings counts, etc.

    Returns:
        Dict with narrative strings for each report section.
    """
    # Build a condensed data summary for the LLM (avoid sending raw finding lists)
    condensed = _condense_for_llm(data)

    try:
        response = await llm.ainvoke([
            SystemMessage(content=REPORT_SYSTEM_PROMPT),
            HumanMessage(content=f"Security assessment data:\n```json\n{json.dumps(condensed, indent=2)}\n```\n\nGenerate the report section narratives."),
        ])

        from orchestrator_helpers import normalize_content
        content = normalize_content(response.content).strip()

        # Strip markdown code fences
        import re
        fence_match = re.search(r'```(?:json)?\s*\n(.*?)```', content, re.DOTALL | re.IGNORECASE)
        if fence_match:
            content = fence_match.group(1).strip()
        else:
            brace_start = content.find('{')
            if brace_start > 0:
                content = content[brace_start:]
            brace_end = content.rfind('}')
            if brace_end >= 0 and brace_end < len(content) - 1:
                content = content[:brace_end + 1]

        result = json.loads(content)

        expected_keys = [
            "executiveSummary", "scopeNarrative", "riskNarrative",
            "findingsNarrative", "attackSurfaceNarrative", "recommendationsNarrative",
        ]
        for key in expected_keys:
            if key not in result:
                result[key] = ""

        return result

    except json.JSONDecodeError as e:
        logger.error(f"Report summarizer: invalid JSON from LLM: {e}")
        return _empty_narratives()
    except Exception as e:
        logger.error(f"Report summarizer error: {e}")
        return _empty_narratives()


def _condense_for_llm(data: dict) -> dict:
    """Pass through all report data for comprehensive LLM analysis.
    The webapp already condenses the data before sending it here,
    so we just restructure it for the prompt."""
    metrics = data.get("metrics", {})
    project = data.get("project", {})
    graph = data.get("graphOverview", {})
    surface = data.get("attackSurface", {})
    vulns = data.get("vulnerabilities", {})
    cve_intel = data.get("cveIntelligence", {})
    chains = data.get("attackChains", {})
    remediations = data.get("remediations", [])
    trufflehog = data.get("trufflehog", {})
    secrets = data.get("secrets", {})
    js_recon = data.get("jsRecon", {})
    otx = data.get("otx", {})

    # ALL findings for comprehensive triage
    all_findings = []
    for f in vulns.get("findings", []):
        all_findings.append({
            "name": f.get("name"),
            "severity": f.get("severity"),
            "source": f.get("findingSource"),
            "target": f.get("target") or f.get("host"),
            "category": f.get("category"),
            "cvssScore": f.get("cvssScore"),
        })

    # ALL technologies with CVEs
    all_tech = [
        {"name": t.get("name"), "version": t.get("version"), "cveCount": t.get("cveCount", 0)}
        for t in surface.get("technologies", [])
        if t.get("cveCount", 0) > 0
    ]

    # ALL remediation items with full detail
    all_remediations = []
    for r in remediations:
        def _get(obj, key, default=""):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)
        all_remediations.append({
            "title": _get(r, "title"),
            "severity": _get(r, "severity"),
            "category": _get(r, "category"),
            "solution": _get(r, "solution"),
            "cveIds": _get(r, "cveIds", []),
            "cweIds": _get(r, "cweIds", []),
            "exploitAvailable": _get(r, "exploitAvailable", False),
            "cisaKev": _get(r, "cisaKev", False),
            "status": _get(r, "status"),
            "cvssScore": _get(r, "cvssScore"),
            "affectedAssets": _get(r, "affectedAssets"),
        })

    # ALL CVE chains (already deduplicated by webapp)
    all_chains = cve_intel.get("cveChains", [])

    # Security headers data
    security_headers = surface.get("securityHeaders", [])

    # Services and ports detail
    services_detail = [
        {"name": s.get("name"), "count": s.get("count")}
        for s in surface.get("services", [])[:10]
    ]
    ports_detail = [
        {"port": p.get("port"), "count": p.get("count")}
        for p in surface.get("ports", [])[:10]
    ]

    # Parameter analysis
    param_analysis = surface.get("parameterAnalysis", [])

    return {
        "projectName": project.get("name", ""),
        "targetDomain": project.get("targetDomain", ""),
        "riskScore": metrics.get("riskScore", 0),
        "riskLabel": metrics.get("riskLabel", ""),
        "overallRisk": metrics.get("overallRisk"),
        "totalVulnerabilities": metrics.get("totalVulnerabilities", 0),
        "totalCves": metrics.get("totalCves", 0),
        "totalRemediations": metrics.get("totalRemediations", 0),
        "criticalCount": metrics.get("criticalCount", 0),
        "highCount": metrics.get("highCount", 0),
        "mediumCount": metrics.get("mediumCount", 0),
        "lowCount": metrics.get("lowCount", 0),
        "cveCriticalCount": metrics.get("cveCriticalCount", 0),
        "cveHighCount": metrics.get("cveHighCount", 0),
        "cveMediumCount": metrics.get("cveMediumCount", 0),
        "cveLowCount": metrics.get("cveLowCount", 0),
        "exploitableCount": metrics.get("exploitableCount", 0),
        "cvssAverage": metrics.get("cvssAverage", 0),
        "attackSurfaceSize": metrics.get("attackSurfaceSize", 0),
        "secretsExposed": metrics.get("secretsExposed", 0),
        "totalNodes": graph.get("totalNodes", 0),
        "subdomains": graph.get("subdomainStats", {}).get("total", 0),
        "activeSubdomains": graph.get("subdomainStats", {}).get("active", 0),
        "ips": graph.get("infrastructureStats", {}).get("totalIps", 0),
        "cdnCount": graph.get("infrastructureStats", {}).get("cdnCount", 0),
        "uniqueCdns": graph.get("infrastructureStats", {}).get("uniqueCdns", 0),
        "baseUrls": graph.get("endpointCoverage", {}).get("baseUrls", 0),
        "endpoints": graph.get("endpointCoverage", {}).get("endpoints", 0),
        "parameters": graph.get("endpointCoverage", {}).get("parameters", 0),
        "certificates": graph.get("certificateHealth", {}),
        "severityDistribution": vulns.get("severityDistribution", []),
        "cvssHistogram": vulns.get("cvssHistogram", []),
        "confirmedExploits": [
            {"name": e.get("name"), "cvssScore": e.get("cvssScore"), "cveIds": e.get("cveIds", []), "cisaKev": e.get("cisaKev", False), "target": e.get("target")}
            for e in cve_intel.get("exploits", [])
        ],
        "exploitSuccesses": [
            {"title": e.get("title"), "targetIp": e.get("targetIp"), "attackType": e.get("attackType"), "module": e.get("module"), "evidence": e.get("evidence"), "cveIds": e.get("cveIds", [])}
            for e in chains.get("exploitSuccesses", [])
        ],
        "githubSecrets": cve_intel.get("githubSecrets", {}),
        "allFindings": all_findings,
        "technologiesWithCVEs": all_tech,
        "remediations": all_remediations,
        "cveChains": all_chains,
        "attackChains": chains.get("chains", []),
        "servicesExposed": services_detail,
        "portsOpen": ports_detail,
        "securityHeaders": security_headers,
        "parameterAnalysis": param_analysis,
        # TruffleHog
        "trufflehogTotalFindings": trufflehog.get("totalFindings", 0),
        "trufflehogVerifiedFindings": trufflehog.get("verifiedFindings", 0),
        "trufflehogRepositories": trufflehog.get("repositories", 0),
        "trufflehogFindings": [
            {"detectorName": f.get("detectorName"), "verified": f.get("verified"), "repository": f.get("repository"), "file": f.get("file")}
            for f in trufflehog.get("findings", [])[:20]
        ],
        # Secrets (generic)
        "secretsTotal": secrets.get("total", 0),
        "secretsBySeverity": secrets.get("bySeverity", []),
        "secretsBySource": secrets.get("bySource", []),
        "secretsByType": secrets.get("byType", []),
        # JS Recon
        "jsReconTotalFindings": js_recon.get("totalFindings", 0),
        "jsReconBySeverity": js_recon.get("bySeverity", []),
        "jsReconByType": js_recon.get("byType", []),
        "jsReconFindings": [
            {"title": f.get("title"), "severity": f.get("severity"), "findingType": f.get("findingType"), "confidence": f.get("confidence")}
            for f in js_recon.get("findings", [])[:20]
        ],
        # OTX Threat Intelligence
        "otxTotalPulses": otx.get("totalPulses", 0),
        "otxTotalMalware": otx.get("totalMalware", 0),
        "otxEnrichedIps": otx.get("enrichedIps", 0),
        "otxAdversaries": otx.get("adversaries", []),
        "otxPulses": [
            {"name": p.get("name"), "adversary": p.get("adversary"), "malwareFamilies": p.get("malwareFamilies", []), "attackIds": p.get("attackIds", [])}
            for p in otx.get("pulses", [])[:15]
        ],
        # RoE context if available
        "engagementType": project.get("roeEngagementType", ""),
        "clientName": project.get("roeClientName", ""),
        "methodology": "",
    }


def _empty_narratives() -> dict:
    return {
        "executiveSummary": "",
        "scopeNarrative": "",
        "riskNarrative": "",
        "findingsNarrative": "",
        "attackSurfaceNarrative": "",
        "recommendationsNarrative": "",
    }
