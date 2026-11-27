import type { ComplianceControlSpec, ComplianceFrameworkId, ComplianceEvidenceSnapshot } from './types'

export const FRAMEWORK_META: Record<ComplianceFrameworkId, { label: string; version: string }> = {
  pci_dss_4_0: { label: 'PCI DSS', version: '4.0' },
  owasp_asvs_4_0: { label: 'OWASP ASVS', version: '4.0' },
  nist_csf_2_0: { label: 'NIST CSF', version: '2.0' },
}

export const ALL_FRAMEWORK_IDS: ComplianceFrameworkId[] = [
  'pci_dss_4_0',
  'owasp_asvs_4_0',
  'nist_csf_2_0',
]

const FRAMEWORK_ALIASES: Record<string, ComplianceFrameworkId> = {
  'pci_dss_4_0': 'pci_dss_4_0',
  'pcidss': 'pci_dss_4_0',
  'pci-dss': 'pci_dss_4_0',
  'pci dss': 'pci_dss_4_0',
  'pci-dss 4.0': 'pci_dss_4_0',
  'pci dss 4.0': 'pci_dss_4_0',
  'pci dss v4.0': 'pci_dss_4_0',
  'owasp_asvs_4_0': 'owasp_asvs_4_0',
  'owasp asvs': 'owasp_asvs_4_0',
  'owasp-asvs': 'owasp_asvs_4_0',
  'owasp asvs 4.0': 'owasp_asvs_4_0',
  'asvs': 'owasp_asvs_4_0',
  'asvs 4.0': 'owasp_asvs_4_0',
  'nist_csf_2_0': 'nist_csf_2_0',
  'nist csf': 'nist_csf_2_0',
  'nist-csf': 'nist_csf_2_0',
  'nist csf 2.0': 'nist_csf_2_0',
  'nist-csf-2.0': 'nist_csf_2_0',
  'nist': 'nist_csf_2_0',
}

export function normalizeFrameworkIds(raw: readonly string[] | null | undefined): ComplianceFrameworkId[] {
  if (!raw || raw.length === 0) return []
  const seen = new Set<ComplianceFrameworkId>()
  for (const item of raw) {
    const key = String(item || '').trim().toLowerCase().replace(/\s+/g, ' ')
    const mapped = FRAMEWORK_ALIASES[key]
    if (mapped) seen.add(mapped)
  }
  return [...seen]
}

function evalVulnScan(ev: ComplianceEvidenceSnapshot, includeMedium: boolean) {
  if (!ev.hasVulnScanEvidence) {
    return { status: 'no_evidence' as const, evidence: 'No vulnerability scan or remediation evidence collected.', findingCount: 0 }
  }
  const hits = includeMedium ? ev.criticalHighVulns + ev.mediumVulns : ev.criticalHighVulns
  if (hits > 0) {
    return {
      status: 'fail' as const,
      evidence: `${hits} ${includeMedium ? 'critical/high/medium' : 'critical/high'} vulnerability finding(s) observed.`,
      findingCount: hits,
    }
  }
  return { status: 'pass' as const, evidence: 'Vulnerability scan completed with 0 matching severity findings.', findingCount: 0 }
}

function evalTls(ev: ComplianceEvidenceSnapshot) {
  if (ev.tlsCertificatesScanned <= 0) {
    return { status: 'no_evidence' as const, evidence: 'No TLS certificate inventory recorded (tlsx/httpx did not run or found no TLS endpoints).', findingCount: 0 }
  }
  const issues = ev.tlsExpiredOrMismatched + ev.tlsSelfSigned
  if (issues > 0) {
    return {
      status: 'fail' as const,
      evidence: `${issues} TLS certificate hygiene issue(s) (expired/mismatched: ${ev.tlsExpiredOrMismatched}, self-signed: ${ev.tlsSelfSigned}).`,
      findingCount: issues,
    }
  }
  return { status: 'pass' as const, evidence: `${ev.tlsCertificatesScanned} TLS certificate(s) inspected; no expired, mismatched, or self-signed certificates found.`, findingCount: 0 }
}

function evalSecrets(ev: ComplianceEvidenceSnapshot) {
  const ran = ev.trufflehogScanned || ev.githubSecretHuntScanned || ev.jsReconScanned || ev.secretsExposed > 0
  if (!ran) {
    return { status: 'no_evidence' as const, evidence: 'No secret-detection scan evidence recorded.', findingCount: 0 }
  }
  const total = ev.secretsExposed + ev.trufflehogFindings + ev.githubSecretFindings
  if (total > 0) {
    return {
      status: 'fail' as const,
      evidence: `${total} exposed secret finding(s) detected across secret scanners.`,
      findingCount: total,
    }
  }
  return { status: 'pass' as const, evidence: 'Secret-detection scans ran with 0 exposed secret findings.', findingCount: 0 }
}

function evalSupplyChain(ev: ComplianceEvidenceSnapshot) {
  if (!ev.supplyChainScanned) {
    return { status: 'no_evidence' as const, evidence: 'No dependency or SBOM supply-chain scan evidence recorded.', findingCount: 0 }
  }
  if (ev.supplyChainMaliciousOrSuspicious > 0) {
    return {
      status: 'fail' as const,
      evidence: `${ev.supplyChainMaliciousOrSuspicious} malicious/suspicious dependency finding(s) flagged.`,
      findingCount: ev.supplyChainMaliciousOrSuspicious,
    }
  }
  return { status: 'pass' as const, evidence: 'Supply-chain scan ran with 0 malicious/suspicious package verdicts.', findingCount: 0 }
}

function evalWebApi(ev: ComplianceEvidenceSnapshot) {
  if (ev.isIpOnlyMode && ev.attackSurfaceSize === 0 && !ev.graphqlScanned && !ev.jsReconScanned) {
    return { status: 'out_of_scope' as const, evidence: 'No HTTP web/API surface in scope for this IP-only assessment.', findingCount: 0 }
  }
  const ran = ev.graphqlScanned || ev.jsReconScanned || ev.hasVulnScanEvidence
  if (!ran) {
    return { status: 'no_evidence' as const, evidence: 'No web/API security checks (JS Recon / GraphQL / Web Vuln) recorded.', findingCount: 0 }
  }
  const total = ev.graphqlFindings + ev.webCachePoisonFindings + ev.jsReconFindings
  if (total > 0) {
    return {
      status: 'fail' as const,
      evidence: `${total} web/API exposure(s) observed (GraphQL: ${ev.graphqlFindings}, Cache Poisoning: ${ev.webCachePoisonFindings}, JS Recon: ${ev.jsReconFindings}).`,
      findingCount: total,
    }
  }
  return { status: 'pass' as const, evidence: 'Web/API checks ran with 0 GraphQL, cache-poisoning, or JS Recon findings.', findingCount: 0 }
}

function evalAttackSurface(ev: ComplianceEvidenceSnapshot) {
  if (!ev.hasReconNodes) {
    return { status: 'no_evidence' as const, evidence: 'No reconnaissance graph inventory collected.', findingCount: 0 }
  }
  return {
    status: 'pass' as const,
    evidence: `Attack surface inventory recorded (${ev.attackSurfaceSize} exposed web/port asset(s)).`,
    findingCount: 0,
  }
}

function evalCveExposure(ev: ComplianceEvidenceSnapshot) {
  if (!ev.hasVulnScanEvidence && ev.cveTotal === 0) {
    return { status: 'no_evidence' as const, evidence: 'No CVE intelligence or vulnerability scan evidence collected.', findingCount: 0 }
  }
  if (ev.cveCriticalHigh > 0) {
    return {
      status: 'fail' as const,
      evidence: `${ev.cveCriticalHigh} critical/high CVE(s) mapped to discovered technologies or packages.`,
      findingCount: ev.cveCriticalHigh,
    }
  }
  return { status: 'pass' as const, evidence: 'Vulnerability/CVE assessment ran with 0 critical/high CVEs.', findingCount: 0 }
}

export const COMPLIANCE_CONTROLS: ComplianceControlSpec[] = [
  // PCI DSS 4.0
  {
    id: 'pci_4_2_1',
    framework: 'pci_dss_4_0',
    code: 'Req. 4.2.1',
    title: 'Strong cryptography and valid certificates for public-facing transmissions',
    category: 'tls',
    evaluate: evalTls,
  },
  {
    id: 'pci_6_2_4',
    framework: 'pci_dss_4_0',
    code: 'Req. 6.2.4',
    title: 'Software engineering techniques prevent common web & API attacks',
    category: 'web_api',
    requiresHttpSurface: true,
    evaluate: evalWebApi,
  },
  {
    id: 'pci_6_3_1',
    framework: 'pci_dss_4_0',
    code: 'Req. 6.3.1',
    title: 'Known security vulnerabilities and CVEs are identified and managed',
    category: 'vuln_mgmt',
    evaluate: evalCveExposure,
  },
  {
    id: 'pci_6_3_2',
    framework: 'pci_dss_4_0',
    code: 'Req. 6.3.2',
    title: 'Bespoke and third-party software dependencies are inventoried and checked',
    category: 'supply_chain',
    evaluate: evalSupplyChain,
  },
  {
    id: 'pci_8_6_1',
    framework: 'pci_dss_4_0',
    code: 'Req. 8.6.1',
    title: 'System and application credentials/secrets are not exposed in code or responses',
    category: 'secrets',
    evaluate: evalSecrets,
  },
  {
    id: 'pci_11_3_2',
    framework: 'pci_dss_4_0',
    code: 'Req. 11.3.2',
    title: 'External vulnerability scans detect and track high/critical exposures',
    category: 'vuln_mgmt',
    evaluate: ev => evalVulnScan(ev, false),
  },

  // OWASP ASVS 4.0
  {
    id: 'asvs_v1_14',
    framework: 'owasp_asvs_4_0',
    code: 'V1.14 / V14.2',
    title: 'Dependency & build supply-chain integrity verified',
    category: 'supply_chain',
    evaluate: evalSupplyChain,
  },
  {
    id: 'asvs_v2_10',
    framework: 'owasp_asvs_4_0',
    code: 'V2.10 / V6.4',
    title: 'No hardcoded API keys, tokens, or secrets in client/repo artifacts',
    category: 'secrets',
    evaluate: evalSecrets,
  },
  {
    id: 'asvs_v9_1',
    framework: 'owasp_asvs_4_0',
    code: 'V9.1 / V9.2',
    title: 'Communications use trusted, non-expired TLS certificates',
    category: 'tls',
    evaluate: evalTls,
  },
  {
    id: 'asvs_v13_1',
    framework: 'owasp_asvs_4_0',
    code: 'V13.1 / V13.4',
    title: 'API & GraphQL endpoints protected against introspection/abuse',
    category: 'web_api',
    requiresHttpSurface: true,
    evaluate: evalWebApi,
  },
  {
    id: 'asvs_v14_1',
    framework: 'owasp_asvs_4_0',
    code: 'V14.1',
    title: 'Application stack free of critical, high, and medium known vulnerabilities',
    category: 'vuln_mgmt',
    evaluate: ev => evalVulnScan(ev, true),
  },

  // NIST CSF 2.0
  {
    id: 'nist_id_am_01',
    framework: 'nist_csf_2_0',
    code: 'ID.AM-01 / 02',
    title: 'External hardware, network, and software attack surface inventoried',
    category: 'attack_surface',
    evaluate: evalAttackSurface,
  },
  {
    id: 'nist_id_ra_01',
    framework: 'nist_csf_2_0',
    code: 'ID.RA-01',
    title: 'Vulnerabilities in external assets and CVEs identified and documented',
    category: 'vuln_mgmt',
    evaluate: evalCveExposure,
  },
  {
    id: 'nist_pr_aa_01',
    framework: 'nist_csf_2_0',
    code: 'PR.AA-01',
    title: 'Identities and credentials protected against accidental leakage',
    category: 'secrets',
    evaluate: evalSecrets,
  },
  {
    id: 'nist_pr_ds_02',
    framework: 'nist_csf_2_0',
    code: 'PR.DS-02',
    title: 'Data-in-transit protected with valid TLS certificates',
    category: 'tls',
    evaluate: evalTls,
  },
  {
    id: 'nist_gv_sc_07',
    framework: 'nist_csf_2_0',
    code: 'GV.SC-07',
    title: 'Third-party software supply-chain risks assessed',
    category: 'supply_chain',
    evaluate: evalSupplyChain,
  },
  {
    id: 'nist_de_cm_09',
    framework: 'nist_csf_2_0',
    code: 'DE.CM-09',
    title: 'Computing hardware, software, and web/API services monitored for flaws',
    category: 'vuln_mgmt',
    evaluate: ev => evalVulnScan(ev, false),
  },
]
