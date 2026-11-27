export type ComplianceFrameworkId = 'pci_dss_4_0' | 'owasp_asvs_4_0' | 'nist_csf_2_0'

export type ControlStatus = 'fail' | 'pass' | 'no_evidence' | 'out_of_scope'

export interface ComplianceEvidenceSnapshot {
  isIpOnlyMode: boolean
  roeForbiddenCategories: string[]
  totalVulnerabilities: number
  criticalHighVulns: number
  mediumVulns: number
  cveTotal: number
  cveCriticalHigh: number
  tlsCertificatesScanned: number
  tlsExpiredOrMismatched: number
  tlsSelfSigned: number
  secretsExposed: number
  trufflehogScanned: boolean
  trufflehogFindings: number
  githubSecretHuntScanned: boolean
  githubSecretFindings: number
  supplyChainScanned: boolean
  supplyChainMaliciousOrSuspicious: number
  graphqlScanned: boolean
  graphqlFindings: number
  webCachePoisonFindings: number
  jsReconScanned: boolean
  jsReconFindings: number
  aiSurfaceScanned: boolean
  aiSurfaceFindings: number
  attackSurfaceSize: number
  hasReconNodes: boolean
  hasVulnScanEvidence: boolean
  remediationsTotal: number
}

export interface ComplianceControlSpec {
  id: string
  framework: ComplianceFrameworkId
  code: string
  title: string
  category: 'tls' | 'vuln_mgmt' | 'secrets' | 'supply_chain' | 'web_api' | 'attack_surface' | 'ai_security'
  requiresHttpSurface?: boolean
  evaluate: (ev: ComplianceEvidenceSnapshot) => {
    status: ControlStatus
    evidence: string
    findingCount: number
  }
}

export interface EvaluatedControl {
  id: string
  code: string
  title: string
  category: ComplianceControlSpec['category']
  status: ControlStatus
  evidence: string
  findingCount: number
}

export interface EvaluatedFrameworkSummary {
  framework: ComplianceFrameworkId
  label: string
  version: string
  counts: Record<ControlStatus, number>
  totalControls: number
  controls: EvaluatedControl[]
}

export interface ComplianceEvaluationReport {
  generatedFrom: 'report_data'
  frameworks: EvaluatedFrameworkSummary[]
}
