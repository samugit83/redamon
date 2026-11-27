import type { ReportData } from '@/lib/report/reportData'
import { ALL_FRAMEWORK_IDS, COMPLIANCE_CONTROLS, FRAMEWORK_META } from './catalogs'
import type {
  ComplianceEvaluationReport,
  ComplianceEvidenceSnapshot,
  ComplianceFrameworkId,
  ControlStatus,
  EvaluatedControl,
  EvaluatedFrameworkSummary,
} from './types'

export function evidenceFromReportData(data: ReportData): ComplianceEvidenceSnapshot {
  const roeForbidden = (data.project.roeForbiddenCategories || []).map(c => c.toLowerCase())
  const totalVulns = data.metrics.totalVulnerabilities ?? 0
  const remediationsTotal = data.metrics.totalRemediations ?? 0
  // Recon nodes alone are not evidence that a vulnerability scan ran: a clean scan
  // with zero findings stays `no_evidence` rather than claiming a `pass`.
  const hasVulnScanEvidence =
    totalVulns > 0 ||
    remediationsTotal > 0 ||
    (data.vulnerabilities?.severityDistribution?.length ?? 0) > 0

  return {
    isIpOnlyMode: Boolean(data.project.ipMode),
    roeForbiddenCategories: roeForbidden,
    totalVulnerabilities: totalVulns,
    criticalHighVulns: (data.metrics.criticalCount ?? 0) + (data.metrics.highCount ?? 0),
    mediumVulns: data.metrics.mediumCount ?? 0,
    cveTotal: data.metrics.totalCves ?? 0,
    cveCriticalHigh: (data.metrics.cveCriticalCount ?? 0) + (data.metrics.cveHighCount ?? 0),
    tlsCertificatesScanned: data.tlsx?.totalCertificates ?? 0,
    tlsExpiredOrMismatched: (data.tlsx?.expired ?? 0) + (data.tlsx?.mismatched ?? 0),
    tlsSelfSigned: data.tlsx?.selfSigned ?? 0,
    secretsExposed: data.secrets?.total ?? 0,
    trufflehogScanned: (data.trufflehog?.sources?.length ?? 0) > 0 || (data.trufflehog?.totalFindings ?? 0) > 0,
    trufflehogFindings: data.trufflehog?.totalFindings ?? 0,
    githubSecretHuntScanned: (data.githubSecrets?.reposScanned ?? 0) > 0 || (data.githubSecrets?.totalSecrets ?? 0) > 0,
    githubSecretFindings: data.githubSecrets?.totalSecrets ?? 0,
    supplyChainScanned: (data.supplyChain?.totalPackages ?? 0) > 0 || (data.supplyChain?.findings?.length ?? 0) > 0,
    supplyChainMaliciousOrSuspicious:
      (data.supplyChain?.maliciousCount ?? 0) + (data.supplyChain?.suspiciousCount ?? 0),
    graphqlScanned: (data.graphqlScan?.endpointsTested ?? 0) > 0 || (data.graphqlScan?.totalFindings ?? 0) > 0,
    graphqlFindings: data.graphqlScan?.totalFindings ?? 0,
    webCachePoisonFindings: data.webCachePoison?.totalFindings ?? 0,
    jsReconScanned: Boolean(data.jsRecon?.coverage?.recorded) || (data.jsRecon?.totalFindings ?? 0) > 0,
    jsReconFindings: data.jsRecon?.totalFindings ?? 0,
    aiSurfaceScanned: (data.aiSurface?.totalAiEndpoints ?? 0) > 0 || (data.aiSurface?.attackToolsRun?.length ?? 0) > 0,
    aiSurfaceFindings: data.aiSurface?.attackFindings?.length ?? 0,
    attackSurfaceSize: data.metrics.attackSurfaceSize ?? 0,
    hasReconNodes: (data.graphOverview?.totalNodes ?? 0) > 0,
    hasVulnScanEvidence,
    remediationsTotal,
  }
}

export function evaluateCompliance(
  evidence: ComplianceEvidenceSnapshot,
  frameworkIds: readonly ComplianceFrameworkId[] = ALL_FRAMEWORK_IDS,
): ComplianceEvaluationReport {
  const frameworks: EvaluatedFrameworkSummary[] = frameworkIds.map((fw) => {
    const specs = COMPLIANCE_CONTROLS.filter(c => c.framework === fw)
    const counts: Record<ControlStatus, number> = {
      fail: 0,
      pass: 0,
      no_evidence: 0,
      out_of_scope: 0,
    }
    const controls: EvaluatedControl[] = specs.map((spec) => {
      const res = spec.evaluate(evidence)
      counts[res.status] += 1
      return {
        id: spec.id,
        code: spec.code,
        title: spec.title,
        category: spec.category,
        status: res.status,
        evidence: res.evidence,
        findingCount: res.findingCount,
      }
    })
    const meta = FRAMEWORK_META[fw]
    return {
      framework: fw,
      label: meta.label,
      version: meta.version,
      counts,
      totalControls: controls.length,
      controls,
    }
  })

  return {
    generatedFrom: 'report_data',
    frameworks,
  }
}
