'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import { TrendingUp } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import {
  useGraphOverview,
  useVulnerabilities,
  useAttackSurface,
  useActivity,
  useAttackChains,
  usePipelineStatus,
  useActiveSessions,
  useRefreshInsights,
} from './hooks/useInsightsData'
import { DashboardHeader } from './components/DashboardHeader'
import { KPICards } from './components/KPICards'
import { SeverityDonut } from './components/SeverityDonut'
import { CvssHistogram } from './components/CvssHistogram'
import { NodeTypeBar } from './components/NodeTypeBar'
import { ConnectedNodesBar } from './components/ConnectedNodesBar'
import { ServicesPie } from './components/ServicesPie'
import { PortDistributionBar } from './components/PortDistributionBar'
import { TechnologyTreemap } from './components/TechnologyTreemap'
import { DnsRecordsPie } from './components/DnsRecordsPie'
import { SecurityHeadersBar } from './components/SecurityHeadersBar'
import { HeaderInsightsPie } from './components/HeaderInsightsPie'
import { EndpointCategoriesBar } from './components/EndpointCategoriesBar'
import { EndpointTypePie } from './components/EndpointTypePie'
import { ParameterAnalysisBar } from './components/ParameterAnalysisBar'
import { CdnVsDirectPie } from './components/CdnVsDirectPie'
import { IpConcentrationBar } from './components/IpConcentrationBar'
import { TimelineArea } from './components/TimelineArea'
import { AgentActivityLine } from './components/AgentActivityLine'
import { AttackChainCards } from './components/AttackChainCards'
import { RemediationStatusBar } from './components/RemediationStatusBar'
import { TechCveBar } from './components/TechCveBar'
import { AttackPatternsBar } from './components/AttackPatternsBar'
import { ExploitsCard } from './components/ExploitsCard'
import { FindingsBySource } from './components/FindingsBySource'
import { FindingsByCategory } from './components/FindingsByCategory'
import { VulnSourcePie } from './components/VulnSourcePie'
import { CweBreakdownBar } from './components/CweBreakdownBar'
import { VulnTargetsBar } from './components/VulnTargetsBar'
import { GvmRemediationPie } from './components/GvmRemediationPie'
import { CisaKevGauge } from './components/CisaKevGauge'
import { ChainSuccessRatePie } from './components/ChainSuccessRatePie'
import { FindingTypesBar } from './components/FindingTypesBar'
import { PhaseProgressionBar } from './components/PhaseProgressionBar'
import { ExploitSuccessesCard } from './components/ExploitSuccessesCard'
import { GvmExploitsCard } from './components/GvmExploitsCard'
import { ChainFailuresBar } from './components/ChainFailuresBar'
import { ChainDecisionsPie } from './components/ChainDecisionsPie'
import { TargetsAttackedBar } from './components/TargetsAttackedBar'
import { TopFindingsTable } from './components/TopFindingsTable'
import { SecurityPostureRadar } from './components/SecurityPostureRadar'
import { RiskScoreGauge } from './components/RiskScoreGauge'
import { AttackKillChainFunnel } from './components/AttackKillChainFunnel'
import { CvssExploitScatter } from './components/CvssExploitScatter'
import { VulnCategoryRose } from './components/VulnCategoryRose'
import { TopVulnTechBubble } from './components/TopVulnTechBubble'
import { AttackFlowSankey } from './components/AttackFlowSankey'
import { AttackChainSankey } from './components/AttackChainSankey'
import { VulnAccumulationArea } from './components/VulnAccumulationArea'
import { formatNumber } from './utils/formatters'
import styles from './page.module.css'

export default function InsightsPage() {
  const { projectId, currentProject, isLoading: projectLoading } = useProject()
  const router = useRouter()
  const refresh = useRefreshInsights()

  const graphOverview = useGraphOverview(projectId)
  const vulns = useVulnerabilities(projectId)
  const surface = useAttackSurface(projectId)
  const activity = useActivity(projectId)
  const attackChains = useAttackChains(projectId)
  const pipeline = usePipelineStatus(projectId)
  const sessions = useActiveSessions()

  const isAnyLoading = graphOverview.isLoading || vulns.isLoading || surface.isLoading || activity.isLoading

  const kpis = useMemo(() => {
    const go = graphOverview.data
    const v = vulns.data
    const a = activity.data
    const ac = attackChains.data
    return [
      { label: 'Total Nodes', value: go?.totalNodes || 0 },
      { label: 'Vulns & CVEs', value: (v?.severityDistribution?.reduce((s, d) => s + d.count, 0) || 0) + (v?.cveSeverity?.reduce((s, d) => s + d.count, 0) || 0), accent: 'var(--status-error)' },
      { label: 'Attack Chains', value: ac?.chains?.length || 0, accent: 'var(--accent-primary)' },
      { label: 'Exploit Successes', value: ac?.exploitSuccesses?.length || 0, accent: 'var(--status-error)' },
      { label: 'Chain Findings', value: ac?.findingsByType?.reduce((s, d) => s + d.count, 0) || 0, accent: 'var(--status-warning)' },
      { label: 'Agent Sessions', value: a?.conversations.total || 0, accent: 'var(--accent-secondary)' },
    ]
  }, [graphOverview.data, vulns.data, activity.data, attackChains.data])

  // No project selected
  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div className={styles.noProject}>
          <TrendingUp size={48} strokeWidth={1.5} />
          <div className={styles.noProjectTitle}>No Project Selected</div>
          <div className={styles.noProjectText}>
            Select a project from the header to view insights and analytics.
          </div>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      {/* Header */}
      <DashboardHeader
        projectName={currentProject?.name || null}
        targetDomain={
          currentProject?.domainBatchMode
            // A batch project has no single targetDomain; name its groups so the
            // header is not blank.
            ? `${currentProject.domainBatchDomains?.length ?? 0} domains`
            : currentProject?.targetDomain || null
        }
        ipMode={currentProject?.ipMode || false}
        isLoading={isAnyLoading}
        onRefresh={refresh}
      />

      {/* KPI Cards + Pipeline Status */}
      <KPICards items={kpis} isLoading={graphOverview.isLoading} pipeline={pipeline.data} sessions={sessions.data} />

      {/* Executive Summary */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Executive Summary</div>
        <div className={styles.grid3}>
          <SecurityPostureRadar graphData={graphOverview.data} vulnData={vulns.data} surfaceData={surface.data} exploitSuccessCount={attackChains.data?.exploitSuccesses?.length || 0} chainFindingsCount={attackChains.data?.findingsByType?.reduce((s: number, d: { count: number }) => s + d.count, 0) || 0} isLoading={graphOverview.isLoading || vulns.isLoading || surface.isLoading || attackChains.isLoading} />
          <RiskScoreGauge vulnData={vulns.data} surfaceData={surface.data} graphData={graphOverview.data} exploitSuccessCount={attackChains.data?.exploitSuccesses?.length || 0} chainFindingsBySeverity={attackChains.data?.findingsBySeverity} isLoading={vulns.isLoading || surface.isLoading || graphOverview.isLoading || attackChains.isLoading} />
          <AttackKillChainFunnel data={attackChains.data?.phaseProgression} isLoading={attackChains.isLoading} />
        </div>
      </div>

      {/* Attack Chains & Exploits */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Attack Chains & Exploits</div>
        <div className={styles.grid4}>
          <ChainSuccessRatePie data={attackChains.data?.chainSuccessRate} isLoading={attackChains.isLoading} />
          <FindingTypesBar data={attackChains.data?.findingsByType} isLoading={attackChains.isLoading} />
          <TargetsAttackedBar data={attackChains.data?.targetsAttacked} isLoading={attackChains.isLoading} />
          <PhaseProgressionBar data={attackChains.data?.phaseProgression} isLoading={attackChains.isLoading} />
        </div>
        <div className={styles.grid4}>
          <div style={{ gridColumn: 'span 2' }}>
            <ExploitSuccessesCard data={attackChains.data?.exploitSuccesses} isLoading={attackChains.isLoading} />
          </div>
          <SeverityDonut data={attackChains.data?.findingsBySeverity} isLoading={attackChains.isLoading} title="Finding Severity" />
          <ChainDecisionsPie data={attackChains.data?.decisions} isLoading={attackChains.isLoading} />
        </div>
        {(attackChains.data?.gvmExploits?.length ?? 0) > 0 && (
          <div className={styles.gridFull}>
            <GvmExploitsCard data={attackChains.data?.gvmExploits} isLoading={attackChains.isLoading} />
          </div>
        )}
        <div className={styles.gridFull}>
          <TopFindingsTable data={attackChains.data?.topFindings} isLoading={attackChains.isLoading} />
        </div>
        <div className={styles.sankeyRow}>
          <AttackFlowSankey data={vulns.data?.cveChains} isLoading={vulns.isLoading} />
          <AttackChainSankey data={attackChains.data?.attackFlowRows} isLoading={attackChains.isLoading} />
        </div>
        <div className={styles.chainRow}>
          <AttackChainCards
            chains={attackChains.data?.chains}
            toolUsage={attackChains.data?.chainToolUsage}
            isLoading={attackChains.isLoading}
          />
          <ChainFailuresBar data={attackChains.data?.failuresByType} isLoading={attackChains.isLoading} />
        </div>
      </div>

      {/* Attack Surface */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Attack Surface</div>
        {/* All 6 stat cards in one row */}
        <div className={styles.surfaceStats}>
          <div className="statCard">
            <div className="statLabel">Subdomains</div>
            <div className="statValue">{formatNumber(graphOverview.data?.subdomainStats.total || 0)}</div>
            <div className={styles.statDetail}>{graphOverview.data?.subdomainStats.resolved || 0} resolved · {graphOverview.data?.subdomainStats.uniqueIps || 0} unique IPs</div>
          </div>
          <div className="statCard">
            <div className="statLabel">Endpoints</div>
            <div className="statValue">{formatNumber(graphOverview.data?.endpointCoverage.endpoints || 0)}</div>
            <div className={styles.statDetail}>{graphOverview.data?.endpointCoverage.baseUrls || 0} base URLs · {graphOverview.data?.endpointCoverage.parameters || 0} params</div>
          </div>
          <div className="statCard">
            <div className="statLabel">Certificates</div>
            <div className="statValue">{formatNumber(graphOverview.data?.certificateHealth.total || 0)}</div>
            <div className={styles.statDetail}>
              {graphOverview.data?.certificateHealth.expired ? <span style={{ color: 'var(--status-error)' }}>{graphOverview.data.certificateHealth.expired} expired</span> : '0 expired'}
              {' · '}
              {graphOverview.data?.certificateHealth.expiringSoon ? <span style={{ color: 'var(--status-warning)' }}>{graphOverview.data.certificateHealth.expiringSoon} expiring</span> : '0 expiring'}
            </div>
          </div>
          <div className="statCard">
            <div className="statLabel">IPs</div>
            <div className="statValue">{formatNumber(graphOverview.data?.infrastructureStats?.totalIps || 0)}</div>
            <div className={styles.statDetail}>{graphOverview.data?.infrastructureStats?.ipv4 || 0} IPv4 · {graphOverview.data?.infrastructureStats?.ipv6 || 0} IPv6</div>
          </div>
          <div className="statCard">
            <div className="statLabel">CDN Coverage</div>
            <div className="statValue">{formatNumber(graphOverview.data?.infrastructureStats?.cdnCount || 0)}</div>
            <div className={styles.statDetail}>{(graphOverview.data?.infrastructureStats?.totalIps || 0) - (graphOverview.data?.infrastructureStats?.cdnCount || 0)} direct · {graphOverview.data?.infrastructureStats?.uniqueCdns || 0} providers</div>
          </div>
          <div className="statCard">
            <div className="statLabel">ASN Diversity</div>
            <div className="statValue">{formatNumber(graphOverview.data?.infrastructureStats?.uniqueAsns || 0)}</div>
            <div className={styles.statDetail}>unique autonomous systems</div>
          </div>
        </div>
        {/* Charts: 4 per row */}
        <div className={styles.grid4}>
          <ServicesPie data={surface.data?.services} isLoading={surface.isLoading} />
          <PortDistributionBar data={surface.data?.ports} isLoading={surface.isLoading} />
          <TechnologyTreemap data={surface.data?.technologies} isLoading={surface.isLoading} />
          <DnsRecordsPie data={surface.data?.dnsRecords} isLoading={surface.isLoading} />
        </div>
        <div className={styles.grid4}>
          <SecurityHeadersBar data={surface.data?.securityHeaders} isLoading={surface.isLoading} />
          <HeaderInsightsPie data={surface.data?.headerCategories} isLoading={surface.isLoading} />
          <CdnVsDirectPie data={surface.data?.cdnDistribution} isLoading={surface.isLoading} />
          <EndpointCategoriesBar data={surface.data?.endpointCategories} isLoading={surface.isLoading} />
        </div>
        <div className={styles.grid3}>
          <EndpointTypePie data={surface.data?.endpointTypes} isLoading={surface.isLoading} />
          <ParameterAnalysisBar data={surface.data?.parameterAnalysis} isLoading={surface.isLoading} />
          <IpConcentrationBar data={surface.data?.ipConcentration} isLoading={surface.isLoading} />
        </div>
      </div>



      {/* Vulnerabilities & CVE Intelligence */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Vulnerabilities & CVE Intelligence</div>
        <div className={styles.grid4}>
          <SeverityDonut data={vulns.data?.severityDistribution} isLoading={vulns.isLoading} title="Vulnerability Severity" />
          <SeverityDonut data={vulns.data?.cveSeverity} isLoading={vulns.isLoading} title="CVE Severity" />
          <CvssHistogram data={vulns.data?.cvssHistogram} isLoading={vulns.isLoading} />
          <VulnSourcePie data={vulns.data?.findings} isLoading={vulns.isLoading} />
        </div>
        <div className={styles.grid4}>
          <FindingsBySource data={vulns.data?.findings} isLoading={vulns.isLoading} />
          <FindingsByCategory data={vulns.data?.findings} isLoading={vulns.isLoading} />
          <CweBreakdownBar data={vulns.data?.cveChains} isLoading={vulns.isLoading} />
          <VulnTargetsBar data={vulns.data?.findings} isLoading={vulns.isLoading} />
        </div>
        <div className={styles.grid2}>
          <TechCveBar data={vulns.data?.cveChains} isLoading={vulns.isLoading} />
          <AttackPatternsBar data={vulns.data?.cveChains} isLoading={vulns.isLoading} />
        </div>
        <div className={styles.grid3}>
          <CvssExploitScatter cveChains={vulns.data?.cveChains} exploits={vulns.data?.exploits} isLoading={vulns.isLoading} />
          <VulnCategoryRose data={vulns.data?.findings} isLoading={vulns.isLoading} />
          <TopVulnTechBubble data={vulns.data?.cveChains} isLoading={vulns.isLoading} />
        </div>
        {/* Conditional row: Exploits + GVM Remediation + CISA KEV */}
        {((vulns.data?.exploits?.length ?? 0) > 0 || (vulns.data?.gvmRemediation?.length ?? 0) > 0) && (
          <div className={styles.grid3}>
            {(vulns.data?.exploits?.length ?? 0) > 0 && (
              <ExploitsCard data={vulns.data?.exploits} isLoading={vulns.isLoading} />
            )}
            {(vulns.data?.gvmRemediation?.length ?? 0) > 0 && (
              <GvmRemediationPie data={vulns.data?.gvmRemediation} isLoading={vulns.isLoading} />
            )}
            {(vulns.data?.exploits?.length ?? 0) > 0 && (
              <CisaKevGauge data={vulns.data?.exploits} isLoading={vulns.isLoading} />
            )}
          </div>
        )}
      </div>

      {/* Graph Overview */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Graph Overview</div>
        <div className={styles.grid2}>
          <NodeTypeBar data={graphOverview.data?.nodeCounts} isLoading={graphOverview.isLoading} />
          <ConnectedNodesBar data={graphOverview.data?.topConnected} isLoading={graphOverview.isLoading} />
        </div>
      </div>

      {/* Activity & Timeline */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Activity & Timeline</div>
        <div className={styles.grid3}>
          <TimelineArea
            data={activity.data?.timeline.remediations}
            isLoading={activity.isLoading}
            title="Remediations Over Time"
            color="#e53935"
          />
          <AgentActivityLine
            data={activity.data?.timeline.conversations}
            isLoading={activity.isLoading}
          />
          <RemediationStatusBar
            data={activity.data?.remediations.byStatus}
            isLoading={activity.isLoading}
          />
        </div>
        <div className={styles.gridFull}>
          <VulnAccumulationArea data={activity.data?.timeline.remediations} isLoading={activity.isLoading} />
        </div>
      </div>

      {/* GitHub Secrets (conditional) */}
      {vulns.data?.githubSecrets && (vulns.data.githubSecrets.repos > 0 || vulns.data.githubSecrets.secrets > 0) && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>GitHub Intelligence</div>
          <div className={styles.secretsGrid}>
            <div className="statCard">
              <div className="statLabel">Repos Scanned</div>
              <div className="statValue">{formatNumber(vulns.data.githubSecrets.repos)}</div>
            </div>
            <div className="statCard">
              <div className="statLabel">Secrets Found</div>
              <div className="statValue" style={{ color: 'var(--status-error)' }}>
                {formatNumber(vulns.data.githubSecrets.secrets)}
              </div>
            </div>
            <div className="statCard">
              <div className="statLabel">Sensitive Files</div>
              <div className="statValue" style={{ color: 'var(--status-warning)' }}>
                {formatNumber(vulns.data.githubSecrets.sensitiveFiles)}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
