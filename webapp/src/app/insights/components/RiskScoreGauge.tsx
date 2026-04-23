'use client'

import { useMemo } from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { ChartCard } from './ChartCard'
import type { VulnerabilityData, AttackSurfaceData, GraphOverviewData } from '../types'

interface RiskScoreGaugeProps {
  vulnData: VulnerabilityData | undefined
  surfaceData: AttackSurfaceData | undefined
  graphData: GraphOverviewData | undefined
  exploitSuccessCount: number
  chainFindingsBySeverity: { severity: string; count: number }[] | undefined
  isLoading: boolean
}

function severityWeight(severity: string): number {
  switch (severity?.toLowerCase()) {
    case 'critical': return 40
    case 'high': return 20
    case 'medium': return 5
    case 'low': return 1
    default: return 0
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return '#e53935'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#f59e0b'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Medium'
  if (score >= 20) return 'Low'
  return 'Minimal'
}

export function RiskScoreGauge({ vulnData, surfaceData, graphData, exploitSuccessCount, chainFindingsBySeverity, isLoading }: RiskScoreGaugeProps) {
  useTheme()

  const { score, color, label } = useMemo(() => {
    if (!vulnData) return { score: 0, color: '#22c55e', label: 'N/A' }

    const vulnScore = (vulnData.severityDistribution || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    const cveScore = (vulnData.cveSeverity || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    const gvmExploitScore = (vulnData.exploits?.length || 0) * 100
    const kevScore = (vulnData.exploits?.filter(e => e.cisaKev)?.length || 0) * 120
    const chainExploitScore = exploitSuccessCount * 100
    const chainFindingsScore = (chainFindingsBySeverity || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    const cvesWithCapec = new Set(
      vulnData.cveChains?.filter(c => c.capecId).map(c => c.cveId)
    ).size
    const capecScore = cvesWithCapec * 15
    const secretsScore = (vulnData.githubSecrets?.secrets || 0) * 60
    const sensitiveFilesScore = (vulnData.githubSecrets?.sensitiveFiles || 0) * 30
    const injectableCount = surfaceData?.parameterAnalysis?.reduce(
      (s, p) => s + p.injectable, 0
    ) || 0
    const injectableScore = injectableCount * 25
    const expiredCertScore = (graphData?.certificateHealth?.expired || 0) * 10
    const SEC_HEADERS = [
      'strict-transport-security', 'content-security-policy',
      'x-frame-options', 'x-content-type-options',
    ]
    let missingHeaderScore = 0
    const totalBaseUrls = graphData?.endpointCoverage?.baseUrls || 0
    if (totalBaseUrls > 0 && surfaceData?.securityHeaders) {
      const headerMap = new Map(
        surfaceData.securityHeaders.map(h => [h.name.toLowerCase(), h.count])
      )
      for (const hdr of SEC_HEADERS) {
        const coverage = (headerMap.get(hdr) || 0) / totalBaseUrls
        missingHeaderScore += Math.round((1 - Math.min(coverage, 1)) * 5)
      }
    }

    const raw = vulnScore + cveScore + gvmExploitScore + kevScore
      + chainExploitScore + chainFindingsScore + capecScore
      + secretsScore + sensitiveFilesScore + injectableScore
      + expiredCertScore + missingHeaderScore
    const normalized = Math.min(100, Math.round(15 * Math.log(raw + 1)))

    return {
      score: normalized,
      color: scoreColor(normalized),
      label: scoreLabel(normalized),
    }
  }, [vulnData, surfaceData, graphData, exploitSuccessCount, chainFindingsBySeverity])

  const isEmpty = !vulnData

  const data = [{ name: 'Risk', value: score, fill: color }]

  return (
    <ChartCard title="Risk Score" subtitle={label} isLoading={isLoading} isEmpty={isEmpty}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: 280, padding: '0 0 8px' }}>
        <div style={{ position: 'relative', width: '100%', flex: '1 1 auto' }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              cx="50%"
              cy="50%"
              innerRadius="70%"
              outerRadius="95%"
              startAngle={210}
              endAngle={-30}
              data={data}
              barSize={14}
            >
              <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
              <RadialBar
                background={{ fill: 'var(--border-secondary)' }}
                dataKey="value"
                angleAxisId={0}
                cornerRadius={10}
              />
            </RadialBarChart>
          </ResponsiveContainer>
          {/* Score overlay — centered on the chart */}
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none',
          }}>
            <span style={{ fontSize: 36, fontWeight: 700, lineHeight: 1, color }}>{score}</span>
            <span style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 4 }}>/ 100</span>
          </div>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-tertiary)', textAlign: 'center' }}>
          12 signals: vulns, CVEs, exploits, KEV, chains, secrets, injection &amp; headers
        </div>
      </div>
    </ChartCard>
  )
}
