export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type DeltaAlertChannelType = 'webhook' | 'slack'

export interface StoredDeltaAlertChannel {
  id: string
  type: DeltaAlertChannelType
  name: string
  url: string
  enabled: boolean
  secret?: string
}

export interface MaskedDeltaAlertChannel {
  id: string
  type: DeltaAlertChannelType
  name: string
  url: string
  enabled: boolean
  hasSecret: boolean
  maskedSecret: string | null
}

export interface DeltaAlertThresholds {
  minVulnSeverity: AlertSeverity
  alertOnNewPorts: boolean
  alertOnNewHosts: boolean
}

export interface DeltaAlertTopItem {
  category: 'vulnerability' | 'cve' | 'port' | 'host'
  severity: AlertSeverity
  title: string
  target?: string
}

export interface DeltaAlertSummaryPayload {
  event: 'recon.delta' | 'recon.delta.test'
  projectId: string
  projectName: string
  scanJobId: string | null
  scheduleId: string | null
  fromVersionId: string | null
  toVersionId: string | null
  triggeredAt: string
  summary: {
    newVulnerabilities: number
    newCves: number
    newlyExposedPorts: number
    newHosts: number
  }
  topItems: DeltaAlertTopItem[]
  deltaPath: string
}
