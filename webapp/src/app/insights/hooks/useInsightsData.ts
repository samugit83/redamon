'use client'

import { useQuery, useQueryClient } from '@tanstack/react-query'
import type {
  GraphOverviewData,
  VulnerabilityData,
  AttackSurfaceData,
  ActivityData,
  AttackChainsData,
  PipelineStatusData,
} from '../types'
import type { SessionsData } from '@/lib/websocket-types'
import { fetchJson } from '@/lib/apiError'
import { useSessionsAccess } from '@/hooks/useActiveSessions'

export function useGraphOverview(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'graph-overview', projectId],
    queryFn: () => fetchJson<GraphOverviewData>(`/api/analytics/graph-overview?projectId=${projectId}`, undefined, 'Failed to load the graph overview'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function useVulnerabilities(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'vulnerabilities', projectId],
    queryFn: () => fetchJson<VulnerabilityData>(`/api/analytics/vulnerabilities?projectId=${projectId}`, undefined, 'Failed to load vulnerabilities'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function useAttackSurface(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'attack-surface', projectId],
    queryFn: () => fetchJson<AttackSurfaceData>(`/api/analytics/attack-surface?projectId=${projectId}`, undefined, 'Failed to load the attack surface'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function useActivity(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'activity', projectId],
    queryFn: () => fetchJson<ActivityData>(`/api/analytics/activity?projectId=${projectId}`, undefined, 'Failed to load activity'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function useAttackChains(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'attack-chains', projectId],
    queryFn: () => fetchJson<AttackChainsData>(`/api/analytics/attack-chains?projectId=${projectId}`, undefined, 'Failed to load attack chains'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function usePipelineStatus(projectId: string | null) {
  return useQuery({
    queryKey: ['insights', 'pipeline-status', projectId],
    queryFn: () => fetchJson<PipelineStatusData>(`/api/analytics/pipeline-status?projectId=${projectId}`, undefined, 'Failed to load pipeline status'),
    enabled: !!projectId,
    staleTime: 15_000,
  })
}

export function useActiveSessions() {
  const access = useSessionsAccess()
  return useQuery({
    queryKey: ['insights', 'sessions'],
    queryFn: () => fetchJson<SessionsData>('/api/agent/sessions', undefined, 'Failed to load agent sessions'),
    enabled: access === 'allowed',
    staleTime: 10_000,
    refetchInterval: 15_000,
  })
}

export function useRefreshInsights() {
  const queryClient = useQueryClient()
  return () => queryClient.invalidateQueries({ queryKey: ['insights'] })
}
