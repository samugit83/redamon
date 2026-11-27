'use client'

import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { fetchJson } from '@/lib/apiError'

export interface TrafficRow {
  id: string
  startedAt: string
  source: string
  runId: string | null
  sessionId: string | null
  tool: string | null
  phase: string | null
  method: string
  scheme: string
  host: string
  port: number
  path: string
  query: string | null
  statusCode: number | null
  respBodySize: number
  respContentType: string | null
  responseTimeMs: number | null
  isTls: boolean
  isReplay: boolean
  hasSetCookie: boolean
  hadAuth: boolean
  reflectedParams: boolean
  blocked: boolean
  inScope: boolean
  // A1: the request went to a host a published supply-chain incident names.
  // Null is the normal state and means "no match OR the catalog was never
  // synced" - it is not a statement that the host is clean.
  iocIncidentId: string | null
  iocIncidentUrl: string | null
}

export interface TrafficDetail extends TrafficRow {
  reqHeaders: Record<string, unknown>
  reqBody: string | null
  reqBodyRef: string | null
  reqBodySize: number
  reqContentType: string | null
  respHeaders: Record<string, unknown>
  respBody: string | null
  respBodyRef: string | null
  respBodySha: string | null
  reqBodySha: string | null
  targetIp: string | null
  httpVersion: string | null
  tlsVersion: string | null
  securityHeadersMissing: string[] | null
  cookieFlagIssues: unknown[] | null
  createdAt: string
}

export interface TrafficFilters {
  page: number
  pageSize: number
  sort: string
  dir: 'asc' | 'desc'
  from: string
  to: string
  source: string
  tool: string[]
  sessionId: string
  runId: string
  host: string
  method: string
  statusClass: string
  q: string
  bodyq: string
  hasSetCookie: boolean
  reflected: boolean
  only5xx: boolean
}

export const DEFAULT_FILTERS: TrafficFilters = {
  page: 0,
  pageSize: 50,
  sort: 'startedAt',
  dir: 'desc',
  from: '',
  to: '',
  source: 'both',
  tool: [],
  sessionId: '',
  runId: '',
  host: '',
  method: '',
  statusClass: '',
  q: '',
  bodyq: '',
  hasSetCookie: false,
  reflected: false,
  only5xx: false,
}

export function trafficFiltersToQuery(f: TrafficFilters): string {
  return buildQuery(f)
}

// The filter fields the DELETE-all-matching + export routes understand (excludes
// pagination/sort). Mirrors the server-side buildTrafficWhere inputs.
export function trafficFilterPayload(f: TrafficFilters): Record<string, string> {
  const out: Record<string, string> = {}
  if (f.from) out.from = f.from
  if (f.to) out.to = f.to
  if (f.source && f.source !== 'both') out.source = f.source
  if (f.tool.length) out.tool = f.tool.join(',')
  if (f.sessionId) out.sessionId = f.sessionId
  if (f.runId) out.runId = f.runId
  if (f.host) out.host = f.host
  if (f.method) out.method = f.method
  if (f.statusClass) out.statusClass = f.statusClass
  if (f.q) out.q = f.q
  if (f.bodyq) out.bodyq = f.bodyq
  if (f.hasSetCookie) out.hasSetCookie = 'true'
  if (f.reflected) out.reflected = 'true'
  if (f.only5xx) out.only5xx = 'true'
  return out
}

async function deleteTraffic(projectId: string, body: { ids: string[] } | { filter: Record<string, string> }): Promise<{ deleted: number }> {
  return fetchJson<{ deleted: number }>(`/api/traffic/${projectId}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify('filter' in body && Object.keys(body.filter).length === 0 ? { all: true } : body),
  }, 'Delete failed')
}

export function useDeleteTraffic(projectId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { ids: string[] } | { filter: Record<string, string> }) =>
      deleteTraffic(projectId as string, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['traffic', 'list', projectId] })
      qc.invalidateQueries({ queryKey: ['traffic', 'facets', projectId] })
    },
  })
}

function buildQuery(f: TrafficFilters): string {
  const p = new URLSearchParams()
  p.set('page', String(f.page))
  p.set('pageSize', String(f.pageSize))
  p.set('sort', f.sort)
  p.set('dir', f.dir)
  if (f.from) p.set('from', f.from)
  if (f.to) p.set('to', f.to)
  if (f.source && f.source !== 'both') p.set('source', f.source)
  if (f.tool.length) p.set('tool', f.tool.join(','))
  if (f.sessionId) p.set('sessionId', f.sessionId)
  if (f.runId) p.set('runId', f.runId)
  if (f.host) p.set('host', f.host)
  if (f.method) p.set('method', f.method)
  if (f.statusClass) p.set('statusClass', f.statusClass)
  if (f.q) p.set('q', f.q)
  if (f.bodyq) p.set('bodyq', f.bodyq)
  if (f.hasSetCookie) p.set('hasSetCookie', 'true')
  if (f.reflected) p.set('reflected', 'true')
  if (f.only5xx) p.set('only5xx', 'true')
  return p.toString()
}

export interface TrafficListResponse {
  rows: TrafficRow[]
  total: number
  page: number
  pageSize: number
}

export function useTrafficList(projectId: string | null, filters: TrafficFilters) {
  return useQuery({
    queryKey: ['traffic', 'list', projectId, filters],
    // The URL carries host/q/bodyq filter text (target data): the fallback never quotes it.
    queryFn: () => fetchJson<TrafficListResponse>(`/api/traffic/${projectId}?${buildQuery(filters)}`, undefined, 'Failed to list traffic'),
    enabled: !!projectId,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  })
}

export interface TrafficFacets {
  tools: string[]
  hosts: string[]
  runs: string[]
  sessions: string[]
}

export function useTrafficFacets(projectId: string | null) {
  return useQuery({
    queryKey: ['traffic', 'facets', projectId],
    queryFn: () => fetchJson<TrafficFacets>(`/api/traffic/${projectId}/facets`, undefined, 'Failed to load facets'),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}

export function useTrafficDetail(projectId: string | null, id: string | null) {
  return useQuery({
    queryKey: ['traffic', 'detail', projectId, id],
    queryFn: () => fetchJson<TrafficDetail>(`/api/traffic/${projectId}/${id}`, undefined, 'Failed to load transaction'),
    enabled: !!projectId && !!id,
    staleTime: 60_000,
  })
}
