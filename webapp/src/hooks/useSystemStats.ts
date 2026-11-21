'use client'

import { useQuery } from '@tanstack/react-query'
import { readApiError } from '@/lib/apiError'

// Shape returned by the orchestrator GET /system/stats (Part 5).
export interface SystemStats {
  mem: {
    host_total: number
    available: number
    os_headroom: number
    service_baseline: number
    scan_pool: number
    /** Every reservation: scans' and Kali sandboxes' bytes together. */
    committed: number
    /** Scans only. */
    active_scans: number
    // Kali sandboxes (group 1); absent from an orchestrator older than the sandbox class.
    active_sandboxes?: number
    sandbox_committed?: number
    sandbox_envelope?: number
    remaining_for_new: number
    pressure: 'ok' | 'warn' | 'critical'
  }
  cpu: { percent: number; cores: number }
  disk?: { total: number; free: number } | null
  governor_enabled: boolean
}

// Shared 5s poll for the top-bar RAM chip and bottom-bar meters. The single
// queryKey dedupes both consumers to one request.
export function useSystemStats() {
  return useQuery<SystemStats>({
    queryKey: ['system', 'stats'],
    queryFn: async () => {
      const res = await fetch('/api/system/stats', { cache: 'no-store' })
      if (!res.ok) throw await readApiError(res, 'Failed to fetch system stats')
      return res.json()
    },
    refetchInterval: 5_000,
    staleTime: 4_000,
    retry: false,
  })
}

export const GB = 1024 ** 3
export const toGB = (bytes: number, digits = 1) => (bytes / GB).toFixed(digits)
