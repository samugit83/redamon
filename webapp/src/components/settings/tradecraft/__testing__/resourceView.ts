/** Fixtures of the 2.0 views the Tradecraft tab renders, for its component tests. */
import type { JobView, ResourceView } from '@/lib/tradecraft/client'

export const RESOURCE: ResourceView = {
  id: 'r1', name: 'Lab Wiki', slug: 'lab-wiki', url: 'https://wiki.tc-fixture.test/', enabled: true, resourceType: 'mkdocs-wiki',
  forcedType: '', storageMode: 'live', llmModel: 'm', githubTokenOverride: '', hasLogin: false, priority: 'normal', mapVersion: 3, overrides: {},
  summary: 's', summarySource: 'generated', summaryLocked: false, report: null, lastVerifiedAt: null, lastRefreshedAt: null,
  lastError: '', entryCount: 12, stale: false, job: null, createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-01T00:00:00.000Z',
}

export const job = (over: Partial<JobView>): JobView => ({
  id: 'j1', kind: 'refresh', status: 'running', stage: '', progress: {}, errorCode: '', cancelRequested: false,
  createdAt: '2026-11-16T09:00:00.000Z', startedAt: null, finishedAt: null, ...over,
})
