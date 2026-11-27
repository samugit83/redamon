'use client'

import { useCallback, useEffect, useState } from 'react'
import { Bell, Loader2, Plus, Send, Trash2 } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { fetchJson, toApiError } from '@/lib/apiError'
import { useRefusal } from '@/hooks/useRefusal'
import styles from './DeltaAlertsPanel.module.css'

type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type ChannelType = 'webhook' | 'slack'

interface ChannelDraft {
  id: string
  type: ChannelType
  name: string
  url: string
  enabled: boolean
  secret: string
  hasSecret: boolean
  persisted: boolean
}

interface OutboxHistoryRow {
  id: string
  channelName: string
  channelType: string
  status: string
  attempts: number
  maxAttempts: number
  lastStatusCode: number | null
  lastError: string | null
  sentAt: string | null
  createdAt: string
  deltaPath: string | null
}

interface ApiConfig {
  enabled: boolean
  minVulnSeverity: AlertSeverity
  alertOnNewPorts: boolean
  alertOnNewHosts: boolean
  channels: Array<{
    id: string
    type: ChannelType
    name: string
    url: string
    enabled: boolean
    hasSecret: boolean
    maskedSecret: string | null
  }>
}

function fmtTime(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

export function DeltaAlertsPanel({ projectId }: { projectId: string | null }) {
  const { alertError } = useAlertModal()
  const toast = useToast()
  const editRefusal = useRefusal('recon:schedule', projectId)?.text ?? null

  const [enabled, setEnabled] = useState(false)
  const [minVulnSeverity, setMinVulnSeverity] = useState<AlertSeverity>('high')
  const [alertOnNewPorts, setAlertOnNewPorts] = useState(true)
  const [alertOnNewHosts, setAlertOnNewHosts] = useState(true)
  const [channels, setChannels] = useState<ChannelDraft[]>([])
  const [history, setHistory] = useState<OutboxHistoryRow[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [dirty, setDirty] = useState(false)

  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      const data = await fetchJson<{ config?: ApiConfig; history?: OutboxHistoryRow[] }>(
        `/api/projects/${projectId}/delta-alerts`,
        undefined,
        'Failed to load delta alerts',
      )
      if (!data?.config) return
      setEnabled(Boolean(data.config.enabled))
      setMinVulnSeverity(data.config.minVulnSeverity ?? 'high')
      setAlertOnNewPorts(Boolean(data.config.alertOnNewPorts))
      setAlertOnNewHosts(Boolean(data.config.alertOnNewHosts))
      setChannels(
        (data.config.channels ?? []).map((ch) => ({
          id: ch.id,
          type: ch.type,
          name: ch.name,
          url: ch.url,
          enabled: ch.enabled,
          secret: ch.maskedSecret ?? '',
          hasSecret: ch.hasSecret,
          persisted: true,
        })),
      )
      setHistory(Array.isArray(data.history) ? data.history : [])
      setDirty(false)
    } catch {
      // Leave panel usable with default disabled state if API is unavailable.
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    load()
  }, [load])

  const addChannel = () => {
    if (channels.length >= 10) return
    const id = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `ch-${Date.now()}-${channels.length}`
    setChannels((prev) => [
      ...prev,
      {
        id,
        type: 'webhook',
        name: `Channel ${prev.length + 1}`,
        url: '',
        enabled: true,
        secret: '',
        hasSecret: false,
        persisted: false,
      },
    ])
    setDirty(true)
  }

  const updateChannel = (id: string, patch: Partial<ChannelDraft>) => {
    setChannels((prev) => prev.map((c) => (c.id === id ? { ...c, ...patch } : c)))
    setDirty(true)
  }

  const removeChannel = (id: string) => {
    setChannels((prev) => prev.filter((c) => c.id !== id))
    setDirty(true)
  }

  const handleSave = async () => {
    if (!projectId) return
    setSaving(true)
    try {
      const payload = {
        enabled,
        minVulnSeverity,
        alertOnNewPorts,
        alertOnNewHosts,
        channels: channels.map((c) => ({
          id: c.id,
          type: c.type,
          name: c.name,
          url: c.url,
          enabled: c.enabled,
          ...(c.type === 'webhook' ? { secret: c.secret } : {}),
        })),
      }
      await fetchJson(
        `/api/projects/${projectId}/delta-alerts`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        },
        'Failed to save delta alert settings',
      )
      toast.info('Delta alert settings saved')
      await load()
    } catch (err) {
      alertError(toApiError(err, 'Failed to save delta alert settings').message, 'Delta alerts not saved')
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async (channelId?: string) => {
    if (!projectId) return
    if (dirty) {
      alertError('Save your alert channel changes before sending a test alert.', 'Unsaved changes')
      return
    }
    setTestingId(channelId ?? '__all__')
    try {
      const res = await fetchJson<{
        ok: boolean
        results: Array<{ channelName: string; ok: boolean; statusCode: number | null; error: string | null }>
      }>(
        `/api/projects/${projectId}/delta-alerts/test`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(channelId ? { channelId } : {}),
        },
        'Failed to send test alert',
      )
      if (res.ok) {
        toast.info('Test delta alert delivered')
      } else {
        const failed = res.results.filter((r) => !r.ok)
        const summary = failed.map((f) => `${f.channelName}: ${f.error || `HTTP ${f.statusCode}`}`).join('; ')
        alertError(summary || 'One or more channels rejected the test alert', 'Test alert failed')
      }
    } catch (err) {
      alertError(toApiError(err, 'Failed to send test alert').message, 'Test alert failed')
    } finally {
      setTestingId(null)
    }
  }

  if (!projectId) return null

  return (
    <section className={styles.panel}>
      <div className={styles.headerRow}>
        <h4 className={styles.heading}>
          <Bell size={13} />
          Scheduled scan delta alerts
          {loading && <Loader2 size={12} className={styles.spinner} />}
        </h4>
        <div className={styles.headerActions}>
          <button
            type="button"
            className={styles.btn}
            onClick={() => handleTest()}
            disabled={!!editRefusal || saving || !!testingId || channels.filter((c) => c.persisted && c.enabled).length === 0}
            title={editRefusal ?? 'Send a test alert to all enabled channels'}
          >
            <Send size={12} />
            Test all
          </button>
          <button
            type="button"
            className={styles.primaryBtn}
            onClick={handleSave}
            disabled={!!editRefusal || saving}
            title={editRefusal ?? undefined}
          >
            {saving ? 'Saving...' : 'Save alerts'}
          </button>
        </div>
      </div>

      <p className={styles.hint}>
        Notify webhooks or Slack after a scheduled full recon completes with new findings above threshold.
      </p>

      <div className={styles.controlsRow}>
        <label className={styles.checkLabel}>
          <input
            type="checkbox"
            checked={enabled}
            disabled={!!editRefusal}
            onChange={(e) => {
              setEnabled(e.target.checked)
              setDirty(true)
            }}
          />
          Enable delta alerts
        </label>

        <label className={styles.fieldLabel}>
          Min severity
          <select
            className={styles.select}
            value={minVulnSeverity}
            disabled={!!editRefusal}
            onChange={(e) => {
              setMinVulnSeverity(e.target.value as AlertSeverity)
              setDirty(true)
            }}
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>

        <label className={styles.checkLabel}>
          <input
            type="checkbox"
            checked={alertOnNewPorts}
            disabled={!!editRefusal}
            onChange={(e) => {
              setAlertOnNewPorts(e.target.checked)
              setDirty(true)
            }}
          />
          New open ports
        </label>

        <label className={styles.checkLabel}>
          <input
            type="checkbox"
            checked={alertOnNewHosts}
            disabled={!!editRefusal}
            onChange={(e) => {
              setAlertOnNewHosts(e.target.checked)
              setDirty(true)
            }}
          />
          New hosts / domains / IPs
        </label>
      </div>

      <div className={styles.channelsBlock}>
        <div className={styles.subHeader}>
          <span>Delivery channels ({channels.length}/10)</span>
          <button
            type="button"
            className={styles.btn}
            onClick={addChannel}
            disabled={!!editRefusal || channels.length >= 10}
            title={editRefusal ?? undefined}
          >
            <Plus size={12} /> Add channel
          </button>
        </div>

        {channels.length === 0 ? (
          <div className={styles.empty}>No alert channels configured.</div>
        ) : (
          <div className={styles.channelList}>
            {channels.map((ch) => (
              <div key={ch.id} className={styles.channelCard}>
                <div className={styles.channelRow}>
                  <input
                    type="checkbox"
                    checked={ch.enabled}
                    disabled={!!editRefusal}
                    onChange={(e) => updateChannel(ch.id, { enabled: e.target.checked })}
                    aria-label={`Enable ${ch.name}`}
                  />
                  <select
                    className={styles.select}
                    value={ch.type}
                    disabled={!!editRefusal}
                    onChange={(e) =>
                      updateChannel(ch.id, {
                        type: e.target.value as ChannelType,
                        secret: '',
                        hasSecret: false,
                      })
                    }
                  >
                    <option value="webhook">Webhook</option>
                    <option value="slack">Slack</option>
                  </select>
                  <input
                    className={styles.input}
                    type="text"
                    value={ch.name}
                    placeholder="Channel name"
                    disabled={!!editRefusal}
                    onChange={(e) => updateChannel(ch.id, { name: e.target.value })}
                  />
                  <input
                    className={styles.urlInput}
                    type="url"
                    value={ch.url}
                    placeholder={ch.type === 'slack' ? 'https://hooks.slack.com/services/...' : 'https://alerts.example/webhook'}
                    disabled={!!editRefusal}
                    onChange={(e) => updateChannel(ch.id, { url: e.target.value })}
                  />
                  {ch.type === 'webhook' && (
                    <input
                      className={styles.input}
                      type="password"
                      value={ch.secret}
                      placeholder={ch.hasSecret ? 'Saved secret (type to replace)' : 'Signing secret (optional)'}
                      disabled={!!editRefusal}
                      onChange={(e) => updateChannel(ch.id, { secret: e.target.value })}
                    />
                  )}
                  <button
                    type="button"
                    className={styles.btn}
                    onClick={() => handleTest(ch.id)}
                    disabled={!!editRefusal || !ch.persisted || testingId === ch.id}
                    title={!ch.persisted ? 'Save first to test' : 'Send test'}
                  >
                    <Send size={12} />
                  </button>
                  <button
                    type="button"
                    className={styles.dangerBtn}
                    onClick={() => removeChannel(ch.id)}
                    disabled={!!editRefusal}
                    aria-label={`Remove ${ch.name}`}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className={styles.historyBlock}>
        <div className={styles.subHeader}>
          <span>Recent deliveries</span>
        </div>
        {history.length === 0 ? (
          <div className={styles.empty}>No delta alerts queued yet.</div>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Time</th>
                <th>Channel</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Result</th>
                <th>Delta</th>
              </tr>
            </thead>
            <tbody>
              {history.map((row) => (
                <tr key={row.id}>
                  <td className={styles.mono}>{fmtTime(row.sentAt || row.createdAt)}</td>
                  <td>{row.channelName || row.channelType}</td>
                  <td>
                    <span className={`${styles.badge} ${styles[`badge_${row.status}`] || ''}`}>
                      {row.status}
                    </span>
                  </td>
                  <td className={styles.mono}>
                    {row.attempts}/{row.maxAttempts}
                  </td>
                  <td className={styles.errCell}>
                    {row.lastError
                      ? row.lastError
                      : row.lastStatusCode
                        ? `HTTP ${row.lastStatusCode}`
                        : '-'}
                  </td>
                  <td>
                    {row.deltaPath ? (
                      <a className={styles.link} href={row.deltaPath}>
                        View delta
                      </a>
                    ) : (
                      '-'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
