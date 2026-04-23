'use client'

import { useState } from 'react'
import { ChevronDown, Braces, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface GraphqlScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode?: 'create' | 'edit'
  onRun?: () => void
}

export function GraphqlScanSection({ data, updateField, projectId, mode, onRun }: GraphqlScanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const enabled = (data as any).graphqlSecurityEnabled ?? false
  const authType = (data as any).graphqlAuthType ?? ''

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Braces size={16} />
          GraphQL Security Scanner
          <NodeInfoTooltip section="GraphqlScan" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run GraphQL Security Scanner"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('graphqlSecurityEnabled' as any, checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Active GraphQL security scanner. Discovers GraphQL endpoints from crawled BaseURLs + Endpoints,
            tests introspection exposure, extracts schema, detects sensitive fields, and flags
            mutation / proxy-path vulnerabilities. Enriches existing Endpoint nodes with
            <code> is_graphql</code> + schema metadata and creates Vulnerability nodes for findings.
          </p>

          {enabled && (
            <>
              {/* Test Modules */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Security Tests</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Introspection Test</span>
                    <p className={styles.toggleDescription}>Probe <code>__schema</code> to detect exposed introspection (passive, low traffic).</p>
                  </div>
                  <Toggle
                    checked={(data as any).graphqlIntrospectionTest ?? true}
                    onChange={(checked) => updateField('graphqlIntrospectionTest' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Verify SSL</span>
                    <p className={styles.toggleDescription}>Reject invalid / self-signed TLS certs on target endpoints.</p>
                  </div>
                  <Toggle
                    checked={(data as any).graphqlVerifySsl ?? true}
                    onChange={(checked) => updateField('graphqlVerifySsl' as any, checked)}
                  />
                </div>
              </div>

              {/* Execution Limits */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Execution Limits</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Timeout (seconds)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).graphqlTimeout ?? 30}
                      onChange={(e) => updateField('graphqlTimeout' as any, parseInt(e.target.value) || 30)}
                      min={1}
                      max={600}
                    />
                    <span className={styles.fieldHint}>Per-endpoint request timeout</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Rate Limit (req/s)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).graphqlRateLimit ?? 10}
                      onChange={(e) => updateField('graphqlRateLimit' as any, parseInt(e.target.value) || 10)}
                      min={0}
                      max={100}
                    />
                    <span className={styles.fieldHint}>0 = unlimited. Capped by ROE_GLOBAL_MAX_RPS.</span>
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Concurrency</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).graphqlConcurrency ?? 5}
                      onChange={(e) => updateField('graphqlConcurrency' as any, parseInt(e.target.value) || 5)}
                      min={1}
                      max={20}
                    />
                    <span className={styles.fieldHint}>Parallel endpoint tests</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Query Depth Limit</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).graphqlDepthLimit ?? 10}
                      onChange={(e) => updateField('graphqlDepthLimit' as any, parseInt(e.target.value) || 10)}
                      min={1}
                      max={50}
                    />
                    <span className={styles.fieldHint}>Max introspection nesting depth</span>
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Retry Count</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).graphqlRetryCount ?? 3}
                      onChange={(e) => updateField('graphqlRetryCount' as any, parseInt(e.target.value) || 3)}
                      min={0}
                      max={10}
                    />
                    <span className={styles.fieldHint}>Retries on 429/5xx and network errors (Cloudflare-friendly)</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Retry Backoff (seconds)</label>
                    <input
                      type="number"
                      step="0.1"
                      className="textInput"
                      value={(data as any).graphqlRetryBackoff ?? 2.0}
                      onChange={(e) => updateField('graphqlRetryBackoff' as any, parseFloat(e.target.value) || 2.0)}
                      min={0}
                    />
                    <span className={styles.fieldHint}>Exponential backoff base between retries</span>
                  </div>
                </div>
              </div>

              {/* Custom Endpoints */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Target Override</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Custom Endpoints</label>
                  <textarea
                    className="textInput"
                    rows={3}
                    placeholder="https://api.target.com/graphql, https://api.target.com/v1/graphql"
                    value={(data as any).graphqlEndpoints ?? ''}
                    onChange={(e) => updateField('graphqlEndpoints' as any, e.target.value)}
                  />
                  <span className={styles.fieldHint}>
                    Comma-separated GraphQL endpoint URLs. Leave empty to auto-discover from crawled BaseURLs/Endpoints (recommended).
                  </span>
                </div>
              </div>

              {/* Authentication */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Authentication</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Auth Type</label>
                    <select
                      className="textInput"
                      value={authType}
                      onChange={(e) => updateField('graphqlAuthType' as any, e.target.value)}
                    >
                      <option value="">None</option>
                      <option value="bearer">Bearer Token</option>
                      <option value="basic">Basic (user:pass)</option>
                      <option value="cookie">Cookie</option>
                      <option value="custom">Custom Header</option>
                    </select>
                    <span className={styles.fieldHint}>Headers are attached to every GraphQL request</span>
                  </div>
                  {authType && (
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Auth Value</label>
                      <input
                        type="password"
                        className="textInput"
                        value={(data as any).graphqlAuthValue ?? ''}
                        onChange={(e) => updateField('graphqlAuthValue' as any, e.target.value)}
                        placeholder={
                          authType === 'bearer' ? 'eyJhbGci...' :
                          authType === 'basic' ? 'user:password' :
                          authType === 'cookie' ? 'session=abc123; csrf=xyz' :
                          authType === 'custom' ? 'secret-token-value' : ''
                        }
                      />
                      <span className={styles.fieldHint}>
                        {authType === 'basic' && 'Will be base64-encoded automatically'}
                        {authType !== 'basic' && 'Value sent verbatim in the header'}
                      </span>
                    </div>
                  )}
                </div>
                {authType === 'custom' && (
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Custom Header Name</label>
                      <input
                        type="text"
                        className="textInput"
                        value={(data as any).graphqlAuthHeader ?? ''}
                        onChange={(e) => updateField('graphqlAuthHeader' as any, e.target.value)}
                        placeholder="X-Api-Key"
                      />
                      <span className={styles.fieldHint}>Header name for the custom auth value above</span>
                    </div>
                  </div>
                )}
              </div>

              {/* graphql-cop External Scanner (Phase 2 §17) */}
              <GraphqlCopSubSection data={data} updateField={updateField} />
            </>
          )}
        </div>
      )}
    </div>
  )
}

interface GraphqlCopSubSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

function GraphqlCopSubSection({ data, updateField }: GraphqlCopSubSectionProps) {
  const [expanded, setExpanded] = useState(false)
  const copEnabled = (data as any).graphqlCopEnabled ?? false

  return (
    <div className={styles.subSection}>
      <h3
        className={styles.subSectionTitle}
        style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
        onClick={() => setExpanded(!expanded)}
      >
        <ChevronDown
          size={14}
          style={{ transform: expanded ? 'rotate(0deg)' : 'rotate(-90deg)', transition: 'transform 150ms' }}
        />
        graphql-cop External Scanner
        <span className={styles.badgeActive} style={{ fontSize: '9px' }}>Active</span>
        <span style={{
          fontSize: '9px', padding: '1px 6px', borderRadius: '3px',
          backgroundColor: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', fontWeight: 500,
        }}>
          12 checks
        </span>
        {copEnabled && (
          <span style={{ fontSize: '9px', color: '#22c55e', fontWeight: 500 }}>ENABLED</span>
        )}
      </h3>

      {expanded && (
        <>
          <p className={styles.sectionDescription} style={{ marginTop: '8px' }}>
            External Docker-based misconfig scanner (<code>dolevf/graphql-cop:1.14</code>).
            Runs 12 checks per endpoint including alias/batch/directive DoS probes, GraphiQL
            detection, trace/debug disclosure, GET-method CSRF, unhandled errors, and field
            suggestions. Traffic is <strong>active</strong> &mdash; DoS probes auto-disable in
            stealth mode. Introspection test is off by default to dedupe with the native scanner above.
          </p>

          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable graphql-cop</span>
              <p className={styles.toggleDescription}>Docker-in-Docker invocation per endpoint. Default: off (opt-in).</p>
            </div>
            <Toggle
              checked={copEnabled}
              onChange={(checked) => updateField('graphqlCopEnabled' as any, checked)}
            />
          </div>

          {copEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Docker Image</label>
                  <input
                    type="text"
                    className="textInput"
                    value={(data as any).graphqlCopDockerImage ?? 'dolevf/graphql-cop:1.14'}
                    onChange={(e) => updateField('graphqlCopDockerImage' as any, e.target.value)}
                  />
                  <span className={styles.fieldHint}>Pinned to 1.14 (DockerHub tag). Override for custom forks.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={(data as any).graphqlCopTimeout ?? 120}
                    onChange={(e) => updateField('graphqlCopTimeout' as any, parseInt(e.target.value) || 120)}
                    min={10}
                    max={600}
                  />
                  <span className={styles.fieldHint}>Per-endpoint timeout</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Force Scan</span>
                  <p className={styles.toggleDescription}>Run checks even if endpoint doesn&apos;t look GraphQL-like (graphql-cop&apos;s <code>-f</code> flag).</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopForceScan ?? false}
                  onChange={(checked) => updateField('graphqlCopForceScan' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Debug Mode</span>
                  <p className={styles.toggleDescription}>Add <code>X-GraphQL-Cop-Test</code> header per request (graphql-cop&apos;s <code>-d</code> flag).</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopDebug ?? false}
                  onChange={(checked) => updateField('graphqlCopDebug' as any, checked)}
                />
              </div>

              <h4 className={styles.subSectionTitle} style={{ marginTop: '16px', fontSize: '12px' }}>
                Checks to Run
              </h4>
              <p className={styles.fieldHint} style={{ marginBottom: '8px' }}>
                Each toggle maps to one graphql-cop test.{' '}
                <strong>Filters findings from the report only &mdash; DoS traffic still fires</strong>{' '}
                until graphql-cop ships <code>-e</code> support on DockerHub (patched in git main v1.15, unreleased).
                To fully suppress a test&apos;s traffic, disable the master <em>Enable graphql-cop</em> toggle above.
              </p>

              {/* Info-leak + CSRF checks (low-noise) */}
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Field Suggestions (LOW &mdash; info leak)</span>
                  <p className={styles.toggleDescription}>&quot;Did you mean X?&quot; errors leak schema fields even with introspection off.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestFieldSuggestions ?? true}
                  onChange={(checked) => updateField('graphqlCopTestFieldSuggestions' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Introspection (HIGH &mdash; info leak)</span>
                  <p className={styles.toggleDescription}>Off by default &mdash; native scanner above already tests this. Enable for dedup validation.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestIntrospection ?? false}
                  onChange={(checked) => updateField('graphqlCopTestIntrospection' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>GraphQL IDE / Playground (LOW)</span>
                  <p className={styles.toggleDescription}>Detect exposed GraphiQL/Playground UI.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestGraphiql ?? true}
                  onChange={(checked) => updateField('graphqlCopTestGraphiql' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>GET Method Query Support (MEDIUM &mdash; CSRF)</span>
                  <p className={styles.toggleDescription}>Queries allowed via GET enable CSRF attacks.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestGetMethod ?? true}
                  onChange={(checked) => updateField('graphqlCopTestGetMethod' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>GET-based Mutations (MEDIUM &mdash; CSRF)</span>
                  <p className={styles.toggleDescription}>Mutations executable via GET requests.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestGetMutation ?? true}
                  onChange={(checked) => updateField('graphqlCopTestGetMutation' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>POST url-encoded CSRF (MEDIUM)</span>
                  <p className={styles.toggleDescription}>GraphQL accepts <code>application/x-www-form-urlencoded</code> POSTs.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestPostCsrf ?? true}
                  onChange={(checked) => updateField('graphqlCopTestPostCsrf' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Trace Mode (INFO &mdash; info leak)</span>
                  <p className={styles.toggleDescription}>Apollo tracing extension disclosure.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestTraceMode ?? true}
                  onChange={(checked) => updateField('graphqlCopTestTraceMode' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Unhandled Errors (INFO &mdash; info leak)</span>
                  <p className={styles.toggleDescription}>Exception stack traces returned to client.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestUnhandledError ?? true}
                  onChange={(checked) => updateField('graphqlCopTestUnhandledError' as any, checked)}
                />
              </div>

              <div style={{
                marginTop: '12px', padding: '8px 12px', borderRadius: '4px',
                backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
                fontSize: '11px', color: '#f87171',
              }}>
                <strong>DoS probes below &mdash; noisy traffic.</strong> Toggling these off hides their findings
                but the packets still fly (see note above). Auto-disabled only in stealth mode.
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Alias Overloading (HIGH &mdash; DoS)</span>
                  <p className={styles.toggleDescription}>Sends 101 aliases in one query to bypass rate limits.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestAliasOverloading ?? true}
                  onChange={(checked) => updateField('graphqlCopTestAliasOverloading' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Array-based Query Batching (HIGH &mdash; DoS)</span>
                  <p className={styles.toggleDescription}>Sends 10+ queries batched in one POST.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestBatchQuery ?? true}
                  onChange={(checked) => updateField('graphqlCopTestBatchQuery' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Directive Overloading (HIGH &mdash; DoS)</span>
                  <p className={styles.toggleDescription}>Sends 10+ repeated directives to exhaust parsing.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestDirectiveOverloading ?? true}
                  onChange={(checked) => updateField('graphqlCopTestDirectiveOverloading' as any, checked)}
                />
              </div>
              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Introspection-based Circular Query (HIGH &mdash; DoS)</span>
                  <p className={styles.toggleDescription}>Deeply nested introspection to trigger recursion DoS.</p>
                </div>
                <Toggle
                  checked={(data as any).graphqlCopTestCircularIntrospection ?? true}
                  onChange={(checked) => updateField('graphqlCopTestCircularIntrospection' as any, checked)}
                />
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
