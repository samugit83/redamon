'use client'

import { useState } from 'react'
import { ChevronDown, Play, ShieldCheck } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { AiToggleLabel } from '../AiToggleLabel'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SecurityChecksSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function SecurityChecksSection({ data, updateField, onRun }: SecurityChecksSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <ShieldCheck size={16} />
          Security Checks
          <NodeInfoTooltip section="SecurityChecks" />
          <WikiInfoButton target="SecurityChecks" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.securityCheckEnabled && (
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
              title="Run Security Checks"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.securityCheckEnabled}
              onChange={(checked) => updateField('securityCheckEnabled', checked)}
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
            Run custom security validation checks on discovered findings. Includes header analysis, SSL/TLS configuration review, and other automated security assessments to verify and contextualize vulnerabilities.
          </p>

          {data.securityCheckEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Timeout (seconds)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.securityCheckTimeout}
                    onChange={(e) => updateField('securityCheckTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.securityCheckMaxWorkers}
                    onChange={(e) => updateField('securityCheckMaxWorkers', parseInt(e.target.value) || 10)}
                    min={1}
                    max={50}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Direct IP Access</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Check Direct IP HTTP</span>
                  <Toggle
                    checked={data.securityCheckDirectIpHttp}
                    onChange={(checked) => updateField('securityCheckDirectIpHttp', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Check Direct IP HTTPS</span>
                  <Toggle
                    checked={data.securityCheckDirectIpHttps}
                    onChange={(checked) => updateField('securityCheckDirectIpHttps', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Check IP API Exposed</span>
                  <Toggle
                    checked={data.securityCheckIpApiExposed}
                    onChange={(checked) => updateField('securityCheckIpApiExposed', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Check WAF Bypass</span>
                  <Toggle
                    checked={data.securityCheckWafBypass}
                    onChange={(checked) => updateField('securityCheckWafBypass', checked)}
                  />
                </div>
                <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-4)' }}>
                  <AiToggleLabel
                    label="Use AI for WAF Classification"
                    tooltip={
                      'Augments the static WAF/CDN header-token check. When the ' +
                      'static list misses (modern WAFs strip or rebrand their ' +
                      'headers), the response gets a second pass through the ' +
                      'configured model, which scores WAF presence 0-100 from ' +
                      'headers, body fingerprints, cookies, and latency. ' +
                      'AI-detected bypasses are tagged with ' +
                      'detection_method=ai_classifier, waf_type, waf_confidence. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <Toggle
                    checked={data.wafAiClassifier}
                    disabled={!data.aiInPipeline}
                    onChange={(checked) => updateField('wafAiClassifier', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>TLS/SSL</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Check TLS Expiring Soon</span>
                  <Toggle
                    checked={data.securityCheckTlsExpiringSoon}
                    onChange={(checked) => updateField('securityCheckTlsExpiringSoon', checked)}
                  />
                </div>
                {data.securityCheckTlsExpiringSoon && (
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Expiry Warning Days</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.securityCheckTlsExpiryDays}
                      onChange={(e) => updateField('securityCheckTlsExpiryDays', parseInt(e.target.value) || 30)}
                      min={1}
                      max={365}
                    />
                  </div>
                )}
                {/* Certificate-data hygiene checks (tlsx/httpx, zero extra network cost). */}
                <div className={styles.toggleDescription} style={{ marginBottom: '6px' }}>
                  Derived from certificates already captured, so they cost no extra
                  requests. If you also enable the Nuclei <code>ssl</code> tag, expect
                  some duplication: a Nuclei SSL finding and a security-check finding
                  for the same weakness are stored as separate findings and are not
                  merged.
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Expired Certificate</span>
                  <Toggle checked={data.securityCheckTlsExpired}
                    onChange={(checked) => updateField('securityCheckTlsExpired', checked)} />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Self-Signed Certificate</span>
                  <Toggle checked={data.securityCheckTlsSelfSigned}
                    onChange={(checked) => updateField('securityCheckTlsSelfSigned', checked)} />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Hostname Mismatch</span>
                  <Toggle checked={data.securityCheckTlsHostnameMismatch}
                    onChange={(checked) => updateField('securityCheckTlsHostnameMismatch', checked)} />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Weak TLS Version (SSLv3/TLS 1.0/1.1)</span>
                  <Toggle checked={data.securityCheckTlsWeakVersion}
                    onChange={(checked) => updateField('securityCheckTlsWeakVersion', checked)} />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Weak Cipher (RC4/3DES/NULL/EXPORT)</span>
                  <Toggle checked={data.securityCheckTlsWeakCipher}
                    onChange={(checked) => updateField('securityCheckTlsWeakCipher', checked)} />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Overbroad Wildcard Certificate</span>
                  <Toggle checked={data.securityCheckTlsWildcardOverbroad}
                    onChange={(checked) => updateField('securityCheckTlsWildcardOverbroad', checked)} />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Security Headers</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing Referrer-Policy</span>
                  <Toggle
                    checked={data.securityCheckMissingReferrerPolicy}
                    onChange={(checked) => updateField('securityCheckMissingReferrerPolicy', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing Permissions-Policy</span>
                  <Toggle
                    checked={data.securityCheckMissingPermissionsPolicy}
                    onChange={(checked) => updateField('securityCheckMissingPermissionsPolicy', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing COOP</span>
                  <Toggle
                    checked={data.securityCheckMissingCoop}
                    onChange={(checked) => updateField('securityCheckMissingCoop', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing CORP</span>
                  <Toggle
                    checked={data.securityCheckMissingCorp}
                    onChange={(checked) => updateField('securityCheckMissingCorp', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing COEP</span>
                  <Toggle
                    checked={data.securityCheckMissingCoep}
                    onChange={(checked) => updateField('securityCheckMissingCoep', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing Cache-Control</span>
                  <Toggle
                    checked={data.securityCheckCacheControlMissing}
                    onChange={(checked) => updateField('securityCheckCacheControlMissing', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>CSP Unsafe Inline</span>
                  <Toggle
                    checked={data.securityCheckCspUnsafeInline}
                    onChange={(checked) => updateField('securityCheckCspUnsafeInline', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Authentication</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Login Without HTTPS</span>
                  <Toggle
                    checked={data.securityCheckLoginNoHttps}
                    onChange={(checked) => updateField('securityCheckLoginNoHttps', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Session Cookie No Secure</span>
                  <Toggle
                    checked={data.securityCheckSessionNoSecure}
                    onChange={(checked) => updateField('securityCheckSessionNoSecure', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Session Cookie No HttpOnly</span>
                  <Toggle
                    checked={data.securityCheckSessionNoHttponly}
                    onChange={(checked) => updateField('securityCheckSessionNoHttponly', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Basic Auth Without TLS</span>
                  <Toggle
                    checked={data.securityCheckBasicAuthNoTls}
                    onChange={(checked) => updateField('securityCheckBasicAuthNoTls', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>DNS Security</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing SPF Record</span>
                  <Toggle
                    checked={data.securityCheckSpfMissing}
                    onChange={(checked) => updateField('securityCheckSpfMissing', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing DMARC Record</span>
                  <Toggle
                    checked={data.securityCheckDmarcMissing}
                    onChange={(checked) => updateField('securityCheckDmarcMissing', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Missing DNSSEC</span>
                  <Toggle
                    checked={data.securityCheckDnssecMissing}
                    onChange={(checked) => updateField('securityCheckDnssecMissing', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Zone Transfer Enabled</span>
                  <Toggle
                    checked={data.securityCheckZoneTransfer}
                    onChange={(checked) => updateField('securityCheckZoneTransfer', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Exposed Services</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Admin Ports Exposed</span>
                  <Toggle
                    checked={data.securityCheckAdminPortExposed}
                    onChange={(checked) => updateField('securityCheckAdminPortExposed', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Database Exposed</span>
                  <Toggle
                    checked={data.securityCheckDatabaseExposed}
                    onChange={(checked) => updateField('securityCheckDatabaseExposed', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Redis No Auth</span>
                  <Toggle
                    checked={data.securityCheckRedisNoAuth}
                    onChange={(checked) => updateField('securityCheckRedisNoAuth', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Kubernetes API Exposed</span>
                  <Toggle
                    checked={data.securityCheckKubernetesApiExposed}
                    onChange={(checked) => updateField('securityCheckKubernetesApiExposed', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>SMTP Open Relay</span>
                  <Toggle
                    checked={data.securityCheckSmtpOpenRelay}
                    onChange={(checked) => updateField('securityCheckSmtpOpenRelay', checked)}
                  />
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Application</h3>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>Insecure Form Action</span>
                  <Toggle
                    checked={data.securityCheckInsecureFormAction}
                    onChange={(checked) => updateField('securityCheckInsecureFormAction', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <span className={styles.toggleLabel}>No Rate Limiting</span>
                  <Toggle
                    checked={data.securityCheckNoRateLimiting}
                    onChange={(checked) => updateField('securityCheckNoRateLimiting', checked)}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
