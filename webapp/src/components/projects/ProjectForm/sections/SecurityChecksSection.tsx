'use client'

import { useState } from 'react'
import { ChevronDown, Play, ShieldCheck } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SecurityChecksSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function SecurityChecksSection({ data, updateField, onRun }: SecurityChecksSectionProps) {
  const jevStatus = useHasJevProvider()
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
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
              className={styles.runPartialButton}
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
                      'detection_method=ai_classifier (jev_classifier on the Jev engine), ' +
                      'waf_type, waf_confidence. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <Toggle
                    checked={data.wafAiClassifier}
                    disabled={!data.aiInPipeline}
                    onChange={(checked) => updateField('wafAiClassifier', checked)}
                  />
                </div>
                {data.wafAiClassifier && (
                  <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                    <span className={styles.fieldLabel}>Engine</span>
                    <JevEngineControl
                      value={data.wafAiUseJev}
                      enabled={data.aiInPipeline && data.wafAiClassifier}
                      jevStatus={jevStatus}
                      onSelect={(useJev) => updateField('wafAiUseJev', useJev)}
                    />
                  </div>
                )}
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

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Page Content</h3>
                <p className={styles.toggleDescription}>
                  Checks the live page titles, server names and certificates httpx and tlsx already
                  collected. No extra requests.
                </p>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Open Consoles Without Login</span>
                    <p className={styles.toggleDescription}>{'Live consoles that show their content without asking to log in: Jupyter, Jenkins, Ray, Spark, Flink, Airflow, Mongo Express, phpMyAdmin, Selenium, Prometheus and others.'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckOpenConsoles ?? true}
                    onChange={(checked) => updateField('securityCheckOpenConsoles', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Debug Pages</span>
                    <p className={styles.toggleDescription}>{'Live debug and error pages that show code or settings: Werkzeug, Django, Laravel, Symfony, Rails, phpinfo, Apache server-status.'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckDebugPages ?? true}
                    onChange={(checked) => updateField('securityCheckDebugPages', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Unfinished Installers</span>
                    <p className={styles.toggleDescription}>{'Live install pages anyone can complete to take over the site: WordPress, Joomla, Drupal, Gitea, TYPO3, PrestaShop and others.'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckUnfinishedInstallers ?? true}
                    onChange={(checked) => updateField('securityCheckUnfinishedInstallers', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Development Servers</span>
                    <p className={styles.toggleDescription}>{"Live sites answered by a development server that is not built for the internet: Werkzeug, Python's built-in server, WEBrick."}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckDevServers ?? true}
                    onChange={(checked) => updateField('securityCheckDevServers', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Directory Listings</span>
                    <p className={styles.toggleDescription}>{'Live pages that list every file in a folder ("Index of /").'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckDirectoryListing ?? true}
                    onChange={(checked) => updateField('securityCheckDirectoryListing', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Defaced Pages</span>
                    <p className={styles.toggleDescription}>{'Live pages whose title says "Hacked by…".'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckDefacedPages ?? true}
                    onChange={(checked) => updateField('securityCheckDefacedPages', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Takeover Error Pages</span>
                    <p className={styles.toggleDescription}>{'Live hosts showing a cloud provider\'s "deleted service" page. Turn on Subdomain Takeover for the full verdict.'}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckTakeoverErrorPages ?? true}
                    onChange={(checked) => updateField('securityCheckTakeoverErrorPages', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Test or Default Certificates</span>
                    <p className={styles.toggleDescription}>{"Live hosts using a Let's Encrypt staging certificate or the default certificate of Kubernetes Ingress or Traefik: a test deployment or an unconfigured host."}</p>
                  </div>
                  <Toggle
                    checked={data.securityCheckTestCertificates ?? true}
                    onChange={(checked) => updateField('securityCheckTestCertificates', checked)}
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
