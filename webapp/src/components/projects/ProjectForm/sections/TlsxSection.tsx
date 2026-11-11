'use client'

import { useState } from 'react'
import { ChevronDown, Lock, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { ipHostnameOverrides } from '@/lib/ipHostnameOverrides'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { RegistryFields } from '../RegistryFields'
import { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '../ipHostnameModes'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TlsxSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function TlsxSection({ data, updateField, onRun }: TlsxSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  // Every hostname mode forces reverse-PTR SNI off in an IP-mode project (a PTR
  // name is a candidate there, never an SNI); recon ignores the stored value.
  const revPtrForced = ipHostnameOverrides(data).find(o => o.key === 'tlsxRevPtrSni')

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Lock size={16} />
          TLS Certificate Grab
          <NodeInfoTooltip section="Tlsx" />
          <WikiInfoButton target="Tlsx" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.tlsxEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run TLS Certificate Grab"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.tlsxEnabled}
              onChange={(checked) => updateField('tlsxEnabled', checked)}
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
            Grabs the <strong>TLS certificate</strong> on every open non-HTTP port with a single handshake
            (SMTPS 465, IMAPS 993, POP3S 995, LDAPS 636, FTPS 990, and any odd TLS port naabu found) using
            <code> tlsx</code>. Fills the gap left by the HTTP probe, which only grabs certs
            on the five HTTPS ports it dials. Writes <code>Certificate</code> nodes with
            issuer / SAN / validity / posture, links them to the IP, and feeds SAN hostnames back into the scan.
            Runs before the HTTP probe so discovered hostnames become probe targets. Default on and quiet.
          </p>

          {data.tlsxEnabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Coverage</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Feed SAN hostnames back into the scan</div>
                    <div className={styles.toggleDescription}>
                      In-scope certificate SAN names become probe targets (apex-scoped, resolve-checked). Foreign names are recorded but never scanned.
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxInjectHostnames}
                    onChange={(checked) => updateField('tlsxInjectHostnames', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Include HTTP/HTTPS ports</div>
                    <div className={styles.toggleDescription}>
                      Also grab certs on ports the HTTP probe already covers (duplicate handshakes). Off by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxIncludeHttpPorts}
                    onChange={(checked) => updateField('tlsxIncludeHttpPorts', checked)}
                  />
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Concurrency</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.tlsxConcurrency ?? 50}
                    onChange={(e) => updateField('tlsxConcurrency', parseInt(e.target.value, 10) || 50)}
                    min={1}
                    max={300}
                  />
                  <span className={styles.fieldHint}>Concurrent handshakes. tlsx&apos;s own default is 300; 50 is quieter.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Handshake timeout (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.tlsxTimeout ?? 5}
                    onChange={(e) => updateField('tlsxTimeout', parseInt(e.target.value, 10) || 5)}
                    min={1}
                    max={60}
                  />
                  <span className={styles.fieldHint}>Per-handshake connect timeout.</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max targets</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.tlsxMaxTargets ?? 2000}
                    onChange={(e) => updateField('tlsxMaxTargets', parseInt(e.target.value, 10) || 2000)}
                    min={1}
                    max={100000}
                  />
                  <span className={styles.fieldHint}>Hard cap on <code>ip:port</code> pairs scanned.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max SAN hostnames injected</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.tlsxMaxInjectedHostnames ?? 200}
                    onChange={(e) => updateField('tlsxMaxInjectedHostnames', parseInt(e.target.value, 10) || 200)}
                    min={0}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Cap on in-scope SAN names merged back as scan targets. JS Recon uses the same cap for the hostnames it finds.</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Deeper probes (louder OPSEC)</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>JARM / JA3 fingerprints</div>
                    <div className={styles.toggleDescription}>
                      ~10 extra handshakes per target. Useful for CDN / infrastructure fingerprinting. Off by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxProbeJarm}
                    onChange={(checked) => updateField('tlsxProbeJarm', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Enumerate supported TLS versions</div>
                    <div className={styles.toggleDescription}>
                      Extra connections per target. Surfaces servers that still <em>support</em> TLS 1.0/1.1.
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxVersionEnum}
                    onChange={(checked) => updateField('tlsxVersionEnum', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Enumerate weak ciphers</div>
                    <div className={styles.toggleDescription}>
                      Extra connections per target. Surfaces weak ciphers a server still accepts.
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxCipherEnum}
                    onChange={(checked) => updateField('tlsxCipherEnum', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Reverse-PTR SNI for bare IPs</div>
                    <div className={styles.toggleDescription}>
                      Derive an SNI from a reverse-DNS lookup when no hostname is known (extra DNS per bare IP).
                      {revPtrForced && (
                        <> Off: forced by {IP_HOSTNAME_SECTION_LABEL} ({ipHostnameModeLabel(data.ipHostnameMode)}).</>
                      )}
                    </div>
                  </div>
                  <Toggle
                    checked={revPtrForced ? revPtrForced.value : data.tlsxRevPtrSni}
                    onChange={(checked) => updateField('tlsxRevPtrSni', checked)}
                    disabled={!!revPtrForced}
                    aria-label="Reverse-PTR SNI for bare IPs"
                  />
                </div>
              </div>
            </>
          )}

          <RegistryFields
            keys={['tlsxCipherConcurrency', 'tlsxDelay', 'tlsxMaxHostnamesPerIp', 'tlsxRetries', 'tlsxRunTimeout', 'tlsxScanMode']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
    </div>
  )
}
