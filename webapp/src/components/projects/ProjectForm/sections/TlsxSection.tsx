'use client'

import { useState, type CSSProperties } from 'react'
import { ChevronDown, Lock, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TlsxSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

const codeStyle: CSSProperties = {
  fontSize: '0.85em',
  padding: '1px 4px',
  backgroundColor: 'rgba(255,255,255,0.06)',
  borderRadius: '3px',
}

export function TlsxSection({ data, updateField, onRun }: TlsxSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
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
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
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
            <code style={codeStyle}> tlsx</code>. Fills the gap left by the HTTP probe, which only grabs certs
            on the five HTTPS ports it dials. Writes <code style={codeStyle}>Certificate</code> nodes with
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
                  <span className={styles.fieldHint}>Hard cap on <code style={codeStyle}>ip:port</code> pairs scanned.</span>
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
                  <span className={styles.fieldHint}>Cap on in-scope SAN names merged back as scan targets.</span>
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
                    </div>
                  </div>
                  <Toggle
                    checked={data.tlsxRevPtrSni}
                    onChange={(checked) => updateField('tlsxRevPtrSni', checked)}
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
