'use client'

import { useState, useEffect, useCallback } from 'react'
import Image from 'next/image'
import {
  ShieldAlert, ExternalLink, Star, Github,
  Rocket, UserPlus, FolderPlus,
  Bot, Play, BookOpen,
} from 'lucide-react'
import {
  DISCLAIMER_VERSION,
  DISCLAIMER_STORAGE_KEY,
  DISCLAIMER_GITHUB_URL,
  REDAMON_GITHUB_URL,
  WIKI_URL,
} from '@/lib/disclaimerVersion'
import styles from './DisclaimerGate.module.css'

interface DisclaimerGateProps {
  children: React.ReactNode
}

interface StoredAcceptance {
  version: string
  acceptedAt: string
}

const CHECKBOXES = [
  {
    id: 'authorization',
    label:
      'I confirm I have explicit written authorization to test target systems and understand unauthorized access is illegal under CFAA, Computer Misuse Act, and equivalent laws.',
  },
  {
    id: 'liability',
    label:
      'I acknowledge this software is provided "AS IS" with no warranty. Authors and contributors bear no liability for any damages, data loss, or legal consequences.',
  },
  {
    id: 'data-privacy',
    label:
      'I understand that reconnaissance data, credentials, and vulnerability details are transmitted to external LLM providers (OpenAI, Anthropic, etc.) and third-party services with no privacy guarantee.',
  },
  {
    id: 'data-persistence',
    label:
      'I understand all data is stored indefinitely in Neo4j/PostgreSQL with no automatic deletion. I am responsible for cleanup after engagements.',
  },
  {
    id: 'ai-agent',
    label:
      'I understand the AI agent operates autonomously and may take unexpected actions including scope drift, service degradation, or unintended exploitation. Approval gates are best-effort safeguards.',
  },
  {
    id: 'third-party',
    label:
      'I understand I must comply with licenses of all bundled tools (AGPL-3.0, GPL, MIT, etc.) and applicable regulations including export controls.',
  },
] as const

export function DisclaimerGate({ children }: DisclaimerGateProps) {
  const [isLoading, setIsLoading] = useState(true)
  const [isAccepted, setIsAccepted] = useState(false)
  const [step, setStep] = useState<'welcome' | 'disclaimer' | 'guide'>('welcome')
  const [checked, setChecked] = useState<boolean[]>(
    () => new Array(CHECKBOXES.length).fill(false)
  )

  useEffect(() => {
    try {
      const stored = localStorage.getItem(DISCLAIMER_STORAGE_KEY)
      if (stored) {
        const parsed: StoredAcceptance = JSON.parse(stored)
        if (parsed.version === DISCLAIMER_VERSION) {
          setIsAccepted(true)
        }
      }
    } catch {
      // localStorage unavailable or corrupted — show the gate
    }
    setIsLoading(false)
  }, [])

  const handleToggle = useCallback((index: number) => {
    setChecked((prev) => {
      const next = [...prev]
      next[index] = !next[index]
      return next
    })
  }, [])

  const handleAccept = useCallback(() => {
    try {
      const value: StoredAcceptance = {
        version: DISCLAIMER_VERSION,
        acceptedAt: new Date().toISOString(),
      }
      localStorage.setItem(DISCLAIMER_STORAGE_KEY, JSON.stringify(value))
    } catch {
      // localStorage unavailable — acceptance lasts this session only
    }
    setIsAccepted(true)
  }, [])

  const allChecked = checked.every(Boolean)

  if (isLoading) {
    return null
  }

  if (isAccepted) {
    return <>{children}</>
  }

  if (step === 'welcome') {
    return (
      <div className={styles.overlay}>
        <div className={styles.card}>
          <Image src="/logo.png" alt="" aria-hidden width={520} height={520} className={styles.eyeBg} />
          <div className={styles.welcomeHeader}>
            <Image src="/logo.png" alt="RedAmon" width={36} height={36} style={{ objectFit: 'contain' }} />
            <h1 className={styles.welcomeTitle}>
              Welcome to <span className={styles.logoAccent}>Red</span>Amon
            </h1>
          </div>

          <div className={styles.body}>
            <p className={styles.welcomeThank}>
              Thank you for downloading and installing <strong>RedAmon</strong>!
            </p>

            <p className={styles.welcomeDesc}>
              <strong>RedAmon</strong> is an open-source, AI-powered
              penetration testing platform that combines autonomous
              reconnaissance, graph-based attack surface mapping, and an
              intelligent agent to help security professionals work faster and
              smarter, from initial footprinting to full engagement reporting.
            </p>

            <div className={styles.missionBox}>
              <p className={styles.missionText}>
                Our commitment is to keep RedAmon always up-to-date and make it
                the <strong>#1 open-source pentesting platform</strong> in the
                world. To get there, we need the community&apos;s help.
              </p>
              <p className={styles.missionText}>
                We&apos;re not asking for money, just a ⭐ GitHub star to help us grow, gain visibility, and attract contributors. If you&apos;d like to go further, feel free to open a pull request or reach out to our maintainers directly.<br />Every contribution matters.
              </p>
              <p className={styles.footerSignature}>
                Happy hunting!<br />Samuele &amp; Ritesh
              </p>
            </div>

            <a
              href={REDAMON_GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.starLink}
            >
              <Github size={20} />
              <Star size={18} className={styles.starIcon} />
              <span>Star RedAmon on GitHub</span>
              <ExternalLink size={13} className={styles.starExternal} />
            </a>
          </div>

          <div className={styles.footer}>
            <p className={styles.footerQuote}>
              &ldquo;Open source is humanity&apos;s greatest collaborative experiment.&rdquo;
            </p>
            <button
              className={styles.acceptButton}
              onClick={() => setStep('disclaimer')}
            >
              OK, continue
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (step === 'guide') {
    return (
      <div className={styles.overlay}>
        <div className={styles.card}>
          <div className={styles.header}>
            <div className={styles.headerLeft}>
              <Rocket size={20} className={styles.headerIcon} />
              <h1 className={styles.title}>Getting Started — Your First Steps</h1>
            </div>
          </div>

          <div className={styles.body}>
            <div className={styles.guideGroups}>
              {/* Setup group */}
              <div className={styles.guideGroup}>
                <p className={styles.guideGroupLabel}>Setup</p>
                <div className={styles.guideSteps}>
                  <div className={styles.guideStep}>
                    <div className={styles.guideStepLeft}>
                      <span className={styles.guideStepNum}>1</span>
                      <UserPlus size={18} className={styles.guideStepIcon} />
                    </div>
                    <div>
                      <p className={styles.guideStepTitle}>Create a User</p>
                      <p className={styles.guideStepDesc}>Go to the Users panel and create your profile. Each user can manage multiple independent projects.</p>
                    </div>
                  </div>
                  <div className={styles.guideStep}>
                    <div className={styles.guideStepLeft}>
                      <span className={styles.guideStepNum}>2</span>
                      <FolderPlus size={18} className={styles.guideStepIcon} />
                    </div>
                    <div>
                      <p className={styles.guideStepTitle}>Create a Project</p>
                      <p className={styles.guideStepDesc}>Set up a project to group all recon data, settings, and agent sessions for a single engagement.</p>
                    </div>
                  </div>

                </div>
              </div>

              {/* Run group */}
              <div className={styles.guideGroup}>
                <p className={styles.guideGroupLabel}>Run</p>
                <div className={styles.guideSteps}>
                  <div className={styles.guideStep}>
                    <div className={styles.guideStepLeft}>
                      <span className={styles.guideStepNum}>3</span>
                      <Play size={18} className={styles.guideStepIcon} />
                    </div>
                    <div>
                      <p className={styles.guideStepTitle}>Launch the Recon Pipeline</p>
                      <p className={styles.guideStepDesc}>From the <strong>Red Zone</strong> press <strong>Start Recon</strong>. Wait for the pipeline to fully complete before starting the AI agent.</p>
                    </div>
                  </div>
                  <div className={styles.guideStep}>
                    <div className={styles.guideStepLeft}>
                      <span className={styles.guideStepNum}>4</span>
                      <Bot size={18} className={styles.guideStepIcon} />
                    </div>
                    <div>
                      <p className={styles.guideStepTitle}>Start the AI Agent</p>
                      <p className={styles.guideStepDesc}>Once recon is done, switch to <strong>Agent AI</strong> to interrogate findings, plan attack paths, and generate reports.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className={styles.footer}>
            <a
              href={WIKI_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.fullDisclaimerLink}
            >
              <BookOpen size={14} />
              Read the complete manual on the Wiki
              <ExternalLink size={12} />
            </a>
            <button className={styles.acceptButton} onClick={handleAccept}>
              Let&apos;s Go →
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.overlay}>
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <ShieldAlert size={22} className={styles.headerIcon} />
            <h1 className={styles.title}>Legal Disclaimer & Terms of Use</h1>
          </div>
        </div>

        <div className={styles.body}>
          <p className={styles.intro}>
            <strong>RedAmon</strong> is an AI-powered penetration testing
            platform intended exclusively for{' '}
            <strong>authorized security testing</strong>,{' '}
            <strong>educational purposes</strong>, and{' '}
            <strong>research</strong>. Before using this tool, you must read and
            accept the following terms.
          </p>

          <div className={styles.linkWrapper}>
            <a
              href={DISCLAIMER_GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.fullDisclaimerLink}
            >
              Read the full legal disclaimer
              <ExternalLink size={13} />
            </a>
          </div>

          <div className={styles.checkboxList}>
            {CHECKBOXES.map((item, index) => (
              <label key={item.id} className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={checked[index]}
                  onChange={() => handleToggle(index)}
                  className={styles.checkbox}
                />
                <span className={styles.checkboxLabel}>{item.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className={styles.footer}>
          <button
            className={styles.acceptButton}
            disabled={!allChecked}
            onClick={() => setStep('guide')}
          >
            I Accept All Terms
          </button>
        </div>
      </div>
    </div>
  )
}
