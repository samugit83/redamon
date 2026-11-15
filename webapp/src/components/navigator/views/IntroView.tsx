'use client'

import styles from '../Navigator.module.css'

export type IntroVariant = 'default' | 'no_project' | 'owner_disallowed' | 'navigator_not_available' | 'navigator_disabled'

const VARIANTS: Record<Exclude<IntroVariant, 'default'>, string> = {
  no_project: 'Select a project in the header to start. AI Navigator works on one project at a time.',
  owner_disallowed: "The owner of this project hasn't enabled AI Navigator for collaborators.",
  navigator_not_available: "AI Navigator isn't available with this kind of access.",
  navigator_disabled: 'AI Navigator has been turned off on this server.',
}

/** The placeholder (plan §9.5): what AI Navigator does, and the way to the AI Agent. */
export function IntroView({ variant = 'default', onOpenAgent, agentAllowed, onExample }: {
  variant?: IntroVariant
  onOpenAgent?: () => void
  agentAllowed: boolean
  onExample?: (text: string) => void
}) {
  const example = (text: string) => (
    onExample
      ? <button type="button" className={styles.example} onClick={() => onExample(text)}>“{text}”</button>
      : <em>“{text}”</em>
  )
  return (
    <div className={styles.intro} data-testid="navigator-intro">
      <p><strong>AI Navigator</strong> helps you find your way around RedAmon and this project.</p>
      {variant !== 'default' && <p className={styles.introNotice} role="status">{VARIANTS[variant]}</p>}
      <p>
        <strong>Ask me about RedAmon:</strong> how a feature works, where a setting lives, what a permission means.
        I answer from the RedAmon documentation and link the exact page.
        <br />{example('How do I schedule a weekly scan?')}
      </p>
      <p>
        <strong>Ask me about this project:</strong> hosts, ports, technologies, findings, triage, scan history and
        the workspace files you can access.
        <br />{example('Which hosts expose SSH?')} · {example('What changed since the last scan?')} · {example('Which critical findings are not triaged yet?')}
      </p>
      <p><strong>I only read.</strong> I never run scans, tools or attacks, and I never change anything.</p>
      <p>
        <strong>I am not the RedAmon AI Agent.</strong> The AI Agent is the autonomous pentester that runs tools
        against your targets. To work with it, open it here:
      </p>
      {onOpenAgent && (agentAllowed
        ? <button type="button" className={styles.agentButton} onClick={onOpenAgent}>Open the AI Agent →</button>
        : <p className={styles.muted}>You don&apos;t have access to the AI Agent on this project.</p>)}
      <p className={styles.muted}>
        Your conversations here belong to this project and only you can see them. I run on your own AI model
        (Settings → Models by feature → AI Navigator).
      </p>
    </div>
  )
}
