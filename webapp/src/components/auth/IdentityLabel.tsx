import styles from './IdentityLabel.module.css'

/**
 * How a security screen names an account (step 2.11, ID-31; feature document §3 F-21): its name,
 * its email and its account type. A display name alone is not an identity: anyone can call
 * themselves "Admin", while the email is unique (whatever its case) and the type is the server's.
 * Used by the user switcher, the Users page dialogs, and the later security screens (act-as
 * banner, share dialog, feed, approvals).
 */

export type AccountType = 'root' | 'admin' | 'member'

export const ACCOUNT_TYPE_LABEL: Record<AccountType, string> = { root: 'Root', admin: 'Admin', member: 'Member' }

/**
 * The type of a listed account. Root is the admin whose address is the instance Root's (the
 * header learns it from /api/auth/me, identity switch on); addresses compare ignoring case, as
 * accounts do.
 */
export function accountTypeFor(user: { role: string; email: string }, root?: { email: string } | null): AccountType {
  if (user.role !== 'admin') return 'member'
  return root && root.email.toLowerCase() === user.email.toLowerCase() ? 'root' : 'admin'
}

interface IdentityLabelProps {
  name: string
  email: string
  /** Identity switch on. Without it (switch off) the stored `role` is shown, as before the switch. */
  accountType?: AccountType
  role?: string
  className?: string
}

/** The words a screen reader says for an account: "name, email, type". */
export function identityText({ name, email, accountType, role }: Omit<IdentityLabelProps, 'className'>): string {
  const type = accountType ? ACCOUNT_TYPE_LABEL[accountType] : role
  return [name || null, email, type || null].filter(Boolean).join(', ')
}

export function IdentityLabel({ name, email, accountType, role, className }: IdentityLabelProps) {
  const badge = accountType ? ACCOUNT_TYPE_LABEL[accountType] : role
  const tone = accountType ?? (role === 'admin' ? 'admin' : 'member')
  return (
    <span
      className={`${styles.label}${className ? ` ${className}` : ''}`}
      role="group"
      data-testid="identity-label"
      aria-label={identityText({ name, email, accountType, role })}
    >
      {name && <span className={styles.name} aria-hidden="true">{name}</span>}
      {badge && (
        <span className={`${styles.badge} ${styles[tone]}`} data-account-type={accountType} aria-hidden="true">
          {badge}
        </span>
      )}
      <span className={styles.email} aria-hidden="true">{email}</span>
    </span>
  )
}

export default IdentityLabel
