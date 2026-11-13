'use client'

import Link from 'next/link'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import type { ActAsEntry, AuditEntryView, AuditLogEntry, AuditPerson, AuditTable, FireteamEntry } from '@/lib/authz/auditReader'
import { personText, valueText } from './auditView'
import pageStyles from '@/app/settings/users/page.module.css'
import usersStyles from '../users/users.module.css'
import styles from './audit.module.css'

export const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

/** A person by name, email and account type; a deleted account by the email its row recorded. */
export function Person({ person }: { person: AuditPerson | null }) {
  if (person && !person.deleted && person.email) {
    const label = <IdentityLabel name={person.name} email={person.email} accountType={person.accountType ?? undefined} />
    return person.id ? <Link href={`/admin/users/${encodeURIComponent(person.id)}`} className={styles.personLink}>{label}</Link> : label
  }
  return <span className={person?.deleted ? styles.deleted : usersStyles.muted}>{personText(person)}</span>
}

function Time({ at }: { at: string }) {
  return <time dateTime={at}>{when(at)}</time>
}

function DetailsButton({ entry, what, onOpen }: { entry: AuditEntryView; what: string; onOpen: (e: AuditEntryView) => void }) {
  return (
    <button type="button" className={pageStyles.actionButton} onClick={() => onOpen(entry)} aria-label={`Details: ${what}, ${when(entry.at)}`}>
      Details
    </button>
  )
}

function Head({ columns }: { columns: string[] }) {
  return (
    <thead>
      <tr>
        {columns.map((c) => <th key={c} scope="col" className={pageStyles.th}>{c}</th>)}
        <th scope="col" className={pageStyles.th}><span className={styles.srOnly}>Details</span></th>
      </tr>
    </thead>
  )
}

function LogRows({ entries, onOpen }: { entries: AuditLogEntry[]; onOpen: (e: AuditEntryView) => void }) {
  return (
    <table className={pageStyles.table} aria-label="Audit log rows">
      <Head columns={['When', 'Action', 'Actor', 'On behalf of', 'Target', 'Project']} />
      <tbody>
        {entries.map((e) => (
          <tr key={e.id} className={pageStyles.tr}>
            <td className={pageStyles.td}><Time at={e.at} /></td>
            <td className={pageStyles.td}>
              <span className={pageStyles.cellStack}>
                <span>{e.label}</span>
                {e.label !== e.action && <code className={usersStyles.muted}>{e.action}</code>}
              </span>
            </td>
            <td className={pageStyles.td}><Person person={e.actor} /></td>
            <td className={pageStyles.td}>{e.onBehalfOf ? <Person person={e.onBehalfOf} /> : <span className={usersStyles.muted}>—</span>}</td>
            <td className={pageStyles.td}>
              {e.target.account ? <Person person={e.target.account} /> : (
                <span className={pageStyles.cellStack}>
                  <span>{e.target.type}</span>
                  {e.target.id && <code className={usersStyles.muted}>{e.target.id}</code>}
                </span>
              )}
            </td>
            <td className={pageStyles.td}>{e.project ? (e.project.name ?? <code>{e.project.id}</code>) : <span className={usersStyles.muted}>—</span>}</td>
            <td className={pageStyles.td}><DetailsButton entry={e} what={e.label} onOpen={onOpen} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function ActAsRows({ entries, onOpen }: { entries: ActAsEntry[]; onOpen: (e: AuditEntryView) => void }) {
  return (
    <table className={pageStyles.table} aria-label="Act-as rows">
      <Head columns={['When', 'Event', 'Admin', 'Account acted as', 'Reason', 'Duration']} />
      <tbody>
        {entries.map((e) => (
          <tr key={e.id} className={pageStyles.tr}>
            <td className={pageStyles.td}><Time at={e.at} /></td>
            <td className={pageStyles.td}>{e.label}</td>
            <td className={pageStyles.td}><Person person={e.admin} /></td>
            <td className={pageStyles.td}><Person person={e.target} /></td>
            <td className={pageStyles.td}>{e.reason ?? <span className={usersStyles.muted}>—</span>}</td>
            <td className={pageStyles.td}>{e.durationMinutes !== null ? `${e.durationMinutes} min` : <span className={usersStyles.muted}>—</span>}</td>
            <td className={pageStyles.td}><DetailsButton entry={e} what={e.label} onOpen={onOpen} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function FireteamRows({ entries, onOpen }: { entries: FireteamEntry[]; onOpen: (e: AuditEntryView) => void }) {
  return (
    <table className={pageStyles.table} aria-label="Fireteam settings rows">
      <Head columns={['When', 'Project', 'Setting', 'Change', 'Changed by']} />
      <tbody>
        {entries.map((e) => (
          <tr key={e.id} className={pageStyles.tr}>
            <td className={pageStyles.td}><Time at={e.at} /></td>
            <td className={pageStyles.td}>{e.project.name ?? <code>{e.project.id}</code>}</td>
            <td className={pageStyles.td}><code>{e.field}</code></td>
            <td className={pageStyles.td}>{valueText(e.oldValue)} → {valueText(e.newValue)}</td>
            <td className={pageStyles.td}><Person person={e.user} /></td>
            <td className={pageStyles.td}><DetailsButton entry={e} what={`${e.field} changed`} onOpen={onOpen} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function AuditRows({ table, entries, onOpen }: { table: AuditTable; entries: AuditEntryView[]; onOpen: (e: AuditEntryView) => void }) {
  return (
    <div className={usersStyles.tableWrap}>
      {table === 'act_as' && <ActAsRows entries={entries as ActAsEntry[]} onOpen={onOpen} />}
      {table === 'fireteam' && <FireteamRows entries={entries as FireteamEntry[]} onOpen={onOpen} />}
      {table === 'audit' && <LogRows entries={entries as AuditLogEntry[]} onOpen={onOpen} />}
    </div>
  )
}
