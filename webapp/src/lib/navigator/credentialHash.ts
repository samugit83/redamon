import { createHash } from 'node:crypto'

/** The registry keeps only this digest of a navigator credential, never the token. */
export function hashCredential(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}
