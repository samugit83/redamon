/**
 * A secret as the UI shows it: four dots and its last four characters. A value
 * of four characters or fewer shows the dots only, since its "last four" would
 * be all of it. The full value is reachable only through a copy button.
 */
export function secretTail(value: string | null | undefined): string {
  const s = value == null ? '' : String(value)
  if (!s) return ''
  if (s.length <= 4) return '••••'
  return `••••${s.slice(-4)}`
}
