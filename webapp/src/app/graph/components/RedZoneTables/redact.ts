export function redactSecret(value: string | null | undefined): string {
  if (!value) return '-'
  const s = String(value)
  if (s.length <= 8) return s.slice(0, 2) + '***'
  return s.slice(0, 4) + '***' + s.slice(-4)
}
