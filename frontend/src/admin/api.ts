import { client } from '../api/client.gen'
import { clearSession, loadSession } from '../shared/session'

export function setupAuth(): boolean {
  const jwt = loadSession()
  if (!jwt) return false
  client.setConfig({ headers: { Authorization: `Bearer ${jwt}` } })
  return true
}

export function sessionExpired(): void {
  clearSession()
  window.location.href = '/login?redirect_uri=%2Fadmin'
}

export function isUnauthorized(status?: number): boolean {
  return status === 401
}

export function problemText(error: unknown, status?: number): string {
  const e = error as { detail?: string; msg?: string } | null | undefined
  return e?.detail ?? e?.msg ?? `Request failed (${status ?? '?'})`
}

export interface Envelope<T> {
  ok?: boolean
  data?: T
}

export function envelope<T>(data: unknown): Envelope<T> {
  return (data ?? {}) as Envelope<T>
}
