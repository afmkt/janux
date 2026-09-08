import { openapiVerifyRefresh } from '../api'
import { client } from '../api/client.gen'
import { clearSession, hasSession } from '../shared/session'

/// Machine-readable 403 signals the server raises (G-155):
/// - `mfa`: a policy required step-up (`X-MFA-Required`) — complete the
///   TOTP round, then retry the action.
/// - `reauth`: the sudo window expired (`X-Reauth-Required`, G-132) —
///   credential mutations need a fresh sign-in.
export type AuthSignal = 'mfa' | 'reauth'

type SignalHandler = (signal: AuthSignal) => void

let signalHandler: SignalHandler | null = null

export function setSignalHandler(handler: SignalHandler | null): void {
  signalHandler = handler
}

export function setupAuth(): boolean {
  // G-139: the session JWT lives in an HttpOnly cookie the browser
  // attaches to every same-origin request — there is no token for JS to
  // hold or leak. The sessionStorage marker only gates the initial
  // render; every 401 falls back to sessionExpired().
  if (!hasSession()) return false

  // G-155: one place watches both 403 signals instead of every call site
  // inspecting headers — the old code rendered them as a contentless
  // "Request failed (403)".
  client.interceptors.response.use((response) => {
    if (response.status === 403) {
      if (response.headers.get('X-MFA-Required') === 'true') signalHandler?.('mfa')
      else if (response.headers.get('X-Reauth-Required') === 'true') signalHandler?.('reauth')
    }
    return response
  })

  // G-157: rotate the HttpOnly session cookie while the console is open.
  // The server re-sets the cookie on refresh (G-139), so the 15-minute
  // session no longer drops the operator mid-edit. A failing refresh is
  // ignored here — a truly expired session surfaces as the next 401's
  // sessionExpired() redirect.
  window.setInterval(() => {
    void openapiVerifyRefresh()
  }, 5 * 60 * 1000)

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

export interface Page<T> {
  items?: T[]
  limit?: number
  offset?: number
  next_offset?: number | null
}

/// Unwrap a paginated list envelope (`{ ok, data: { items, ... } }`).
export function pageItems<T>(data: unknown): T[] {
  return envelope<Page<T>>(data).data?.items ?? []
}

export interface PageWalk<T> {
  items: T[]
  unauthorized: boolean
  errorText: string | null
}

interface PageCallResult {
  data?: unknown
  error?: unknown
  response?: { ok: boolean; status: number }
}

/// Walk every page of a paginated list endpoint by following `next_offset`,
/// so admin views keep showing the full dataset instead of silently
/// truncating at the server's default page size.
export async function fetchAllPages<T>(
  fetchPage: (query: { limit: number; offset: number }) => Promise<PageCallResult>,
): Promise<PageWalk<T>> {
  const items: T[] = []
  let offset = 0
  for (;;) {
    const { data, error: err, response } = await fetchPage({ limit: 200, offset })
    if (isUnauthorized(response?.status)) return { items: [], unauthorized: true, errorText: null }
    if (!response?.ok) {
      return { items: [], unauthorized: false, errorText: problemText(err, response?.status) }
    }
    const page = envelope<Page<T>>(data).data
    items.push(...(page?.items ?? []))
    const next = page?.next_offset
    // Follow the server's cursor; bail on a missing or non-advancing one so
    // a buggy backend cannot spin this loop forever.
    if (next == null || next <= offset) break
    offset = next
  }
  return { items, unauthorized: false, errorText: null }
}
