import { clearSession, hasSession } from '../shared/session'

export function setupAuth(): boolean {
  // G-139: the session JWT lives in an HttpOnly cookie the browser
  // attaches to every same-origin request — there is no token for JS to
  // hold or leak. The sessionStorage marker only gates the initial
  // render; every 401 falls back to sessionExpired().
  return hasSession()
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
