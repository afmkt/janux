import { useCallback, useEffect, useState } from 'react'
import { openapiVerifySessionInfo } from '../api'
import {
  envelope,
  fetchAllPages,
  isUnauthorized,
  problemText,
  sessionExpired,
  type PageCallResult,
  type PageWalk,
} from './api'

// A bare API result as the generated SDK returns it. `data`/`error` carry the
// decoded body; `response` (when present) exposes the HTTP status and `ok` flag.
// The call epilogue below is the single place that knows how to read that.
export interface RunResult {
  ok: boolean
  data: unknown
}

// ─── Session identity ─────────────────────────────────────────────────────────
// G-155/G-162: whoami is the one call that reports the actor's roles + proven
// factors. Self-service tabs call it on mount (and after a credential change).
export interface SessionMe {
  username: string
  roles: string[]
  mfa: string[]
}

export async function whoami(): Promise<SessionMe | null> {
  const { data, response } = await openapiVerifySessionInfo()
  if (!response?.ok) return null
  const info = envelope<SessionMe>(data).data
  return info?.username ? info : null
}

export function useWhoami() {
  const [me, setMe] = useState<SessionMe | null>(null)
  const refresh = useCallback(() => {
    void whoami().then(setMe)
   }, [])
  useEffect(() => {
    refresh()
   }, [refresh])
  return { me, refresh }
}

// ─── The call epilogue, centralised ───────────────────────────────────────────
// Every admin API call used to hand-roll this same block (~37 copies):
//
//   setBusy(true); setError(null)
//   const { data, error: err, response } = await fn()
//   setBusy(false)
//   if (isUnauthorized(response?.status)) return sessionExpired()
//   if (!response?.ok) setError(problemText(err, response?.status))
//
// `run` performs it once and returns { ok, data }. On a 401 it redirects to
// sign-in (sessionExpired) and reports not-ok; on any other non-2xx it routes
// the RFC 7807 problem text into the shared error state.
export function useApi() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = useCallback(
     async (fn: () => Promise<PageCallResult>): Promise<RunResult> => {
      setBusy(true)
      setError(null)
      try {
        const { data, error: err, response } = await fn()
        if (isUnauthorized(response?.status)) {
          sessionExpired()
          return { ok: false, data: undefined }
         }
        if (!response?.ok) {
          setError(problemText(err, response?.status))
          return { ok: false, data: undefined }
         }
        return { ok: true, data }
       } finally {
        setBusy(false)
       }
      },
      [setBusy, setError],
    )
  return { busy, error, run, setError, setBusy }
}

// ─── A paged CRUD resource ────────────────────────────────────────────────────
// The eight list tabs (users, roles, policies, domains, clients, providers,
// keys, tenants) each repeated the same scaffold: a list, a load that walks
// every page, and a busy/error pair. `useCrud` owns that; a tab supplies only
// its fetch and keeps its own form fields + action buttons.
export function useCrud<T>(fetchPage: (query: { limit: number; offset: number }) => Promise<PageCallResult>) {
  const { busy, error, run, setError, setBusy } = useApi()
  const [items, setItems] = useState<T[]>([])
  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const r: PageWalk<T> = await fetchAllPages<T>(fetchPage)
      if (r.unauthorized) {
        sessionExpired()
        return
       }
      if (r.errorText) {
        setError(r.errorText)
        return
       }
      setItems(r.items)
     } finally {
      setBusy(false)
     }
    }, [fetchPage, setBusy, setError])
  useMount(load)
  return { items, busy, error, setError, run, load }
}

// Fetch-on-mount, deferred one microtask. The project's
// `react-hooks/set-state-in-effect` rule forbids calling a setState-reaching
// function directly in an effect body; `Promise.resolve().then(fn)` is the
// exempt, codebase-standard form. Centralized here so the idiom is written
// once instead of repeating `Promise.resolve().then(load)` at call sites.
export function useMount(fn: () => void) {
  useEffect(() => {
    void Promise.resolve().then(fn)
        }, [fn])
}

// Row shapes shared between more than one tab.
export interface RoleRow {
  name: string
  level: number
  builtin: boolean
}
