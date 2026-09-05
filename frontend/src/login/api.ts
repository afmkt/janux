export interface SocialProvider {
  id: string
  request: string
}

export interface FactorInfo {
  enabled: boolean
  request: string
  verify?: string
  identifier?: string | null
  providers?: SocialProvider[]
}

export interface Discovery {
  issuer: string
  /**
   * False when the host is not a registered tenant domain: the server
   * still answers discovery (Tier A — issuer and endpoint URLs are
   * derived from the request) but advertises no factors, so no login
   * ceremony can succeed. Absent on older servers; treat as provisioned.
   */
  janux_provisioned?: boolean
  acr_values_supported: string[]
  janux_factors: Record<string, FactorInfo>
}

export const NOT_PROVISIONED_TEXT =
  'This site is not set up yet — the domain is not provisioned on this Janux server.'

export async function fetchDiscovery(): Promise<Discovery> {
  const res = await fetch('/.well-known/openid-configuration')
  if (!res.ok) throw new Error(`Discovery failed (${res.status})`)
  return (await res.json()) as Discovery
}

export interface CeremonyResult {
  ok?: boolean
  code?: number
  msg?: string
  jwt?: string | null
  data?: string
  detail?: string
}

export async function postJson(url: string, body: unknown): Promise<CeremonyResult> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = (await res.json().catch(() => ({}))) as CeremonyResult
  if (!res.ok || data.ok === false) {
    throw new Error(data.msg ?? data.detail ?? `Request failed (${res.status})`)
  }
  return data
}

export function sessionJwt(data: CeremonyResult): string {
  const jwt = data.jwt ?? data.data
  if (!jwt) throw new Error('Authentication succeeded but no session was issued')
  return jwt
}

export { clearSession, loadSession, storeSession } from '../shared/session'

function sameOriginRedirect(target: string): string | null {
  try {
    const url = new URL(target, window.location.origin)
    return url.origin === window.location.origin ? url.href : null
  } catch {
    return null
  }
}

export { sameOriginRedirect }

export async function routeAfterAuth(jwt: string): Promise<boolean> {
  const params = new URLSearchParams(window.location.search)
  const clientId = params.get('client_id')
  const state = params.get('state')
  const redirectUri = params.get('redirect_uri')

  if (clientId && state) {
    const res = await fetch(`/authorize/resume?state=${encodeURIComponent(state)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${jwt}` },
    })
    const data = (await res.json().catch(() => ({}))) as { redirect?: string; detail?: string }
    if (data.redirect) {
      window.location.href = data.redirect
      return true
    }
    throw new Error(data.detail ?? 'Failed to resume the authorization request')
  }

  if (redirectUri) {
    const safe = sameOriginRedirect(redirectUri)
    if (safe) {
      window.location.href = safe
      return true
    }
  }

  return false
}
