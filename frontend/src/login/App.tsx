import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Container,
  Divider,
  MantineProvider,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import '@mantine/core/styles.css'
import {
  fetchDiscovery,
  postJson,
  routeAfterAuth,
  sessionJwt,
  storeSession,
  type Discovery,
} from './api'
import { passkeyCeremony } from './webauthn'

const ERROR_TEXT: Record<string, string> = {
  session_expired: 'Your session expired — please sign in again.',
  invalid_state: 'This sign-in link is no longer valid — please try again.',
}

const params = new URLSearchParams(window.location.search)
const urlError = params.get('error')
const landing = {
  token: params.get('token'),
  username: params.get('username'),
  email: params.get('email'),
  code: params.get('code'),
}
// A magic-link landing is only actionable when the link carries all three
// ceremony halves; a bare `?token=…` used to render a blank page (G-25).
const landingTokenComplete = Boolean(landing.token && landing.username && landing.email)
let landingHandled = false

// Verify URL fallback when discovery is unreachable at landing time.
const EMAIL_VERIFY_FALLBACK = '/api/v1/auth/email/verify'

type Phase = 'form' | 'email-sent' | 'otp-code' | 'done'

function App() {
  const [discovery, setDiscovery] = useState<Discovery | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [phase, setPhase] = useState<Phase>('form')
  const [busy, setBusy] = useState(() => Boolean(landing.code || landingTokenComplete))
  const [error, setError] = useState<string | null>(() => {
    if (urlError) return ERROR_TEXT[urlError] ?? urlError
    if (landing.token && !landingTokenComplete) {
      return 'This sign-in link is incomplete — use the full link from your email.'
    }
    return null
  })
  const [username, setUsername] = useState('')
  const [activeFactor, setActiveFactor] = useState<string | null>(null)
  const [identifier, setIdentifier] = useState('')
  const [otpCode, setOtpCode] = useState('')
  const [otpToken, setOtpToken] = useState<string | null>(null)
  // State copy of `landing.code` so a failed redeem can clear it and fall
  // back to the normal login form instead of a dead page.
  const [socialCode, setSocialCode] = useState<string | null>(landing.code)

  const finish = useCallback(async (jwt: string) => {
    storeSession(jwt)
    const navigated = await routeAfterAuth(jwt)
    if (!navigated) setPhase('done')
  }, [])

  useEffect(() => {
    if (landingHandled) return
    if (landing.code) {
      // Social callback landing (G-60): exchange the one-shot code for the
      // session JWT, then route onward (OIDC resume / redirect).
      landingHandled = true
      postJson('/api/v1/auth/social/redeem', { code: landing.code })
        .then((data) => finish(sessionJwt(data)))
        .catch((e: Error) => {
          setError(e.message)
          // Consumed/expired code: fall back to the normal login form.
          setSocialCode(null)
        })
        .finally(() => {
          // The one-shot code is gone (consumed or expired) — strip it from
          // the URL so refresh/back never retries a dead code.
          const rest = new URLSearchParams(window.location.search)
          rest.delete('code')
          const qs = rest.toString()
          window.history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
          setBusy(false)
        })
      return
    }
    if (landingTokenComplete) {
      landingHandled = true
      // G-25: the verify URL comes from discovery (janux_factors), with the
      // well-known path as fallback when discovery is unreachable.
      fetchDiscovery()
        .then((d) => d.janux_factors.email?.verify ?? EMAIL_VERIFY_FALLBACK)
        .catch(() => EMAIL_VERIFY_FALLBACK)
        .then((verifyUrl) =>
          postJson(verifyUrl, {
            token: landing.token,
            name: landing.username,
            email: landing.email,
          })
            .then((data) => finish(sessionJwt(data)))
            .catch((e: Error) => setError(e.message))
            .finally(() => setBusy(false)),
        )
      return
    }
    fetchDiscovery()
      .then(setDiscovery)
      .catch((e: Error) => setLoadError(e.message))
  }, [finish])

  const factors = discovery?.janux_factors ?? {}
  const emailFactor = factors.email
  const otpFactor = factors.otp
  const passkeyFactor = factors.passkey
  const socialProviders = factors.social?.providers ?? []

  const requireUsername = (): boolean => {
    if (!username.trim()) {
      setError('Enter your username first')
      return false
    }
    return true
  }

  const submitEmail = async () => {
    if (!emailFactor || !requireUsername() || !identifier.trim()) return
    setBusy(true)
    setError(null)
    try {
      // G-25: carry the parked return context (OIDC client_id/state or a
      // plain redirect_uri) so the emailed link can resume it after verify.
      const body: Record<string, string> = {
        name: username.trim(),
        email: identifier.trim(),
      }
      const clientId = params.get('client_id')
      const state = params.get('state')
      const redirectUri = params.get('redirect_uri')
      if (clientId) body.client_id = clientId
      if (state) body.state = state
      if (redirectUri) body.redirect_uri = redirectUri
      await postJson(emailFactor.request, body)
      setPhase('email-sent')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const submitOtpRequest = async () => {
    if (!otpFactor || !requireUsername() || !identifier.trim()) return
    setBusy(true)
    setError(null)
    try {
      const data = await postJson(otpFactor.request, {
        name: username.trim(),
        mobile: identifier.trim(),
      })
      if (!data.jwt) throw new Error('OTP request succeeded but no ceremony token was issued')
      setOtpToken(data.jwt)
      setPhase('otp-code')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const submitOtpVerify = async () => {
    if (!otpFactor?.verify || !otpCode.trim() || !otpToken) return
    setBusy(true)
    setError(null)
    try {
      const data = await postJson(otpFactor.verify, {
        token: otpToken,
        name: username.trim(),
        mobile: identifier.trim(),
        code: otpCode.trim(),
      })
      await finish(sessionJwt(data))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const submitPasskey = async () => {
    if (!passkeyFactor?.verify || !requireUsername()) return
    setBusy(true)
    setError(null)
    try {
      const jwt = await passkeyCeremony(passkeyFactor.request, passkeyFactor.verify, username.trim())
      await finish(jwt)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const selectFactor = (factor: string) => {
    setError(null)
    if (activeFactor === factor) {
      setActiveFactor(null)
      setIdentifier('')
      return
    }
    setActiveFactor(factor)
    setIdentifier('')
  }

  return (
    <MantineProvider>
      <Container size="xs" py="xl">
        <Stack gap="md">
          <div>
            <Title order={2}>Sign in</Title>
            <Text c="dimmed" size="sm">
              Sign in or create an account — same flow.
            </Text>
          </div>

          {error && <Alert color="red">{error}</Alert>}
          {loadError && <Alert color="red">{loadError}</Alert>}
          {busy && phase === 'form' && !landingTokenComplete && !socialCode && (
            <Text c="dimmed">Working…</Text>
          )}

          {phase === 'form' && !landingTokenComplete && !socialCode && (
            <>
              <TextInput
                label="Username"
                value={username}
                onChange={(e) => setUsername(e.currentTarget.value)}
                disabled={busy}
              />

              {emailFactor && (
                <Button
                  variant={activeFactor === 'email' ? 'filled' : 'default'}
                  fullWidth
                  disabled={busy}
                  onClick={() => selectFactor('email')}
                >
                  Email me a sign-in link
                </Button>
              )}
              {activeFactor === 'email' && (
                <>
                  <TextInput
                    label="Email address"
                    placeholder="you@example.com"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.currentTarget.value)}
                    disabled={busy}
                  />
                  <Button fullWidth onClick={submitEmail} loading={busy}>
                    Send link
                  </Button>
                </>
              )}

              {otpFactor && (
                <Button
                  variant={activeFactor === 'otp' ? 'filled' : 'default'}
                  fullWidth
                  disabled={busy}
                  onClick={() => selectFactor('otp')}
                >
                  Text me a code
                </Button>
              )}
              {activeFactor === 'otp' && (
                <>
                  <TextInput
                    label="Mobile number"
                    placeholder="+86…"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.currentTarget.value)}
                    disabled={busy}
                  />
                  <Button fullWidth onClick={submitOtpRequest} loading={busy}>
                    Send code
                  </Button>
                </>
              )}

              {(emailFactor || otpFactor) && (passkeyFactor || socialProviders.length > 0) && (
                <Divider label="or" labelPosition="center" />
              )}

              {passkeyFactor && (
                <Button variant="default" fullWidth disabled={busy} onClick={submitPasskey}>
                  Use a passkey
                </Button>
              )}

              {socialProviders.map((p) => (
                <Button
                  key={p.id}
                  variant="default"
                  fullWidth
                  disabled={busy}
                  onClick={() => {
                    // Carry the return context through the IdP hop (G-60):
                    // parked OIDC client_id/state, or a plain redirect_uri.
                    const ctx = new URLSearchParams()
                    const clientId = params.get('client_id')
                    const state = params.get('state')
                    const redirectUri = params.get('redirect_uri')
                    if (clientId) ctx.set('client_id', clientId)
                    if (state) ctx.set('state', state)
                    if (redirectUri) ctx.set('redirect_uri', redirectUri)
                    const qs = ctx.toString()
                    window.location.href = qs ? `${p.request}?${qs}` : p.request
                  }}
                >
                  Continue with {p.id}
                </Button>
              ))}

              {!discovery && !loadError && <Text c="dimmed">Loading…</Text>}
            </>
          )}

          {phase === 'email-sent' && (
            <>
              <Alert color="green">
                Check your inbox — a sign-in link is on its way to {identifier}.
              </Alert>
              <Button variant="default" fullWidth onClick={submitEmail} loading={busy}>
                Send it again
              </Button>
            </>
          )}

          {phase === 'otp-code' && (
            <>
              <Alert color="green">Enter the 6-digit code sent to {identifier}.</Alert>
              <TextInput
                label="Code"
                value={otpCode}
                onChange={(e) => setOtpCode(e.currentTarget.value)}
                disabled={busy}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
              <Button fullWidth onClick={submitOtpVerify} loading={busy}>
                Verify
              </Button>
            </>
          )}

          {phase === 'done' && <Alert color="green">Signed in.</Alert>}
        </Stack>
      </Container>
    </MantineProvider>
  )
}

export default App
