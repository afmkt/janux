import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Container,
  List,
  MantineProvider,
  Stack,
  Text,
  Title,
} from '@mantine/core'
import '@mantine/core/styles.css'
import { clearSession, loadSession } from '../shared/session'

const consentState = new URLSearchParams(window.location.search).get('state')

interface ConsentInfo {
  client_id: string
  scopes: { scope: string; label: string }[]
}

function backToLogin(): void {
  window.location.href = `/login?redirect_uri=${encodeURIComponent(
    `/consent?state=${consentState}`,
  )}`
}

function App() {
  const [info, setInfo] = useState<ConsentInfo | null>(null)
  const [error, setError] = useState<string | null>(() =>
    consentState ? null : 'Missing consent state — restart the sign-in from the application.',
  )
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!consentState) return
    const jwt = loadSession()
    if (!jwt) {
      backToLogin()
      return
    }
    fetch(`/consent/info?state=${encodeURIComponent(consentState)}`, {
      headers: { Authorization: `Bearer ${jwt}` },
    })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as {
          ok?: boolean
          data?: ConsentInfo
          detail?: string
        }
        if (res.status === 401) {
          clearSession()
          backToLogin()
          return
        }
        if (!res.ok || !data.data) {
          throw new Error(data.detail ?? `Failed to load the consent request (${res.status})`)
        }
        setInfo(data.data)
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  const decide = useCallback(async (decision: 'accept' | 'deny') => {
    const jwt = loadSession()
    if (!jwt || !consentState) return
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/consent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({ state: consentState, decision }),
      })
      const data = (await res.json().catch(() => ({}))) as { redirect?: string; detail?: string }
      if (data.redirect) {
        window.location.href = data.redirect
        return
      }
      throw new Error(data.detail ?? 'Failed to submit the consent decision')
    } catch (e) {
      setError((e as Error).message)
      setBusy(false)
    }
  }, [])

  return (
    <MantineProvider>
      <Container size="xs" py="xl">
        <Stack gap="md">
          <div>
            <Title order={2}>Authorize application</Title>
            {info && (
              <Text c="dimmed" size="sm">
                {info.client_id} is requesting access to your account.
              </Text>
            )}
          </div>

          {error && <Alert color="red">{error}</Alert>}

          {info && (
            <>
              {info.scopes.length > 0 ? (
                <List>
                  {info.scopes.map((s) => (
                    <List.Item key={s.scope}>{s.label}</List.Item>
                  ))}
                </List>
              ) : (
                <Text c="dimmed" size="sm">
                  No additional permissions are requested.
                </Text>
              )}
              <Button fullWidth onClick={() => decide('accept')} loading={busy}>
                Allow
              </Button>
              <Button
                variant="default"
                fullWidth
                onClick={() => decide('deny')}
                disabled={busy}
              >
                Deny
              </Button>
            </>
          )}

          {!info && !error && <Text c="dimmed">Loading…</Text>}
        </Stack>
      </Container>
    </MantineProvider>
  )
}

export default App
