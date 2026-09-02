import { useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Container,
  List,
  MantineProvider,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import '@mantine/core/styles.css'
import { loadSession } from '../shared/session'

const urlCode = new URLSearchParams(window.location.search).get('user_code')

interface DeviceInfo {
  client_id: string
  scopes: { scope: string; label: string }[]
}

interface InfoResponse {
  data?: DeviceInfo
  detail?: string
}

interface ApproveResponse {
  status?: string
  already_processed?: boolean
  redirect?: string
  detail?: string
}

type Phase = 'enter-code' | 'details' | 'done'

function loginRedirect(code: string): string {
  return `/login?redirect_uri=${encodeURIComponent(`/device-login?user_code=${code}`)}`
}

function App() {
  const [phase, setPhase] = useState<Phase>(urlCode ? 'details' : 'enter-code')
  const [code, setCode] = useState(urlCode ?? '')
  const [info, setInfo] = useState<DeviceInfo | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(() => Boolean(urlCode))

  useEffect(() => {
    if (!urlCode) return
    fetch(`/device-login/info?user_code=${encodeURIComponent(urlCode)}`)
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as InfoResponse
        if (!res.ok || !data.data) {
          throw new Error(data.detail ?? `Unknown or expired code (${res.status})`)
        }
        setInfo(data.data)
      })
      .catch((e: Error) => {
        setError(e.message)
        setPhase('enter-code')
      })
      .finally(() => setBusy(false))
  }, [])

  const submitCode = async () => {
    const trimmed = code.trim()
    if (!trimmed) return
    setBusy(true)
    setError(null)
    try {
      const res = await fetch(`/device-login/info?user_code=${encodeURIComponent(trimmed)}`)
      const data = (await res.json().catch(() => ({}))) as InfoResponse
      if (!res.ok || !data.data) {
        throw new Error(data.detail ?? `Unknown or expired code (${res.status})`)
      }
      setInfo(data.data)
      setPhase('details')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const decide = async (action: 'approve' | 'deny') => {
    const trimmed = code.trim()
    if (!trimmed) return
    const jwt = loadSession()
    if (!jwt) {
      window.location.href = loginRedirect(trimmed)
      return
    }
    setBusy(true)
    setError(null)
    try {
      const res = await fetch('/device-login/approve', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({ user_code: trimmed, action }),
      })
      const data = (await res.json().catch(() => ({}))) as ApproveResponse
      if (res.status === 401 && data.redirect) {
        window.location.href = data.redirect
        return
      }
      if (!res.ok) {
        throw new Error(data.detail ?? `Submitting the decision failed (${res.status})`)
      }
      setResult(
        data.already_processed
          ? `This code was already ${data.status ?? 'processed'} — you can close this page.`
          : `Authorization ${data.status ?? 'processed'} — you can close this page.`,
      )
      setPhase('done')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <MantineProvider>
      <Container size="xs" py="xl">
        <Stack gap="md">
          <div>
            <Title order={2}>Device authorization</Title>
            <Text c="dimmed" size="sm">
              Enter the code shown on your device to authorize it.
            </Text>
          </div>

          {error && <Alert color="red">{error}</Alert>}
          {result && <Alert color="green">{result}</Alert>}

          {phase === 'enter-code' && (
            <>
              <TextInput
                label="Code"
                placeholder="e.g. ABCD-1234"
                value={code}
                onChange={(e) => setCode(e.currentTarget.value)}
                disabled={busy}
              />
              <Button fullWidth onClick={submitCode} loading={busy}>
                Continue
              </Button>
            </>
          )}

          {phase === 'details' && info && (
            <>
              <Text c="dimmed" size="sm">
                <b>{info.client_id}</b> is requesting access to your account.
              </Text>
              {info.scopes.length > 0 ? (
                <List>
                  {info.scopes.map((s) => (
                    <List.Item key={s.scope}>{s.label}</List.Item>
                  ))}
                </List>
              ) : (
                <Text c="dimmed" size="sm">No additional permissions are requested.</Text>
              )}
              <Button fullWidth onClick={() => decide('approve')} loading={busy}>
                Approve
              </Button>
              <Button variant="default" fullWidth onClick={() => decide('deny')} disabled={busy}>
                Deny
              </Button>
              <Button
                variant="subtle"
                fullWidth
                disabled={busy}
                onClick={() => {
                  setPhase('enter-code')
                  setInfo(null)
                  setError(null)
                }}
              >
                Use a different code
              </Button>
            </>
          )}

          {phase === 'details' && !info && busy && <Text c="dimmed">Loading…</Text>}
        </Stack>
      </Container>
    </MantineProvider>
  )
}

export default App
