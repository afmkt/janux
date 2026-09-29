import { useState } from 'react'
import { Alert, Button, Group, Text, TextInput } from '@mantine/core'
import { openapiTotpEnroll, openapiTotpVerify } from '../../api'
import { SESSION_COOKIE } from '../../shared/session'
import { envelope, type AuthSignal } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useWhoami } from '../common'

function SignalPanel({ kind, onDone }: { kind: AuthSignal; onDone: () => void }) {
  const { me } = useWhoami()
  const { busy, error, run, setError } = useApi()
  const [stage, setStage] = useState<'code1' | 'code2'>('code1')
  const [credName, setCredName] = useState('default')
  const [code, setCode] = useState('')
  const [stepToken, setStepToken] = useState('')

  if (kind === 'reauth') {
    return (
        <Alert color="orange" title="Re-authentication required" withCloseButton onClose={onDone}>
          <Text size="sm">
           Credential changes require a recent sign-in (this session is older than the sudo
            window). Sign in again, then retry the action.
          </Text>
          <Button
        mt="sm"
        size="xs"
        variant="default"
        onClick={() => {
             window.location.href = '/login?redirect_uri=%2Fadmin'
            }}
        >
         Go to sign-in
         </Button>
        </Alert>
        )
    }

  const submit = async () => {
    if (!me || !code.trim()) return
    if (stage === 'code1') {
        // Step 1: the CURRENT code exchanges for a one-time step-up token
        // (the server consumes the code and re-exposes nothing).
      const { ok, data } = await run(() =>
        openapiTotpEnroll({ body: { name: credName.trim() || 'default', code: code.trim() } }),
         )
      if (!ok) return
      const token = envelope<{ token?: string }>(data).data?.token
      if (!token) return setError('Step-up token missing from the enroll response')
      setStepToken(token)
      setStage('code2')
      setCode('')
      return
       }
      // Step 2: the NEXT code completes the step-up; the re-minted session
      // lands in the HttpOnly cookie (G-139) carrying the totp factor.
    const { ok } = await run(() =>
      openapiTotpVerify({
        body: {
          user: me.username,
          name: credName.trim() || 'default',
          code: code.trim(),
          token: stepToken,
          cookie: SESSION_COOKIE,
           },
          })
    )
    if (!ok) return
    onDone()
     }

  return (
       <Alert color="blue" title="Two-factor step-up required" withCloseButton onClose={onDone}>
        <ErrorAlert error={error} />
        <Text size="sm">
         {stage === 'code1'
          ? 'A policy on this action requires TOTP. Enter your current authenticator code.'
          : 'Enter the NEXT authenticator code to complete the step-up, then retry the action.'}
        </Text>
        <Group mt="sm">
         <TextInput
         label="Credential name"
         placeholder="default"
         value={credName}
         onChange={(e) => setCredName(e.currentTarget.value)}
         disabled={busy || stage === 'code2'}
         size="xs"
             />
         <TextInput
         label="Code"
         placeholder="123456"
         value={code}
         onChange={(e) => setCode(e.currentTarget.value)}
         disabled={busy || !me}
         inputMode="numeric"
         autoComplete="one-time-code"
         size="xs"
             />
         <Button size="xs" onClick={submit} loading={busy} disabled={!me || !code.trim()}>
          {stage === 'code1' ? 'Continue' : 'Complete step-up'}
          </Button>
        </Group>
        {!me && (
         <Text size="xs" c="dimmed" mt="xs">
          Loading session identity… (if this persists, sign in again)
          </Text>
          )}
        </Alert>
        )
}

export default SignalPanel
