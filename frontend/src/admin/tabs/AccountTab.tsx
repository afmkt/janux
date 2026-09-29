import { useState } from 'react'
import { Alert, Button, Group, Stack, Text, TextInput, Title } from '@mantine/core'
import {
  openapiEmailAdd,
  openapiOtpAdd,
  openapiOtpAddVerify,
  openapiPasskeyRequest,
  openapiPasskeyVerify,
} from '../../api'
import { SESSION_COOKIE } from '../../shared/session'
import { base64urlToBytes, bytesToBase64url } from '../../login/webauthn'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useWhoami } from '../common'

function AccountTab() {
  const { me, refresh } = useWhoami()
  const { busy, error, run, setError } = useApi()
  const [notice, setNotice] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [mobile, setMobile] = useState('')
  const [otpToken, setOtpToken] = useState<string | null>(null)
  const [otpCode, setOtpCode] = useState('')

  const addEmail = async () => {
    if (!email.trim()) return
    setNotice(null)
    const { ok } = await run(() => openapiEmailAdd({ body: { email: email.trim() } }))
    if (!ok) return
    setEmail('')
    setNotice(
       'Confirmation link sent — open it in this browser while signed in to finish adding the address.',
        )
       }

  const addMobile = async () => {
    if (!mobile.trim()) return
    setNotice(null)
    const { ok, data } = await run(() => openapiOtpAdd({ body: { mobile: mobile.trim() } }))
    if (!ok) return
       // MobileResponse carries the add-ceremony token in `jwt`.
    const token = (data as { jwt?: string } | null)?.jwt
    if (!token) return setError('No ceremony token in the response')
    setOtpToken(token)
          }

  const confirmMobile = async () => {
    if (!otpToken || !otpCode.trim()) return
    const { ok } = await run(() =>
      openapiOtpAddVerify({ body: { token: otpToken, code: otpCode.trim() } }),
        )
    if (!ok) return
    setOtpToken(null)
    setOtpCode('')
    setMobile('')
    setNotice('Mobile number added — SMS sign-in is now available.')
            }

  const addPasskey = async () => {
    if (!me) return
    setNotice(null)
    const req = await run(() => openapiPasskeyRequest({ body: me.username }))
    if (!req.ok) return
    const challenge = req.data as { publicKey?: PublicKeyCredentialCreationOptionsJSON; token?: string }
    const opts = challenge.publicKey
    const token = challenge.token
    if (!opts || !token) {
      setError('Unexpected passkey challenge response')
      return
       }
       // The server sends the WebAuthn JSON wire shape; convert the
       // base64url fields to buffers and hand the DOM API its own type
       // (the JSON↔DOM field types differ only in string-vs-union
       // strictness, so one localized cast does the conversion).
    const publicKey = {
      ...opts,
      challenge: base64urlToBytes(opts.challenge),
      user: {
        ...opts.user,
        id: base64urlToBytes(opts.user.id),
          },
      excludeCredentials: (opts.excludeCredentials ?? []).map((c) => ({
        id: base64urlToBytes(c.id),
        type: 'public-key',
        transports: c.transports,
        })),
    } as unknown as PublicKeyCredentialCreationOptions
    try {
      const credential = (await navigator.credentials.create({ publicKey })) as
        | PublicKeyCredential
        | null
      if (!credential) {
        setError('Passkey creation was cancelled')
        return
          }
      const att = credential.response as AuthenticatorAttestationResponse
      const verify = await run(() =>
        openapiPasskeyVerify({
          body: {
            username: me.username,
            credential: {
              id: credential.id,
              rawId: bytesToBase64url(credential.rawId),
              type: credential.type,
              response: {
                clientDataJSON: bytesToBase64url(att.clientDataJSON),
                attestationObject: bytesToBase64url(att.attestationObject),
                  },
              },
            token,
            cookie: SESSION_COOKIE,
              },
            }),
            )
      if (!verify.ok) return
      setNotice('Passkey registered — you can now sign in with it.')
      refresh()
            } catch (e) {
      setError(e instanceof Error ? e.message : 'Passkey registration failed')
        }
        }

  return (
        <Stack gap="md">
          <ErrorAlert error={error} />
          {notice && <Alert color="green" withCloseButton onClose={() => setNotice(null)}>{notice}</Alert>}

          {me && (
            <Text size="sm" c="dimmed">
              Signed in as <b>{me.username}</b> — roles: {me.roles.join(', ') || '(none)'} — factors
              proven this session: {me.mfa.length > 0 ? me.mfa.join(', ') : '(single factor)'}
            </Text>
          )}

          <Title order={4}>Add an email address</Title>
          <Group align="flex-end">
            <TextInput
              label="Email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.currentTarget.value)}
              disabled={busy}
            />
            <Button onClick={addEmail} loading={busy} disabled={!email.trim()}>
              Send confirmation
            </Button>
          </Group>

          <Title order={4}>Add a mobile number</Title>
          {!otpToken ? (
            <Group align="flex-end">
              <TextInput
                label="Mobile"
                placeholder="13800000000"
                value={mobile}
                onChange={(e) => setMobile(e.currentTarget.value)}
                disabled={busy}
              />
              <Button onClick={addMobile} loading={busy} disabled={!mobile.trim()}>
                Send SMS code
              </Button>
            </Group>
          ) : (
            <Group align="flex-end">
              <TextInput
                label="SMS code"
                placeholder="123456"
                value={otpCode}
                onChange={(e) => setOtpCode(e.currentTarget.value)}
                disabled={busy}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
              <Button onClick={confirmMobile} loading={busy} disabled={!otpCode.trim()}>
                Confirm
              </Button>
              <Button variant="subtle" color="gray" onClick={() => setOtpToken(null)} disabled={busy}>
                Cancel
              </Button>
            </Group>
          )}

          <Title order={4}>Passkeys</Title>
          <Group>
            <Button onClick={addPasskey} loading={busy} disabled={!me}>
              Register a passkey
            </Button>
          </Group>
          <Text size="xs" c="dimmed">
            Adding credentials requires a recently authenticated session (sudo mode) — if you get a
            403, sign in again first.
          </Text>
        </Stack>
      )
}

export default AccountTab
