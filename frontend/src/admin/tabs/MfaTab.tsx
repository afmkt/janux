import { useState } from 'react'
import {
  Alert,
  Button,
  Group,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import {
  openapiTotpEnroll,
  openapiTotpListTotp,
  openapiTotpRemoveTotp,
  openapiTotpVerify,
} from '../../api'
import { SESSION_COOKIE } from '../../shared/session'
import { envelope, pageItems } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useWhoami } from '../common'

interface TotpRecord {
  name: string
  active: boolean
}

function MfaTab() {
  const { me, refresh } = useWhoami()
  const { busy, error, run, setError } = useApi()
  const [notice, setNotice] = useState<string | null>(null)
  const [credName, setCredName] = useState('default')
  const [pending, setPending] = useState<{ token: string; uri: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [targetUser, setTargetUser] = useState('')
  const [records, setRecords] = useState<TotpRecord[]>([])

  const startEnroll = async () => {
    if (!credName.trim()) return
    setNotice(null)
    const { ok, data } = await run(() => openapiTotpEnroll({ body: { name: credName.trim() } }))
    if (!ok) return
    const d = envelope<{ token?: string; uri?: string; qr?: string }>(data).data
    if (!d?.token) return setError('Unexpected enroll response')
    setPending({ token: d.token, uri: d.uri ?? '', qr: d.qr ?? '' })
     }

  const confirmEnroll = async () => {
    if (!me || !pending || !code.trim()) return
    const { ok } = await run(() =>
      openapiTotpVerify({
        body: {
          user: me.username,
          name: credName.trim(),
          code: code.trim(),
          token: pending.token,
          cookie: SESSION_COOKIE,
            },
              }),
              )
    if (!ok) return
    setPending(null)
    setCode('')
    setNotice('TOTP enrolled — your session was re-minted with the second factor.')
    refresh()
         }

  const listRecords = async () => {
    if (!targetUser.trim()) return
    const { ok, data } = await run(() => openapiTotpListTotp({ body: { name: targetUser.trim() } }))
    if (!ok) return
    setRecords(pageItems<TotpRecord>(data))
           }

  const removeRecord = async (rec: TotpRecord) => {
    if (!window.confirm(`Remove TOTP credential "${rec.name}" from ${targetUser}?`)) return
    const { ok } = await run(() => openapiTotpRemoveTotp({ body: { name: targetUser.trim(), totp: rec.name } }))
    if (!ok) return
    void listRecords()
            }

  const qrSrc = pending?.qr
        ? pending.qr.startsWith('data:')
          ? pending.qr
          : `data:image/png;base64,${pending.qr}`
        : null

  return (
        <Stack gap="md">
          <ErrorAlert error={error} />
          {notice && <Alert color="green" withCloseButton onClose={() => setNotice(null)}>{notice}</Alert>}

          <Title order={4}>Your second factor</Title>
          {me && (
            <Text size="sm" c="dimmed">
              Signed in as <b>{me.username}</b> — factors proven this session:{' '}
               {me.mfa.length > 0 ? me.mfa.join(', ') : '(single factor)'}
            </Text>
            )}
          {!pending ? (
            <Group align="flex-end">
              <TextInput
              label="Credential name"
              placeholder="default"
              value={credName}
              onChange={(e) => setCredName(e.currentTarget.value)}
              disabled={busy}
                 />
              <Button onClick={startEnroll} loading={busy}>
              Enroll TOTP
               </Button>
            </Group>
            ) : (
            <Stack gap="sm">
              <Text size="sm">
              Scan the QR code (or enter the URI manually) in your authenticator app, then confirm
              with a code:
               </Text>
              {qrSrc && <img src={qrSrc} alt="TOTP enrollment QR code" width={180} height={180} />}
              <Text size="xs" c="dimmed" style={{ wordBreak: 'break-all' }}>
               {pending.uri}
              </Text>
              <Group align="flex-end">
                <TextInput
                label="Code"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.currentTarget.value)}
                disabled={busy}
                inputMode="numeric"
                autoComplete="one-time-code"
                    />
                <Button onClick={confirmEnroll} loading={busy} disabled={!code.trim()}>
                Confirm enrollment
                 </Button>
                <Button variant="subtle" color="gray" onClick={() => setPending(null)} disabled={busy}>
                Cancel
                 </Button>
              </Group>
            </Stack>
            )}

          <Title order={4}>Manage a user's TOTP credentials</Title>
          <Group align="flex-end">
            <TextInput
            label="Username"
            placeholder="alice"
            value={targetUser}
            onChange={(e) => setTargetUser(e.currentTarget.value)}
            disabled={busy}
               />
            <Button variant="default" onClick={listRecords} loading={busy} disabled={!targetUser.trim()}>
            List
             </Button>
            </Group>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Active</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {records.map((rec) => (
                  <Table.Tr key={rec.name}>
                    <Table.Td>{rec.name}</Table.Td>
                    <Table.Td>{rec.active ? 'yes' : 'no'}</Table.Td>
                    <Table.Td>
                      <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => removeRecord(rec)}>
                       Remove
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                 ))}
              </Table.Tbody>
            </Table>
          </Stack>
         )
}

export default MfaTab
