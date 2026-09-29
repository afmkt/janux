import { useState } from 'react'
import { Button, Group, PasswordInput, Stack, Table, TextInput } from '@mantine/core'
import {
  openapiSocialAddProvider,
  openapiSocialAllProviders,
  openapiSocialRemoveProvider,
} from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

interface ProviderRow {
  id: string
  client_id: string
  issuer_url: string
  scopes: string[]
}

function ProvidersTab() {
  const { items: providers, error, busy, run, load } = useCrud<ProviderRow>((query) =>
    openapiSocialAllProviders({ query }),
      )
  const [name, setName] = useState('')
  const [issuerUrl, setIssuerUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')

  const create = async () => {
    if (!name.trim() || !issuerUrl.trim() || !clientId.trim() || !clientSecret.trim()) return
    const { ok } = await run(() =>
      openapiSocialAddProvider({
        body: {
          name: name.trim(),
          issuer_url: issuerUrl.trim(),
          client_id: clientId.trim(),
          client_secret: clientSecret.trim(),
           },
            }),
            )
    if (!ok) return
    setName('')
    setIssuerUrl('')
    setClientId('')
    setClientSecret('')
    void load()
          }

  const remove = async (n: string) => {
    if (!window.confirm(`Remove social provider "${n}"?`)) return
    const { ok } = await run(() => openapiSocialRemoveProvider({ body: { name: n } }))
    if (!ok) return
    void load()
           }

  return (
          <Stack gap="md">
           <ErrorAlert error={error} />
           <Group align="flex-end">
              <TextInput
          label="Name"
          placeholder="github"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          disabled={busy}
               />
              <TextInput
          label="Issuer URL"
          placeholder="https://..."
          value={issuerUrl}
          onChange={(e) => setIssuerUrl(e.currentTarget.value)}
          disabled={busy}
               />
              <TextInput
          label="Client ID"
          value={clientId}
          onChange={(e) => setClientId(e.currentTarget.value)}
          disabled={busy}
               />
              <PasswordInput
          label="Client secret"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.currentTarget.value)}
          disabled={busy}
               />
              <Button onClick={create} loading={busy}>
          Create
           </Button>
            </Group>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Provider</Table.Th>
                  <Table.Th>Issuer</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {providers.map((p) => (
                  <Table.Tr key={p.id}>
                    <Table.Td>{p.id}</Table.Td>
                    <Table.Td>{p.issuer_url}</Table.Td>
                    <Table.Td>
                      <Button
              size="xs"
              color="red"
              variant="default"
              disabled={busy}
              onClick={() => remove(p.id)}
               >
                    Delete
                    </Button>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Stack>
          )
}

export default ProvidersTab
