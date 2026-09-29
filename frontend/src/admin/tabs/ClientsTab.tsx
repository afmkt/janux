import { useState } from 'react'
import {
  Badge,
  Button,
  Group,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import {
  openapiIdpDeleteOauth2Client,
  openapiIdpListOauth2Clients,
  openapiIdpNewOauth2Client,
  openapiOidcExtSetClientMeta,
} from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

interface ClientRow {
  id: string
  redirect_uris: string
  grant_types: string
  response_types: string
  token_endpoint_auth_method: string
  scope: string
  domain_id: string
  active: boolean
}

function ClientsTab() {
  const { items: clients, error, busy, run, load } = useCrud<ClientRow>((query) =>
    openapiIdpListOauth2Clients({ query }),
     )
  const [clientId, setClientId] = useState('')
  const [secret, setSecret] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [grantTypes, setGrantTypes] = useState('authorization_code refresh_token')
  const [responseTypes, setResponseTypes] = useState('code')
  const [authMethod, setAuthMethod] = useState('client_secret_post')
  const [scopes, setScopes] = useState('openid email profile')
     // G-163: extended OIDC metadata (client_name / back-channel logout /
     // post-logout redirect URIs) had no UI; the oauth2client/meta endpoint
     // was admin-API-only. The client list does not carry these back, so the
     // form is an overlay that merges the supplied fields onto the stored row.
  const [metaClientId, setMetaClientId] = useState('')
  const [metaClientName, setMetaClientName] = useState('')
  const [metaLogoutUri, setMetaLogoutUri] = useState('')
  const [metaPostLogoutUris, setMetaPostLogoutUris] = useState('')

  const create = async () => {
    if (!clientId.trim() || !secret.trim()) return
    const { ok } = await run(() =>
      openapiIdpNewOauth2Client({
        body: {
          client_id: clientId.trim(),
          secret: secret.trim(),
          redirect_uris: redirectUris.trim(),
          grant_types: grantTypes.trim(),
          response_types: responseTypes.trim(),
          token_endpoint_auth_method: authMethod,
          default_scopes: scopes.trim(),
          },
           }),
          )
    if (!ok) return
    setClientId('')
    setSecret('')
    void load()
       }

  const remove = async (id: string) => {
    if (!window.confirm(`Delete OAuth2 client "${id}"? Its outstanding machine tokens are revoked.`)) return
    const { ok } = await run(() => openapiIdpDeleteOauth2Client({ body: { client_id: id } }))
    if (!ok) return
    void load()
        }

   // G-163: extended OIDC metadata (client_name / back-channel logout / post-
   // logout redirect URIs) had no UI -- the oauth2client/meta endpoint was
   // admin-API-only. The list DTO carries none of these back, so this is an
   // overlay that writes only the fields the operator filled in.
  const submitMeta = async () => {
    if (!metaClientId.trim()) return
       // The meta endpoint MERGES supplied fields onto the stored row, so an
       // empty field is OMITTED (leaving the stored value intact) instead of
       // sent as "" which would clobber it. post_logout_redirect_uris is
       // space-separated, matching the redirect-URI idiom above.
    const body: {
      client_id: string
      client_name?: string
      backchannel_logout_uri?: string
      post_logout_redirect_uris?: string[]
       } = { client_id: metaClientId.trim() }
    if (metaClientName.trim()) body.client_name = metaClientName.trim()
    if (metaLogoutUri.trim()) body.backchannel_logout_uri = metaLogoutUri.trim()
    const uris = metaPostLogoutUris.trim()
    if (uris) body.post_logout_redirect_uris = uris.split(/\s+/)
    const { ok } = await run(() => openapiOidcExtSetClientMeta({ body }))
    if (!ok) return
    setMetaClientId('')
    setMetaClientName('')
    setMetaLogoutUri('')
    setMetaPostLogoutUris('')
       }

  return (
       <Stack gap="md">
         <ErrorAlert error={error} />
         <Group align="flex-end">
           <TextInput
          label="Client ID"
          value={clientId}
          onChange={(e) => setClientId(e.currentTarget.value)}
          disabled={busy}
             />
           <PasswordInput
          label="Secret"
          value={secret}
          onChange={(e) => setSecret(e.currentTarget.value)}
          disabled={busy}
             />
           <TextInput
          label="Redirect URIs (space-separated)"
          value={redirectUris}
          onChange={(e) => setRedirectUris(e.currentTarget.value)}
          disabled={busy}
             />
           <TextInput
          label="Grant types"
          value={grantTypes}
          onChange={(e) => setGrantTypes(e.currentTarget.value)}
          disabled={busy}
             />
           <TextInput
          label="Response types"
          value={responseTypes}
          onChange={(e) => setResponseTypes(e.currentTarget.value)}
          disabled={busy}
             />
           <Select
          label="Token auth"
          data={['client_secret_post', 'client_secret_basic', 'none']}
          value={authMethod}
          onChange={(v) => setAuthMethod(v ?? 'client_secret_post')}
          disabled={busy}
             />
           <TextInput
          label="Default scopes"
          value={scopes}
          onChange={(e) => setScopes(e.currentTarget.value)}
          disabled={busy}
             />
           <Button onClick={create} loading={busy}>
            Create
            </Button>
          </Group>
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Client</Table.Th>
                <Table.Th>Scopes</Table.Th>
                <Table.Th>Grants</Table.Th>
                <Table.Th>Auth</Table.Th>
                <Table.Th>Active</Table.Th>
                <Table.Th>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {clients.map((c) => (
                <Table.Tr key={c.id}>
                  <Table.Td>{c.id}</Table.Td>
                  <Table.Td>{c.scope}</Table.Td>
                  <Table.Td>{c.grant_types}</Table.Td>
                  <Table.Td>{c.token_endpoint_auth_method}</Table.Td>
                  <Table.Td>
                    {c.active ? <Badge color="green">active</Badge> : <Badge>inactive</Badge>}
                  </Table.Td>
                  <Table.Td>
                    <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(c.id)}>
                     Delete
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>

          <Title order={4}>Set extended metadata</Title>
          <Text size="xs" c="dimmed">
            Merges the supplied fields onto a client's stored metadata (back-channel
            logout, post-logout redirects). Empty fields leave the stored value intact.
          </Text>
          <Group align="flex-end">
            <Select
          label="Client"
          data={clients.map((c) => c.id)}
          value={metaClientId}
          onChange={(v) => setMetaClientId(v ?? '')}
          disabled={busy}
          searchable
          clearable
          placeholder="client_id"
             />
            <TextInput
          label="Client name"
          value={metaClientName}
          onChange={(e) => setMetaClientName(e.currentTarget.value)}
          disabled={busy}
             />
            <TextInput
          label="Back-channel logout URI (https)"
          value={metaLogoutUri}
          onChange={(e) => setMetaLogoutUri(e.currentTarget.value)}
          disabled={busy}
             />
            <TextInput
          label="Post-logout redirect URIs (space-separated)"
          value={metaPostLogoutUris}
          onChange={(e) => setMetaPostLogoutUris(e.currentTarget.value)}
          disabled={busy}
             />
            <Button onClick={submitMeta} loading={busy} disabled={!metaClientId.trim()}>
             Save metadata
            </Button>
          </Group>
        </Stack>
        )
}

export default ClientsTab
