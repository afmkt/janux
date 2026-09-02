import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Container,
  Group,
  MantineProvider,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import '@mantine/core/styles.css'
import {
  openapiAdminAddDomain,
  openapiAdminAllDomains,
  openapiAdminAllTenants,
  openapiAdminDeleteDomain,
  openapiAdminNewTenant,
  openapiAdminRemoveTenant,
  openapiKeyAddKey,
  openapiKeyAllKeys,
  openapiKeyDeleteKey,
  openapiIdpDeleteOauth2Client,
  openapiIdpListOauth2Clients,
  openapiIdpNewOauth2Client,
  openapiPolicyAddPolicy,
  openapiPolicyAllPolicies,
  openapiPolicyDeletePolicy,
  openapiRoleAddRole,
  openapiRoleAllRoles,
  openapiRoleDeleteRole,
  openapiSocialAddProvider,
  openapiSocialAllProviders,
  openapiSocialRemoveProvider,
  openapiUserActivateUser,
  openapiUserAddRole,
  openapiUserAddUser,
  openapiUserAllUsers,
  openapiUserDeleteUser,
  openapiUserRemoveRole,
  type OpenapiDbHttpMethod,
  type OpenapiPolicySourceResolver,
  type OpenapiPolicyTargetResolver,
} from '../api'
import { envelope, isUnauthorized, problemText, sessionExpired, setupAuth } from './api'

const authed = setupAuth()

interface RoleRow {
  name: string
  level: number
  builtin: boolean
}

interface PolicyRow {
  id?: string | null
  resource: string
  domain: string
  role: string
  action?: OpenapiDbHttpMethod | null
  source: OpenapiPolicySourceResolver
  target: OpenapiPolicyTargetResolver
  mfa: boolean
  allowed: boolean
}

interface KeyRow {
  domain: string
  name: string
  public: string
}

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

interface ProviderRow {
  id: string
  client_id: string
  issuer_url: string
  scopes: string[]
}

function ErrorAlert({ error }: { error: string | null }) {
  if (!error) return null
  return <Alert color="red">{error}</Alert>
}

function UsersTab() {
  const [users, setUsers] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [newUser, setNewUser] = useState('')
  const [roleUser, setRoleUser] = useState('')
  const [roleName, setRoleName] = useState('')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiUserAllUsers()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setUsers(envelope<string[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!newUser.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiUserAddUser({ body: { name: newUser.trim() } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setNewUser('')
    void load()
  }

  const activate = async (user: string, active: boolean) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiUserActivateUser({ body: { user, active } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) setError(problemText(err, response?.status))
  }

  const remove = async (user: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiUserDeleteUser({ body: { user } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  const changeRole = async (add: boolean) => {
    if (!roleUser.trim() || !roleName.trim()) return
    setBusy(true)
    setError(null)
    const body = { user: roleUser.trim(), role: roleName.trim() }
    const { error: err, response } = add
      ? await openapiUserAddRole({ body })
      : await openapiUserRemoveRole({ body })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) setError(problemText(err, response?.status))
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group>
        <TextInput
          label="New user"
          placeholder="username"
          value={newUser}
          onChange={(e) => setNewUser(e.currentTarget.value)}
          disabled={busy}
        />
        <Button onClick={create} loading={busy} mt="lg">
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>User</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.map((u) => (
            <Table.Tr key={u}>
              <Table.Td>{u}</Table.Td>
              <Table.Td>
                <Group gap="xs">
                  <Button size="xs" variant="default" disabled={busy} onClick={() => activate(u, true)}>
                    Activate
                  </Button>
                  <Button size="xs" variant="default" disabled={busy} onClick={() => activate(u, false)}>
                    Deactivate
                  </Button>
                  <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(u)}>
                    Delete
                  </Button>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      <div>
        <Text fw={600} mb="xs">
          Grant / revoke role
        </Text>
        <Group>
          <TextInput
            label="User"
            value={roleUser}
            onChange={(e) => setRoleUser(e.currentTarget.value)}
            disabled={busy}
          />
          <TextInput
            label="Role"
            value={roleName}
            onChange={(e) => setRoleName(e.currentTarget.value)}
            disabled={busy}
          />
          <Button variant="default" onClick={() => changeRole(true)} disabled={busy} mt="lg">
            Add role
          </Button>
          <Button variant="default" onClick={() => changeRole(false)} disabled={busy} mt="lg">
            Remove role
          </Button>
        </Group>
      </div>
    </Stack>
  )
}

function RolesTab() {
  const [roles, setRoles] = useState<RoleRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [level, setLevel] = useState('10')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiRoleAllRoles()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setRoles(envelope<RoleRow[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!name.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiRoleAddRole({
      body: { name: name.trim(), level: Number(level) || 0 },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setName('')
    void load()
  }

  const remove = async (role: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiRoleDeleteRole({ body: { name: role } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group>
        <TextInput
          label="New role"
          placeholder="role name"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          disabled={busy}
        />
        <NumberInput
          label="Level"
          value={level}
          onChange={(v) => setLevel(String(v))}
          disabled={busy}
          min={0}
        />
        <Button onClick={create} loading={busy} mt="lg">
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Role</Table.Th>
            <Table.Th>Level</Table.Th>
            <Table.Th>Builtin</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {roles.map((r) => (
            <Table.Tr key={r.name}>
              <Table.Td>{r.name}</Table.Td>
              <Table.Td>{r.level}</Table.Td>
              <Table.Td>{r.builtin ? <Badge>builtin</Badge> : null}</Table.Td>
              <Table.Td>
                <Button
                  size="xs"
                  color="red"
                  variant="default"
                  disabled={busy || r.builtin}
                  onClick={() => remove(r.name)}
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

function PoliciesTab() {
  const [policies, setPolicies] = useState<PolicyRow[]>([])
  const [roleNames, setRoleNames] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [resource, setResource] = useState('')
  const [role, setRole] = useState<string | null>(null)
  const [action, setAction] = useState<string | null>(null)
  const [source, setSource] = useState<OpenapiPolicySourceResolver>('Nothing')
  const [target, setTarget] = useState('"Nothing"')
  const [mfa, setMfa] = useState(false)

  const load = useCallback(async () => {
    const [pol, rol] = await Promise.all([openapiPolicyAllPolicies(), openapiRoleAllRoles()])
    if (isUnauthorized(pol.response?.status) || isUnauthorized(rol.response?.status)) {
      return sessionExpired()
    }
    if (!pol.response?.ok) return setError(problemText(pol.error, pol.response?.status))
    setPolicies(envelope<PolicyRow[]>(pol.data).data ?? [])
    if (rol.response?.ok) {
      setRoleNames((envelope<RoleRow[]>(rol.data).data ?? []).map((r) => r.name))
    }
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!resource.trim() || !role) return
    let parsedTarget: OpenapiPolicyTargetResolver
    try {
      parsedTarget = JSON.parse(target) as OpenapiPolicyTargetResolver
    } catch {
      setError('Target must be valid JSON, e.g. "Nothing"')
      return
    }
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiPolicyAddPolicy({
      body: {
        resource: resource.trim(),
        domain: '',
        role,
        action: (action ?? null) as OpenapiDbHttpMethod | null,
        source,
        target: parsedTarget,
        mfa,
        allowed: true,
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setResource('')
    void load()
  }

  const remove = async (p: PolicyRow) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiPolicyDeletePolicy({
      body: { resource: p.resource, action: p.action ?? null, role: p.role },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group align="flex-end">
        <TextInput
          label="Resource"
          placeholder="/api/v1/..."
          value={resource}
          onChange={(e) => setResource(e.currentTarget.value)}
          disabled={busy}
        />
        <Select
          label="Role"
          data={roleNames}
          value={role}
          onChange={setRole}
          disabled={busy}
          searchable
        />
        <Select
          label="Method"
          data={['GET', 'POST', 'PUT', 'DELETE', 'PATCH']}
          value={action}
          onChange={setAction}
          disabled={busy}
          clearable
          placeholder="all"
        />
        <Select
          label="Source"
          data={['Nothing', 'User', 'Domain', 'Role']}
          value={source}
          onChange={(v) => setSource((v ?? 'Nothing') as OpenapiPolicySourceResolver)}
          disabled={busy}
        />
        <TextInput
          label="Target (JSON)"
          placeholder='"Nothing"'
          value={target}
          onChange={(e) => setTarget(e.currentTarget.value)}
          disabled={busy}
        />
        <Checkbox label="MFA" checked={mfa} onChange={(e) => setMfa(e.currentTarget.checked)} disabled={busy} />
        <Button onClick={create} loading={busy}>
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Resource</Table.Th>
            <Table.Th>Role</Table.Th>
            <Table.Th>Method</Table.Th>
            <Table.Th>Source</Table.Th>
            <Table.Th>MFA</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {policies.map((p, i) => (
            <Table.Tr key={p.id ?? `${p.resource}-${p.role}-${i}`}>
              <Table.Td>{p.resource}</Table.Td>
              <Table.Td>{p.role}</Table.Td>
              <Table.Td>{p.action ?? 'all'}</Table.Td>
              <Table.Td>{p.source}</Table.Td>
              <Table.Td>{p.mfa ? 'yes' : ''}</Table.Td>
              <Table.Td>
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(p)}>
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

function DomainsTab() {
  const [domains, setDomains] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [tenant, setTenant] = useState('')
  const [domain, setDomain] = useState('')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiAdminAllDomains()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setDomains(envelope<string[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!tenant.trim() || !domain.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiAdminAddDomain({
      body: { tenant: tenant.trim(), domain: domain.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setDomain('')
    void load()
  }

  const remove = async (d: string) => {
    if (!tenant.trim()) {
      setError('Enter the tenant name to delete a domain')
      return
    }
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiAdminDeleteDomain({
      body: { tenant: tenant.trim(), domain: d },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group>
        <TextInput
          label="Tenant"
          placeholder="tenant name"
          value={tenant}
          onChange={(e) => setTenant(e.currentTarget.value)}
          disabled={busy}
        />
        <TextInput
          label="New domain"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.currentTarget.value)}
          disabled={busy}
        />
        <Button onClick={create} loading={busy} mt="lg">
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Domain</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {domains.map((d) => (
            <Table.Tr key={d}>
              <Table.Td>{d}</Table.Td>
              <Table.Td>
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(d)}>
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

function ClientsTab() {
  const [clients, setClients] = useState<ClientRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [clientId, setClientId] = useState('')
  const [secret, setSecret] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [grantTypes, setGrantTypes] = useState('authorization_code refresh_token')
  const [responseTypes, setResponseTypes] = useState('code')
  const [authMethod, setAuthMethod] = useState('client_secret_post')
  const [scopes, setScopes] = useState('openid email profile')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiIdpListOauth2Clients()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setClients(envelope<ClientRow[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!clientId.trim() || !secret.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiIdpNewOauth2Client({
      body: {
        client_id: clientId.trim(),
        secret: secret.trim(),
        redirect_uris: redirectUris.trim(),
        grant_types: grantTypes.trim(),
        response_types: responseTypes.trim(),
        token_endpoint_auth_method: authMethod,
        default_scopes: scopes.trim(),
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setClientId('')
    setSecret('')
    void load()
  }

  const remove = async (id: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiIdpDeleteOauth2Client({ body: { client_id: id } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
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
              <Table.Td>{c.active ? <Badge color="green">active</Badge> : <Badge>inactive</Badge>}</Table.Td>
              <Table.Td>
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(c.id)}>
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

function ProvidersTab() {
  const [providers, setProviders] = useState<ProviderRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [issuerUrl, setIssuerUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiSocialAllProviders()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    const list = envelope<ProviderRow[]>(data).data
    setProviders(Array.isArray(list) ? list : [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!name.trim() || !issuerUrl.trim() || !clientId.trim() || !clientSecret.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiSocialAddProvider({
      body: {
        name: name.trim(),
        issuer_url: issuerUrl.trim(),
        client_id: clientId.trim(),
        client_secret: clientSecret.trim(),
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setName('')
    setIssuerUrl('')
    setClientId('')
    setClientSecret('')
    void load()
  }

  const remove = async (n: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiSocialRemoveProvider({ body: { name: n } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
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
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(p.id)}>
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

function KeysTab() {
  const [keys, setKeys] = useState<KeyRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [domain, setDomain] = useState('')
  const [name, setName] = useState('')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiKeyAllKeys()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setKeys(envelope<KeyRow[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!domain.trim() || !name.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiKeyAddKey({
      body: { domain: domain.trim(), name: name.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setName('')
    void load()
  }

  const remove = async (keyName: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiKeyDeleteKey({ body: { name: keyName } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group>
        <TextInput
          label="Domain"
          value={domain}
          onChange={(e) => setDomain(e.currentTarget.value)}
          disabled={busy}
        />
        <TextInput
          label="Key name"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          disabled={busy}
        />
        <Button onClick={create} loading={busy} mt="lg">
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Name</Table.Th>
            <Table.Th>Domain</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {keys.map((k) => (
            <Table.Tr key={`${k.domain}-${k.name}`}>
              <Table.Td>{k.name}</Table.Td>
              <Table.Td>{k.domain}</Table.Td>
              <Table.Td>
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(k.name)}>
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

function TenantsTab() {
  const [tenants, setTenants] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [admin, setAdmin] = useState('')

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiAdminAllTenants()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setTenants(envelope<string[]>(data).data ?? [])
  }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
  }, [load])

  const create = async () => {
    if (!name.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiAdminNewTenant({
      body: {
        name: name.trim(),
        domain: domain.trim() || null,
        admin: admin.trim() || null,
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setName('')
    setDomain('')
    setAdmin('')
    void load()
  }

  const remove = async (tenantName: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiAdminRemoveTenant({ body: { name: tenantName } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  return (
    <Stack gap="md">
      <ErrorAlert error={error} />
      <Group>
        <TextInput
          label="New tenant"
          placeholder="tenant name"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          disabled={busy}
        />
        <TextInput
          label="First domain (optional)"
          value={domain}
          onChange={(e) => setDomain(e.currentTarget.value)}
          disabled={busy}
        />
        <TextInput
          label="First admin (optional)"
          value={admin}
          onChange={(e) => setAdmin(e.currentTarget.value)}
          disabled={busy}
        />
        <Button onClick={create} loading={busy} mt="lg">
          Create
        </Button>
      </Group>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Tenant</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {tenants.map((t) => (
            <Table.Tr key={t}>
              <Table.Td>{t}</Table.Td>
              <Table.Td>
                <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(t)}>
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

function App() {
  useEffect(() => {
    if (!authed) window.location.href = '/login?redirect_uri=%2Fadmin'
  }, [])

  if (!authed) {
    return (
      <MantineProvider>
        <Container size="xs" py="xl">
          <Text c="dimmed">Redirecting to sign-in…</Text>
        </Container>
      </MantineProvider>
    )
  }

  return (
    <MantineProvider>
      <Container py="xl">
        <Stack gap="md">
          <Title order={2}>Admin console</Title>
          <Tabs defaultValue="users">
            <Tabs.List>
              <Tabs.Tab value="users">Users</Tabs.Tab>
              <Tabs.Tab value="roles">Roles</Tabs.Tab>
              <Tabs.Tab value="policies">Policies</Tabs.Tab>
              <Tabs.Tab value="domains">Domains</Tabs.Tab>
              <Tabs.Tab value="clients">OAuth2 clients</Tabs.Tab>
              <Tabs.Tab value="providers">Social providers</Tabs.Tab>
              <Tabs.Tab value="keys">Signing keys</Tabs.Tab>
              <Tabs.Tab value="tenants">Tenants</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="users" pt="md">
              <UsersTab />
            </Tabs.Panel>
            <Tabs.Panel value="roles" pt="md">
              <RolesTab />
            </Tabs.Panel>
            <Tabs.Panel value="policies" pt="md">
              <PoliciesTab />
            </Tabs.Panel>
            <Tabs.Panel value="domains" pt="md">
              <DomainsTab />
            </Tabs.Panel>
            <Tabs.Panel value="clients" pt="md">
              <ClientsTab />
            </Tabs.Panel>
            <Tabs.Panel value="providers" pt="md">
              <ProvidersTab />
            </Tabs.Panel>
            <Tabs.Panel value="keys" pt="md">
              <KeysTab />
            </Tabs.Panel>
            <Tabs.Panel value="tenants" pt="md">
              <TenantsTab />
            </Tabs.Panel>
          </Tabs>
        </Stack>
      </Container>
    </MantineProvider>
  )
}

export default App
