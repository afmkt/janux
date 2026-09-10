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
  Switch,
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
  openapiEmailAdd,
  openapiKeyAddKey,
  openapiKeyAllKeys,
  openapiKeyDeleteKey,
  openapiKeyRetireKey,
  openapiIdpDeleteOauth2Client,
  openapiIdpListOauth2Clients,
  openapiIdpNewOauth2Client,
  openapiOtpAdd,
  openapiOtpAddVerify,
  openapiOtpRemove,
  openapiEmailRemove,
  openapiOidcExtOidcConfig,
  openapiOidcExtSetClientMeta,
  openapiOidcExtSetOidcConfig,
  openapiOpsMetrics,
  openapiPasskeyDeactivate,
  openapiPasskeyRequest,
  openapiPasskeyVerify,
  openapiPolicyAddPolicy,
  openapiPolicyAllPolicies,
  openapiPolicyDeletePolicy,
  openapiRoleAddRole,
  openapiRoleAllRoles,
  openapiRoleDeleteRole,
  openapiSocialAddProvider,
  openapiSocialAllProviders,
  openapiSocialRemoveProvider,
  openapiTotpEnroll,
  openapiTotpListTotp,
  openapiTotpRemoveTotp,
  openapiTotpVerify,
  openapiUserActivateUser,
  openapiUserAddRole,
  openapiUserAddUser,
  openapiUserAllUsers,
  openapiUserDeleteUser,
  openapiUserRemoveRole,
  openapiUserUserRoles,
  openapiVerifySessionInfo,
  type OpenapiDbHttpMethod,
  type OpenapiOidcExtOidcTenantConfig,
  type OpenapiPolicySourceResolver,
  type OpenapiPolicyTargetResolver,
} from '../api'
import { SESSION_COOKIE } from '../shared/session'
import { base64urlToBytes, bytesToBase64url } from '../login/webauthn'
import {
  envelope,
  fetchAllPages,
  isUnauthorized,
  pageItems,
  problemText,
  sessionExpired,
  setSignalHandler,
  setupAuth,
  type AuthSignal,
} from './api'

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
  retired: boolean
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
  // G-163: a user's effective roles used to be invisible in the console.
  const [rolesView, setRolesView] = useState<{ user: string; roles: string[] } | null>(null)

  const load = useCallback(async () => {
    const r = await fetchAllPages<string>((query) => openapiUserAllUsers({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setUsers(r.items)
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
    if (!window.confirm(`Delete user "${user}"? The account and its role grants are removed.`)) return
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

  const showRoles = async (user: string) => {
    setBusy(true)
    setError(null)
    const { data, error: err, response } = await openapiUserUserRoles({ query: { user } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setRolesView({ user, roles: envelope<string[]>(data).data ?? [] })
  }

  // G-163/G-101: per-user credential removal — the recovery levers for a
  // locked-out or compromised account (each is H3-gated server-side).
  const removePasskeys = async (user: string) => {
    if (!window.confirm(`Deactivate ALL passkeys of "${user}"? They must re-register afterwards.`)) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiPasskeyDeactivate({ body: { name: user } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) setError(problemText(err, response?.status))
  }

  const removeEmail = async (user: string) => {
    const email = window.prompt(`Email address to remove from "${user}":`)
    if (!email?.trim()) return
    if (!window.confirm(`Remove ${email.trim()} from "${user}"?`)) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiEmailRemove({
      query: { name: user, email: email.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) setError(problemText(err, response?.status))
  }

  const removeMobile = async (user: string) => {
    const mobile = window.prompt(`Mobile number to remove from "${user}":`)
    if (!mobile?.trim()) return
    if (!window.confirm(`Remove ${mobile.trim()} from "${user}"?`)) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiOtpRemove({
      query: { name: user, mobile: mobile.trim() },
    })
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
            <Table.Th>Roles</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.map((u) => (
            <Table.Tr key={u}>
              <Table.Td>{u}</Table.Td>
              <Table.Td>
                {rolesView?.user === u ? (
                  <Group gap="xs">
                    {rolesView.roles.length === 0 && <Text size="xs" c="dimmed">(none)</Text>}
                    {rolesView.roles.map((r) => (
                      <Badge key={r} variant="light">
                        {r}
                      </Badge>
                    ))}
                  </Group>
                ) : (
                  <Button size="xs" variant="subtle" disabled={busy} onClick={() => showRoles(u)}>
                    Show
                  </Button>
                )}
              </Table.Td>
              <Table.Td>
                <Group gap="xs">
                  <Button size="xs" variant="default" disabled={busy} onClick={() => activate(u, true)}>
                    Activate
                  </Button>
                  <Button size="xs" variant="default" disabled={busy} onClick={() => activate(u, false)}>
                    Deactivate
                  </Button>
                  <Button size="xs" variant="default" disabled={busy} onClick={() => removePasskeys(u)}>
                    Drop passkeys
                  </Button>
                  <Button size="xs" variant="default" disabled={busy} onClick={() => removeEmail(u)}>
                    Remove email
                  </Button>
                  <Button size="xs" variant="default" disabled={busy} onClick={() => removeMobile(u)}>
                    Remove mobile
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
    const r = await fetchAllPages<RoleRow>((query) => openapiRoleAllRoles({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setRoles(r.items)
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
    if (!window.confirm(`Delete role "${role}"? Its policies and memberships are removed too.`)) return
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
  // G-163: deny policies are first-class server-side (a deny outranks
  // every allow) — the UI could neither create nor see them before.
  const [allowed, setAllowed] = useState(true)

  const load = useCallback(async () => {
    const [pol, rol] = await Promise.all([
      fetchAllPages<PolicyRow>((query) => openapiPolicyAllPolicies({ query })),
      fetchAllPages<RoleRow>((query) => openapiRoleAllRoles({ query })),
    ])
    if (pol.unauthorized || rol.unauthorized) return sessionExpired()
    if (pol.errorText) return setError(pol.errorText)
    setPolicies(pol.items)
    if (!rol.errorText) {
      setRoleNames(rol.items.map((r) => r.name))
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
        allowed,
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setResource('')
    void load()
  }

  const remove = async (p: PolicyRow) => {
    // G-156: destructive admin actions confirm first.
    if (!window.confirm(`Delete policy ${p.resource} → ${p.role}?`)) return
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
          data={[
            'GET',
            'HEAD',
            'POST',
            'PUT',
            'DELETE',
            'CONNECT',
            'OPTIONS',
            'TRACE',
            'PATCH',
          ]}
          value={action}
          onChange={setAction}
          disabled={busy}
          clearable
          searchable
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
        <Select
          label="Effect"
          data={[
            { value: 'allow', label: 'Allow' },
            { value: 'deny', label: 'Deny' },
          ]}
          value={allowed ? 'allow' : 'deny'}
          onChange={(v) => setAllowed(v !== 'deny')}
          disabled={busy}
          allowDeselect={false}
        />
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
            <Table.Th>Effect</Table.Th>
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
                <Badge color={p.allowed ? 'green' : 'red'} variant="light">
                  {p.allowed ? 'Allow' : 'Deny'}
                </Badge>
              </Table.Td>
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
    const r = await fetchAllPages<string>((query) => openapiAdminAllDomains({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setDomains(r.items)
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
    if (!window.confirm(`Remove domain "${d}" from this tenant?`)) return
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
  // G-163: extended OIDC metadata (client_name / back-channel logout /
  // post-logout redirect URIs) had no UI; the oauth2client/meta endpoint
  // was admin-API-only. The client list does not carry these back, so the
  // form is an overlay that merges the supplied fields onto the stored row.
  const [metaClientId, setMetaClientId] = useState('')
  const [metaClientName, setMetaClientName] = useState('')
  const [metaLogoutUri, setMetaLogoutUri] = useState('')
  const [metaPostLogoutUris, setMetaPostLogoutUris] = useState('')

  const load = useCallback(async () => {
    const r = await fetchAllPages<ClientRow>((query) => openapiIdpListOauth2Clients({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setClients(r.items)
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
    if (!window.confirm(`Delete OAuth2 client "${id}"? Its outstanding machine tokens are revoked.`)) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiIdpDeleteOauth2Client({ body: { client_id: id } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }


  // G-163: extended OIDC metadata (client_name / back-channel logout / post-
  // logout redirect URIs) had no UI -- the oauth2client/meta endpoint was
  // admin-API-only. The list DTO carries none of these back, so this is an
  // overlay that writes only the fields the operator filled in.
  const submitMeta = async () => {
    if (!metaClientId.trim()) return
    setBusy(true)
    setError(null)
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
    const { error: err, response } = await openapiOidcExtSetClientMeta({ body })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
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

function ProvidersTab() {
  const [providers, setProviders] = useState<ProviderRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [issuerUrl, setIssuerUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')

  const load = useCallback(async () => {
    const r = await fetchAllPages<ProviderRow>((query) => openapiSocialAllProviders({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setProviders(r.items)
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
    if (!window.confirm(`Remove social provider "${n}"?`)) return
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
    const r = await fetchAllPages<KeyRow>((query) => openapiKeyAllKeys({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setKeys(r.items)
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

  const retire = async (keyName: string) => {
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiKeyRetireKey({ body: { name: keyName } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    void load()
  }

  const remove = async (keyName: string) => {
    if (!window.confirm(`Delete retired key "${keyName}"? Any token still signed by it stops verifying.`)) return
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
            <Table.Th>Status</Table.Th>
            <Table.Th>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {keys.map((k) => (
            <Table.Tr key={`${k.domain}-${k.name}`}>
              <Table.Td>{k.name}</Table.Td>
              <Table.Td>{k.domain}</Table.Td>
              <Table.Td>{k.retired ? 'Retired' : 'Signing'}</Table.Td>
              <Table.Td>
                {/* G-97 lifecycle: retire stops signing but keeps verifying
                    outstanding tokens; only a retired key can be deleted. */}
                {k.retired ? (
                  <Button size="xs" color="red" variant="default" disabled={busy} onClick={() => remove(k.name)}>
                    Delete
                  </Button>
                ) : (
                  <Button size="xs" color="orange" variant="default" disabled={busy} onClick={() => retire(k.name)}>
                    Retire
                  </Button>
                )}
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
    const r = await fetchAllPages<string>((query) => openapiAdminAllTenants({ query }))
    if (r.unauthorized) return sessionExpired()
    if (r.errorText) return setError(r.errorText)
    setTenants(r.items)
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
    // G-156: the most destructive action in the console confirms first.
    if (!window.confirm(`DELETE TENANT "${tenantName}"? Every user, key and policy of that tenant is destroyed.`)) return
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

// ─── Session identity, 403 signals, TOTP + credential self-service ──────────
// G-138: TOTP enrollment/step-up UI — without it an `mfa: true` policy was
// a dead end (no page could enroll or satisfy it).
// G-155: the server's machine-readable 403s (X-MFA-Required /
// X-Reauth-Required) are surfaced and actionable instead of rendering as a
// contentless "Request failed (403)".
// G-162: self-service credential management (email, mobile, passkey).

interface SessionMe {
  username: string
  roles: string[]
  mfa: string[]
}

async function whoami(): Promise<SessionMe | null> {
  const { data, response } = await openapiVerifySessionInfo()
  if (!response?.ok) return null
  const info = envelope<SessionMe>(data).data
  return info?.username ? info : null
}

function SignalPanel({ kind, onDone }: { kind: AuthSignal; onDone: () => void }) {
  const [me, setMe] = useState<SessionMe | null>(null)
  const [stage, setStage] = useState<'code1' | 'code2'>('code1')
  const [credName, setCredName] = useState('default')
  const [code, setCode] = useState('')
  const [stepToken, setStepToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void whoami().then(setMe)
  }, [])

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
    setBusy(true)
    setError(null)
    if (stage === 'code1') {
      // Step 1: the CURRENT code exchanges for a one-time step-up token
      // (the server consumes the code and re-exposes nothing).
      const { data, error: err, response } = await openapiTotpEnroll({
        body: { name: credName.trim() || 'default', code: code.trim() },
      })
      setBusy(false)
      if (!response?.ok) return setError(problemText(err, response?.status))
      const token = envelope<{ token?: string }>(data).data?.token
      if (!token) return setError('Step-up token missing from the enroll response')
      setStepToken(token)
      setStage('code2')
      setCode('')
      return
    }
    // Step 2: the NEXT code completes the step-up; the re-minted session
    // lands in the HttpOnly cookie (G-139) carrying the totp factor.
    const { error: err, response } = await openapiTotpVerify({
      body: {
        user: me.username,
        name: credName.trim() || 'default',
        code: code.trim(),
        token: stepToken,
        cookie: SESSION_COOKIE,
      },
    })
    setBusy(false)
    if (!response?.ok) return setError(problemText(err, response?.status))
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

interface TotpRecord {
  name: string
  active: boolean
}

function MfaTab() {
  const [me, setMe] = useState<SessionMe | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [credName, setCredName] = useState('default')
  const [pending, setPending] = useState<{ token: string; uri: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [targetUser, setTargetUser] = useState('')
  const [records, setRecords] = useState<TotpRecord[]>([])

  useEffect(() => {
    void whoami().then(setMe)
  }, [])

  const startEnroll = async () => {
    if (!credName.trim()) return
    setBusy(true)
    setError(null)
    setNotice(null)
    const { data, error: err, response } = await openapiTotpEnroll({
      body: { name: credName.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    const d = envelope<{ token?: string; uri?: string; qr?: string }>(data).data
    if (!d?.token) return setError('Unexpected enroll response')
    setPending({ token: d.token, uri: d.uri ?? '', qr: d.qr ?? '' })
  }

  const confirmEnroll = async () => {
    if (!me || !pending || !code.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiTotpVerify({
      body: {
        user: me.username,
        name: credName.trim(),
        code: code.trim(),
        token: pending.token,
        cookie: SESSION_COOKIE,
      },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setPending(null)
    setCode('')
    setNotice('TOTP enrolled — your session was re-minted with the second factor.')
    void whoami().then(setMe)
  }

  const listRecords = async () => {
    if (!targetUser.trim()) return
    setBusy(true)
    setError(null)
    const { data, error: err, response } = await openapiTotpListTotp({
      body: { name: targetUser.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setRecords(pageItems<TotpRecord>(data))
  }

  const removeRecord = async (rec: TotpRecord) => {
    if (!window.confirm(`Remove TOTP credential "${rec.name}" from ${targetUser}?`)) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiTotpRemoveTotp({
      body: { name: targetUser.trim(), totp: rec.name },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
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

function AccountTab() {
  const [me, setMe] = useState<SessionMe | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [mobile, setMobile] = useState('')
  const [otpToken, setOtpToken] = useState<string | null>(null)
  const [otpCode, setOtpCode] = useState('')

  useEffect(() => {
    void whoami().then(setMe)
  }, [])

  const addEmail = async () => {
    if (!email.trim()) return
    setBusy(true)
    setError(null)
    setNotice(null)
    const { error: err, response } = await openapiEmailAdd({ body: { email: email.trim() } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setEmail('')
    setNotice(
      'Confirmation link sent — open it in this browser while signed in to finish adding the address.',
    )
  }

  const addMobile = async () => {
    if (!mobile.trim()) return
    setBusy(true)
    setError(null)
    setNotice(null)
    const { data, error: err, response } = await openapiOtpAdd({ body: { mobile: mobile.trim() } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    // MobileResponse carries the add-ceremony token in `jwt`.
    const token = (data as { jwt?: string } | null)?.jwt
    if (!token) return setError('No ceremony token in the response')
    setOtpToken(token)
  }

  const confirmMobile = async () => {
    if (!otpToken || !otpCode.trim()) return
    setBusy(true)
    setError(null)
    const { error: err, response } = await openapiOtpAddVerify({
      body: { token: otpToken, code: otpCode.trim() },
    })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setOtpToken(null)
    setOtpCode('')
    setMobile('')
    setNotice('Mobile number added — SMS sign-in is now available.')
  }

  const addPasskey = async () => {
    if (!me) return
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const { data, error: err, response } = await openapiPasskeyRequest({ body: me.username })
      if (!response?.ok) {
        setError(problemText(err, response?.status))
        return
      }
      const challenge = data as { publicKey?: PublicKeyCredentialCreationOptionsJSON; token?: string }
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
      const credential = (await navigator.credentials.create({
        publicKey,
      })) as PublicKeyCredential | null
      if (!credential) {
        setError('Passkey creation was cancelled')
        return
      }
      const att = credential.response as AuthenticatorAttestationResponse
      const { error: verr, response: vres } = await openapiPasskeyVerify({
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
      })
      if (!vres?.ok) {
        setError(problemText(verr, vres?.status))
        return
      }
      setNotice('Passkey registered — you can now sign in with it.')
      void whoami().then(setMe)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Passkey registration failed')
    } finally {
      setBusy(false)
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

// G-163: tenant OIDC feature switches (Dynamic Client Registration) had no UI;
// the oidc/config read/write endpoints were admin-API-only.
function OidcConfigTab() {
  const [dcrEnabled, setDcrEnabled] = useState<boolean | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    const { data, error: err, response } = await openapiOidcExtOidcConfig()
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setDcrEnabled(envelope<OpenapiOidcExtOidcTenantConfig>(data).data?.dcr_enabled ?? false)
   }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
   }, [load])

  const save = async (dcr_enabled: boolean) => {
    if (dcr_enabled === dcrEnabled) return
    setBusy(true)
    setError(null)
    setNotice(null)
    const { error: err, response } = await openapiOidcExtSetOidcConfig({ body: { dcr_enabled } })
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setDcrEnabled(dcr_enabled)
    setNotice(`Dynamic client registration is now ${dcr_enabled ? 'enabled' : 'disabled'}.`)
   }

  return (
     <Stack gap="md">
       <ErrorAlert error={error} />
       {notice && <Alert color="green" withCloseButton onClose={() => setNotice(null)}>{notice}</Alert>}
       <Text size="sm" c="dimmed">
       Dynamic Client Registration (RFC 7591/7592): when on, any caller may
       self-register a new OAuth2 client with no admin involvement. This is an
       open surface -- enable it only for trusted networks.
       </Text>
       <Group align="center">
         <Text size="sm">Dynamic Client Registration</Text>
         <Switch
          checked={dcrEnabled ?? false}
          onChange={(e) => void save(e.currentTarget.checked)}
          disabled={busy || dcrEnabled === null}
          />
       </Group>
       <Text size="xs" c="dimmed">
       {dcrEnabled
          ? 'Enabled -- self-service client registration is open for this tenant.'
          : 'Disabled -- new clients must be created by an admin.'}
       </Text>
      </Stack>
   )
  }

// G-163: the admin-gated Prometheus metrics endpoint had no view.
function MetricsTab() {
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    const { data, error: err, response } = await openapiOpsMetrics()
    setBusy(false)
    if (isUnauthorized(response?.status)) return sessionExpired()
    if (!response?.ok) return setError(problemText(err, response?.status))
    setText(typeof data === 'string' ? data : '')
   }, [])

  useEffect(() => {
    void Promise.resolve().then(load)
   }, [load])

  return (
     <Stack gap="md">
       <ErrorAlert error={error} />
       <Group>
         <Button size="xs" onClick={load} loading={busy}>
          Reload
          </Button>
         <Text size="xs" c="dimmed">Prometheus text exposition format (process-global).</Text>
       </Group>
       <pre
        style={{
           whiteSpace: 'pre-wrap',
            fontFamily: 'monospace',
            fontSize: '0.75rem',
            background: 'var(--mantine-color-gray-filled-hover)',
            padding: '0.75rem',
            borderRadius: '4px',
          }}
       >
       {text ?? 'Loading…'}
        </pre>
      </Stack>
   )
  }

function App() {
  // G-155: the api client interceptor funnels X-MFA-Required /
  // X-Reauth-Required 403s into this state; the panel below makes them
  // actionable instead of a contentless error string.
  const [signal, setSignal] = useState<AuthSignal | null>(null)

  useEffect(() => {
    if (!authed) window.location.href = '/login?redirect_uri=%2Fadmin'
  }, [])

  useEffect(() => {
    setSignalHandler(setSignal)
    return () => setSignalHandler(null)
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
          {signal && <SignalPanel kind={signal} onDone={() => setSignal(null)} />}
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
              <Tabs.Tab value="oidc">OIDC config</Tabs.Tab>
              <Tabs.Tab value="metrics">Metrics</Tabs.Tab>
              <Tabs.Tab value="mfa">MFA</Tabs.Tab>
              <Tabs.Tab value="account">Account</Tabs.Tab>
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
            <Tabs.Panel value="oidc" pt="md">
              <OidcConfigTab />
            </Tabs.Panel>
            <Tabs.Panel value="metrics" pt="md">
              <MetricsTab />
            </Tabs.Panel>
            <Tabs.Panel value="mfa" pt="md">
              <MfaTab />
            </Tabs.Panel>
            <Tabs.Panel value="account" pt="md">
              <AccountTab />
            </Tabs.Panel>
          </Tabs>
        </Stack>
      </Container>
    </MantineProvider>
  )
}

export default App
