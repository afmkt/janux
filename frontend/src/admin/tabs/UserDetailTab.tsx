import { useCallback, useState } from 'react'
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Modal,
  MultiSelect,
  Select,
  Stack,
  Text,
  Title,
} from '@mantine/core'
import {
  openapiApikeyMint,
  openapiEmailRemove,
  openapiOtpRemove,
  openapiPasskeyDeactivate,
  openapiRoleAllRoles,
  openapiUserActivateUser,
  openapiUserAddRole,
  openapiUserDeleteUser,
  openapiUserRemoveRole,
  openapiUserUserRoles,
} from '../../api'
import { envelope, pageItems } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useMount, useWhoami, type RoleRow } from '../common'

/** Lifetime presets for API-key mint (seconds). Clamped server-side to [1h, 1y]. */
const LIFETIME_OPTIONS = [
  { value: '3600', label: '1 hour' },
  { value: '86400', label: '1 day' },
  { value: '604800', label: '7 days' },
  { value: '2592000', label: '30 days' },
  { value: '31536000', label: '1 year' },
]

interface UserDetailTabProps {
  username: string
  onBack: () => void
}

/**
 * Dedicated surface for a single user. All person-centric admin actions live
 * here (roles, credentials, status, danger zone, and — when viewing yourself —
 * API-key mint). The Users list is only a directory into this page.
 */
function UserDetailTab({ username, onBack }: UserDetailTabProps) {
  const { me } = useWhoami()
  const { busy, error, run, setError } = useApi()
  const [roles, setRoles] = useState<string[]>([])
  const [catalog, setCatalog] = useState<RoleRow[]>([])
  const [roleToAdd, setRoleToAdd] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // API key mint (only when the signed-in actor is this user — mint is session-bound)
  const isSelf = me?.username === username
  const [lifetime, setLifetime] = useState<string | null>('86400')
  const [keyRoles, setKeyRoles] = useState<string[]>([])
  const [mintedToken, setMintedToken] = useState<string | null>(null)
  const [mintedExpires, setMintedExpires] = useState<number | null>(null)

  const loadRoles = useCallback(async () => {
    const { ok, data } = await run(() => openapiUserUserRoles({ query: { user: username } }))
    if (!ok) return
    setRoles(envelope<string[]>(data).data ?? [])
  }, [run, username])

  const loadCatalog = useCallback(async () => {
    const { ok, data } = await run(() => openapiRoleAllRoles({ query: { limit: 500, offset: 0 } }))
    if (!ok) return
    setCatalog(pageItems<RoleRow>(data))
  }, [run])

  const loadAll = useCallback(() => {
    void loadRoles()
    void loadCatalog()
  }, [loadRoles, loadCatalog])

  useMount(loadAll)

  const activate = async (active: boolean) => {
    setNotice(null)
    const { ok } = await run(() => openapiUserActivateUser({ body: { user: username, active } }))
    if (!ok) return
    setNotice(active ? 'User activated.' : 'User deactivated.')
  }

  const addRole = async () => {
    if (!roleToAdd) return
    setNotice(null)
    const { ok } = await run(() =>
      openapiUserAddRole({ body: { user: username, role: roleToAdd } }),
    )
    if (!ok) return
    setRoleToAdd(null)
    void loadRoles()
  }

  const removeRole = async (role: string) => {
    if (!window.confirm(`Revoke role "${role}" from "${username}"?`)) return
    setNotice(null)
    const { ok } = await run(() => openapiUserRemoveRole({ body: { user: username, role } }))
    if (!ok) return
    void loadRoles()
  }

  const removePasskeys = async () => {
    if (!window.confirm(`Deactivate ALL passkeys of "${username}"? They must re-register afterwards.`))
      return
    setNotice(null)
    const { ok } = await run(() => openapiPasskeyDeactivate({ body: { name: username } }))
    if (!ok) return
    setNotice('All passkeys deactivated.')
  }

  const removeEmail = async () => {
    const email = window.prompt(`Email address to remove from "${username}":`)
    if (!email?.trim()) return
    if (!window.confirm(`Remove ${email.trim()} from "${username}"?`)) return
    setNotice(null)
    const { ok } = await run(() =>
      openapiEmailRemove({ query: { name: username, email: email.trim() } }),
    )
    if (!ok) return
    setNotice(`Removed email ${email.trim()}.`)
  }

  const removeMobile = async () => {
    const mobile = window.prompt(`Mobile number to remove from "${username}":`)
    if (!mobile?.trim()) return
    if (!window.confirm(`Remove ${mobile.trim()} from "${username}"?`)) return
    setNotice(null)
    const { ok } = await run(() =>
      openapiOtpRemove({ query: { name: username, mobile: mobile.trim() } }),
    )
    if (!ok) return
    setNotice(`Removed mobile ${mobile.trim()}.`)
  }

  const removeUser = async () => {
    if (!window.confirm(`Delete user "${username}"? The account and its role grants are removed.`))
      return
    const { ok } = await run(() => openapiUserDeleteUser({ body: { user: username } }))
    if (!ok) return
    onBack()
  }

  const mintApiKey = async () => {
    setNotice(null)
    setMintedToken(null)
    const secs = lifetime ? Number(lifetime) : undefined
    const { ok, data } = await run(() =>
      openapiApikeyMint({
        body: {
          lifetime_seconds: secs && secs > 0 ? secs : null,
          roles: keyRoles.length > 0 ? keyRoles : null,
        },
      }),
    )
    if (!ok) return
    const payload = envelope<{
      access_token: string
      expires_in: number
      typ: string
    }>(data).data
    if (!payload?.access_token) {
      setError('Mint succeeded but no token was returned')
      return
    }
    setMintedToken(payload.access_token)
    setMintedExpires(payload.expires_in)
  }

  const copyToken = async () => {
    if (!mintedToken) return
    try {
      await navigator.clipboard.writeText(mintedToken)
      setNotice('API key copied to clipboard.')
    } catch {
      setError('Could not copy — select the token and copy manually.')
    }
  }

  const roleOptions = catalog.map((r) => ({ value: r.name, label: `${r.name} (L${r.level})` }))
  // Key roles must be a subset of the *session* roles (backend rule).
  const keyRoleOptions = (me?.roles ?? []).map((r) => ({ value: r, label: r }))

  return (
    <Stack gap="lg">
      <Group gap="sm">
        <Button variant="subtle" color="gray" onClick={onBack} size="compact">
          ← Users
        </Button>
        <Text size="sm" c="dimmed">
          Identity / Users / {username}
        </Text>
      </Group>

      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={3}>{username}</Title>
          {isSelf && (
            <Badge mt="xs" variant="light" color="grape">
              You
            </Badge>
          )}
        </div>
        <Group gap="xs">
          <Button size="sm" variant="default" disabled={busy} onClick={() => activate(true)}>
            Activate
          </Button>
          <Button size="sm" variant="default" disabled={busy} onClick={() => activate(false)}>
            Deactivate
          </Button>
        </Group>
      </Group>

      <ErrorAlert error={error} />
      {notice && (
        <Alert color="green" withCloseButton onClose={() => setNotice(null)}>
          {notice}
        </Alert>
      )}

      {/* ── Roles ───────────────────────────────────────────────────────── */}
      <Card withBorder padding="md" radius="md">
        <Title order={4} mb="sm">
          Roles
        </Title>
        <Group gap="xs" mb="md" wrap="wrap">
          {roles.length === 0 && (
            <Text size="sm" c="dimmed">
              (none)
            </Text>
          )}
          {roles.map((r) => (
            <Badge
              key={r}
              variant="light"
              rightSection={
                <Button
                  size="compact-xs"
                  variant="transparent"
                  color="gray"
                  px={4}
                  disabled={busy}
                  onClick={() => removeRole(r)}
                  aria-label={`Revoke ${r}`}
                >
                  ×
                </Button>
              }
            >
              {r}
            </Badge>
          ))}
        </Group>
        <Group align="flex-end">
          <Select
            label="Grant role"
            placeholder="Pick a role"
            data={roleOptions.filter((o) => !roles.includes(o.value))}
            value={roleToAdd}
            onChange={setRoleToAdd}
            searchable
            clearable
            disabled={busy}
            style={{ flex: 1, minWidth: 180 }}
          />
          <Button onClick={addRole} loading={busy} disabled={!roleToAdd}>
            Add
          </Button>
        </Group>
      </Card>

      {/* ── Credentials ─────────────────────────────────────────────────── */}
      <Card withBorder padding="md" radius="md">
        <Title order={4} mb="sm">
          Credentials
        </Title>
        <Text size="sm" c="dimmed" mb="md">
          Recovery levers for a locked-out or compromised account. Each action is gated server-side.
        </Text>
        <Group gap="xs">
          <Button size="sm" variant="default" disabled={busy} onClick={removePasskeys}>
            Drop all passkeys
          </Button>
          <Button size="sm" variant="default" disabled={busy} onClick={removeEmail}>
            Remove email…
          </Button>
          <Button size="sm" variant="default" disabled={busy} onClick={removeMobile}>
            Remove mobile…
          </Button>
        </Group>
      </Card>

      {/* ── API keys (self only) ────────────────────────────────────────── */}
      {isSelf ? (
        <Card withBorder padding="md" radius="md">
          <Title order={4} mb="sm">
            API keys
          </Title>
          <Text size="sm" c="dimmed" mb="md">
            Mint a long-lived <Code>api_key+jwt</Code> for automation. The token is shown once; store
            it securely. Keys cannot refresh or mint further keys.
          </Text>
          <Group align="flex-end" mb="md">
            <Select
              label="Lifetime"
              data={LIFETIME_OPTIONS}
              value={lifetime}
              onChange={setLifetime}
              disabled={busy}
              style={{ minWidth: 140 }}
            />
            <MultiSelect
              label="Roles (optional subset)"
              placeholder="All session roles"
              data={keyRoleOptions}
              value={keyRoles}
              onChange={setKeyRoles}
              disabled={busy}
              clearable
              style={{ flex: 1, minWidth: 200 }}
            />
            <Button onClick={mintApiKey} loading={busy}>
              Mint API key
            </Button>
          </Group>
          <Text size="xs" c="dimmed">
            Leaving roles empty copies your full session role set. Requested roles must be a subset
            — escalation is rejected.
          </Text>
        </Card>
      ) : (
        <Card withBorder padding="md" radius="md">
          <Title order={4} mb="sm">
            API keys
          </Title>
          <Text size="sm" c="dimmed">
            API keys are minted by the signed-in principal for themselves. Open this user while
            signed in as them, or use Account → API keys, to mint.
          </Text>
        </Card>
      )}

      {/* ── Danger zone ─────────────────────────────────────────────────── */}
      <Card withBorder padding="md" radius="md" style={{ borderColor: 'var(--mantine-color-red-6)' }}>
        <Title order={4} mb="sm" c="red">
          Danger zone
        </Title>
        <Text size="sm" c="dimmed" mb="md">
          Permanently delete the account and its role grants. Credentials are removed with the user.
        </Text>
        <Button color="red" variant="light" disabled={busy} onClick={removeUser}>
          Delete user
        </Button>
      </Card>

      {/* One-time token reveal */}
      <Modal
        opened={!!mintedToken}
        onClose={() => {
          setMintedToken(null)
          setMintedExpires(null)
        }}
        title="API key minted"
        size="lg"
      >
        <Stack gap="md">
          <Alert color="yellow">
            Copy this token now — it will not be shown again. Treat it like a password.
          </Alert>
          {mintedExpires != null && (
            <Text size="sm" c="dimmed">
              Effective lifetime: {mintedExpires} seconds
            </Text>
          )}
          <Code block style={{ wordBreak: 'break-all', maxHeight: 200, overflow: 'auto' }}>
            {mintedToken}
          </Code>
          <Group>
            <Button onClick={copyToken}>Copy to clipboard</Button>
            <Button
              variant="default"
              onClick={() => {
                setMintedToken(null)
                setMintedExpires(null)
              }}
            >
              Done
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}

export default UserDetailTab
