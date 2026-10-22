import { useState } from 'react'
import { Badge, Button, Group, Stack, Table, Text, TextInput } from '@mantine/core'
import { openapiUserAddUser, openapiUserAllUsers, openapiUserUserRoles } from '../../api'
import { envelope } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'
import UserDetailTab from './UserDetailTab'

interface UsersTabProps {
  /** Username taken from the hash (`#users/alice`). When set, render the detail surface. */
  selectedUser?: string | null
  onSelectUser: (username: string | null) => void
}

/**
 * Users is a directory, not a control panel. The list shows identity + a role
 * preview and one primary action (Open). All person-centric operations live on
 * the dedicated user detail page (`UserDetailTab`).
 */
function UsersTab({ selectedUser, onSelectUser }: UsersTabProps) {
  const { items: users, error, busy, run, load } = useCrud<string>((query) =>
    openapiUserAllUsers({ query }),
  )
  const [newUser, setNewUser] = useState('')
  // Per-row role cache so we can show badges without a "Show" click.
  const [roleCache, setRoleCache] = useState<Record<string, string[]>>({})
  const [loadingRoles, setLoadingRoles] = useState<string | null>(null)

  const create = async () => {
    if (!newUser.trim()) return
    const { ok } = await run(() => openapiUserAddUser({ body: { name: newUser.trim() } }))
    if (!ok) return
    const name = newUser.trim()
    setNewUser('')
    void load()
    // Jump straight into the new user so the operator can grant roles next.
    onSelectUser(name)
  }

  const ensureRoles = async (user: string) => {
    if (roleCache[user] !== undefined) return
    setLoadingRoles(user)
    const { ok, data } = await run(() => openapiUserUserRoles({ query: { user } }))
    setLoadingRoles(null)
    if (!ok) return
    setRoleCache((prev) => ({ ...prev, [user]: envelope<string[]>(data).data ?? [] }))
  }

  if (selectedUser) {
    return <UserDetailTab username={selectedUser} onBack={() => onSelectUser(null)} />
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
          onKeyDown={(e) => {
            if (e.key === 'Enter') void create()
          }}
        />
        <Button onClick={create} loading={busy} mt="lg" disabled={!newUser.trim()}>
          Create
        </Button>
      </Group>
      <Table highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>User</Table.Th>
            <Table.Th>Roles</Table.Th>
            <Table.Th style={{ width: 100 }} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={3}>
                <Text size="sm" c="dimmed">
                  No users yet.
                </Text>
              </Table.Td>
            </Table.Tr>
          )}
          {users.map((u) => {
            const cached = roleCache[u]
            return (
              <Table.Tr key={u} style={{ cursor: 'pointer' }} onClick={() => onSelectUser(u)}>
                <Table.Td>
                  <Text fw={500}>{u}</Text>
                </Table.Td>
                <Table.Td>
                  {cached !== undefined ? (
                    <Group gap="xs" wrap="wrap">
                      {cached.length === 0 && (
                        <Text size="xs" c="dimmed">
                          (none)
                        </Text>
                      )}
                      {cached.map((r) => (
                        <Badge key={r} variant="light" size="sm">
                          {r}
                        </Badge>
                      ))}
                    </Group>
                  ) : (
                    <Button
                      size="compact-xs"
                      variant="subtle"
                      loading={loadingRoles === u}
                      disabled={busy}
                      onClick={(e) => {
                        e.stopPropagation()
                        void ensureRoles(u)
                      }}
                    >
                      Load roles
                    </Button>
                  )}
                </Table.Td>
                <Table.Td>
                  <Button
                    size="xs"
                    variant="light"
                    onClick={(e) => {
                      e.stopPropagation()
                      onSelectUser(u)
                    }}
                  >
                    Open
                  </Button>
                </Table.Td>
              </Table.Tr>
            )
          })}
        </Table.Tbody>
      </Table>
    </Stack>
  )
}

export default UsersTab
