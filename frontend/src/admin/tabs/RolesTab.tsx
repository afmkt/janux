import { useState } from 'react'
import { Badge, Button, NumberInput, TextInput, Group, Stack, Table } from '@mantine/core'
import { openapiRoleAddRole, openapiRoleAllRoles, openapiRoleDeleteRole } from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud, type RoleRow } from '../common'

function RolesTab() {
  const { items: roles, error, busy, run, load } = useCrud<RoleRow>((query) =>
    openapiRoleAllRoles({ query }),
    )
  const [name, setName] = useState('')
  const [level, setLevel] = useState('10')

  const create = async () => {
    if (!name.trim()) return
    const { ok } = await run(() =>
      openapiRoleAddRole({ body: { name: name.trim(), level: Number(level) || 0 } }),
     )
    if (!ok) return
    setName('')
    void load()
    }

  const remove = async (role: string) => {
    if (!window.confirm(`Delete role "${role}"? Its policies and memberships are removed too.`)) return
    const { ok } = await run(() => openapiRoleDeleteRole({ body: { name: role } }))
    if (!ok) return
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

export default RolesTab
