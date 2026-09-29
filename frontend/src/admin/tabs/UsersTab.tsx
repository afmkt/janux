import { useState } from 'react'
import { Badge, Button, Group, Stack, Table, Text, TextInput } from '@mantine/core'
import {
  openapiEmailRemove,
  openapiOtpRemove,
  openapiPasskeyDeactivate,
  openapiUserActivateUser,
  openapiUserAddRole,
  openapiUserAddUser,
  openapiUserAllUsers,
  openapiUserDeleteUser,
  openapiUserRemoveRole,
  openapiUserUserRoles,
} from '../../api'
import { envelope } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

function UsersTab() {
  const { items: users, error, busy, run, load } = useCrud<string>((query) =>
    openapiUserAllUsers({ query }),
   )
  const [newUser, setNewUser] = useState('')
  const [roleUser, setRoleUser] = useState('')
  const [roleName, setRoleName] = useState('')
   // G-163: a user's effective roles used to be invisible in the console.
  const [rolesView, setRolesView] = useState<{ user: string; roles: string[] } | null>(null)

  const create = async () => {
    if (!newUser.trim()) return
    const { ok } = await run(() => openapiUserAddUser({ body: { name: newUser.trim() } }))
    if (!ok) return
    setNewUser('')
    void load()
   }

  const activate = async (user: string, active: boolean) => {
    await run(() => openapiUserActivateUser({ body: { user, active } }))
   }

  const remove = async (user: string) => {
    if (!window.confirm(`Delete user "${user}"? The account and its role grants are removed.`)) return
    const { ok } = await run(() => openapiUserDeleteUser({ body: { user } }))
    if (!ok) return
    void load()
   }

  const changeRole = async (add: boolean) => {
    if (!roleUser.trim() || !roleName.trim()) return
    const body = { user: roleUser.trim(), role: roleName.trim() }
    await run(add ? () => openapiUserAddRole({ body }) : () => openapiUserRemoveRole({ body }))
   }

  const showRoles = async (user: string) => {
    const { ok, data } = await run(() => openapiUserUserRoles({ query: { user } }))
    if (!ok) return
    setRolesView({ user, roles: envelope<string[]>(data).data ?? [] })
   }

   // G-163/G-101: per-user credential removal — the recovery levers for a
   // locked-out or compromised account (each is H3-gated server-side).
  const removePasskeys = async (user: string) => {
    if (!window.confirm(`Deactivate ALL passkeys of "${user}"? They must re-register afterwards.`)) return
    await run(() => openapiPasskeyDeactivate({ body: { name: user } }))
   }

  const removeEmail = async (user: string) => {
    const email = window.prompt(`Email address to remove from "${user}":`)
    if (!email?.trim()) return
    if (!window.confirm(`Remove ${email.trim()} from "${user}"?`)) return
    await run(() => openapiEmailRemove({ query: { name: user, email: email.trim() } }))
   }

  const removeMobile = async (user: string) => {
    const mobile = window.prompt(`Mobile number to remove from "${user}":`)
    if (!mobile?.trim()) return
    if (!window.confirm(`Remove ${mobile.trim()} from "${user}"?`)) return
    await run(() => openapiOtpRemove({ query: { name: user, mobile: mobile.trim() } }))
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

export default UsersTab
