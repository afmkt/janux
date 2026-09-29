import { useState } from 'react'
import { Button, Group, Stack, Table, TextInput } from '@mantine/core'
import { openapiAdminAllTenants, openapiAdminNewTenant, openapiAdminRemoveTenant } from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

function TenantsTab() {
  const { items: tenants, error, busy, run, load } = useCrud<string>((query) =>
    openapiAdminAllTenants({ query }),
        )
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [admin, setAdmin] = useState('')

  const create = async () => {
    if (!name.trim()) return
    const { ok } = await run(() =>
      openapiAdminNewTenant({
        body: {
          name: name.trim(),
          domain: domain.trim() || null,
          admin: admin.trim() || null,
            },
             }),
             )
    if (!ok) return
    setName('')
    setDomain('')
    setAdmin('')
    void load()
       }

  const remove = async (tenantName: string) => {
    // G-156: the most destructive action in the console confirms first.
    if (!window.confirm(`DELETE TENANT "${tenantName}"? Every user, key and policy of that tenant is destroyed.`)) return
    const { ok } = await run(() => openapiAdminRemoveTenant({ body: { name: tenantName } }))
    if (!ok) return
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
                       <Button
              size="xs"
              color="red"
              variant="default"
              disabled={busy}
              onClick={() => remove(t)}
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

export default TenantsTab
