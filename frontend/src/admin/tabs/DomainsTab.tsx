import { useState } from 'react'
import { Button, Group, Stack, Table, TextInput } from '@mantine/core'
import { openapiAdminAddDomain, openapiAdminAllDomains, openapiAdminDeleteDomain } from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

function DomainsTab() {
  const { items: domains, error, busy, run, load, setError } = useCrud<string>((query) =>
    openapiAdminAllDomains({ query }),
     )
  const [tenant, setTenant] = useState('')
  const [domain, setDomain] = useState('')

  const create = async () => {
    if (!tenant.trim() || !domain.trim()) return
    const { ok } = await run(() =>
      openapiAdminAddDomain({ body: { tenant: tenant.trim(), domain: domain.trim() } }),
       )
    if (!ok) return
    setDomain('')
    void load()
      }

  const remove = async (d: string) => {
    if (!window.confirm(`Remove domain "${d}" from this tenant?`)) return
    if (!tenant.trim()) {
      setError('Enter the tenant name to delete a domain')
      return
       }
    const { ok } = await run(() =>
      openapiAdminDeleteDomain({ body: { tenant: tenant.trim(), domain: d } }),
       )
    if (!ok) return
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

export default DomainsTab
