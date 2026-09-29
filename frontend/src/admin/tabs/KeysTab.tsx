import { useState } from 'react'
import { Button, Group, Stack, Table, TextInput } from '@mantine/core'
import {
  openapiKeyAddKey,
  openapiKeyAllKeys,
  openapiKeyDeleteKey,
  openapiKeyRetireKey,
} from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useCrud } from '../common'

interface KeyRow {
  domain: string
  name: string
  public: string
  retired: boolean
}

function KeysTab() {
  const { items: keys, error, busy, run, load } = useCrud<KeyRow>((query) =>
    openapiKeyAllKeys({ query }),
      )
  const [domain, setDomain] = useState('')
  const [name, setName] = useState('')

  const create = async () => {
    if (!domain.trim() || !name.trim()) return
    const { ok } = await run(() =>
      openapiKeyAddKey({ body: { domain: domain.trim(), name: name.trim() } }),
        )
    if (!ok) return
    setName('')
    void load()
        }

  const retire = async (keyName: string) => {
    const { ok } = await run(() => openapiKeyRetireKey({ body: { name: keyName } }))
    if (!ok) return
    void load()
        }

  const remove = async (keyName: string) => {
    if (!window.confirm(`Delete retired key "${keyName}"? Any token still signed by it stops verifying.`)) return
    const { ok } = await run(() => openapiKeyDeleteKey({ body: { name: keyName } }))
    if (!ok) return
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

export default KeysTab
