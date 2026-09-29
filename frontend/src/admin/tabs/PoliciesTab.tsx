import { useCallback, useState } from 'react'
import { Badge, Button, Checkbox, Group, Select, Stack, Table, TextInput } from '@mantine/core'
import {
  openapiPolicyAddPolicy,
  openapiPolicyAllPolicies,
  openapiPolicyDeletePolicy,
  openapiRoleAllRoles,
  type OpenapiDbHttpMethod,
  type OpenapiPolicySourceResolver,
  type OpenapiPolicyTargetResolver,
} from '../../api'
import { fetchAllPages, sessionExpired } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useMount, type RoleRow } from '../common'

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

function PoliciesTab() {
  const { busy, error, run, setError } = useApi()
  const [policies, setPolicies] = useState<PolicyRow[]>([])
  const [roleNames, setRoleNames] = useState<string[]>([])
  const [resource, setResource] = useState('')
  const [role, setRole] = useState<string | null>(null)
  const [action, setAction] = useState<string | null>(null)
  const [source, setSource] = useState<OpenapiPolicySourceResolver>('Nothing')
  const [target, setTarget] = useState('"Nothing"')
  const [mfa, setMfa] = useState(false)
     // G-163: deny policies are first-class server-side (a deny outranks
     // every allow) — the UI could neither create nor see them before.
  const [allowed, setAllowed] = useState(true)

     // Policies and the role dropdown load in parallel; a 403/401 on either
     // still routes through the shared handlers below.
  const load = useCallback(async () => {
    setError(null)
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
     }, [setError])

  useMount(load)

  const create = async () => {
    if (!resource.trim() || !role) return
    let parsedTarget: OpenapiPolicyTargetResolver
    try {
      parsedTarget = JSON.parse(target) as OpenapiPolicyTargetResolver
       } catch {
      setError('Target must be valid JSON, e.g. "Nothing"')
      return
       }
    const { ok } = await run(() =>
      openapiPolicyAddPolicy({
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
          }),
       )
    if (!ok) return
    setResource('')
    void load()
      }

  const remove = async (p: PolicyRow) => {
      // G-156: destructive admin actions confirm first.
    if (!window.confirm(`Delete policy ${p.resource} → ${p.role}?`)) return
    const { ok } = await run(() =>
      openapiPolicyDeletePolicy({
        body: { resource: p.resource, action: p.action ?? null, role: p.role },
          }),
          )
    if (!ok) return
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
           <Checkbox
           label="MFA"
           checked={mfa}
           onChange={(e) => setMfa(e.currentTarget.checked)}
           disabled={busy}
            />
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

export default PoliciesTab
