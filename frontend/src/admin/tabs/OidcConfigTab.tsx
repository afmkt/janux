import { useCallback, useState } from 'react'
import { Alert, Group, Stack, Switch, Text } from '@mantine/core'
import {
  openapiOidcExtOidcConfig,
  openapiOidcExtSetOidcConfig,
  type OpenapiOidcExtOidcTenantConfig,
} from '../../api'
import { envelope } from '../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useMount } from '../common'

// G-163: tenant OIDC feature switches (Dynamic Client Registration) had no UI;
// the oidc/config read/write endpoints were admin-API-only.
function OidcConfigTab() {
  const { busy, error, run } = useApi()
  const [dcrEnabled, setDcrEnabled] = useState<boolean | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const load = useCallback(async () => {
    const { ok, data } = await run(() => openapiOidcExtOidcConfig())
    if (!ok) return
    setDcrEnabled(envelope<OpenapiOidcExtOidcTenantConfig>(data).data?.dcr_enabled ?? false)
      }, [run])

  useMount(load)

  const save = async (dcr_enabled: boolean) => {
    if (dcr_enabled === dcrEnabled) return
    setNotice(null)
    const { ok } = await run(() => openapiOidcExtSetOidcConfig({ body: { dcr_enabled } }))
    if (!ok) return
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

export default OidcConfigTab
