import { useEffect, useState } from 'react'
import { Container, MantineProvider, Stack, Tabs, Text, Title } from '@mantine/core'
import '@mantine/core/styles.css'
import { setSignalHandler, setupAuth, type AuthSignal } from './api'
import SignalPanel from './tabs/SignalPanel'
import UsersTab from './tabs/UsersTab'
import RolesTab from './tabs/RolesTab'
import PoliciesTab from './tabs/PoliciesTab'
import DomainsTab from './tabs/DomainsTab'
import ClientsTab from './tabs/ClientsTab'
import ProvidersTab from './tabs/ProvidersTab'
import KeysTab from './tabs/KeysTab'
import TenantsTab from './tabs/TenantsTab'
import OidcConfigTab from './tabs/OidcConfigTab'
import MetricsTab from './tabs/MetricsTab'
import MfaTab from './tabs/MfaTab'
import AccountTab from './tabs/AccountTab'

const authed = setupAuth()

// One registry: each panel lives in its own file under ./tabs and is mounted
// only when its tab is active. The 403-signal interception, auth gate, and
// cookie refresh live in ./api; per-tab data handling lives with each tab.
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
