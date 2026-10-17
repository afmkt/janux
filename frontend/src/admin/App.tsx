import { useEffect, useState } from 'react'
import {
  AppShell,
  Avatar,
  Badge,
  Button,
  Container,
  Group,
  Menu,
  Stack,
  Text,
  Title,
} from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import '@mantine/core/styles.css'
import { setSignalHandler, setupAuth, type AuthSignal } from './api'
import { clearSession } from '../shared/session'
import { ColorSchemeToggle, ThemeProvider } from '../shared/providers'
import { useWhoami, type SessionMe } from './common'
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

// ─── Information architecture ─────────────────────────────────────────────────
// The console groups its panels by *intent* so an operator scans a short tree
// instead of a 12-item strip. Each panel still lives in its own file under
// ./tabs and is mounted only when its section is active (the <SectionContent>
// switch below, the same lazy-mount behavior the old Mantine <Tabs> had — no
// panel fetches until it is shown). `account` is self-service, so it lives in
// the user menu rather than the nav tree.
type Section =
  | 'users'
  | 'roles'
  | 'policies'
  | 'tenants'
  | 'domains'
  | 'providers'
  | 'oidc'
  | 'mfa'
  | 'keys'
  | 'clients'
  | 'metrics'
  | 'account'

interface NavEntry {
  section: Section
  label: string
  group: string
}

const NAV: NavEntry[] = [
  { section: 'users', label: 'Users', group: 'Identity' },
  { section: 'roles', label: 'Roles', group: 'Identity' },
  { section: 'policies', label: 'Policies', group: 'Identity' },
  { section: 'tenants', label: 'Tenants', group: 'Directory' },
  { section: 'domains', label: 'Domains', group: 'Directory' },
  { section: 'providers', label: 'Social providers', group: 'Authentication' },
  { section: 'oidc', label: 'OIDC config', group: 'Authentication' },
  { section: 'mfa', label: 'MFA', group: 'Authentication' },
  { section: 'keys', label: 'Signing keys', group: 'Security' },
  { section: 'clients', label: 'OAuth2 clients', group: 'Security' },
  { section: 'metrics', label: 'Metrics', group: 'Insights' },
]

const GROUPS = ['Identity', 'Directory', 'Authentication', 'Security', 'Insights']

// Hash routing: the section the URL hash selects, unknown/empty falling back to
// Users. A hash keeps deep-links and back/forward working without a new server
// route — the catch-all serves admin.html and the hash never reaches janux.
// `account` is self-service (in the user menu), so it is a valid target that is
// not part of the nav tree.
function sectionFromHash(): Section {
  const h = window.location.hash.replace(/^#/, '') as Section
  if (h === 'account') return 'account'
  return NAV.some((n) => n.section === h) ? h : 'users'
}

function SectionContent({ section }: { section: Section }) {
  switch (section) {
    case 'roles':
      return <RolesTab />
    case 'policies':
      return <PoliciesTab />
    case 'tenants':
      return <TenantsTab />
    case 'domains':
      return <DomainsTab />
    case 'providers':
      return <ProvidersTab />
    case 'oidc':
      return <OidcConfigTab />
    case 'mfa':
      return <MfaTab />
    case 'keys':
      return <KeysTab />
    case 'clients':
      return <ClientsTab />
    case 'metrics':
      return <MetricsTab />
    case 'account':
      return <AccountTab />
    case 'users':
    default:
      return <UsersTab />
  }
}

function Sidebar({
  section,
  onNavigate,
}: {
  section: Section
  onNavigate: (section: Section) => void
}) {
  return (
    <Stack gap="lg">
      {GROUPS.map((group) => {
        const items = NAV.filter((n) => n.group === group)
        if (items.length === 0) return null
        return (
          <div key={group}>
            <Text size="xs" fw={700} c="dimmed" tt="uppercase" lh="1.5">
              {group}
            </Text>
            <Stack gap="xs" mt="xs">
              {items.map((item) => (
                <Button
                  key={item.section}
                  fullWidth
                  variant={section === item.section ? 'filled' : 'subtle'}
                  onClick={() => onNavigate(item.section)}
                >
                  {item.label}
                </Button>
              ))}
            </Stack>
          </div>
        )
      })}
    </Stack>
  )
}

function UserMenu({ me, onAccount }: { me: SessionMe | null; onAccount: () => void }) {
  const signOut = () => {
    clearSession()
    window.location.assign('/login')
  }
  return (
    <Menu shadow="md" position="bottom-end" withinPortal>
      <Menu.Target>
        <Button
          variant="subtle"
          size="compact"
          leftSection={<Avatar size={28} name={me?.username} />}
          aria-label="Account menu"
        >
          {me ? me.username : 'Loading…'}
        </Button>
      </Menu.Target>
      <Menu.Dropdown>
        <Text fw={600}>{me ? me.username : 'Signed out'}</Text>
        {me?.roles?.length ? (
          <Group gap="xs" mt="xs" wrap="wrap">
            {me.roles.map((role) => (
              <Badge key={role} variant="light" size="sm">
                {role}
              </Badge>
            ))}
          </Group>
        ) : null}
        {me?.mfa?.length ? (
          <Text size="xs" c="dimmed" mt="xs">
            MFA: {me.mfa.join(', ')}
          </Text>
        ) : null}
        <Menu.Divider />
        <Menu.Item leftSection={<span aria-hidden>◈</span>} onClick={onAccount}>
          Account
        </Menu.Item>
        <Menu.Item color="red" onClick={signOut}>
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  )
}

function Console() {
  const [section, setSection] = useState<Section>(sectionFromHash)
  const [opened, setOpened] = useState(false)
  const [signal, setSignal] = useState<AuthSignal | null>(null)
  const { me } = useWhoami()
  const mobile = useMediaQuery('(max-width: 767px)')

  // G-155: the api client interceptor funnels X-MFA-Required / X-Reauth-Required
  // 403s into this state; the SignalPanel below makes them actionable.
  useEffect(() => {
    setSignalHandler(setSignal)
    return () => setSignalHandler(null)
  }, [])

  // Keep the section in sync with the URL so back/forward and deep-links work.
  useEffect(() => {
    const onHash = () => setSection(sectionFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const navigate = (next: Section) => {
    window.location.hash = next
    setSection(next)
    // Closing the mobile overlay after a tap keeps the content unobscured.
    setOpened(false)
  }

  const active = NAV.find((n) => n.section === section)

  return (
    <AppShell
      navbar={{ width: 220, breakpoint: 'sm', collapsed: { desktop: false, mobile: !opened } }}
      header={{ height: 56 }}
      padding="lg"
      withBorder
    >
      <AppShell.Header p="md">
        <Group h="100%" justify="space-between">
          <Group gap="xs">
            {mobile && (
              <Button
                variant="subtle"
                size="compact"
                color="gray"
                onClick={() => setOpened((o) => !o)}
                aria-label="Toggle navigation"
              >
                ☰
              </Button>
            )}
            <Avatar src="/favicon.svg" size={30} radius="md" />
            <Text fw={700} size="lg" lh={1}>
              Janux
            </Text>
            <Badge variant="subtle" color="gray">
              console
            </Badge>
          </Group>
          <Group gap="xs">
            <ColorSchemeToggle />
            <UserMenu me={me} onAccount={() => navigate('account')} />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <Sidebar section={section} onNavigate={navigate} />
      </AppShell.Navbar>

      <AppShell.Main>
        <Stack gap="md">
          <div>
            <Title order={2} mb="xs">
              Admin console
            </Title>
            <Text c="dimmed" size="sm">
              {active ? `${active.group} / ${active.label}` : 'Account'}
            </Text>
          </div>
          {signal && <SignalPanel kind={signal} onDone={() => setSignal(null)} />}
          <SectionContent section={section} />
        </Stack>
      </AppShell.Main>
    </AppShell>
  )
}

// Unauthenticated: the session marker is absent, so we render a short notice and
// bounce to sign-in carrying a redirect_uri back to the console. The effect does
// the navigation; the visible text covers the brief window before it fires so a
// no-session load never looks like a dead page.
function RedirectToLogin() {
  useEffect(() => {
    window.location.href = '/login?redirect_uri=%2Fadmin'
  }, [])
  return (
    <Container size="xs" py="xl">
      <Text c="dimmed">Redirecting to sign-in…</Text>
    </Container>
  )
}

function App() {
  return (
    <ThemeProvider>
      {authed ? <Console /> : <RedirectToLogin />}
    </ThemeProvider>
  )
}

export default App
