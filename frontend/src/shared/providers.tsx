import { type ReactNode } from 'react'
import { Button, MantineProvider, useMantineColorScheme } from '@mantine/core'
import '@mantine/core/styles.css'
import { mantineTheme } from './theme'

// The shared Mantine entry point for every Janux SPA. Wrapping the provider here
// (instead of dropping a bare <MantineProvider> in each App) is the one place to
// change the brand theme or the default color scheme and have it land everywhere.
//
// Mantine 9 manages the color scheme through a storage-backed manager
// (localStorage by default), so there is no controlled `colorScheme` prop: the
// value is read on mount and `useMantineColorScheme` below flips it. A brief
// light-first paint can occur on reload because the initial apply is client-side;
// an inline boot script is off the table under the served CSP (script-src 'self').
export function ThemeProvider({ children }: { children: ReactNode }) {
  return (
    <MantineProvider theme={mantineTheme} defaultColorScheme="auto">
      {children}
    </MantineProvider>
  )
}

// A compact scheme switch for a shell's right-hand cluster. The label reads the
// scheme the click switches *to*, so it doubles as the affordance.
export function ColorSchemeToggle() {
  const { colorScheme, toggleColorScheme } = useMantineColorScheme()
  return (
    <Button
      variant="subtle"
      size="compact"
      onClick={toggleColorScheme}
      aria-label="Toggle color scheme"
    >
      {colorScheme === 'dark' ? 'Light' : 'Dark'}
    </Button>
  )
}
