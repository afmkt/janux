import type { MantineThemeOverride } from '@mantine/core'

// The one brand theme shared by all four Janux SPAs (admin, login, consent,
// device) so the console and the auth ceremony read as a single product instead
// of four bare Mantine defaults. Mantine 9's neutral base is fine; we only pin
// the accent, a slightly tighter radius, and a modern font stack so the shell
// feels intentional rather than framework-generated. `primaryColor` is the one
// knob to rebrand — swap it and every SPA follows.
export const mantineTheme: MantineThemeOverride = {
  primaryColor: 'grape',
  primaryShade: 6,
  defaultRadius: 8,
  fontFamily:
    "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
  headings: {
    fontFamily:
      "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
  },
}
