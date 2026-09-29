import { Alert } from '@mantine/core'

// One shared error line so every tab renders failures identically; the 401/403
// handling lives in the shared call helpers in common.tsx, so a tab only needs
// to render this for its `error` string.
export function ErrorAlert({ error }: { error: string | null }) {
  if (!error) return null
  return <Alert color="red">{error}</Alert>
}
