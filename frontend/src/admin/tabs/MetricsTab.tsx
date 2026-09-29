import { useCallback, useState } from 'react'
import { Button, Group, Stack, Text } from '@mantine/core'
import { openapiOpsMetrics } from '../../api'
import { ErrorAlert } from '../ErrorAlert'
import { useApi, useMount } from '../common'

// G-163: the admin-gated Prometheus metrics endpoint had no view.
function MetricsTab() {
  const { busy, error, run } = useApi()
  const [text, setText] = useState<string | null>(null)

  const load = useCallback(async () => {
    const { ok, data } = await run(() => openapiOpsMetrics())
    if (!ok) return
    setText(typeof data === 'string' ? data : '')
      }, [run])

  useMount(load)

  return (
       <Stack gap="md">
          <ErrorAlert error={error} />
          <Group>
             <Button size="xs" onClick={load} loading={busy}>
             Reload
              </Button>
              <Text size="xs" c="dimmed">Prometheus text exposition format (process-global).</Text>
             </Group>
             <pre
        style={{
           whiteSpace: 'pre-wrap',
            fontFamily: 'monospace',
            fontSize: '0.75rem',
            background: 'var(--mantine-color-gray-filled-hover)',
            padding: '0.75rem',
            borderRadius: '4px',
          }}
       >
       {text ?? 'Loading…'}
         </pre>
       </Stack>
      )
}

export default MetricsTab
