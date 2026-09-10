import { startHarness } from './support/harness'
import { stash } from './support/store'

// Boots the single shared janux server (+ mock Resend) for the whole UI run and
// hands the handle to globalTeardown via a module singleton — the running
// processes stay alive across every worker until teardown reaps them.
export default async function globalSetup(): Promise<void> {
   const harness = await startHarness()
   stash(harness)
}
