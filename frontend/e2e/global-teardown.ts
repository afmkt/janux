import { unstash } from './support/store'

// Stops the shared janux server and capture server started by globalSetup.
export default async function globalTeardown(): Promise<void> {
   const harness = unstash()
   if (harness) await harness.stop()
}
