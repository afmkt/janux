import type { Harness } from './harness'

// globalSetup and globalTeardown run in the same runner process, so a module
// singleton lets us hand the live janux handle over reliably.
let current: Harness | null = null

export function stash(h: Harness): void {
   current = h
}

export function unstash(): Harness | null {
   const h = current
   current = null
   return h
}
