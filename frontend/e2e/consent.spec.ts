import { test, expect } from '@playwright/test'
import { readState } from './support/harness'

// Consent SPA (`/consent`) — the OIDC consent round-trip. Two guards are
// genuinely exercised without a live authorize request (G-165):
//
//  • state-presence guard: no `?state=` means the page can't resolve a pending
//    request, so it surfaces "Missing consent state" and renders the heading.
//  • auth guard: a `?state=` with no session hits /consent/info, which 401s
//    (the session is the missing HttpOnly cookie), and the SPA routes the
//    visitor back through /login carrying the consent `redirect_uri`.
//
// The full approve/deny happy path needs a live OIDC authorize request plus a
// signed-in session (an OAuth2 client registration) — out of scope for these
// isolated smoke tests and recorded as the residual gap in gaps.md.

test.describe('consent SPA', () => {
   test('renders the heading and flags a missing consent state', async ({ page }) => {
      const { baseURL } = readState()
       // No `?state=`: the page can't resolve a request, so it shows the guard.
      await page.goto(`${baseURL}/consent`)
      await expect(page.getByRole('heading', { name: /Authorize application/i })).toBeVisible()
      await expect(page.getByText(/Missing consent state/i)).toBeVisible()
       })

   test('routes an unauthenticated visitor back to login', async ({ page }) => {
      const { baseURL } = readState()
       // A pending consent with no session: /consent/info 401s, and the SPA must
       // carry the visitor back through /login rather than hang.
      await page.goto(`${baseURL}/consent?state=demo-state`)
      await expect(page).toHaveURL(/\/login\?.*redirect_uri=/)
      await expect(page.getByRole('button', { name: /Email me a sign-in link/i })).toBeVisible()
       })
})
