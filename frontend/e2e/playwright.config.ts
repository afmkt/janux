import type { PlaywrightTestConfig } from '@playwright/test'

// G-165: real, browser-driven coverage of the four SPAs. One shared janux
// server is started for the whole run (like the Rust e2e tier's single
// `TestEnv`) and torn down afterward; every test drives a real Chromium
// against it. Single worker: the server and the single admin session are
// process-global, so tests must run serially.
const config: PlaywrightTestConfig = {
   testDir: '.',
   testMatch: '**/*.spec.ts',
   globalSetup: './global-setup.ts',
   globalTeardown: './global-teardown.ts',
   use: {},
   fullyParallel: false,
   workers: 1,
   reporter: 'list',
   projects: [
      {
         name: 'chromium',
         use: { browserName: 'chromium' },
       },
    ],
}

export default config
