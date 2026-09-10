// Test harness for the browser-driven UI suite (G-165).
//
// The four SPAs (login / device / consent / admin) are embedded in the janux
// binary at compile time (rust-embed over `frontend/dist`) and served by the
// same process that answers their API. A real `janux` subprocess is started
// against a throwaway data dir, exactly like the Rust e2e tier's `TestEnv`, so
// the browser exercises the genuine serve + protect/policy stack — not a mock.
//
// Magic-link email cannot reach a real inbox in CI, so `resend.base_url` is
// pointed at a tiny local capture server that records the last email and hands
// back the embedded ceremony link. This is the same seam the Rust mail unit
// tests use (`spawn_mock_resend`); here it lets a real browser click through a
// genuine login instead of the deleted password-era selectors.

import { spawn, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import process from 'node:process';

// Playwright executes this module with cwd = e2e/. Anchor everything at the
// repo root (two levels above this file), so janux, the frontend build, and a
// TMPDIR resolve the same way no matter what the runner's cwd is.
const REPO_ROOT = resolve(process.cwd(), '..');

// Playwright runs this module with cwd = e2e/. Anchor everything at the repo
// root (two levels up from this file so janux, frontend, and a TMPDIR live
// where we expect regardless of the runner's working directory).

// ─── Port allocation ──────────────────────────────────────────────────────────
// Free TCP port: bind 0, capture, release.
async function freePort(): Promise<number> {
   return new Promise((resolve, reject) => {
      const s = createServer();
      s.once('error', reject);
      s.listen(0, '127.0.0.1', () => {
         const addr = s.address();
         if (!addr || typeof addr === 'string') {
            s.close();
            reject(new Error('could not resolve a free port'));
             return;
           }
         s.close(() => resolve(addr.port));
         });
        });
  }

export interface EnvUrls {
    baseURL: string;
    mockUrl: string;
 }

// ─── Mock Resend endpoint ─────────────────────────────────────────────────────
// Accepts any delivery and records the last email; `GET /__link` returns the
// query string embedded in that email's verify link (`token=…&username=…&email=
// …`), which is what the login SPA consumes when a user follows the magic link.
class MockResend {
    private server: Server | null = null;
    private lastLink = '';

    async start(port: number): Promise<void> {
        this.server = createServer((req, res) => {
             if (req.url === '/__link') {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(JSON.stringify(this.lastLink));
                 return;
              }
            let body = '';
            req.on('data', (c) => {
                body += c;
                });
             req.on('end', () => {
                    // resend-rs posts `{ from, to, subject, html }`; the verify
                    // link lives in the html. Take everything after the first
                    // `?` in that link.
                 try {
                    const parsed = JSON.parse(body) as { html?: string };
                    // The link is `…/log?token=…&…`; grab the query after it.
                     const m = parsed.html?.match(/token=[^"'<>\s]+/);
                     if (m) this.lastLink = m[0];
                    } catch {
                       // not JSON — ignore
                    }
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end('{"id":"mock-' + randomUUID() + '"}');
              });
            });
        await new Promise<void>((resolve, reject) => {
             this.server!.once('error', reject);
             this.server!.listen(port, '127.0.0.1', () => resolve());
            });
    }

    async stop(): Promise<void> {
        if (!this.server) return;
        await new Promise<void>((resolve) => this.server!.close(() => resolve()));
        this.server = null;
    }
}

async function getLink(mockUrl: string): Promise<string> {
    const res = await fetch(`${mockUrl}/__link`);
    const raw = (await res.text()) as string;
    return JSON.parse(raw) as string;
}

// ─── Server health ────────────────────────────────────────────────────────────
async function waitForHealth(baseURL: string, timeoutMs = 30_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
         try {
            const res = await fetch(`${baseURL}/api/v1/healthy`);
            if (res.ok) {
                const body = (await res.json()) as { ok?: boolean };
                if (body.ok) return;
                }
           } catch {
              // server not up yet
           }
         if (Date.now() > deadline) throw new Error('janux did not become healthy in time');
        await new Promise((r) => setTimeout(r, 150));
      }
}

// ─── Test tenant config ───────────────────────────────────────────────────────
// Mirrors `STANDARD_ADMIN_POLICIES` from src/seed.rs — the same rows
// `tests/common.rs` seeds. A tenant with no policies default-denies every
// admin endpoint (`protect` is default-deny), so the console's data load would
// 403 and assert nothing. The domain is `localhost` because the policies bind
// `domain = "localhost"`; the browser therefore talks to
// `http://localhost:<port>` so the Host header resolves the tenant by that
// domain.
const POLICY_ROWS: [string, string][] = [
    // root: cross-tenant lifecycle
     ['/api/v1/admin/tenant/list', 'root'],
      ['/api/v1/admin/tenant/create', 'root'],
       ['/api/v1/admin/tenant/delete', 'root'],
      // admin: everything inside its own tenant
      ['/api/v1/admin/domain/list', 'admin'],
       ['/api/v1/admin/domain/create', 'admin'],
        ['/api/v1/admin/domain/delete', 'admin'],
        ['/api/v1/admin/user/list', 'admin'],
         ['/api/v1/admin/user/create', 'admin'],
          ['/api/v1/admin/user/activate', 'admin'],
           ['/api/v1/admin/user/delete', 'admin'],
            ['/api/v1/admin/user/add_role', 'admin'],
             ['/api/v1/admin/user/remove_role', 'admin'],
              ['/api/v1/admin/user/remove_email', 'admin'],
               ['/api/v1/admin/user/attach_email', 'admin'],
                ['/api/v1/admin/user/remove_mobile', 'admin'],
                 ['/api/v1/admin/user/remove_passkey', 'admin'],
                  ['/api/v1/admin/user/remove_social', 'admin'],
                   ['/api/v1/admin/user/roles', 'admin'],
                    ['/api/v1/admin/role/list', 'admin'],
                     ['/api/v1/admin/role/create', 'admin'],
                      ['/api/v1/admin/role/delete', 'admin'],
                       ['/api/v1/admin/provider/list', 'admin'],
                        ['/api/v1/admin/provider/create', 'admin'],
                         ['/api/v1/admin/provider/delete', 'admin'],
                          ['/api/v1/admin/policy/list', 'admin'],
                           ['/api/v1/admin/policy/create', 'admin'],
                            ['/api/v1/admin/policy/delete', 'admin'],
                             ['/api/v1/admin/key/list', 'admin'],
                              ['/api/v1/admin/key/create', 'admin'],
                               ['/api/v1/admin/key/delete', 'admin'],
                                ['/api/v1/admin/key/retire', 'admin'],
                                 ['/api/v1/admin/totp/list', 'admin'],
                                  ['/api/v1/admin/totp/remove', 'admin'],
                                   ['/api/v1/admin/oauth2client/list', 'admin'],
                                    ['/api/v1/admin/oauth2client/create', 'admin'],
                                     ['/api/v1/admin/oauth2client/delete', 'admin'],
                                      ['/api/v1/admin/oauth2client/meta', 'admin'],
                                       ['/api/v1/admin/oidc/config', 'admin'],
                                        ['/api/v1/admin/metrics', 'admin'],
                                        // user: self-service
                                        ['/api/v1/admin/user/activate/self', 'user'],
                                         ['/api/v1/admin/user/delete/self', 'user'],
                                         // scim: machine provisioning
                                         ['/scim/v2/Users', 'scim'],
                                          ['/scim/v2/Users/{id}', 'scim'],
];

function writeConfig(dataDir: string, port: number, mockUrl: string): string {
   const rows = POLICY_ROWS.map(
        ([resource, role]) =>
            `     { domain = "localhost", resource = "${resource}", role = "${role}", source = "Nothing", target = "Nothing", mfa = false, allowed = true },`,
        );
   const content = [
        'data_dir = "' + dataDir + '"',
        'encryption_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"',
        'trust_forwarded_headers = false',
        '',
        '[bind]',
        'address = "127.0.0.1"',
        'port = ' + port,
        '',
        '[[seed]]',
        'name = "test-tenant"',
        'domains = [{ id = "localhost", cors = [] }]',
        'roles = ["root", "admin", "scim", "user", "guest"]',
        'policies = [',
        ...rows,
        ']',
        'users = [',
        '     { id = "admin", active = true, roles = ["root","admin","user"], email = "admin@example.com" },',
        '     { id = "user", active = true, roles = ["user"] }',
        ']',
        '',
        '[seed.resend]',
        'from = "noreply@example.com"',
        'resend_key = "re_test_key"',
        'template = ""',
        'verify_url = "http://localhost/login"',
        'base_url = "' + mockUrl + '"',
        '',
        '[seed.alisms]',
        'api_secret = "test_api_secret"',
        'api_key = "test_api_key"',
        'template_code = "TEST_12345"',
        'sign_name = "Test Company"',
        'region_id = "cn-shanghai"',
        'endpoint = "dysmsapi.aliyuncs.com"',
        '',
        ].join('\n');
   const path = join(dataDir, '..', 'config.toml');
   writeFileSync(path, content);
   return path;
}

// ─── Harness lifecycle ────────────────────────────────────────────────────────
export interface Harness {
    urls: EnvUrls;
    statePath: string;
    janux: ChildProcess;
    mock: MockResend;
    workdir: string;
    stop(): Promise<void>;
}

function binPath(): string {
    // Overridable so CI can point at a freshly compiled artifact; falls back to
    // the local debug build (the same binary the Rust e2e tier spawns).
   const fromEnv = process.env.JANUX_BIN;
   if (fromEnv) return fromEnv;
   // The harness runs from `frontend/`; the binary is at the repo root.
   return join(REPO_ROOT, 'target', 'debug', 'janux');
}

export async function startHarness(): Promise<Harness> {
   const [januxPort, mockPort] = await Promise.all([freePort(), freePort()]);
   const baseURL = 'http://localhost:' + januxPort;
   const mockUrl = 'http://127.0.0.1:' + mockPort;

   const workdir = join((process.env.TMPDIR ?? '/tmp'), 'janux-ui-' + randomUUID());
   mkdirSync(workdir, { recursive: true });
   const dataDir = join(workdir, 'data');
   mkdirSync(dataDir, { recursive: true });

   const mock = new MockResend();
   await mock.start(mockPort);

   const configPath = writeConfig(dataDir, januxPort, mockUrl);
   const janux = spawn(binPath(), ['-c', configPath], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
   });

   // Capture janux's I/O so a boot failure surfaces instead of timing out.
   let januxLog = '';
   janux.stdout?.on('data', (d) => {
      januxLog += d.toString();
       });
   janux.stderr?.on('data', (d) => {
      januxLog += d.toString();
       });
   janux.on('exit', (code, signal) => {
      januxLog += `\n[janux exited code=${code} signal=${signal}]`;
       });

   try {
      await waitForHealth('http://127.0.0.1:' + januxPort);
        } catch {
         janux.kill('SIGKILL');
         await mock.stop();
         throw new Error('janux did not become healthy:\n' + januxLog.slice(-2000));
        }

   const urls: EnvUrls = { baseURL, mockUrl };
   const statePath = join(REPO_ROOT, 'frontend', 'e2e', '.state.json');
   writeFileSync(statePath, JSON.stringify(urls));

   return {
        urls,
        statePath,
        janux,
        mock,
        workdir,
         stop(): Promise<void> {
            janux.kill('SIGKILL');
            return new Promise<void>((resolve) => {
                 if (janux.exitCode !== null) {
                    resolve();
                    } else {
                      janux.once('exit', () => resolve());
                   }
                }).then(() => mock.stop()).finally(() => {
                  rmSync(workdir, { recursive: true, force: true });
                  try {
                     rmSync(statePath, { force: true });
                     } catch {
                        // state file already gone
                     }
                });
            },
         };
}

// Read the env URLs written by globalSetup (a fresh process, so the running
// handles cannot be shared across the Playwright worker boundary).
export function readState(): EnvUrls {
   return JSON.parse(readFileSync(join(REPO_ROOT, 'frontend', 'e2e', '.state.json'), 'utf-8')) as EnvUrls;
}

export async function latestMagicLink(mockUrl: string, timeoutMs = 10_000): Promise<string> {
   const deadline = Date.now() + timeoutMs;
   let sawLink = false;
   while (Date.now() <= deadline) {
      const link = await getLink(mockUrl);
      sawLink = link.length > 0;
      if (link.includes('token=')) return link;
      await new Promise((r) => setTimeout(r, 100));
        }
   throw new Error('never received a magic link' + (sawLink ? ' (got a token-less link)' : ''));
}
