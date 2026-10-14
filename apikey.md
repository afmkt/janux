# API key JWTs

Design record for long-lived **API key** tokens in Janux. Implementers should treat this document as the source of truth for the feature.

## Goal

Allow any authenticated session to mint a long-lived JWT that acts as an API key: same identity and (optionally narrowed) roles, distinct token type, configurable lifetime, revocable with the existing revocation machinery.

This is **not** a new opaque secret store. The API key **is** a JWT, signed with the tenant’s existing RSA key material (`kid` / JWKS), verifiable like every other Janux token.

## Token shape

| Field | Value |
|-------|--------|
| **Format** | RSA-signed JWT (same keys / JWKS as session and OIDC tokens) |
| **`typ` (payload)** | `"api_key+jwt"` — must be readable via `TokenPayload::typ()` |
| **Identity** | Same as the minting session: `sub`, `JwtData.user`, `username`, `domain` |
| **Roles** | Copy of the session’s roles, or an explicit **subset** (never a superset) |
| **`mfa`** | Copied from the session at mint time (frozen; not refreshed) |
| **Lifetime** | Caller-supplied; clamped to **[1 hour, 1 year]** |
| **Max lifetime** | 1 year (31_536_000 seconds) |
| **Min lifetime** | 1 hour (3_600 seconds) |
| **`jti`** | Not required. Optional later: content hash. Key rotation already uses header `kid`. |
| **Rotation** | **None.** API keys are not refreshed via `/api/v1/auth/refresh`. They live until `exp` or explicit revoke. |

### `typ` placement

Put `typ: "api_key+jwt"` in the **token payload** (flattened data), consistent with OIDC refresh tokens that already carry a payload `typ`. The top-level JOSE header may remain the library default (`JWT`); discrimination for accept/reject paths uses `TokenPayload::typ()`, not the JOSE header alone.

Implementation options (pick one, keep `TokenPayload::typ()` correct):

1. Extend `JwtData` with `typ: Option<String>` (session tokens leave it `None` / omit), or
2. A thin wrapper, e.g. `ApiKeyData { #[serde(flatten)] session: JwtData, typ: String }`.

## Endpoint

Follow existing `/api/v1/auth/…` conventions. **Not** under `/admin`. Session-gated (cookie or `Authorization: Bearer` session JWT).

```http
POST /api/v1/auth/api-key
Authorization: Bearer <session-jwt>   # or HttpOnly session cookie
Content-Type: application/json

{
  "lifetime_seconds": 2592000,
  "roles": ["user"]
}
```

### Request body

| Field | Required | Rules |
|-------|----------|--------|
| `lifetime_seconds` | **Yes** | Integer; clamped to `[3600, 31536000]`. Out-of-range → `400` with a clear validation error (do not silently clamp without documenting; prefer reject or clamp—**implement clamp and echo the effective value in the response**). |
| `roles` | **No** | If omitted, `null`, or empty → copy the full role set from the session. If non-empty → every entry must be in the session’s roles; any extra / unknown role → `400`. No privilege escalation. |

### Success response

Same envelope as the rest of the API:

```json
{
  "ok": true,
  "data": {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 2592000,
    "typ": "api_key+jwt"
  }
}
```

`expires_in` is the **effective** lifetime in seconds after clamping.

### Errors

| Condition | Status |
|-----------|--------|
| Missing / invalid session | `401` |
| Body validation (lifetime, roles) | `400` / `422` (`ApiProblem`) |
| Signing / internal failure | `500` |

## Who can mint

Any principal with a **valid session JWT** (user or machine-shaped session). Not admin-only. The mint endpoint only re-encodes identity already proven by the session; it does not grant new rights beyond optional role narrowing.

## Validation and acceptance rules

Reuse `validate_token` / `InvalidJwt`.

| Path class | Accept `api_key+jwt`? |
|------------|------------------------|
| Forward-auth / RBAC (`/api/v1/auth/verify`, policy engine) | **Yes** (treat like a session for role checks) |
| Built-in role guards (`protect_admin`, `protect_user`, `protect_scim`, …) | **Yes**, if roles in the token match |
| Credential add/remove (factor add/remove, sudo / reauth) | **Yes** — an API key is a full session for these; same principal, same roles |
| `/api/v1/auth/refresh` | **No** — `reject_typ` refuses the marker, so a key cannot rotate or extend itself past its `exp` |
| Self-mint (an API key calling `POST /api/v1/auth/api-key`) | **No** — the `reject_if_apikey` hoop blocks it; a key that could mint a successor would escape its `exp` via an unbounded rotation chain |
| OIDC `/userinfo`, introspect, etc. | Follow existing token-type rules; do not treat API keys as OIDC access tokens unless explicitly desired |

API keys **must not** participate in internal session refresh chains or session-family poison markers keyed on `auth_time` in a way that confuses them with interactive sessions. Exactly two self-propagating paths are refused: `/auth/refresh` (via `reject_typ` in `refresh_jwt`) and self-mint (via the `reject_if_apikey` hoop on the `api-key` endpoint). Both exist because a key that could rotate or mint a successor would escape its `exp` and live forever. **Every other path — including credential add/remove — accepts the key like a session**; there is no per-route `typ` gate for them.

## Revocation

**Reuse the current JWT revocation API** (`revoke_token` → process-wide `InvalidJwt` store keyed by the full token string).

- Client presents the API-key JWT to the existing logout / RFC 7009 revoke path (same as any other Bearer token Janux already invalidates).
- No separate API-key registry table is required for v1.
- Listing “my API keys” is **out of scope** for v1 (stateless mint; holder must store the token).

## Signing and key rotation

- Sign with the tenant domain’s current key (`current_key` / `kid` in the JOSE header).
- Verification uses existing `jwt_decode` + JWKS; retired keys still verify until drained (existing G-97 behaviour).
- No new key type or encryption path.

## Relation to `client_credentials`

| | Session → API key (this feature) | `client_credentials` machine token |
|--|-----------------------------------|-------------------------------------|
| **Mint auth** | Live user/machine **session** | Client id + secret |
| **`typ`** | `api_key+jwt` | Session-shaped `JwtData` (no distinct typ today) |
| **Lifetime** | 1 h – 1 y (request) | Up to 90 days (existing constant) |
| **Roles** | From session (optional subset) | From registered machine scopes (e.g. `scim`) |
| **Use case** | “Long-lived token as me” | Service principal / SCIM |

Do not conflate the two issuance paths. API keys are for session holders; `client_credentials` remains the machine-client grant.

## Implementation checklist

1. **Payload + `typ`** — ensure minted API-key JWTs expose `typ == "api_key+jwt"` via `TokenPayload::typ()`.
2. **Handler** — `POST /api/v1/auth/api-key`: session gate, parse body, clamp lifetime, subset-check roles, `jwt_authenticate` (or shared mint helper) with the new lifetime and payload.
3. **Router** — mount under the existing `/api/v1/auth` tree with the `session` (or equivalent) hoop; rate-limit like other auth writes.
4. **Reject only the self-propagating paths** — `/auth/refresh` (in `refresh_jwt`, via `reject_typ`) and self-mint (the `api-key` endpoint's `reject_if_apikey` hoop). Credential add/remove and sudo/reauth **accept** the key like a session; there is deliberately no per-route `typ` gate for those.
5. **Revoke** — confirm existing revoke/logout accepts and blacklists the full API-key string.
6. **Tests**
   - Mint with default roles and with a legal subset
   - Reject role escalation
   - Lifetime below min / above max
   - API key accepted on verify / role guard / credential add-remove
   - API key rejected on refresh
   - API key rejected on self-mint
   - Revoke then reject
7. **OpenAPI / frontend** — regenerate client if the project’s OpenAPI pipeline requires it; admin UI for “create API key” is optional follow-up.

## Non-goals (v1)

- Opaque random API keys (non-JWT)
- Server-side key listing / naming / last-used metadata
- Per-key IP allow-lists
- Refresh or sliding expiration for API keys
- Admin-only mint restriction
- Required `roles` parameter (optional narrowing only)

## Constants (suggested)

```text
API_KEY_TYP                 = "api_key+jwt"
API_KEY_MIN_LIFETIME_SECS   = 3600          // 1 hour
API_KEY_MAX_LIFETIME_SECS   = 31536000      // 1 year
```

Convert to minutes only at the `jwt_authenticate(..., minutes: i32, ...)` boundary if that helper stays minute-based.
