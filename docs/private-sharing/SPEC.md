# Private sharing: password and share links

## §G

Let owner share a private page with people in any browser, no account: by password, by share link, or both on the same site.

## §C

- Password and links are independent optional grants on an `owner` or `team` site. Site can have neither, either, or both. Not new visibility values.
- Bearer token, ACL, existing `/s/{id}/` URLs, and public sites keep working.
- S3 bucket stays private. All reads go through HTTP process.
- No user accounts or OAuth for viewers. No per-viewer identity or view tracking.
- Share link is opaque random token checked against DB, not HMAC. Revocation needs DB lookup anyway; no signing key to manage or rotate.
- New dependency allowed: `golang.org/x/crypto` for argon2id.
- `?` items need user confirmation before their task starts.

Why subdomains: published pages use CSP sandbox, so origin is opaque. Chrome 156 test (2026-11-02): `SameSite=Lax` and `Strict` cookies reach HTML only, not CSS, images, or scripts. Own origin per site, no sandbox, fixes this in principle. Firefox and Safari not tested.

Hostnames stay same-site as `/admin` because all share `noomz.space`. `SameSite` gives no protection between them, and an unsandboxed page can set cookies for parent domains. V5 and V6 cover this. Separate registrable domain would be stronger; content domain is config, so it can change later.

## §I

- `I.host`: `https://{id}.u.artifacts.noomz.space/` serves protected site. Config `ARTIFACT_HOST_CONTENT_DOMAIN`. Empty disables feature.
- `I.password`: `PUT /v1/sites/{id}/password` JSON `{"password"}`; `DELETE` clears. CLI `ah password set SITE_ID` (prompt or `--stdin`), `ah password clear SITE_ID`.
- `I.link`: `POST /v1/sites/{id}/links` JSON `{"label","expires_in"}` returns URL once; `DELETE /v1/sites/{id}/links/{link_id}` revokes. CLI `ah link create SITE_ID [--label L] [--expires 7d]`, `ah link revoke SITE_ID LINK_ID`.
- `I.access`: `GET /v1/sites/{id}/access` returns `has_password`, link metadata, `content_url`. CLI `ah access SITE_ID`.
- `I.viewer`: `GET /__ah/link/{token}` exchanges link for session; `GET|POST /__ah/login` password form. Both on content host only.
- `I.admin`: `/admin` shows password and link state per site; can clear password and revoke links.
- `I.deploy`: wildcard DNS, wildcard TLS cert `*.u.artifacts.noomz.space` (DNS-01), nginx server block.

## §V

- V1: Valid bearer, password session, or link session each grants read. Link does not also require password. Grants never widen beyond the one site.
- V2: Grants are independent. Changing password ends password sessions only. Revoking link ends that link's sessions only. Removing one grant leaves other working.
- V3: Revocation, expiry, password change, and site delete take effect on next request. Session validity checked against DB every request. Sessions survive server restart.
- V4: Only site owner manages grants through API and CLI. Admin may clear or revoke, not read secrets or create. Team members cannot manage.
- V5: Content host serves content and `/__ah/*` only. `/admin`, `/v1`, `/s`, and `/healthz` return 404 there. Host must match `[0-9a-f]{32}` plus exact content domain. Unknown ID, or site without active grant, returns 404.
- V6: Admin POST routes require CSRF token and reject cross-origin `Origin`. Admin cookie uses `__Host-` prefix. Ships before any content host goes live.
- V7: Grant cookie `__Host-ah_grant`: random ID, hash stored server-side, `HttpOnly`, `Secure`, `SameSite=Lax`, host-only, `Path=/`. Never holds password or link token. Plain-HTTP local dev may drop prefix and `Secure`.
- V8: Password stored as argon2id only; length 8 to 1024 bytes. Link token 256-bit random, stored as SHA-256, shown once. Plaintext of either never in DB, logs, list, or access responses. CLI never takes password as flag value.
- V9: Password attempts limited per site+IP and per site overall, 5 failures per 15 minutes per site+IP. Limit returns 429. Wrong password and limit responses do not reveal other grants. Password POST requires CSRF token.
- V10: Invalid, expired, and revoked link tokens give same 404. Link route responds 303 to `/` with cookie, `Referrer-Policy: no-referrer`. nginx does not log `/__ah/link/` paths.
- V11: Link expiry required: default 7 days, maximum 365 days. Link usable repeatedly until expiry or revoke. Session lasts 24 hours, never past link expiry.
- V12: Protected responses send `Cache-Control: private, no-store`, `X-Robots-Tag: noindex`, CSP `frame-ancestors 'none'`. Login redirect keeps path; target must be same-host path, no open redirect.
- V13: Anonymous request to `/s/{id}/...` on site with active grant redirects to content host, same path. With no active grant, responds as today. Bearer requests to `/s/` served as today.
- V14: Grants on `public` site rejected 400. Publish that would make site with grants `public` rejected 400 until grants removed.
- V15: Republish without explicit visibility keeps existing visibility and team. New site without visibility stays `public` for compatibility. Republish keeps password and links.
- V16: Site delete removes S3 prefix first, then grants and sessions. Published file under `__ah/` rejected 400. Migration leaves existing sites, tokens, and URLs unchanged.
- V17: Tests cover each grant alone and both together, independent revocation, restart survival, host routing, CSRF, rate limit, and secret absence from logs and responses. Assets verified in Chrome, Firefox, Safari over real HTTPS.

## §T

| id | status | task | cites |
|---|---|---|---|
| T1 | x | Fix republish visibility reset, with regression test; ship alone first, live bug today | V15 |
| T2 | x | Add admin CSRF tokens, `Origin` check, `__Host-` cookie | V6 |
| T3 | . | `?` Choose DNS provider and token handling for DNS-01; set wildcard DNS and cert | I.deploy |
| T4 | . | Add schema migration and domain types for password, links, sessions | V3,V8,V16 |
| T5 | . | Add host routing and content handler; prove isolation from admin and API | V5,V12,V16,I.host |
| T6 | . | Add password API, CLI, login form, limiter, sessions | V1,V2,V4,V7,V8,V9,V14,I.password,I.viewer |
| T7 | . | Add link API, CLI, exchange route, expiry, revoke | V1,V2,V3,V4,V7,V8,V10,V11,V14,I.link,I.viewer |
| T8 | . | Add access API and CLI; admin state and revoke; `/s/` redirect | V4,V13,I.access,I.admin |
| T9 | . | Update nginx and deploy scripts; document in README and skill | V10,I.deploy |
| T10 | . | Run full tests; verify both grants live over HTTPS in Chrome, Firefox, Safari | V17 |

## §B

| id | date | cause | fix |
|---|---|---|---|
| B1 | 2026-11-02 | CLI and server default visibility to `public`, and `SetCurrent` overwrites it, so `ah publish --site X DIR` without `--visibility` makes private site public | V15,T1 |
