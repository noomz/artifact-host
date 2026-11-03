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

Accepted risk (2026-11-02): keep `{id}.u.artifacts.noomz.space`. Registrable domain is `noomz.space`, so page script can toss cookies at sibling apps, and phishing reputation is shared. V12 CSP blocks forms, `fetch`, and remote images, but script can still leak data through navigation.

## §I

- `I.host`: `https://{id}.u.artifacts.noomz.space/` serves protected site. Config `ARTIFACT_HOST_CONTENT_DOMAIN`. Empty disables feature.
- `I.password`: `PUT /v1/sites/{id}/password` JSON `{"password"}`; `DELETE` clears. CLI `ah password set SITE_ID` (prompt or `--stdin`), `ah password clear SITE_ID`.
- `I.link`: `POST /v1/sites/{id}/links` JSON `{"label","expires_in"}` returns URL once; `DELETE /v1/sites/{id}/links/{link_id}` revokes. CLI `ah link create SITE_ID [--label L] [--expires 7d]`, `ah link revoke SITE_ID LINK_ID`.
- `I.access`: `GET /v1/sites/{id}/access` returns `has_password`, link metadata, `content_url`. CLI `ah access SITE_ID`.
- `I.viewer`: `GET /__ah/link/{token}` warning page, `POST` exchanges link for session; `GET|POST /__ah/login` password form. Both on content host only.
- `I.admin`: `/admin` shows password and link state per site; can clear password and revoke links.
- `I.deploy`: wildcard DNS on Route 53 (zone `noomz.space`), wildcard TLS cert `*.u.artifacts.noomz.space` (DNS-01 through `certbot-dns-route53`, IAM user `artifact-host-certbot`, script `deploy/setup-wildcard-cert.sh`), nginx server block.

## §V

- V1: Valid bearer, password session, or link session each grants read. Link does not also require password. Grants never widen beyond the one site.
- V2: Grants are independent. Changing password ends password sessions only. Revoking link ends that link's sessions only. Removing one grant leaves other working.
- V3: Revocation, expiry, password change, and site delete take effect on next request. Session validity checked against DB every request. Sessions survive server restart.
- V4: Only site owner manages grants through API and CLI. Admin may clear or revoke, not read secrets or create. Team members cannot manage.
- V5: Content host serves site files and `/__ah/*` only. Its router never reaches `/admin`, `/v1`, `/s`, or `/healthz` handlers; those are ordinary site paths there. Non-GET/HEAD outside `/__ah/*` returns 404. Host must match `[0-9a-f]{32}` plus exact content domain. Unknown ID, or site without active grant, returns 404.
- V6: Admin POST routes require CSRF token and reject cross-origin `Origin`. Admin cookie uses `__Host-` prefix. Ships before any content host goes live.
- V7: Grant cookie `__Host-ah_grant`: random ID, hash stored server-side, `HttpOnly`, `Secure`, `SameSite=Lax`, host-only, `Path=/`. Never holds password or link token. Plain-HTTP local dev may drop prefix and `Secure`.
- V8: Password stored as argon2id only; length 8 to 1024 bytes. Link token 256-bit random, stored as SHA-256, shown once. Plaintext of either never in DB, logs, list, or access responses. CLI never takes password as flag value.
- V9: Password attempts limited per site+IP and per site overall, 5 failures per 15 minutes per site+IP. Limit returns 429. Wrong password and limit responses do not reveal other grants. Password POST requires CSRF token.
- V10: Invalid, expired, and revoked link tokens give same 404 on GET and POST. GET shows server-owned warning page with Continue button, creates no session. POST requires CSRF token, responds 303 to `/` with cookie. Both send `Referrer-Policy: no-referrer`. nginx does not log `/__ah/link/` paths.
- V11: Link expiry required: default 7 days, maximum 365 days. Link usable repeatedly until expiry or revoke. Session lasts 24 hours, never past link expiry.
- V12: Protected responses send `Cache-Control: private, no-store`, `X-Robots-Tag: noindex`. Site files send CSP `default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://esm.sh; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data: blob:; connect-src 'self'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'`. CDN list fixed in code, never any host. `/__ah/*` pages use own CSP with `form-action 'self'`, `frame-ancestors 'none'`. Login redirect keeps path; target must be same-host path, no open redirect.
- V13: Anonymous request to `/s/{id}/...` on site with active grant redirects to content host, same path. With no active grant, responds as today. Bearer requests to `/s/` served as today.
- V14: Grants on `public` site rejected 400. Publish that would make site with grants `public` rejected 400 until grants removed.
- V15: Republish without explicit visibility keeps existing visibility and team. New site without visibility stays `public` for compatibility. Republish keeps password and links.
- V16: Site delete removes S3 prefix first, then grants and sessions. Published file under `__ah/` rejected 400. Migration leaves existing sites, tokens, and URLs unchanged.
- V17: Tests cover each grant alone and both together, independent revocation, restart survival, host routing, CSRF, rate limit, and secret absence from logs and responses. Assets verified in Chrome, Firefox, Safari over real HTTPS.
- V18: DNS-01 credential may change only TXT at `_acme-challenge.u.artifacts.noomz.space`. Stored in root-only `/root/.aws/credentials`, never in app `.env` or container.
- V19: Content host returns 404 to requests with `Service-Worker: script`, so pages cannot register a worker that outlives revocation or intercepts `/__ah/*`.

## §T

| id | status | task | cites |
|---|---|---|---|
| T1 | x | Fix republish visibility reset, with regression test; ship alone first, live bug today | V15 |
| T2 | x | Add admin CSRF tokens, `Origin` check, `__Host-` cookie | V6 |
| T3 | x | Choose DNS provider and token handling for DNS-01; set wildcard DNS and cert | V18,I.deploy |
| T4 | x | Add schema migration and domain types for password, links, sessions | V3,V8,V16 |
| T5 | x | Add host routing and content handler; prove isolation from admin and API | V5,V12,V16,V19,I.host |
| T6 | x | Add password API, CLI, login form, limiter, sessions | V1,V2,V4,V7,V8,V9,V14,I.password,I.viewer |
| T7 | x | Add link API, CLI, exchange route, expiry, revoke | V1,V2,V3,V4,V7,V8,V10,V11,V14,I.link,I.viewer |
| T8 | x | Add access API and CLI; admin state and revoke; `/s/` redirect | V4,V13,I.access,I.admin |
| T9 | . | Update nginx and deploy scripts; document in README and skill | V10,I.deploy |
| T10 | . | Run full tests; verify both grants live over HTTPS in Chrome, Firefox, Safari | V17 |
| T11 | . | Stop published pages on `/s/` sharing hostname with `/admin`; design needs user confirmation | B2 |

## §B

| id | date | cause | fix |
|---|---|---|---|
| B1 | 2026-11-02 | CLI and server default visibility to `public`, and `SetCurrent` overwrites it, so `ah publish --site X DIR` without `--visibility` makes private site public | V15,T1 |
| B2 | 2026-11-02 | Published pages on `/s/{id}/` share hostname with `/admin`, and sandbox allows forms and scripts, so page can show fake admin login. Live, not fixed by T1 to T10 | T11 |
