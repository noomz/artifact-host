# artifact-host

Self-hosted static host for HTML that agents make. Claude, Codex, and Pi can already render a page locally or on a vendor URL. Those shares stay on that vendor. This process serves the files from your S3 bucket and your ACL.

Visibility is `public`, `owner` (one user), or `team`. Agents publish through the `ah` CLI or `POST /v1/sites`.

## Run

Go 1.23. Needs SQLite on disk and an S3 bucket. MinIO (image `quay.io/minio/minio`) is enough locally:

```bash
docker compose up -d
aws --endpoint-url http://localhost:9000 s3 mb s3://artifacts
export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=miniopass AWS_REGION=us-east-1
export ARTIFACT_HOST_ADMIN_TOKEN=$(openssl rand -hex 32)
export ARTIFACT_HOST_S3_BUCKET=artifacts
export ARTIFACT_HOST_S3_ENDPOINT=http://localhost:9000
go run ./cmd/ah serve --listen :8080 --base-url http://localhost:8080
```

```bash
export ARTIFACT_HOST_URL=http://localhost:8080
ah user add ada          # prints id + token; save the token
export ARTIFACT_HOST_TOKEN=...
ah publish --name "Hello" --visibility public ./testdata/hello
ah list --scope owned --name hello
ah rename SITE_ID "New name"
```

`GET` the returned `url`. Owner and team sites need `Authorization: Bearer <token>` on read. Names are optional, need not be unique, and do not change URLs. Names are trimmed and limited to 200 Unicode characters. Use `ah rename SITE_ID ""` to clear one. Republish with `--site SITE_ID` and omit `--name` to preserve its name. Omit `--visibility` to keep its current visibility and team. A new site without `--visibility` is public.

`ah list` returns your sites and team-visible sites shared with your teams. Filter by `--name` (case-insensitive substring), `--visibility public|owner|team`, or `--scope all|owned|team`. Team scope includes your own team-visible sites when you are a member of that team. Results are JSON.

Admin UI is `/admin` (login with the admin token). Sessions are random ids, not the admin token. Create users, rotate tokens, teams, delete sites. New tokens are shown once on the POST response. The site list shows each site's password and share-link state, and admin can clear a password or revoke a link, but cannot read or create them. When `ARTIFACT_HOST_CONTENT_DOMAIN` is set, browsers never read a page on the `/admin` hostname: anonymous visits to `/s/SITE_ID/` on a public site, or on a site with a password or link, redirect to the site's own content host (see Private sharing). Only bearer reads, and owner or team sites without a grant, stay on `/s/`, and those pages get `Content-Security-Policy: sandbox` so they cannot use the admin cookie.

## Private sharing

An `owner` or `team` site can also be opened in any browser, without an account, by password, by share link, or both. These are grants on the site, not visibility values. Public sites cannot have grants.

```bash
ah password set SITE_ID            # prompts; or: printf %s "$PW" | ah password set SITE_ID --stdin
ah password clear SITE_ID
ah link create SITE_ID --label "Review" --expires 7d   # prints the URL once
ah link revoke SITE_ID LINK_ID
ah access SITE_ID                  # has_password, links, content_url
```

Public sites and sites with a grant are served from their own host, `https://SITE_ID.u.artifacts.noomz.space/`, set by `ARTIFACT_HOST_CONTENT_DOMAIN` (empty turns the feature off and keeps every page on `/s/`). Anyone can read a public site there, with no login. Pages on the content host get a CSP that allows only their own files plus a few fixed CDNs (jsDelivr, unpkg, cdnjs, esm.sh, Google Fonts) and blocks forms, so inline other assets and use relative links. Viewers of a protected site there see a password form or a share-link page with a Continue button, then get a 24-hour session cookie. A link session never outlives the link. Links expire after 7 days by default, at most 365 days. Changing the password ends password sessions only; revoking a link ends that link's sessions only. Both take effect on the next request. Anonymous visits to `/s/SITE_ID/` on a public or granted site redirect (302) to the content host, same path and query. Bearer reads on `/s/` work as before.

The password is never a flag value, and neither the password nor the link token is stored or logged in plain text. Only the site owner can set grants. Team members cannot. Password attempts are limited to 5 failures per 15 minutes per site and IP.

## API

| Method | Path | Who |
| --- | --- | --- |
| `POST` | `/v1/users` | admin token, JSON `{"name"}` |
| `POST` | `/v1/teams` | admin |
| `POST` | `/v1/teams/{id}/members` | admin, JSON `{"user_id"}` |
| `POST` | `/v1/sites` | user token, tar body, headers `Visibility`, optional `Site-Id`, `Team-Id`, `Site-Name` (URL query-encoded UTF-8) |
| `GET` | `/v1/sites` | user token; optional query `name`, `visibility`, `scope` (`all`, `owned`, `team`) |
| `PATCH` | `/v1/sites/{id}` | owner user token, JSON `{"name":"New name"}`; empty name clears |
| `PUT` | `/v1/sites/{id}/password` | owner, JSON `{"password"}` (8 to 1024 bytes) |
| `DELETE` | `/v1/sites/{id}/password` | owner |
| `POST` | `/v1/sites/{id}/links` | owner, JSON `{"label","expires_in"}`, `expires_in` like `7d` or `12h` (default `7d`); URL returned once |
| `DELETE` | `/v1/sites/{id}/links/{link_id}` | owner |
| `GET` | `/v1/sites/{id}/access` | owner; `has_password`, link metadata, `content_url` |
| `GET` | `/s/{id}/...` | ACL on the site; anonymous on a public or granted site gets 302 to the content host |
| `GET` | `https://{id}.u.artifacts.noomz.space/...` | content host: anyone on a public site, password or link session otherwise |
| `GET`, `POST` | `/__ah/login`, `/__ah/link/{token}` | content host only; viewer forms |

## Deploy

Production on proxy-a is `https://artifacts.noomz.space`, with content hosts under `*.u.artifacts.noomz.space`. Bucket `noomz-artifact-host` in `ap-southeast-1`. Run these from your laptop:

1. `deploy/setup-wildcard-cert.sh` (once, safe to re-run): the IAM user `artifact-host-certbot` may change only the `_acme-challenge.u.artifacts.noomz.space` TXT record. Its key goes in `/root/.aws/credentials` on the host, never in the app's `.env`. The script also issues the `*.u.artifacts.noomz.space` cert through `certbot-dns-route53` (it renews and reloads nginx by itself) and sets the wildcard A record in Route 53.
2. `deploy/bootstrap-proxy-a.sh` (first install) or `deploy/rebuild-proxy-a.sh` (push HEAD first). Both run `deploy/install-proxy-a.sh` on the host. That script stops if the wildcard cert is missing, then installs `nginx-http.conf` for the main host and `nginx-content.conf` for content hosts. It ends by checking `/healthz` and a 404 from an unknown content host.

`nginx-content.conf` turns off access and error logs for `/__ah/link/`, and turns off logging on the plain-HTTP redirect, since those paths hold link tokens. `go test ./deploy` checks this and that all deploy files name the same content domain.

The agent skill is `skill/SKILL.md`. Copy it into the agent's skills directory.

## Build

```bash
go test ./...
go build -o ah ./cmd/ah
```
