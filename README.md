# artifact-host

Self-hosted static host for HTML that agents make. Claude, Codex, and Pi can already render a page locally or on a vendor URL. Those shares stay on that vendor. This process serves the files from your S3 bucket and your ACL.

Visibility is `public`, `owner` (one user), or `team`. Agents publish through the `ah` CLI or `POST /v1/sites`.

## Run

Go 1.23. Needs SQLite on disk and an S3 bucket. MinIO (image `quay.io/minio/minio`) is enough locally:

```bash
docker compose up -d
aws --endpoint-url http://localhost:9000 s3 mb s3://artifacts
export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=miniopass AWS_REGION=us-east-1
export ARTIFACT_HOST_ADMIN_TOKEN=change-me
export ARTIFACT_HOST_S3_BUCKET=artifacts
export ARTIFACT_HOST_S3_ENDPOINT=http://localhost:9000
go run ./cmd/ah serve --listen :8080 --base-url http://localhost:8080
```

```bash
export ARTIFACT_HOST_URL=http://localhost:8080
ah user add ada          # prints id + token; save the token
export ARTIFACT_HOST_TOKEN=...
ah publish --visibility public ./testdata/hello
```

`GET` the returned `url`. Owner and team sites need `Authorization: Bearer <token>` on read.

Admin UI is `/admin` (login with the admin token). Sessions are random ids, not the admin token. Create users, rotate tokens, teams, delete sites. New tokens are shown once on the POST response. Published pages get `Content-Security-Policy: sandbox` so they cannot use the admin cookie. A separate user-content origin is still the long-term isolation.

## API

| Method | Path | Who |
| --- | --- | --- |
| `POST` | `/v1/users` | admin token, JSON `{"name"}` |
| `POST` | `/v1/teams` | admin |
| `POST` | `/v1/teams/{id}/members` | admin, JSON `{"user_id"}` |
| `POST` | `/v1/sites` | user token, tar body, headers `Visibility`, optional `Site-Id`, `Team-Id` |
| `GET` | `/s/{id}/...` | ACL on the site |

Production on proxy-a is `https://artifacts.noomz.space`. Install: `deploy/install-proxy-a.sh` (nginx like `stm.noomz.space`, bucket `noomz-artifact-host` in `ap-southeast-1`). Put AWS keys in `/opt/artifact-host/.env` on the host.

The agent skill is `skill/SKILL.md`. Copy it into the agent's skills directory.

## Build

```bash
go test ./...
go build -o ah ./cmd/ah
```
