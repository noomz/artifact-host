# artifact-host

Go 1.23. One binary `ah` (`cmd/ah`). Domain types in `internal/domain`. Publish and ACL in `internal/sites`. SQLite in `internal/meta`. S3 in `internal/blob`. HTTP in `internal/httpapi`. CLI in `internal/cli`.

Admin HTML is `/admin`. Cookie `ah_session` is a random id, not the admin token; on HTTPS it and `ah_csrf` are named with the `__Host-` prefix. Register admin POST routes through the `post` helper in `mountAdmin` so they get the CSRF and `Origin` check, and add the hidden `csrf` field to each form. Do not put raw user tokens in cookies or logs. `/s/*` is CSP-sandboxed; with a content domain set, anonymous `/s/` on public or granted sites redirects to `{id}.<content domain>`, so browsers never read pages on the admin hostname. Delete site must remove the S3 prefix first.

Private files always go through the HTTP process. Do not make the S3 bucket public.

`go test ./...` before you call a unit done.
