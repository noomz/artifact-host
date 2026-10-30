# artifact-host

Go 1.23. One binary `ah` (`cmd/ah`). Domain types in `internal/domain`. Publish and ACL in `internal/sites`. SQLite in `internal/meta`. S3 in `internal/blob`. HTTP in `internal/httpapi`. CLI in `internal/cli`.

Admin HTML is `/admin`. Cookie `ah_session` is a random id, not the admin token. Do not put raw user tokens in cookies or logs. `/s/*` is CSP-sandboxed. Delete site must remove the S3 prefix first.

Private files always go through the HTTP process. Do not make the S3 bucket public.

`go test ./...` before you call a unit done.
