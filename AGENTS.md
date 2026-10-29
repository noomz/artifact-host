# artifact-host

Go 1.23. One binary `ah` (`cmd/ah`). Domain types in `internal/domain`. Publish and ACL in `internal/sites`. SQLite in `internal/meta`. S3 in `internal/blob`. HTTP in `internal/httpapi`. CLI in `internal/cli`.

Private files always go through the HTTP process. Do not make the S3 bucket public.

`go test ./...` before you call a unit done.
