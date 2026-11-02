# OpenDesign agent handoff

## §G

Let an agent export a local OpenDesign artifact and publish it through artifact-host, without integrating OpenDesign into the server.

## §C

- OpenDesign runs locally for each user. No shared OpenDesign service, UI button, plugin, fork, or unpublished-project indexing.
- Artifact-host remains the only catalog of published artifacts. Its existing ownership, team ACL, and list API apply.
- Reuse `ah publish`; do not duplicate its HTTP implementation or add OpenDesign-specific server routes.
- Require the user's artifact-host token. Never expose tokens in exported files, URLs, or logs. Never use the admin token.
- OpenDesign's `od` CLI must be identified explicitly; macOS `/usr/bin/od` is not OpenDesign.
- Upstream CLI behavior is source-reviewed at revision `12d970eacc8971150e3c76470d2a9afe16dc2ed1`. Local OpenDesign 0.26.1 synthetic exports were published, updated, ACL-checked, and rendered in headless Chrome under artifact-host CSP. One real project export (2026-11-02, OpenDesign 0.26.1, a single self-contained HTML file with an inline script) passed the same checks against a local artifact-host. Exports with local assets, or with scripts that need same-origin APIs or cross-origin requests, are untested. Real project compatibility varies.

## §I

- `I.agent`: artifact-host agent skill describes an OpenDesign-to-artifact-host handoff.
- `I.export`: OpenDesign CLI exports a project-relative HTML entry. Upstream test exercises `od export index.html --project PROJECT_ID --format html --out OUTPUT_PATH --json` ([source](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/apps/daemon/tests/export-html-cli.test.ts)). Entry path need not be `index.html` in OpenDesign.
- `I.publish`: existing `ah publish --name NAME --visibility VISIBILITY [--team TEAM_ID] [--site SITE_ID] DIR` publishes export from a directory containing root `index.html`.
- `I.list`: existing `GET /v1/sites` and `ah list` find published artifacts under existing ACL rules.

## §V

- V1: Agent confirms the intended project and HTML entry before export; no guessing which local project to publish.
- V2: Export goes to a fresh isolated temporary directory as `index.html`; publish only that export and required approved assets, never the OpenDesign workspace, credentials, or unrelated files.
- V3: Agent checks export success, file existence, and publish success before reporting a URL. Failed export never triggers publish. Temporary export is cleaned up after use.
- V4: Agent does not default to public visibility without user authorization. Owner, team, and public use existing artifact-host ACL semantics; team requires a team ID.
- V5: Updates use a user-specified existing site ID. Without one, publish creates a new site. Existing name remains unchanged on update unless explicitly supplied.
- V6: Agent verifies the returned site appears in the authenticated list API and that access behavior matches requested visibility; do not put credentials in URLs.
- V7: Exported HTML may depend on assets, remote requests, or browser features incompatible with artifact-host CSP. Inspect and test representative outputs; document unsupported cases rather than claiming universal compatibility.
- V8: OpenDesign CLI absence, Apple `od` collision, export errors, missing credentials, and oversized output produce clear failure without falling back to a different project or publishing workspace contents.
- V9: OpenDesign UI changes, unpublished artifact discovery, and automatic bidirectional sync are out of scope.

## §T

| id | status | task | cites |
|---|---|---|---|
| T1 | x | Verify local OpenDesign CLI version, export command, project selection, and representative HTML output | I.export,V1,V7,V8 |
| T2 | x | Define and implement minimal agent handoff using existing publish skill and CLI | I.agent,I.export,I.publish,V1,V2,V3,V4,V5,V8 |
| T3 | x | Test isolated export, failure handling, names, visibility, updates, and authenticated discovery; exercise real OpenDesign export when available | I.list,V2,V3,V4,V5,V6,V7,V8 |
| T4 | x | Document setup, supported output, privacy constraints, and limitations; run `go test ./...` | I.agent,V6,V7,V8,V9 |

## §B

| id | date | cause | fix |
|---|---|---|---|
| B1 | 2026-10-31 | System Node ABI differs from the installed Electron app's native SQLite module | Use and verify the app's matching Electron runtime; V8 |
| B2 | 2026-11-02 | CLI default daemon port 7456 was held by an OrbStack container, not the desktop daemon on its dynamic port; export failed with `API_TOKEN_REQUIRED` and could otherwise reach the wrong instance | Handoff finds the daemon and passes `--daemon-url`; V1,V8 |
| B3 | 2026-11-02 | `io.LimitReader` made an over-limit tar body end like EOF: a cut on an entry boundary returned 201 with entries dropped, other cuts returned bare `400 invalid` | `http.MaxBytesReader`, 413 with limit in message, regression test; V8 |
