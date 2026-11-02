# OpenDesign handoff

Export one local OpenDesign project, then publish the standalone HTML through `ah`. Artifact-host lists published sites only. This does not install or expose an OpenDesign service.

1. Obtain the intended OpenDesign project ID and project-relative HTML entry path from the user or unambiguous conversation context. Ask if ambiguous. Obtain explicit visibility (`owner`, `team`, or `public`), team ID for team visibility, and optional artifact name and existing site ID. Do not assume public access. For updates, omit `--name` unless a rename was requested.
2. Locate the OpenDesign CLI and confirm `export --help` identifies OpenDesign. On macOS, `/usr/bin/od` is Apple's octal dump, not OpenDesign. The desktop app may not put its CLI on PATH. For the installed macOS 0.26.1 app, the following invokes its bundled Electron runtime and CLI (system Node can have an incompatible native-module ABI):

   ```bash
   ELECTRON_RUN_AS_NODE=1 "/Applications/Open Design.app/Contents/MacOS/Open Design" \
     "/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs" export --help
   ```

   This app-bundle path is version-dependent. If no working CLI or local daemon is available, stop and explain how to start or locate OpenDesign. Never substitute Apple's `od`.

   Find the daemon URL and pass it explicitly. The desktop app's daemon uses a dynamic loopback port. The CLI default, `http://127.0.0.1:7456`, can be a different OpenDesign instance or another program. A container that publishes that port can answer `API_TOKEN_REQUIRED`, because its traffic does not arrive from a loopback peer. Do not look for a token to fix this: the desktop daemon does not need one for loopback requests. On macOS, list the app's listening ports, then choose the URL where `GET /api/projects` returns the intended project ID:

   ```bash
   lsof -nP -iTCP -sTCP:LISTEN | grep '^Open'
   ```

3. Create a fresh private temporary directory. Export the selected project entry to `index.html` inside it:

   ```bash
   od export ENTRY --project PROJECT_ID --format html --out TEMP_DIR/index.html --json --daemon-url DAEMON_URL
   ```

   Here `od` means the verified OpenDesign CLI invocation from step 2, not necessarily a literal command on PATH. Stop if export fails, its JSON reports failure, or `index.html` is missing or empty. Inspect the output and any required assets. Never publish the OpenDesign workspace, hidden files, or secrets. Artifact-host limits uploads to 32 MiB and serves a CSP-sandboxed page; not every export will work unchanged.
4. Run `ah publish --visibility VISIBILITY` with the temporary directory, and add `--team`, `--site`, or `--name` only as applicable. Use `ARTIFACT_HOST_URL` and the user's `ARTIFACT_HOST_TOKEN` as described in the main skill. Do not use the admin token or put credentials in URLs, exports, or logs. Clean up the temporary directory whether export or publish succeeds or fails.
5. Confirm publish returned an ID and URL. Find that ID in authenticated `ah list`; check public read returns the expected page or, for owner/team, anonymous read returns 401 and an authorized read succeeds. Team access needs a team-member credential to verify independently; report it as unverified if unavailable. Check actual rendered behavior where possible, especially scripts, assets, and cross-origin requests under the sandbox. Report verification limits and the URL; never reveal the token.
