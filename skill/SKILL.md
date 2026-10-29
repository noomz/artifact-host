---
name: artifact-host
description: Publish a static HTML site to self-hosted artifact-host. Use when the user wants to share an agent-made page, dashboard, or HTML export as a public, owner-only, or team URL, or when Claude/Codex/Pi artifact sharing is too limited.
---

# Publish to artifact-host

## Done when

The user has a URL. `GET` on that URL returns the page (public) or 401 without a bearer token (owner/team).

## Steps

1. Need `ARTIFACT_HOST_URL` and `ARTIFACT_HOST_TOKEN`. If missing, stop and ask. Do not invent a host.
2. Put the site in one directory with `index.html` at the top. No backend. Relative asset paths only.
3. If the session has no HTML yet, write a single-file `index.html` (inline CSS/JS). Do not wait on Claude Design, Codex Sites, or a vendor artifact tool.
4. Publish:

```bash
ah publish --visibility public ./DIR
```

`--visibility owner` for only the token owner. `--visibility team --team TEAM_ID` for a team. `--site SITE_ID` replaces the current version of an existing site.

If `ah` is not on PATH, POST a tar of the directory to `$ARTIFACT_HOST_URL/v1/sites` with `Authorization: Bearer $ARTIFACT_HOST_TOKEN` and header `Visibility`.

5. Give the user the JSON `url` field. Do not paste the token.

## Do not

- Do not upload `.git` or secrets.
- Do not claim the page is private if visibility is `public`.
- Do not use the vendor artifact share button as a substitute when the user asked for artifact-host.
