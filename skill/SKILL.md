---
name: artifact-host
description: Publish a static HTML site to self-hosted artifact-host. Use when the user wants to share an agent-made page, dashboard, HTML export, or OpenDesign project as a public, owner-only, or team URL, or share a private page by password or share link with people who have no account.
---

# Publish to artifact-host

## Done when

The user has a URL. `GET` on that URL returns the page (public) or 401 without a bearer token (owner/team).

## Steps

1. Need `ARTIFACT_HOST_URL` and `ARTIFACT_HOST_TOKEN`. If missing, stop and ask. Do not invent a host. For an OpenDesign project, follow [OpenDesign handoff](references/open-design.md) instead of steps 2–4 below, then give the user the result.
2. Put the site in one directory with `index.html` at the top. No backend. Relative asset paths only.
3. If the session has no HTML yet, write a single-file `index.html` (inline CSS/JS). Do not wait on Claude Design, Codex Sites, or a vendor artifact tool.
4. Publish:

```bash
ah publish --visibility public ./DIR
```

`--visibility owner` for only the token owner. `--visibility team --team TEAM_ID` for a team. `--site SITE_ID` replaces the current version of an existing site and keeps its visibility and team unless you pass `--visibility`.

If `ah` is not on PATH, POST a tar of the directory to `$ARTIFACT_HOST_URL/v1/sites` with `Authorization: Bearer $ARTIFACT_HOST_TOKEN` and header `Visibility`.

5. Give the user the JSON `url` field. Do not paste the token.

## Share a private page without an account

Only for `owner` or `team` sites, and only the site owner's token can do it. Public sites reject grants. Password and link can be used alone or together.

- Password: `ah password set SITE_ID` prompts. In a non-interactive session, pipe it: `printf %s "$PW" | ah password set SITE_ID --stdin`. Use the password the user gave. Never pass it as a flag, and do not echo it back. 8 to 1024 bytes.
- Link: `ah link create SITE_ID --label "who it is for" --expires 7d` (default 7d, max 365d). The URL is printed once, so give it to the user right away. It is a secret: anyone with it can read the site until it expires or is revoked.
- Check state: `ah access SITE_ID` prints `has_password`, link ids and expiry, and `content_url`. The page for viewers is `content_url`, not the `/s/` URL.
- Undo: `ah password clear SITE_ID`, `ah link revoke SITE_ID LINK_ID`. Takes effect on the next request.

If the server says share links need `ARTIFACT_HOST_CONTENT_DOMAIN`, the feature is off on that host. Tell the user. Do not fall back to making the site public.

## Do not

- Do not upload `.git` or secrets.
- Do not claim the page is private if visibility is `public`.
- Do not make a site `public` to share it with someone who lacks an account. Use a password or link.
- Do not use the vendor artifact share button as a substitute when the user asked for artifact-host.
