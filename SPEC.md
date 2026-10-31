# Artifact discovery and OpenDesign

## §G

Let users name, find, and filter their artifacts.

## §C

- Keep existing artifacts, URLs, ownership, visibility, and publish flows working.
- Private artifacts remain behind HTTP authorization. S3 bucket stays private.
- Do not expose another user's private artifact metadata through listing or filtering.
- OpenDesign research uses primary sources. Separate open-source license, hosting costs, and model/API costs.
- OpenDesign integration is out of scope; track it as a separate effort.
- Questions marked `?` need user confirmation before implementation.

## §I

- `I.publish`: `ah publish` and `POST /v1/sites` accept artifact name.
- `I.list`: authenticated user lists and filters artifacts through CLI and HTTP API.
- `I.rename`: `ah rename SITE_ID NEW_NAME` and authenticated HTTP API rename or clear an artifact name.
- `I.admin`: admin site list displays artifact name.
- `I.research`: document OpenDesign license, costs, integration paths, and security considerations with source links.

## §V

- V1: Artifact name is display metadata, not identity. Existing site IDs and URLs stay unchanged.
- V2: Existing artifacts without names remain readable, listable, and republishable after schema migration.
- V3: Listing requires authentication and returns artifacts owned by requesting user plus team-visible artifacts shared with teams they belong to. Other users' public artifacts are excluded. Return each artifact once.
- V4: Filters include case-insensitive partial name search, visibility (`public`, `owner`, `team`), and scope (`owned`, `team`, both). Filters apply only within authorized results. Empty result is a valid empty list.
- V5: Names are optional and may repeat. Only the owner can rename or clear a name. Empty name clears it. Rename neither republishes nor changes URL. Publishing an existing artifact without specifying a name preserves its name.
- V6: Existing clients may publish without a name. Trim leading and trailing whitespace. Allow Unicode and duplicate names, up to 200 Unicode characters after trimming. Empty or whitespace-only means unnamed.
- V7: OpenDesign evaluation cites primary sources and states unverified assumptions. Do not equate Apache license with zero model, infrastructure, or third-party costs.
- V8: Tests cover migration, owner isolation, filter behavior, naming, and backwards-compatible republish.

## §T

| id | status | task | cites |
|---|---|---|---|
| T1 | x | Specify name validation and test boundary cases | V5,V6,I.publish,I.rename |
| T1a | x | Specify authenticated rename API and CLI; test owner-only rename and clearing | V1,V5,V8,I.rename |
| T2 | x | Research OpenDesign license, export formats, self-hosting, costs, and safe integration options; record recommendation in `docs/research/open-design.md` | V7,I.research |
| T2a | x | Keep OpenDesign integration out of this spec as a separate effort | V7,I.research |
| T3 | x | Design and test backwards-compatible site metadata migration and name persistence | V1,V2,V5,V6,V8 |
| T4 | x | Add authenticated owned-and-team list API and filters with isolation tests | V3,V4,V8,I.list |
| T5 | x | Add CLI naming and listing, admin display, and user documentation | V1,V4,V5,V6,V8,I.publish,I.list,I.admin |
| T6 | x | Run full Go tests and exercise publish, list, filters, and republish against real service | V2,V3,V4,V5,V8 |

## §B

| id | date | cause | fix |
|---|---|---|---|
