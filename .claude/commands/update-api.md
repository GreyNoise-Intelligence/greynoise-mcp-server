---
description: Audit and update this MCP server's API usage against the GreyNoise OpenAPI contract
---

Run the full GreyNoise MCP API audit-and-update. Follow every step in order. Do
not skip, reorder, or improvise. Never commit, stage, or push — leave changes as
a working-tree diff.

## 1. Refresh the vendored spec

Run `scripts/refresh-spec.sh`. It fetches the authoritative
`api/docs/oas-production.yaml` from the greynoise monorepo into
`spec/oas-production.yaml`.

- If it fails (no `gh`, no auth, no access): STOP and report. Do not audit a
  stale spec silently.
- Then run `git diff --stat spec/oas-production.yaml`. Record whether the spec
  changed and summarize the changed paths.

## 2. Enumerate every API call the server makes

Grep `src/tools/`, `src/resources/`, and `src/utils/` for `client.get`,
`client.post`, `client.put`, `client.delete`, and `client.patch`. Build a table
of:

`{ file, HTTP method, endpoint path, query/path/body params sent, zod response schema passed to the client }`

Include the tag list call in `src/utils/tag-cache.ts`.

## 3. Reconcile each call against `spec/oas-production.yaml`

For each endpoint, find the matching `path` + method in the spec and classify:

- **OK** — path, method, required params, and every response field the code
  reads all exist in the spec.
- **DRIFT** — path/method correct but params or response fields differ (renamed,
  moved query↔body, new required param, changed type).
- **BROKEN** — path or method no longer matches (e.g. version bump, rename).
- **GONE** — endpoint absent from the spec entirely.

Check specifically: path string, HTTP method, required parameters and their
`in` location (query/path/body), and that each response field validated by the
zod schema (in `src/greynoise/schemas.ts` and `src/greynoise/schemas/`) is
present in the spec's response schema.

## 4. Apply safe fixes

Apply ONLY changes that make the code match the contract:

- Endpoint path / method corrections
- Zod parameter schema updates (names, required/optional, types, locations)
- Zod response schema updates in `src/greynoise/schemas.ts` and `src/greynoise/schemas/`
- Tool description text where the contract semantics changed

Do NOT:

- Invent endpoints or params not in the spec
- Change tool behavior beyond matching the contract
- Auto-resolve anything BROKEN/GONE or any ambiguous reshape — leave the code and
  flag it for human review.

## 5. Verify

Run `npm ci` (if `node_modules` missing), then `npm run typecheck`, `npm test`,
`npm run build`. Fix any type errors your edits introduced. Do not weaken tests
to make them pass.

## 6. Report

Write `AUDIT.md` at the repo root containing:

- Spec refresh result (changed? which paths?)
- The reconciliation table from step 3 with each endpoint's status
- What was changed and in which files
- A **Needs human review** section listing every BROKEN/GONE/ambiguous item

Leave all edits as an unstaged working-tree diff. State plainly what passed and
what still needs a human. Do not commit or push.
