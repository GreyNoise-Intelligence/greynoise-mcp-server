# GreyNoise MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server for the GreyNoise API. It gives MCP-compatible clients (Claude Desktop, Claude Code, Cursor, etc.) access to GreyNoise threat intelligence — IP context, GNQL search, Recall timeseries, tags, CVEs, sensor sessions, BSI, callback/C2 data — plus operational tools to act on findings (blocklists and alerts).

**Requires a GreyNoise API key.** Your plan's entitlements determine which capabilities are available; the server exposes every tool and returns a clear "not entitled" message for any your plan doesn't include, so the rest keep working.

## Installation

### MCPB bundle (Claude Desktop)

Download `greynoise-mcp-server.mcpb` from the [releases page](https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/releases) and double-click to install. It prompts for your API key.

### npx (config-based clients)

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "npx",
      "args": ["@greynoise/greynoise-mcp-server"],
      "env": { "GREYNOISE_API_KEY": "your-greynoise-api-key" }
    }
  }
}
```

### Local build

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "node",
      "args": ["/absolute/path/to/greynoise-mcp-server/build/index.js"],
      "env": { "GREYNOISE_API_KEY": "your-greynoise-api-key" }
    }
  }
}
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GREYNOISE_API_KEY` | yes (stdio) | — | GreyNoise API key. For HTTP transport the key is taken per-request from the `Authorization: Bearer` header instead. |
| `GREYNOISE_API_BASE` | no | `https://api.greynoise.io/` | Override the API base (e.g. staging). |
| `PORT` | no | `9191` | HTTP transport listen port. |
| `MCP_ALLOWED_HOSTS` | no | `127.0.0.1:<port>,localhost:<port>` | Allowed Host header values (DNS-rebinding protection) for HTTP transport. |

## Transports

```bash
npx @greynoise/greynoise-mcp-server                      # stdio (default)
npx @greynoise/greynoise-mcp-server --transport http     # streamable HTTP on $PORT
```

stdio is the default and what desktop/CLI clients use. HTTP transport authenticates each request via a `Bearer` token, builds an isolated server per request, and enforces DNS-rebinding protection. Express is loaded lazily for HTTP; install it if you use that transport (`npm install express`).

## Capabilities

Every tool returns both human-readable text and machine-readable `structuredContent` (validated against a published `outputSchema`), and carries MCP annotations so clients can apply safety policy — read-only tools run freely; write tools are marked, and destructive ones (`delete-*`) request confirmation.

### IP analysis

| Tool | Description |
|---|---|
| `lookup-ip-context` | Full context for one IP: classification, tags, ISI (scan/HTTP/TLS/SSH/TCP raw data), BSI, geo, network metadata. |
| `quick-check-ip` | Fast, lightweight classification + business-service check for one IP. |
| `multi-ip-check` | Check up to 10,000 IPs at once, with a summary breakdown. |

### GNQL (GreyNoise Query Language)

| Tool | Description |
|---|---|
| `gnql-query` | Full GNQL search including raw scan data; scroll pagination. |
| `gnql-metadata-query` | Lighter GNQL search (metadata only). Supports `format: "csv"` for spreadsheet output. |
| `gnql-stats` | Aggregate statistics for a GNQL query (top orgs, countries, tags, ASNs, classifications, …). |

### Recall (temporal analysis)

| Tool | Description |
|---|---|
| `gnql-timeseries` | Hourly IP-activity records for a query over a time range. |
| `gnql-timeseries-stats` | Unique-IP counts per hour/day over a time range. |

### Tags

| Tool | Description |
|---|---|
| `get-tag-list` | Complete tag list (cached 1h). |
| `search-tags` | Search tags by query / category / intention / CVE. |
| `get-tag-details` | Full record for one tag by id or slug. |
| `get-tag-activity` | Time-series activity for a tag or CVE. |
| `analyze-tags-activity` | Filter tags and aggregate their activity into a summary. |

### Vulnerabilities

| Tool | Description |
|---|---|
| `get-cve-details` | GreyNoise intel for one CVE: CVSS/EPSS, KEV status, exploitation + observed activity. |
| `get-trending-vulnerabilities` | Currently trending and anomalous vulnerability tags. |

### Sessions (sensor network data)

| Tool | Description |
|---|---|
| `search-sessions` | Query/filter sensor sessions over a time range (Lucene syntax). |
| `session-fields` | Discover the queryable session field schema. |
| `session-counts` | Session counts grouped by one or more fields (nested drill-down). |
| `session-connections` | Connection graph (nodes + links) between source/destination fields. |
| `session-timeseries` | Session volume over time, optionally grouped by a field. |
| `session-unique-values` | Distinct values of a field, optionally with counts. |
| `get-session` | Full metadata for one session by ID. |
| `get-session-pcap` | Download one session's PCAP to a temp file. |
| `export-sessions-pcap` | Export a PCAP across multiple sessions matching a query. |
| `export-session-data` | Download one session as PCAP or raw payload. |

### BSI — Business Service Intelligence *(requires BSI license)*

| Tool | Description |
|---|---|
| `bsi-lookup` | Provider matches for one IPv4. |
| `bsi-bulk-lookup` | Provider matches for up to 1,000 IPv4 addresses. |
| `bsi-trust-stats` / `bsi-company-stats` / `bsi-category-stats` | IP/CIDR counts grouped by trust level / company / category. |

### Callback / C2 *(requires entitlement)*

| Tool | Description |
|---|---|
| `callback-ip-lookup` | One callback/C2 IP: attack stage, RIOT status, enrichment, downloaded files. |
| `list-callback-ips` | Paginated callback IPs filtered by stage, dates, file attributes, scanners. |
| `export-callback-ips` | Export matching callback IPs as a plain list. |
| `callback-overview` | Aggregate statistics for matching callback IPs. |

### Operational — Blocklists *(write; requires entitlement)*

| Tool | Notes |
|---|---|
| `create-blocklist` | Create a dynamic blocklist from a GNQL query. |
| `list-blocklists` / `get-blocklist` / `get-blocklist-ips` | Read. |
| `update-blocklist` | Update query/name/limit/enabled. |
| `delete-blocklist` | **Destructive** — clients confirm. |

### Operational — Alerts *(write; requires entitlement)*

| Tool | Notes |
|---|---|
| `create-alert` | Scheduled GNQL alert with email/webhook recipients. |
| `list-alerts` / `get-alert` | Read. |
| `update-alert` | Update query/schedule/recipients/name/enabled. |
| `enable-alert` / `disable-alert` | Resume / pause. |
| `delete-alert` | **Destructive** — clients confirm. |
| `test-alert-webhook` | Send a test payload to a webhook URL. |

## Resources

Read-only URIs clients can fetch or reference directly:

| Resource | Description |
|---|---|
| `greynoise://ip/{ip}` | IP context (JSON). |
| `greynoise://cve/{cveId}` | CVE exploitation details (JSON). |
| `greynoise://tag/{slug}` | Tag metadata by slug (with slug autocompletion). |
| `greynoise://article/{id}` | A single GreyNoise research article. |
| `greynoise://articles` | List of published research articles. |
| `greynoise://article-categories` | Article categories. |

## Prompts

Guided analysis workflows:

| Prompt | Arguments (`*` = required) |
|---|---|
| `ip-threat-analysis` | `ip*`, `include_related` |
| `cve-analysis` | `cve_id*`, `timeframe` |
| `vendor-threat-report` | `vendor*`, `technology`, `timeframe*` |
| `emerging-threat-report` | `days`, `focus_area` |
| `security-posture-assessment` | `organization*`, `technologies*`, `industry` |
| `threat-hunting` | `indicator_type*`, `indicator_value*`, `environment*` |

## Development

```bash
npm install
npm run build        # bundle with tsup -> build/index.js
npm run dev          # watch + rebuild + run
npm test             # jest
npm run typecheck    # tsc --noEmit
npm run pack:mcpb    # build the .mcpb bundle
```

The zod schemas in `src/greynoise/schemas/` are the single source of truth for API response shapes (they validate responses at runtime and drive each tool's `outputSchema`). A vendored copy of the API's OpenAPI spec lives in `spec/oas-production.yaml`; run the `/update-api` reconciliation to check tools/schemas against it.

## Releasing

Releases are automated via GitHub Actions, with a manual approval gate. Two workflows:

- **`.github/workflows/ci.yml`** — runs on every PR/push: typecheck, tests, build, `npm audit`, and a `.mcpb` build. No credentials required.
- **`.github/workflows/release.yml`** — runs on a `v*` tag: publishes to npm via **staged publishing** and drafts a GitHub Release with the `.mcpb`. Nothing goes public without a human.

### Prerequisites (one-time, already configured)

- **npm Trusted Publisher (OIDC)** — configured on npmjs.com for this repo + `release.yml` with **`npm stage publish`** (stage-only) permission. No `NPM_TOKEN` is stored; auth is tokenless via GitHub OIDC.
- The workflow has `id-token: write` and `contents: write`, and upgrades npm to satisfy staged publishing (npm ≥ 11.15.0, Node ≥ 22.14).

### Cutting a release

Push a version tag — that's the whole release. The **git tag is the single source of truth**: the workflow stamps it into `package.json` + `manifest.json` (and the User-Agent) at build time, so there's nothing to bump or keep in sync by hand.

```bash
git tag v0.5.1 && git push origin v0.5.1
```

The tag triggers `release.yml`, which **stages** that version to npm and creates a **draft** GitHub Release. Neither is public yet.

### Approving (the manual gate)

Staged publishes require a maintainer with 2FA — they can't be approved from CI (by design):

```bash
npm stage list @greynoise/greynoise-mcp-server   # find the stage-id
npm stage view <stage-id>                         # (optional) inspect
npm stage approve <stage-id>                       # 2FA -> version goes live
```

(Or approve from the package page on npmjs.com.) Then publish the draft GitHub Release from the Releases tab to make the `.mcpb` public.

## Changelog

See [NEWS.md](NEWS.md).
