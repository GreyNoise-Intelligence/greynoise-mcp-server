# MCP Server For GreyNoise

**REQUIRES AN ENTERPRISE API KEY**

## Installation

### MCPB (MCP Bundle)

If you use Claude Desktop or another client that supports MCPB bundles, download `greynoise-mcp-server.mcpb` from the [releases page](https://github.com/GreyNoise-Intelligence/greynoise-mcp-server/releases) and double-click to install.

### For Production/NPX Usage
```bash
npx @greynoise/greynoise-mcp-server --help
```

Sample entry for Claude Desktop:

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "npx",
      "args": ["@greynoise/greynoise-mcp-server"],
      "env": {
        "GREYNOISE_API_KEY": "your-greynoise-api-key"
      }
    }
  }
}
```

Or for local development:

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "node",
      "args": ["/absolute/path/to/greynoise-mcp-server/build/index.js"],
      "env": {
        "GREYNOISE_API_KEY": "your-greynoise-api-key"
      }
    }
  }
}
```

### For Development

Clone the repo and then `npm install && npm run build`.

## Build System

This project uses `tsup` for modern bundling:

- **`npm run build`**: Creates optimized bundle for distribution
- **`npm run build:dev`**: Development build with source maps
- **`npm run dev`**: Watch mode with auto-rebuild

The bundled output includes all core dependencies except Express (kept external for the optional HTTP transport).

## Releasing

Releases are automated via GitHub Actions, with a manual approval gate. There are two workflows:

- **`.github/workflows/ci.yml`** — runs on every PR/push: typecheck, tests, build, `npm audit`, and a `.mcpb` build. No credentials required.
- **`.github/workflows/release.yml`** — runs on a `v*` tag: publishes to npm via **staged publishing** and drafts a GitHub Release with the `.mcpb`. Nothing goes public without a human.

### Prerequisites (one-time, already configured)

- **npm Trusted Publisher (OIDC)** — configured on npmjs.com for this repo + `release.yml` with **`npm stage publish`** (stage-only) permission. No `NPM_TOKEN` secret is stored; auth is tokenless via GitHub OIDC.
- The workflow has `id-token: write` (OIDC) and `contents: write` (GitHub Release) permissions and upgrades npm to satisfy staged-publishing requirements (npm ≥ 11.15.0, Node ≥ 22.14).

### Cutting a release

1. Merge your work to `main`.
2. Bump the version (single source of truth is `package.json`; the `version` script keeps `manifest.json` in sync, and the User-Agent is injected from it at build time):
   ```bash
   npm version minor        # or patch / major — creates the commit + vX.Y.Z tag
   git push --follow-tags
   ```
   The tag must match `package.json`; the workflow fails otherwise.
3. The tag triggers `release.yml`, which **stages** the version to npm and creates a **draft** GitHub Release. Neither is public yet.

### Approving (the manual gate)

Staged publishes require a maintainer with 2FA — they can't be approved from CI (by design). After the workflow succeeds:

```bash
npm stage list @greynoise/greynoise-mcp-server   # find the stage-id
npm stage view <stage-id>                         # (optional) inspect it
npm stage approve <stage-id>                       # 2FA prompt → version goes live on npm
```

(You can also approve from the package page on npmjs.com.) Then publish the draft GitHub Release from the repo's Releases tab when you're ready to make the `.mcpb` public.

## Transport Options

### stdio (Default)
```bash
npx @greynoise/greynoise-mcp-server --transport stdio
```

### http
HTTP transport requires Express to be available:
```bash
npm install express
node @greynoise/greynoise-mcp-server --transport http
```

## Available Tools

### IP Analysis

1. **lookup-ip-context** - Get detailed context for an IP address including Internet Scanner Intelligence (ISI) and Business Service Intelligence (BSI). Returns classification, tags, scanning activity, HTTP/TLS/SSH fingerprints, geographic info, and more.

2. **quick-check-ip** - Fast, lightweight check returning just classification and BSI status.

3. **multi-ip-check** - Check up to 10,000 IP addresses at once. Returns classification, BSI status, and trust level for each IP.

### GNQL (GreyNoise Query Language)

4. **gnql-query** - Search GreyNoise data with GNQL. Returns full IP context results including raw scan data. Supports scroll pagination.

5. **gnql-metadata-query** - Lightweight GNQL search returning IP metadata without raw scan data. Supports CSV output format.

6. **gnql-stats** - Get aggregate statistics for GNQL query results (classification breakdown, top organizations, countries, tags, etc).

### Recall (Temporal Analysis)

7. **gnql-timeseries** - Retrieve hourly IP activity records for a time range. Enables temporal analysis of scanning patterns.

8. **gnql-timeseries-stats** - Get unique IP counts per hour/day over a time range for trend analysis.

### Tags

9. **get-tag-list** - Retrieve the complete list of GreyNoise tags with metadata.

10. **search-tags** - Search for tags matching a query.

11. **get-tag-details** - Get comprehensive metadata about a specific tag.

12. **get-tag-activity** - Get activity data for a tag including trends over time.

13. **analyze-tags-activity** - Analyze activity patterns across multiple tags.

### Vulnerabilities

14. **get-trending-vulnerabilities** - Get vulnerabilities actively being exploited in the wild.

15. **get-cve-details** - Get detailed CVE information including GreyNoise exploitation observations.

### Sessions (PCAP)

16. **get-session** - Get full metadata and connection details for a single sensor session by ID.

17. **get-session-pcap** - Download the raw PCAP capture for a single session. Saves to a temporary file and returns the path.

18. **export-sessions-pcap** - Export a PCAP file containing packets from multiple sessions matching a time range and optional Lucene query. Saves to a temporary file and returns the path.

## Usage Examples

### IP Analysis

```javascript
// Get detailed context for an IP
{ "tool_name": "lookup-ip-context", "parameters": { "ip": "71.6.135.131" } }

// Quick check
{ "tool_name": "quick-check-ip", "parameters": { "ip": "8.8.8.8" } }

// Bulk check
{ "tool_name": "multi-ip-check", "parameters": { "ips": ["8.8.8.8", "1.1.1.1"] } }
```

### GNQL Queries

```javascript
// Search for malicious IPs seen today
{ "tool_name": "gnql-query", "parameters": { "query": "classification:malicious last_seen:1d", "size": 10 } }

// Lightweight metadata search
{ "tool_name": "gnql-metadata-query", "parameters": { "query": "tags:Mirai", "size": 25 } }

// Get stats for a query
{ "tool_name": "gnql-stats", "parameters": { "query": "classification:malicious", "count": 10 } }
```

### Temporal Analysis (Recall)

```javascript
// Hourly activity for an IP
{ "tool_name": "gnql-timeseries", "parameters": { "query": "ip:71.6.135.131" } }

// Daily unique IP counts for malicious activity
{ "tool_name": "gnql-timeseries-stats", "parameters": { "query": "classification:malicious", "interval": "day" } }
```

### Sessions

```javascript
// Get session metadata
{ "tool_name": "get-session", "parameters": { "session_id": "7e98a36cf76f29a020876691892c5f" } }

// Download session PCAP
{ "tool_name": "get-session-pcap", "parameters": { "session_id": "7e98a36cf76f29a020876691892c5f" } }

// Export PCAPs for sessions matching a query
{ "tool_name": "export-sessions-pcap", "parameters": { "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-07T23:59:59Z", "query": "destination.port:443", "size": 50 } }
```

## Available Prompts

1. **vendor-threat-report** - Comprehensive threat report for a vendor technology.
   Parameters: vendor (required), technology (optional), timeframe 1-90 days (required)

2. **ip-threat-analysis** - Detailed IP threat analysis with classification, tags, history, and recommendations.
   Parameters: ip (required), include_related (optional)

3. **cve-analysis** - CVE analysis including exploitation status and risk assessment.
   Parameters: cve_id (required), timeframe 1-90 days (optional)

4. **emerging-threat-report** - Report on emerging threats based on trending activity.
   Parameters: days (optional: 1/7/30), focus_area (optional)

5. **security-posture-assessment** - Security posture assessment for an organization's technology stack.
   Parameters: organization (required), technologies (required), industry (optional)

6. **threat-hunting** - Threat hunting plan for specific indicators or patterns.
   Parameters: indicator_type (required: ip/tag/behavior/actor/cve), indicator_value (required), environment (required)

## Changelog

See [NEWS.md](NEWS.md) for release notes.
