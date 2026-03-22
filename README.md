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

The bundled output includes all core dependencies except Express (for HTTP transport) and dotenv (due to dynamic require limitations).

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
