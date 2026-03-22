# Brainstorm: GreyNoise v3 API Migration

**Date:** 2026-03-22
**Status:** Draft

## What We're Building

A comprehensive migration of the greynoise-mcp-server from v2 to v3 GreyNoise API endpoints, plus new tool additions. This covers:

1. **IP Lookup tools migration** -- `lookup-ip-context`, `quick-check-ip`, `multi-ip-check` all move to v3 endpoints with restructured response handling
2. **Retire `riot-lookup`** -- Business service intelligence (BSI) is now embedded in the v3 IP response
3. **New GNQL query tools** -- `gnql-query` (full, with raw_data) and `gnql-metadata-query` (lightweight, no raw_data)
4. **New Recall tools** -- `gnql-timeseries` and `gnql-timeseries-stats` for temporal analysis
5. **Migrate `gnql-stats`** -- Move from `v2/experimental/gnql/stats` to v3 if a v3 equivalent exists, otherwise keep on v2

## Why This Approach

**Big-bang in-place migration** chosen over incremental or phased approaches because:

- Codebase is small (~15 tool files, ~400 lines of types)
- Avoids v2/v3 tool confusion for MCP consumers
- Clean end state with no transitional cruft
- Natural to update types and formatters once rather than iterating

## Key Decisions

### 1. IP Lookup Endpoint Changes

| Tool | Current Endpoint | New Endpoint |
|------|-----------------|--------------|
| `lookup-ip-context` | `GET v2/noise/context/{ip}` | `GET v3/ip/{ip}` |
| `quick-check-ip` | `GET v2/noise/quick/{ip}` | `GET v3/ip/{ip}?quick=true` |
| `multi-ip-check` | POST v2 multi-IP | `POST v3/ip` |

### 2. Retire `riot-lookup`

The v3 IP response includes `business_service_intelligence` (the RIOT equivalent). No need for a separate tool. Remove `riot-lookup.ts`, its registration, and its barrel export.

### 3. Response Structure Overhaul

The v3 IP response is fundamentally restructured:

```
v2 (flat):
  ip, seen, classification, tags[], metadata.*, raw_data.*

v3 (nested):
  ip
  business_service_intelligence: { found, category, name, description, ... }
  internet_scanner_intelligence: { seen, classification, tags[{object}], metadata.*, raw_data.* }
  request_metadata: { restricted_fields }
```

Major field changes:
- **`tags`**: Was `string[]`, now array of objects with `id`, `slug`, `name`, `category`, `intention`, `description`, `references`, `recommend_block`, `cves`, timestamps
- **`cve`** renamed to **`cves`**
- **`tor`** moved from `metadata` to `internet_scanner_intelligence` top level
- **`metadata`** gains: `mobile`, `source_city` (was `city`), `destination_cities`, `destination_asns`, `single_destination`, `carrier`, `datacenter`, `domain`, `rdns_parent`, `rdns_validated`, `latitude`, `longitude`
- **`metadata`** loses: `city` (now `source_city`), `country`/`country_code` (now `source_country`/`source_country_code` only)
- **`raw_data`** gains: `http` (replaces `web`), `tls`, `ssh`, `tcp`, `source`

### 4. New GNQL Tools (Two Separate Tools)

**`gnql-query`** -- Full GNQL search
- Endpoint: `GET /v3/gnql`
- Params: `query` (required), `size`, `scroll`
- Returns full results including raw_data

**`gnql-metadata-query`** -- Lightweight GNQL search
- Endpoint: `GET /v3/gnql/metadata`
- Params: `query` (required), `size`, `scroll`, `quick`, `format`
- Returns results without raw_data, supports CSV format

### 5. New Recall Tools

**`gnql-timeseries`** -- Temporal IP activity
- Endpoint: `GET /v3/gnql/timeseries`
- Params: `query` (required), `start_time`, `end_time`, `granularity`, `size`, `scroll`
- Returns hourly GNQL records for time range analysis

**`gnql-timeseries-stats`** -- Temporal aggregation
- Endpoint: `GET /v3/gnql/timeseries/stats`
- Params: `query` (required), `granularity`, `start_time`, `end_time`
- Returns unique IP counts per hour/day over time range

### 6. Keep `quick-check-ip` Separate

Despite v3 consolidating quick check into a query param, keep it as a distinct MCP tool for clarity. It will call `GET v3/ip/{ip}?quick=true`.

### 7. `gnql-stats` Stays on v2 (For Now)

The stats endpoint (`v2/experimental/gnql/stats`) doesn't have a clear v3 replacement. Keep it on v2 unless a v3 equivalent is confirmed.

## Files Affected

### Types (`src/types/greynoise-response.ts`)
- Rewrite `IPContextResponse` to match v3 nested structure
- Add `BusinessServiceIntelligence` interface
- Update `InternetScannerIntelligence` with new fields
- Add `Tag` object interface (was just string)
- Add types for GNQL query responses, timeseries responses
- Add `RequestMetadata` interface

### Formatters (`src/utils/formatters.ts`)
- Rewrite `formatIPContext()` for nested v3 structure
- Add BSI section to formatted output
- Update tag formatting (objects instead of strings)
- Add new raw_data sections (http, tls, ssh, tcp, source)
- Add formatters for GNQL query results, timeseries data

### Tools
- **Modify**: `lookup-ip-context.ts`, `quick-check-ip.ts`, `multi-ip-check.ts`
- **Remove**: `riot-lookup.ts`
- **Add**: `gnql-query.ts`, `gnql-metadata-query.ts`, `gnql-timeseries.ts`, `gnql-timeseries-stats.ts`

### Registration (`src/index.ts`, `src/tools/index.ts`)
- Remove riot-lookup registration
- Add registrations for 4 new tools
- Update barrel exports

## Resolved Questions

1. **HTTP 206 handling** -- Yes, surface `request_metadata.restricted_fields` as an info note in formatted output so the user/LLM knows data is incomplete.

2. **Pagination for GNQL tools** -- Expose `scroll` as an optional parameter. Let the LLM/user manage pagination manually. Avoids runaway fetches and keeps tools simple.

## Open Questions

1. **gnql-stats v3** -- Need to confirm whether `v2/experimental/gnql/stats` has a v3 equivalent or if it stays on v2.
