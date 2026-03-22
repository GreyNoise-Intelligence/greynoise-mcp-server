---
title: "feat: Migrate to GreyNoise v3 API endpoints"
type: feat
status: completed
date: 2026-03-22
origin: docs/brainstorms/2026-03-22-v3-api-migration-brainstorm.md
---

# feat: Migrate to GreyNoise v3 API Endpoints

## Overview

Comprehensive migration of greynoise-mcp-server from v2 to v3 GreyNoise API endpoints. This includes updating 3 existing IP tools, retiring 1 tool, adding 4 new GNQL tools, rewriting TypeScript types for the restructured v3 response format, and updating all Markdown formatters.

## Problem Statement / Motivation

The GreyNoise API is moving to v3 with significant improvements:
- Unified IP response combining scanner intelligence and business service intelligence (RIOT)
- Richer tag metadata (objects instead of plain strings)
- New raw_data sections (HTTP details, TLS/JA4, SSH/JA4SSH, TCP/JA4T)
- New GNQL query and temporal recall endpoints
- Plan-aware responses with `request_metadata.restricted_fields`

The current server uses v2 endpoints and will eventually lose support. The v3 structure is also more useful to LLM consumers.

## Proposed Solution

Big-bang in-place migration (see brainstorm: `docs/brainstorms/2026-03-22-v3-api-migration-brainstorm.md`). Update all IP tools to v3, retire riot-lookup, add 4 new GNQL tools, rewrite types and formatters. Chosen over incremental approach because the codebase is small and a clean cut avoids v2/v3 tool confusion.

## Technical Approach

### Architecture

No architectural changes to the server itself. Same tool registration pattern, same fetch utilities, same transport support. Changes are confined to:
1. Type definitions (response interfaces)
2. Tool files (endpoint URLs, response handling)
3. Formatters (Markdown output for new response shapes)
4. Registration (add/remove tools, update server instructions)

### LLM Context Management Strategy

GNQL query and timeseries endpoints can return thousands of records. To prevent LLM context window overrun, all multi-result tools use a **summary + small page** pattern:

1. **Small default page sizes**: `size` defaults to 25 (not 10000). The LLM must explicitly request larger pages or scroll for more.
2. **Summary header on every response**: Before detailed results, include a summary block:
   - Total result count
   - Classification breakdown (malicious/benign/unknown counts)
   - Top 5 tags, organizations, countries
   - Whether more results are available (complete: true/false)
3. **Detailed results follow the summary**: First N results rendered in compact format.
4. **Scroll token at the end**: When `complete === false`, include the scroll token and a note like "Pass scroll token to retrieve next page."

This applies to: `gnql-query`, `gnql-metadata-query`, `gnql-timeseries`, `gnql-timeseries-stats`.

For `multi-ip-check`, the 10,000 IP max is an API limit but formatter should still cap detailed output (e.g., first 50 IPs in table, remainder summarized as counts).

For `lookup-ip-context` (single IP), raw_data sections with large arrays (HTTP paths, user agents) should truncate with "and N more" after 10-20 items.

### Implementation Phases

#### Phase 1: Types and Interfaces

Rewrite `src/types/greynoise-response.ts` to define v3 response shapes.

**Tasks:**

- [x] Add `BusinessServiceIntelligence` interface (`src/types/greynoise-response.ts`)
  ```typescript
  interface BusinessServiceIntelligence {
    found: boolean;
    category?: string;
    name?: string;
    description?: string;
    explanation?: string;
    last_updated?: string;
    reference?: string;
    trust_level?: string;
  }
  ```

- [x] Add `InternetScannerTag` interface (rich tag object, replacing `string[]`)
  ```typescript
  interface InternetScannerTag {
    id: string;
    slug: string;
    name: string;
    category: string;
    intention: string;  // "malicious" | "suspicious" | "benign" | "unknown"
    description: string;
    references: string[];
    recommend_block: boolean;
    cves: string[];
    created_at: string;
    updated_at: string;
  }
  ```
  Note: The existing `GreyNoiseTag` (line 4) has a `label` field not present in v3 IP-embedded tags. Keep `GreyNoiseTag` for standalone tag endpoints; `InternetScannerTag` is for IP-embedded tags.

- [x] Add `InternetScannerMetadata` interface with v3 fields
  New fields vs v2: `mobile`, `source_city` (replaces `city`), `destination_cities`, `destination_asns`, `single_destination`, `carrier`, `datacenter`, `domain`, `rdns_parent`, `rdns_validated`, `latitude`, `longitude`.
  Removed: `city`, `country`, `country_code`, `tor` (moved up a level).

- [x] Add `RawDataHttp`, `RawDataTls`, `RawDataSsh`, `RawDataTcp`, `RawDataSource` interfaces for new raw_data sections

- [x] Add `InternetScannerIntelligence` interface wrapping ISI fields
  Top-level fields: `ip`, `seen`, `classification`, `first_seen`, `last_seen`, `last_seen_timestamp`, `found`, `actor`, `bot`, `spoofable`, `cves` (was `cve`), `tor` (moved from metadata), `vpn`, `vpn_service`, `metadata`, `tags` (InternetScannerTag[]), `raw_data`

- [x] Add `V3RequestMetadata` interface: `{ restricted_fields?: string[] }`

- [x] Rewrite `IPContextResponse` to v3 shape:
  ```typescript
  interface IPContextResponse {
    ip: string;
    business_service_intelligence: BusinessServiceIntelligence;
    internet_scanner_intelligence: InternetScannerIntelligence;
    request_metadata?: V3RequestMetadata;
  }
  ```

- [x] Add `IPQuickCheckV3Response` for `?quick=true`:
  ```typescript
  interface IPQuickCheckV3Response {
    ip: string;
    business_service_intelligence: { found: boolean; trust_level?: string };
    internet_scanner_intelligence: { found: boolean; classification?: string };
  }
  ```

- [x] Add `MultiIPV3Response` for POST /v3/ip:
  ```typescript
  interface MultiIPV3Response {
    data: IPContextResponse[];
    request_metadata: V3RequestMetadata & {
      message?: string;
      ips_not_found?: string[];
    };
  }
  ```

- [x] Add `GnqlQueryResponse` for GET /v3/gnql:
  ```typescript
  interface GnqlQueryResponse {
    data: IPContextResponse[];
    request_metadata: {
      complete: boolean;
      scroll?: string;
      query: string;
      adjusted_query?: string;
      restricted_fields?: string[];
      message?: string;
    };
  }
  ```

- [x] Add `GnqlMetadataQueryResponse` for GET /v3/gnql/metadata (same shape as GnqlQueryResponse but results lack raw_data)

- [x] Add `GnqlTimeseriesResponse` for GET /v3/gnql/timeseries:
  ```typescript
  interface GnqlTimeseriesResponse {
    data: Array<{
      timestamp: string;
      ip: string;
      count?: number;
      classification?: string;
    }>;
    request_metadata: {
      complete: boolean;
      scroll?: string;
      query: string;
      adjusted_query?: string;
    };
  }
  ```

- [x] Add `GnqlTimeseriesStatsResponse` for GET /v3/gnql/timeseries/stats (unique IP counts per time bucket)

- [x] Remove `RIOTLookupResponse` interface (riot-lookup being retired)
- [x] Remove old `IPQuickCheckResponse` and `MultiIPQuickCheckResponse` interfaces

#### Phase 2: Formatters

Update `src/utils/formatters.ts` for v3 response shapes.

**Tasks:**

- [x] Rewrite `formatIPContext()` for nested v3 structure (`src/utils/formatters.ts:316`)
  - Access fields via `data.internet_scanner_intelligence.*` and `data.business_service_intelligence.*`
  - Add **Business Service Intelligence** section when `bsi.found === true` (name, category, description, trust_level, reference)
  - Update **Location**: `metadata.source_city` (was `city`), `metadata.source_country` (was `country`), add `latitude`/`longitude` if present
  - `tor` now at `internet_scanner_intelligence.tor` (was `metadata.tor`)
  - `cves` (was `cve`)
  - Add `mobile`, `carrier`, `datacenter`, `domain`, `rdns_parent` to Organization Details where present

- [x] Update tag formatting in `formatIPContext()`
  Tags are now `InternetScannerTag[]`. Render as compact list: `name (intention)` per tag. Example: `Mirai (malicious), Shodan (benign)`. Do not expand all 10 fields per tag -- that would produce walls of text. Reference `get-tag-details` for full metadata.

- [x] Add raw_data sections to `formatIPContext()`
  - **HTTP Activity**: paths, user agents, methods (truncated with "and N more" for large arrays)
  - **TLS/SSL**: JA3 fingerprints (existing), JA4 fingerprints (new), cipher
  - **SSH**: HASSH fingerprints (existing), JA4SSH (new), keys
  - **TCP**: JA4T, JA4L fingerprints
  - **Source**: bytes count

- [x] Add `restricted_fields` info note to `formatIPContext()`
  When `data.request_metadata?.restricted_fields` is non-empty, append:
  ```
  ---
  **Note:** Some fields are restricted by your API plan: [field1, field2, ...]
  ```

- [x] Add `formatGnqlQueryResults()` formatter
  **Summary header first**: total count, classification breakdown, top 5 tags/orgs/countries from the page. Then render each IP result compactly: IP, classification, BSI status, key ISI metadata (actor, tags as names, top ports). End with pagination info: `complete` status, `scroll` token if more results available.

- [x] Add `formatGnqlTimeseries()` formatter
  Renders time-bucketed data as a table or list. Include pagination metadata.

- [x] Add `formatGnqlTimeseriesStats()` formatter
  Renders unique IP counts per time bucket.

- [x] Add `formatQuickCheckV3()` formatter for v3 quick check response
  Show BSI found/trust_level and ISI found/classification in a compact format.

- [x] Add `formatMultiIPV3()` formatter for v3 multi-IP response
  Summary counts first (total, by classification, BSI matches). Then Markdown table (first 50 IPs) with columns: IP, Classification, BSI Found, Trust Level. If >50, summarize remainder. Include `ips_not_found` list if present.

- [x] Remove unused `formatGnqlStatsResponse()` function (defined at line 136, never called anywhere)

#### Phase 3: Migrate Existing IP Tools

**Tasks:**

- [x] Update `lookup-ip-context.ts`
  - Change endpoint from `v2/noise/context/${ip}` to `v3/ip/${ip}` (line 28)
  - Response type stays `IPContextResponse` (but the interface shape changes in Phase 1)
  - Formatter call stays `formatIPContext(contextData)` (but the function changes in Phase 2)

- [x] Update `quick-check-ip.ts`
  - Change endpoint from `v2/noise/quick/${ip}` to `v3/ip/${ip}` with `params: { quick: "true" }` (line 27)
  - Change response type from `IPQuickCheckResponse` to `IPQuickCheckV3Response`
  - Replace inline formatting (lines 33-58) with `formatQuickCheckV3()` call
  - Remove emoji usage (lines 33, 38, 40, 47, 49)

- [x] Update `multi-ip-check.ts`
  - Change endpoint from `v2/noise/multi/quick` to `v3/ip` (line 30)
  - Change response type from `MultiIPQuickCheckResponse` to `MultiIPV3Response`
  - Update max from 100 to 10000 per v3 docs (line 13: `.max(100)` -> `.max(10000)`)
  - Replace inline formatting (lines 37-57) with `formatMultiIPV3()` call
  - Response is now `{ data: [...], request_metadata: {...} }` not a bare array -- iterate `multiCheckData.data`
  - Surface `request_metadata.ips_not_found` if present

- [x] Remove `riot-lookup.ts`
  - Delete `src/tools/riot-lookup.ts`
  - Remove `export * from './riot-lookup.js'` from `src/tools/index.ts`
  - Remove `registerRiotLookupTool` import and call from `src/index.ts` (lines 59, 161)

#### Phase 4: Add New GNQL Tools

All new tools follow the established pattern: export `register*Tool(server, apiBase, apiKeyGetter)`, use `server.tool()` with Zod schema, resolve API key with try/catch IIFE, call `fetchGreyNoise`, format response, return `{ content: [{ type: "text", text }] }`.

**Tasks:**

- [x] Create `src/tools/gnql-query.ts` -- `registerGnqlQueryTool`
  - Tool name: `gnql-query`
  - Description: "Search GreyNoise data using GNQL (GreyNoise Query Language). Returns full IP context results including raw scan data."
  - Include GNQL facet documentation in description (copy from gnql-stats.ts lines 11-84, the existing GNQL docs)
  - Endpoint: `GET v3/gnql`
  - Params: `query` (required string), `size` (optional number, 1-10000, default 25), `scroll` (optional string for pagination)
  - Response type: `GnqlQueryResponse`
  - Format with `formatGnqlQueryResults()`
  - Include scroll token in output when `request_metadata.complete === false`

- [x] Create `src/tools/gnql-metadata-query.ts` -- `registerGnqlMetadataQueryTool`
  - Tool name: `gnql-metadata-query`
  - Description: "Search GreyNoise data using GNQL, returning IP metadata without raw scan data. Lighter and faster than gnql-query."
  - Endpoint: `GET v3/gnql/metadata`
  - Params: `query` (required), `size` (optional, 1-10000, default 25), `scroll` (optional), `quick` (optional boolean), `format` (optional enum: "json" | "csv")
  - Response type: `GnqlMetadataQueryResponse`
  - For CSV format, return raw CSV text. For JSON, format with `formatGnqlQueryResults()`

- [x] Create `src/tools/gnql-timeseries.ts` -- `registerGnqlTimeseriesTool`
  - Tool name: `gnql-timeseries`
  - Description: "Retrieve hourly GNQL records for a time range. Enables temporal analysis of IP activity matching any GNQL query (Recall)."
  - Endpoint: `GET v3/gnql/timeseries`
  - Params: `query` (required), `start_time` (optional string, ISO 8601), `end_time` (optional), `granularity` (optional string), `size` (optional number), `scroll` (optional string)
  - Response type: `GnqlTimeseriesResponse`
  - Format with `formatGnqlTimeseries()`

- [x] Create `src/tools/gnql-timeseries-stats.ts` -- `registerGnqlTimeseriesStatsTool`
  - Tool name: `gnql-timeseries-stats`
  - Description: "Get the number of unique IPs matching a GNQL query per hour/day over a time range (Recall Stats)."
  - Endpoint: `GET v3/gnql/timeseries/stats`
  - Params: `query` (required), `granularity` (optional string), `start_time` (optional), `end_time` (optional)
  - Response type: `GnqlTimeseriesStatsResponse`
  - Format with `formatGnqlTimeseriesStats()`

#### Phase 5: Registration and Wiring

**Tasks:**

- [x] Update `src/tools/index.ts` barrel exports
  - Remove: `export * from './riot-lookup.js'`
  - Add: `export * from './gnql-query.js'`
  - Add: `export * from './gnql-metadata-query.js'`
  - Add: `export * from './gnql-timeseries.js'`
  - Add: `export * from './gnql-timeseries-stats.js'`

- [x] Update `src/index.ts` imports and registration
  - Remove `registerRiotLookupTool` from import (line 59) and registration (line 161)
  - Add imports for 4 new register functions
  - Add 4 registration calls with `(server, GREYNOISE_API_BASE, getStaticApiKey)`

- [x] Update server `instructions` string (`src/index.ts:132-140`)
  - Remove "RIOT business service lookups" reference
  - Add: "Business Service Intelligence (BSI) is included in IP lookup responses"
  - Add: "GNQL querying for searching the GreyNoise dataset with full or metadata-only results"
  - Add: "Recall/timeseries analysis for temporal IP activity patterns"

#### Phase 6: Cleanup and Verification

**Tasks:**

- [x] Remove `RIOTLookupResponse`, `IPQuickCheckResponse`, `MultiIPQuickCheckResponse` from types file
- [x] Remove `formatGnqlStatsResponse()` dead code from formatters (line 136-197, never called)
- [x] Build the project: `npm run build`
- [x] Verify no TypeScript errors
- [x] Test each tool manually against the v3 API:
  - `lookup-ip-context` with a known IP (e.g., 8.8.8.8)
  - `quick-check-ip` with same IP
  - `multi-ip-check` with 2-3 IPs
  - `gnql-query` with `classification:malicious last_seen:1d`
  - `gnql-metadata-query` with same query
  - `gnql-timeseries` with a simple query
  - `gnql-timeseries-stats` with same query
  - `gnql-stats` (unchanged, verify still works on v2)
- [x] Verify restricted_fields note appears when API plan limits fields (may need a test account)
- [x] Version bump in `package.json` -- this is a breaking change (riot-lookup removed, response shapes changed). Consider semver implications.
- [x] Update User-Agent version in `src/utils/fetch.ts` to match new version

## System-Wide Impact

### Interaction Graph

Tool call -> handler resolves API key (AsyncLocalStorage or static) -> `fetchGreyNoise`/`postToGreyNoise` -> GreyNoise API -> response parsed as new type -> formatter produces Markdown -> returned to MCP client.

No callbacks, middleware, or observers beyond the existing Express auth middleware for HTTP transport. The auth middleware (`checkAuthorization` in index.ts) is unaffected -- it passes through Bearer tokens as API keys.

### Error & Failure Propagation

- `fetchGreyNoise` throws on non-OK responses. HTTP 206 passes `response.ok` (2xx) and is handled normally.
- Each tool catches errors and returns `{ isError: true }` with error message. This pattern is unchanged.
- New consideration: v3 may return different error response bodies. The existing error handling (`error.message`) should still work since `fetchGreyNoise` throws with status + response text.

### State Lifecycle Risks

None. The server is stateless (no database, no persistent state beyond the 1-hour tag cache in `tag-cache.ts`, which is unaffected).

### API Surface Parity

- **Removed tool**: `riot-lookup` -- MCP clients referencing this tool will get "unknown tool" errors. This is a breaking change.
- **Changed response shapes**: Any MCP client that parses raw tool output text (unlikely but possible) will need to adapt to new Markdown format.
- **Prompts**: The prompts in `src/prompts/` reference `lookup-ip-context` by name. They don't reference `riot-lookup`. However, `ip-threat-analysis.ts` and `threat-hunting.ts` should be reviewed to ensure they guide the LLM to expect BSI data in the IP context response rather than calling a separate RIOT tool.

## Acceptance Criteria

### Functional Requirements

- [x] `lookup-ip-context` returns v3 response with BSI + ISI sections formatted as Markdown
- [x] `quick-check-ip` returns v3 quick response with BSI found/trust + ISI classification
- [x] `multi-ip-check` accepts up to 10,000 IPs and returns v3 structured results including ips_not_found
- [x] `gnql-query` searches GreyNoise with GNQL and returns paginated full results
- [x] `gnql-metadata-query` searches with GNQL and returns lightweight results (no raw_data)
- [x] `gnql-timeseries` returns temporal IP activity for a query and time range
- [x] `gnql-timeseries-stats` returns unique IP counts per time bucket
- [x] `gnql-stats` continues to work on v2 endpoint (no regression)
- [x] `riot-lookup` is fully removed (no registration, no exports, no types)
- [x] All tag, CVE, and trending vulnerability tools continue working (no regression)
- [x] Restricted fields from HTTP 206 responses are surfaced as info notes

### Non-Functional Requirements

- [x] Project builds without TypeScript errors
- [x] All new tools follow established registration pattern
- [x] Markdown output is readable and not excessively verbose (especially rich tags)
- [x] GNQL documentation is included in new tool descriptions for LLM guidance

## Dependencies & Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| v3 response shape differs from docs/sample | Types and formatters break | Test against real API early; use optional fields liberally |
| Tags sample shows object (singular) vs spec says array | Formatter breaks | Docs say array; treat sample as simplified; handle both defensively |
| riot-lookup removal breaks MCP clients | Client errors | Document as breaking change; major version bump |
| No existing tests | Regressions undetected | Manual testing against live API; consider adding snapshot tests post-migration |
| gnql-stats v2 endpoint deprecated later | Tool breaks | Out of scope; tracked as open question |

## Sources & References

### Origin

- **Brainstorm document:** [docs/brainstorms/2026-03-22-v3-api-migration-brainstorm.md](../brainstorms/2026-03-22-v3-api-migration-brainstorm.md)
  - Key decisions: big-bang migration, retire riot-lookup, keep quick-check-ip separate, expose scroll params, surface restricted_fields

### Internal References

- Tool registration pattern: `src/tools/lookup-ip-context.ts:8-56`
- Current types: `src/types/greynoise-response.ts:348-479`
- Current formatter: `src/utils/formatters.ts:316-394`
- Fetch utility: `src/utils/fetch.ts`
- Server instructions: `src/index.ts:132-140`
- Tool barrel exports: `src/tools/index.ts`

### External References

- v3 IP Lookup: https://docs.greynoise.io/reference/v3ip
- v3 Multi-IP: https://docs.greynoise.io/reference/v3multiip
- v3 GNQL Query: https://docs.greynoise.io/reference/gnqlv3query
- v3 GNQL Metadata: https://docs.greynoise.io/reference/gnqlv3metadataquery
- v3 GNQL Timeseries: https://docs.greynoise.io/reference/gnqltimeseries
- v3 GNQL Timeseries Stats: https://docs.greynoise.io/reference/gnqltimeseriesstats
- v2 GNQL Stats (staying): https://docs.greynoise.io/reference/gnqlstats-1
