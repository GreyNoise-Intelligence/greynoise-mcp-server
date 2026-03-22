# NEWS

## 2026-03-22 | v0.3.4

### Bug Fixes
- Fixed MCPB bundle crash in Claude Desktop: `esbuildOptions.packages = 'external'` was overriding tsup's `noExternal`, leaving MCP SDK, zod, and node-fetch as unresolvable external imports in the standalone bundle
- Removed `dotenv` dependency; `GREYNOISE_API_KEY` now read directly from `process.env`
- Bundle is now fully self-contained (1.2 MB) with only Node built-in externals

## 2026-03-22 | v0.3.2

### Breaking Changes
- Migrated all IP tools from v2 to v3 API endpoints
- Removed `riot-lookup` tool (Business Service Intelligence is now included in IP lookup responses)
- Response format changed for `lookup-ip-context`, `quick-check-ip`, and `multi-ip-check` (v3 nested structure)
- `multi-ip-check` now accepts up to 10,000 IPs (was 100)

### New Tools
- `gnql-query` - Full GNQL search with raw scan data and scroll pagination
- `gnql-metadata-query` - Lightweight GNQL search without raw data, supports CSV output
- `gnql-timeseries` - Hourly IP activity records for temporal analysis (Recall)
- `gnql-timeseries-stats` - Unique IP counts per hour/day over time (Recall Stats)

### Improvements
- IP context now includes Business Service Intelligence (BSI) alongside Internet Scanner Intelligence (ISI)
- Tags in IP responses are now rich objects with category, intention, CVEs, and block recommendations
- New raw data sections: HTTP activity, TLS/JA4, SSH/JA4SSH, TCP/JA4T fingerprints
- Restricted fields from plan limitations surfaced as info notes
- Default page size of 25 for GNQL tools to prevent LLM context overrun
- Summary headers on multi-result responses (classification breakdown, top tags/orgs/countries)
- Migrated from DXT to MCPB bundle format

## 2025-10-07 | v0.2.4

- Added `SECURITY.md`
- Re-ran `npm audit fix`
- Re-built DXT


## 2025-09-18 | v0.2.3

- Fixes #2


## 2025-09-17 | v0.2.2

- Initial release
