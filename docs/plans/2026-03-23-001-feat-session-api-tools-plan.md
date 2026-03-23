---
title: "feat: Add Session API Tools (get-session, get-session-pcap, export-sessions-pcap)"
type: feat
status: completed
date: 2026-03-23
origin: docs/brainstorms/2026-03-23-session-tools-brainstorm.md
---

# feat: Add Session API Tools

## Overview

Add three new MCP tools for GreyNoise v3 Sessions API endpoints, enabling session metadata lookup and PCAP download capabilities. This is the first feature to introduce binary file downloads and disk I/O in the server.

## Proposed Solution

Follow existing tool patterns exactly. Add a new `fetchGreyNoiseBinary()` function for binary endpoints that streams response bodies to disk. Return file paths and metadata as text content to the LLM. (see brainstorm: docs/brainstorms/2026-03-23-session-tools-brainstorm.md)

## Technical Approach

### New Files

#### `src/tools/get-session.ts`

- Tool name: `"get-session"`
- Params: `session_id` (required string), `scope` (optional string, default "workspace")
- Endpoint: `GET /v3/sessions/{session_id}?scope={scope}`
- Uses existing `fetchGreyNoise<SessionResponse>()` (JSON endpoint)
- Formats via new `formatSession()` formatter
- Returns Markdown text content

#### `src/tools/get-session-pcap.ts`

- Tool name: `"get-session-pcap"`
- Params: `session_id` (required string), `scope` (optional string, default "workspace")
- Endpoint: `GET /v3/sessions/{session_id}/frames?scope={scope}`
- Uses new `fetchGreyNoiseBinary()` to stream PCAP to `os.tmpdir()/session-{session_id}.pcap`
- Returns text: file path, file size, session ID
- On empty response (0 bytes or just PCAP header): return informative "no frames" message, delete empty file
- On write error or partial download: delete temp file, return error

#### `src/tools/export-sessions-pcap.ts`

- Tool name: `"export-sessions-pcap"`
- Params:
  - `start_time` (required string, ISO 8601)
  - `end_time` (required string, ISO 8601)
  - `query` (optional string, Lucene query)
  - `size` (optional number, default 100)
  - `sort_by` (optional string, default "lastPacket")
  - `sort_desc` (optional boolean, default true — serialized to string "true"/"false" for URL)
  - `scope` (optional string, default "workspace")
- Endpoint: `GET /v3/sessions/export?start_time=...&end_time=...&...`
- Uses new `fetchGreyNoiseBinary()` to stream to `os.tmpdir()/sessions-export-{ISO-timestamp}.pcap`
- Returns text: file path, file size, query params echoed back
- Same empty/error handling as get-session-pcap

### Modified Files

#### `src/utils/fetch.ts` — Add `fetchGreyNoiseBinary()`

```typescript
export async function fetchGreyNoiseBinary(
  endpoint: string,
  GREYNOISE_API_BASE: string,
  GREYNOISE_API_KEY: string,
  outputPath: string,
  params: Record<string, string> = {},
): Promise<{ filePath: string; fileSize: number }>
```

Key implementation details:
- Same auth headers as `fetchGreyNoise` (`key` header, User-Agent)
- Set `Accept: application/vnd.tcpdump.pcap`
- **Check response status before reading body** — on non-2xx, read body as text for error message (prevents writing JSON error payload as .pcap)
- **Stream response to disk** using `response.body.pipe(fs.createWriteStream(outputPath))` to handle large PCAPs without exhausting heap memory
- Return `{ filePath, fileSize }` on success
- On any error after file is opened: `fs.unlink(outputPath)` before re-throwing (partial file cleanup)
- Query params appended to URL via `URLSearchParams`

#### `src/types/greynoise-response.ts` — Add `SessionResponse`

Based on the OpenAPI schema (Session object has `additionalProperties: true`):

```typescript
export interface SessionResponse {
  _id: string;
  firstPacket: string;
  lastPacket: string;
  "source.ip": string;
  "source.port": number;
  "destination.ip": string;
  "destination.port": number;
  "source.bytes": number;
  "source.packets": number;
  "destination.bytes": number;
  "destination.packets": number;
  classification?: string;
  [key: string]: any;  // dynamic additional fields
}
```

#### `src/utils/formatters.ts` — Add `formatSession()`

Extract known fields into structured Markdown:
- Session ID, timestamps (first/last packet)
- Source IP:port and destination IP:port
- Bytes/packets in each direction
- Classification
- Remaining dynamic fields listed at the end

#### `src/tools/index.ts` — Add barrel exports

```typescript
export * from './get-session.js';
export * from './get-session-pcap.js';
export * from './export-sessions-pcap.js';
```

#### `src/index.ts` — Register tools + update instructions

- Import three new `register*Tool` functions
- Call each with `(server, GREYNOISE_API_BASE, getStaticApiKey)`
- Add "Sessions" category to the `instructions` string

### Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Binary fetch strategy | Stream to disk | Avoids OOM on large PCAPs; node-fetch v3 body is a ReadableStream |
| Partial file cleanup | Delete on error | Corrupt PCAP at "success" path is worse than no file |
| Empty PCAP detection | Check file size <= 24 bytes | PCAP global header is 24 bytes; anything <= that means no packets |
| sort_desc schema type | `z.boolean().default(true)` | Natural for LLM callers; serialize to string for URL |
| scope parameter | Optional, default "workspace" | Exposed in schema; "demo" and "all" accepted but undocumented (see brainstorm) |
| session_id validation | `z.string().min(1)` | Let API validate format; session IDs are hex strings from our testing |
| File naming | `session-{id}.pcap`, `sessions-export-{timestamp}.pcap` | Predictable, findable in temp dir (see brainstorm) |
| PCAP tool response | File path + file size | No PCAP parsing; keep tool simple (see brainstorm) |

## Acceptance Criteria

- [x] `get-session` tool returns formatted Markdown for a valid session ID
- [x] `get-session-pcap` tool saves valid PCAP to temp dir and returns file path
- [x] `export-sessions-pcap` tool saves valid PCAP to temp dir and returns file path
- [x] All three tools handle 404/401/403/429 errors with `isError: true` responses
- [x] `fetchGreyNoiseBinary()` streams to disk (not buffered in memory)
- [x] Partial files are cleaned up on download failure
- [x] Empty PCAP responses produce informative "no data" message
- [x] All tools registered in `src/index.ts` and exported from `src/tools/index.ts`
- [x] Server `instructions` string updated to mention session tools
- [x] `npm run build` succeeds
- [ ] `npm test` passes (no test files exist in project)

## Implementation Order

1. Add `SessionResponse` type to `src/types/greynoise-response.ts`
2. Add `fetchGreyNoiseBinary()` to `src/utils/fetch.ts`
3. Add `formatSession()` to `src/utils/formatters.ts`
4. Create `src/tools/get-session.ts`
5. Create `src/tools/get-session-pcap.ts`
6. Create `src/tools/export-sessions-pcap.ts`
7. Wire up exports in `src/tools/index.ts`
8. Register tools and update instructions in `src/index.ts`
9. Build and test

## Sources

- **Origin brainstorm:** [docs/brainstorms/2026-03-23-session-tools-brainstorm.md](docs/brainstorms/2026-03-23-session-tools-brainstorm.md) — Key decisions: PCAP saved to temp dir, structured formatter for session metadata, scope defaults to workspace with undocumented demo/all
- **Existing tool pattern reference:** `src/tools/quick-check-ip.ts`, `src/tools/gnql-query.ts`
- **V3 migration plan:** `docs/plans/2026-03-22-001-feat-v3-api-migration-plan.md`
