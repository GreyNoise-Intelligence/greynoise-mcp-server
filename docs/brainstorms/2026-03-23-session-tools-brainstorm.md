# Brainstorm: GreyNoise Session API Tools

**Date:** 2026-03-23
**Status:** Ready for planning

## What We're Building

Three new MCP tools for the GreyNoise v3 Sessions API:

1. **`get-session`** — Retrieve session metadata by ID (`GET /v3/sessions/{session_id}`)
2. **`get-session-pcap`** — Download PCAP for a single session (`GET /v3/sessions/{session_id}/frames`)
3. **`export-sessions-pcap`** — Export PCAP for multiple sessions matching a query (`GET /v3/sessions/export`)

These extend the MCP server's capabilities from IP/tag/CVE analysis into raw network session data captured by GreyNoise sensors.

## Why This Approach

The session endpoints provide deep-dive forensic capability — actual packet captures from GreyNoise sensors. Combined with existing IP context and GNQL tools, users can go from "this IP is malicious" to "here's exactly what traffic it generated."

## Key Decisions

### Binary PCAP handling
PCAP endpoints return binary data that LLMs can't interpret. **Decision: Save to file, return path.** PCAPs are saved to the OS temp directory with predictable names (`session-{id}.pcap`, `sessions-export-{timestamp}.pcap`). The tool returns the file path plus metadata (file size, session ID). Downstream tools or the user can then open with Wireshark/tshark.

### Session metadata formatting
The `get-session` endpoint returns a dynamic JSON schema (`additionalProperties: true`). **Decision: Structured formatter.** Extract known fields (source/dest IPs, ports, timestamps, classification, bytes/packets) into readable Markdown. Append any additional dynamic fields. Consistent with existing tool formatting patterns.

### Scope parameter
**Decision: Default to "workspace".** The `scope` query parameter is exposed as optional, defaulting to `"workspace"`. Values `"demo"` and `"all"` are accepted but undocumented in tool descriptions.

### File save location
**Decision: OS temp directory.** Use `os.tmpdir()` for PCAP file output. No configuration needed. Predictable naming convention.

## Implementation Notes

### Files to create
- `src/tools/get-session.ts` — Session metadata lookup
- `src/tools/get-session-pcap.ts` — Single session PCAP download
- `src/tools/export-sessions-pcap.ts` — Multi-session PCAP export

### Files to modify
- `src/tools/index.ts` — Export new registration functions
- `src/index.ts` — Register new tools
- `src/types/greynoise-response.ts` — Add `SessionResponse` type
- `src/utils/formatters.ts` — Add `formatSession()` formatter
- `src/utils/fetch.ts` — May need a `fetchGreyNoiseBinary()` variant for PCAP downloads (existing `fetchGreyNoise` assumes JSON)

### Tool parameters

**get-session:**
- `session_id` (required, string)
- `scope` (optional, string, default: "workspace")

**get-session-pcap:**
- `session_id` (required, string)
- `scope` (optional, string, default: "workspace")

**export-sessions-pcap:**
- `start_time` (required, string, ISO 8601)
- `end_time` (required, string, ISO 8601)
- `query` (optional, string, Lucene query)
- `size` (optional, number, default: 100)
- `sort_by` (optional, string, default: "lastPacket")
- `sort_desc` (optional, string, "true"/"false", default: "true")
- `scope` (optional, string, default: "workspace")

### Binary fetch pattern
The existing `fetchGreyNoise()` parses JSON. PCAP endpoints need a binary fetch that:
- Uses the same auth headers (`key` header)
- Returns an `ArrayBuffer` or `Buffer` instead of parsed JSON
- Writes to disk using `fs.writeFile`
- Returns the file path and size

## Open Questions

None — all key decisions resolved.
