import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { randomUUID } from "crypto";
import { tmpdir } from "os";
import { join } from "path";
import { defineTool } from "./define-tool.js";
import {
  sessionsResponseSchema,
  sessionFieldsResponseSchema,
  sessionCountsResponseSchema,
  sessionConnectionsResponseSchema,
  sessionTimeseriesResponseSchema,
  sessionUniqueValuesSchema,
  sessionExportFileSchema,
} from "../greynoise/schemas/sessions-search.js";
import {
  formatSessionsSearch,
  formatSessionFields,
  formatSessionCounts,
  formatSessionConnections,
  formatSessionTimeseries,
  formatSessionUniqueValues,
} from "../utils/formatters/sessions-search.js";

const scope = z.enum(["workspace", "demo"]).optional().describe("Data scope: workspace (default) or demo");
const startTime = z.string().describe("Start time, ISO 8601 (e.g. 2025-01-01T00:00:00Z)");
const endTime = z.string().describe("End time, ISO 8601 (e.g. 2025-01-07T23:59:59Z)");
const query = z.string().optional().describe("Lucene query string to filter sessions");
const bool = (dflt: boolean, desc: string) => z.boolean().optional().default(dflt).describe(desc);
const b = (v: boolean | undefined) => (v === undefined ? undefined : String(v));

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export function registerSessionSearchTools(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "search-sessions",
    title: "Search Sessions",
    description:
      "Query and filter GreyNoise sensor network sessions over a time range. Returns a paginated list with source/destination IPs and ports, timestamps, byte/packet counts, and classification. Use Lucene query syntax (e.g. destination.port:443).",
    inputSchema: {
      start_time: startTime,
      end_time: endTime,
      query,
      page: z.number().int().min(1).optional().describe("Page number (default: 1)"),
      page_size: z.number().int().min(1).max(100).optional().describe("Results per page, 1-100 (default: 25)"),
      sort_by: z.string().optional().describe("Field to sort by (default: lastPacket)"),
      sort_desc: bool(true, "Sort descending (default: true)"),
      scope,
    },
    outputSchema: sessionsResponseSchema,
    handler: async ({ start_time, end_time, query, page, page_size, sort_by, sort_desc, scope }, { client }) => {
      const data = await client.get("v3/sessions", sessionsResponseSchema, {
        start_time,
        end_time,
        query,
        page,
        page_size,
        sort_by,
        sort_desc: b(sort_desc),
        scope,
      });
      return { text: formatSessionsSearch(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "session-fields",
    title: "List Session Fields",
    description:
      "Discover the queryable session field schema: field identifiers, types, groups, and whether each is sortable. Use these field names when building session queries, counts, connections, timeseries, and unique-value requests.",
    inputSchema: { scope },
    outputSchema: sessionFieldsResponseSchema,
    handler: async ({ scope }, { client }) => {
      const data = await client.get("v3/sessions/fields", sessionFieldsResponseSchema, { scope });
      return { text: formatSessionFields(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "session-counts",
    title: "Session Counts",
    description:
      "Aggregate session counts grouped by one or more fields over a time range. Multiple fields produce nested (drill-down) buckets.",
    inputSchema: {
      start_time: startTime,
      end_time: endTime,
      fields: z.string().describe("Comma-separated fields to aggregate on (e.g. source.ip,destination.port)"),
      query,
      size: z.number().int().min(1).max(100).optional().describe("Buckets per aggregation level, 1-100 (default: 10)"),
      scope,
    },
    outputSchema: sessionCountsResponseSchema,
    handler: async ({ start_time, end_time, fields, query, size, scope }, { client }) => {
      const data = await client.get("v3/sessions/counts", sessionCountsResponseSchema, {
        start_time,
        end_time,
        fields,
        query,
        size,
        scope,
      });
      return { text: formatSessionCounts(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "session-connections",
    title: "Session Connections",
    description:
      "Build a connection graph (nodes + links) between a source field and a destination field over a time range. Useful for visualizing communication relationships.",
    inputSchema: {
      start_time: startTime,
      end_time: endTime,
      query,
      src_field: z.string().optional().describe("Source field to aggregate on (default: source.ip)"),
      dest_field: z.string().optional().describe("Destination field to aggregate on (default: destination.ip)"),
      max_nodes: z.number().int().min(1).max(10000).optional().describe("Max nodes to return, 1-10000 (default: 100)"),
      min_connections: z.number().int().min(1).optional().describe("Min connections to include a node (default: 1)"),
      scope,
    },
    outputSchema: sessionConnectionsResponseSchema,
    handler: async ({ start_time, end_time, query, src_field, dest_field, max_nodes, min_connections, scope }, { client }) => {
      const data = await client.get("v3/sessions/connections", sessionConnectionsResponseSchema, {
        start_time,
        end_time,
        query,
        src_field,
        dest_field,
        max_nodes,
        min_connections,
        scope,
      });
      return { text: formatSessionConnections(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "session-timeseries",
    title: "Session Timeseries",
    description:
      "Return session volume over time, optionally grouped by a field. Without a field, returns a single timeseries; with a field, returns per-group timeseries.",
    inputSchema: {
      start_time: startTime,
      end_time: endTime,
      query,
      field: z.string().optional().describe("Field to group the timeseries by"),
      size: z.number().int().min(1).max(100).optional().describe("Groups to return when field is set, 1-100 (default: 10)"),
      interval: z.enum(["auto", "1s", "1m", "1h", "1d"]).optional().describe("Time bucket interval (default: auto)"),
      scope,
    },
    outputSchema: sessionTimeseriesResponseSchema,
    handler: async ({ start_time, end_time, query, field, size, interval, scope }, { client }) => {
      const data = await client.get("v3/sessions/timeseries", sessionTimeseriesResponseSchema, {
        start_time,
        end_time,
        query,
        field,
        size,
        interval,
        scope,
      });
      return { text: formatSessionTimeseries(data), structured: data };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "session-unique-values",
    title: "Session Unique Values",
    description:
      "Return the distinct values of a single session field over a time range (server produces a CSV). Optionally include per-value counts. Useful for extracting distinct IPs, ports, or other field values matching a query.",
    inputSchema: {
      start_time: startTime,
      end_time: endTime,
      field: z.string().describe("Field to get unique values for (e.g. source.ip)"),
      query,
      include_counts: bool(false, "Include per-value counts in the output (default: false)"),
      scope,
    },
    outputSchema: sessionUniqueValuesSchema,
    handler: async ({ start_time, end_time, field, query, include_counts, scope }, { client, log }) => {
      await log("info", `Fetching unique values for ${field}...`);
      const raw = await client.getText("v3/sessions/unique", {
        start_time,
        end_time,
        field,
        query,
        include_counts: b(include_counts),
        scope,
      });
      const parsed = parseCsv(raw);
      const header = parsed.length > 0 ? parsed[0].map((h) => h.trim().toLowerCase()) : [];
      const countIdx = header.findIndex((h) => h === "count" || h.endsWith("count"));
      const valueIdx = header.findIndex((_, i) => i !== countIdx);
      const vIdx = valueIdx >= 0 ? valueIdx : 0;
      const cIdx = countIdx >= 0 ? countIdx : include_counts ? 1 : -1;
      const rows = parsed
        .slice(1)
        .map((r) => {
          const value = (r[vIdx] ?? "").trim();
          const rec: { value: string; count?: number } = { value };
          if (cIdx >= 0 && r[cIdx] !== undefined) {
            const n = Number(r[cIdx].trim());
            if (!Number.isNaN(n)) rec.count = n;
          }
          return rec;
        })
        .filter((rec) => rec.value.length > 0);
      const values = rows.map((r) => (r.count !== undefined ? `${r.value} (${r.count})` : r.value));
      const structured = { field, include_counts: !!include_counts, total: rows.length, values, rows };
      if (rows.length === 0) {
        return { text: `No unique values found for ${field} in the given range.`, structured };
      }
      return { text: formatSessionUniqueValues(structured), structured };
    },
  });

  defineTool(server, apiBase, apiKeyGetter, {
    name: "export-session-data",
    title: "Export Session Data",
    description:
      "Download a single session's data for a given session ID as a PCAP or raw payload (type: pcap | rawSource | rawDestination; default pcap). Saves the binary to a temp file and returns its path. Not available when scope=demo.",
    inputSchema: {
      session_id: z.string().min(1).describe("The unique session identifier"),
      type: z
        .enum(["pcap", "rawSource", "rawDestination"])
        .optional()
        .describe("Export format: pcap | rawSource | rawDestination (default: pcap)"),
      scope,
    },
    outputSchema: sessionExportFileSchema,
    annotations: { readOnlyHint: false },
    handler: async ({ session_id, type, scope }, { client, log }) => {
      const fmt = type ?? "pcap";
      const ext = fmt === "pcap" ? "pcap" : "bin";
      const outputPath = join(tmpdir(), `greynoise-session-${randomUUID()}.${ext}`);
      await log("info", `Exporting session ${session_id} as ${fmt}...`);
      const { filePath, fileSize } = await client.getBinary(
        `v3/sessions/${encodeURIComponent(session_id)}/export`,
        outputPath,
        { type, scope },
        fmt === "pcap" ? "application/vnd.tcpdump.pcap" : "application/octet-stream",
      );
      const structured = { filePath, fileSize, type: fmt };
      let text = `# Session Data Export\n\n`;
      text += `**Session**: ${session_id}\n**Type**: ${fmt}\n**File**: ${filePath}\n**Size**: ${fileSize.toLocaleString()} bytes\n`;
      return { text, structured };
    },
  });
}
