import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { gnqlTimeseriesSchema, gnqlTimeseriesResultSchema } from "../greynoise/schemas/gnql.js";
import { formatGnqlTimeseries } from "../utils/formatters/gnql.js";

export function registerGnqlTimeseriesTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "gnql-timeseries",
    title: "GNQL Timeseries",
    description: `Retrieve hourly GNQL records for a time range. Enables temporal analysis of IP activity matching any GNQL query (Recall).

Returns IP records bucketed by hour, useful for investigating when specific IPs were active and what they were doing.

Time bounds use ISO 8601 (e.g. 2025-01-15T00:00:00Z). size is results per hourly bucket (default: 25, max: 10000).`,
    inputSchema: {
      query: z.string().describe("GNQL query string"),
      start_time: z.string().optional().describe("Start of time range (ISO 8601 format, e.g. 2025-01-15T00:00:00Z)"),
      end_time: z.string().optional().describe("End of time range (ISO 8601 format)"),
      size: z.number().min(1).max(10000).default(25).optional().describe("Results per hourly bucket (default: 25)"),
    },
    outputSchema: gnqlTimeseriesResultSchema,
    handler: async ({ query, start_time, end_time, size }, { client }) => {
      const params: Record<string, unknown> = { query, size: size ?? 25 };
      if (start_time) params.start = start_time;
      if (end_time) params.end = end_time;
      const data = await client.get("v3/gnql/timeseries", gnqlTimeseriesSchema, params);
      return { text: formatGnqlTimeseries(data), structured: { buckets: data } };
    },
  });
}
