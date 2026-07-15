import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { gnqlTimeseriesStatsSchema } from "../greynoise/schemas/gnql.js";
import { formatGnqlTimeseriesStats } from "../utils/formatters/gnql.js";

export function registerGnqlTimeseriesStatsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "gnql-timeseries-stats",
    title: "GNQL Timeseries Stats",
    description: `Get the number of unique IPs matching a GNQL query per hour/day over a time range (Recall Stats).

Returns aggregated counts of unique IPs per time bucket, useful for trend analysis and understanding how scanning/attack activity changes over time.

interval must be 'hour' or 'day'. Time bounds use ISO 8601 format.`,
    inputSchema: {
      query: z.string().describe("GNQL query string"),
      interval: z.enum(["hour", "day"]).describe("Time bucket interval ('hour' or 'day')"),
      start_time: z.string().optional().describe("Start of time range (ISO 8601 format)"),
      end_time: z.string().optional().describe("End of time range (ISO 8601 format)"),
    },
    outputSchema: gnqlTimeseriesStatsSchema,
    handler: async ({ query, interval, start_time, end_time }, { client }) => {
      const params: Record<string, unknown> = { query, interval };
      if (start_time) params.start = start_time;
      if (end_time) params.end = end_time;
      const data = await client.get("v3/gnql/timeseries/stats", gnqlTimeseriesStatsSchema, params);
      return { text: formatGnqlTimeseriesStats(data), structured: data };
    },
  });
}
