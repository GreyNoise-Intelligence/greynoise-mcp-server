import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GnqlTimeseriesResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatGnqlTimeseries } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGnqlTimeseriesTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "gnql-timeseries",
    `Retrieve hourly GNQL records for a time range. Enables temporal analysis of IP activity matching any GNQL query (Recall).

Returns IP records bucketed by hour, useful for investigating when specific IPs were active and what they were doing.`,
    {
      query: z.string().describe("GNQL query string"),
      start_time: z.string().optional().describe("Start of time range (ISO 8601 format, e.g. 2025-01-15T00:00:00Z)"),
      end_time: z.string().optional().describe("End of time range (ISO 8601 format)"),
      size: z.number().min(1).max(10000).default(25).optional().describe("Results per hourly bucket (default: 25)"),
    },
    async ({ query, start_time, end_time, size }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const params: Record<string, any> = { query, size: size ?? 25 };
        if (start_time) params.start_time = start_time;
        if (end_time) params.end_time = end_time;

        const data = await fetchGreyNoise<GnqlTimeseriesResponse>(
          `v3/gnql/timeseries`,
          apiBase,
          apiKey,
          params,
        );

        return {
          content: [
            {
              type: "text",
              text: formatGnqlTimeseries(data),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error querying GNQL timeseries: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
