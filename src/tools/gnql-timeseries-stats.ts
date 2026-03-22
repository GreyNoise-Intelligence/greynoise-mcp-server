import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GnqlTimeseriesStatsResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatGnqlTimeseriesStats } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGnqlTimeseriesStatsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "gnql-timeseries-stats",
    `Get the number of unique IPs matching a GNQL query per hour/day over a time range (Recall Stats).

Returns aggregated counts of unique IPs per time bucket, useful for trend analysis and understanding how scanning/attack activity changes over time.`,
    {
      query: z.string().describe("GNQL query string"),
      interval: z.enum(["hour", "day"]).describe("Time bucket interval ('hour' or 'day')"),
      start_time: z.string().optional().describe("Start of time range (ISO 8601 format)"),
      end_time: z.string().optional().describe("End of time range (ISO 8601 format)"),
    },
    async ({ query, interval, start_time, end_time }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const params: Record<string, any> = { query, interval };
        if (start_time) params.start_time = start_time;
        if (end_time) params.end_time = end_time;

        const data = await fetchGreyNoise<GnqlTimeseriesStatsResponse>(
          `v3/gnql/timeseries/stats`,
          apiBase,
          apiKey,
          params,
        );

        return {
          content: [
            {
              type: "text",
              text: formatGnqlTimeseriesStats(data),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error querying GNQL timeseries stats: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
