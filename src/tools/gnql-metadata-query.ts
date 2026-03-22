import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GnqlMetadataQueryResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatGnqlQueryResults } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGnqlMetadataQueryTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "gnql-metadata-query",
    `Search GreyNoise data using GNQL, returning IP metadata without raw scan data. Lighter and faster than gnql-query.

Supports the same GNQL query syntax as gnql-query. Use this when you need IP classification, tags, and metadata but not raw scan details (ports, fingerprints, HTTP paths).

Supports CSV output format via the format parameter. Results are paginated.`,
    {
      query: z.string().describe("GNQL query string"),
      size: z.number().min(1).max(10000).default(25).optional().describe("Results per page (default: 25, max: 10000)"),
      scroll: z.string().optional().describe("Pagination scroll token from a previous response"),
      quick: z.boolean().optional().describe("If true, return only IP and classification/trust level"),
      format: z.enum(["json", "csv"]).optional().describe("Output format (default: json)"),
    },
    async ({ query, size, scroll, quick, format }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const params: Record<string, any> = { query, size: size ?? 25 };
        if (scroll) params.scroll = scroll;
        if (quick) params.quick = "true";
        if (format) params.format = format;

        // For CSV format, return raw text
        if (format === "csv") {
          const data = await fetchGreyNoise<any>(
            `v3/gnql/metadata`,
            apiBase,
            apiKey,
            params,
          );
          return {
            content: [
              {
                type: "text",
                text: typeof data === "string" ? data : JSON.stringify(data),
              },
            ],
          };
        }

        const data = await fetchGreyNoise<GnqlMetadataQueryResponse>(
          `v3/gnql/metadata`,
          apiBase,
          apiKey,
          params,
        );

        return {
          content: [
            {
              type: "text",
              text: formatGnqlQueryResults(data),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error querying GNQL metadata: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
