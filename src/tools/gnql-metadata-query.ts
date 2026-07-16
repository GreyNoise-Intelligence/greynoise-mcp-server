import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { gnqlQuerySchema } from "../greynoise/schemas/gnql.js";
import { formatGnqlQueryResults, formatGnqlMetadataCsv } from "../utils/formatters/gnql.js";

export function registerGnqlMetadataQueryTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "gnql-metadata-query",
    title: "GNQL Metadata Query",
    description: `Search GreyNoise data using GNQL, returning IP metadata without raw scan data. Lighter and faster than gnql-query.

Supports the same GNQL query syntax as gnql-query. Use this when you need IP classification, tags, and metadata but not raw scan details (ports, fingerprints, HTTP paths).

Results are paginated via the scroll token. Set quick=true to return only IP and classification/trust level.

Set format="csv" for spreadsheet-friendly CSV output (columns: ip, classification, actor, organization, source_country, tags, ports, bsi_found, bsi_name, bsi_trust_level); default "json" renders a Markdown summary. structuredContent is always the full JSON regardless of format.`,
    inputSchema: {
      query: z.string().describe("GNQL query string"),
      size: z.number().min(1).max(10000).default(25).optional().describe("Results per page (default: 25, max: 10000)"),
      scroll: z.string().optional().describe("Pagination scroll token from a previous response"),
      quick: z.boolean().optional().describe("If true, return only IP and classification/trust level"),
      format: z.enum(["json", "csv"]).default("json").describe("Output format for the text response (default: json)"),
    },
    outputSchema: gnqlQuerySchema,
    handler: async ({ query, size, scroll, quick, format }, { client }) => {
      const params: Record<string, unknown> = { query, size: size ?? 25 };
      if (scroll) params.scroll = scroll;
      if (quick) params.quick = "true";
      const data = await client.get("v3/gnql/metadata", gnqlQuerySchema, params);
      const text = format === "csv" ? formatGnqlMetadataCsv(data) : formatGnqlQueryResults(data);
      return { text, structured: data };
    },
  });
}
