import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { gnqlQuerySchema } from "../greynoise/schemas/gnql.js";
import { formatGnqlQueryResults } from "../utils/formatters/gnql.js";

export function registerGnqlQueryTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "gnql-query",
    title: "GNQL Query",
    description: `Search GreyNoise data using GNQL (GreyNoise Query Language). Returns full IP context results including raw scan data.

GNQL is a domain-specific query language that uses Lucene deep under the hood.

Facets:

- "ip" - The IP address of the scanning device
- "classification" - Whether the device has been categorized as unknown, benign, or malicious
- "first_seen" / "last_seen" - Date the device was first/most recently observed
- "actor" - The benign actor the device has been associated with (Shodan, Censys, etc)
- "tags" - Tags assigned to the device over the past 90 days
- "cve" - CVEs associated with the device
- "vpn" / "vpn_service" / "bot" / "tor" - Boolean/string indicators
- "metadata.category" - Network category (business, isp, hosting, education, mobile)
- "metadata.source_country" / "metadata.source_country_code" - Source location
- "metadata.organization" / "metadata.asn" / "metadata.rdns" - Network info
- "raw_data.scan.port" / "raw_data.scan.protocol" - Scan targets
- "raw_data.web.paths" / "raw_data.web.useragents" - HTTP activity
- "raw_data.ja3.fingerprint" / "raw_data.hassh.fingerprint" - TLS/SSH fingerprints

Examples:

- "classification:malicious last_seen:1d" - Malicious IPs seen in last day
- "tags:Mirai" - Devices tagged as Mirai
- "raw_data.scan.port:445 metadata.os:Windows*" - Windows hosts scanning port 445
- "cve:CVE-2021-30461" - Devices associated with a CVE
- "source_country:Iran destination_country:Ukraine single_destination:true" - Targeted scanning

Results are paginated. Use the scroll parameter to retrieve additional pages.`,
    inputSchema: {
      query: z.string().describe("GNQL query string"),
      size: z.number().min(1).max(10000).default(25).optional().describe("Results per page (default: 25, max: 10000)"),
      scroll: z.string().optional().describe("Pagination scroll token from a previous response"),
    },
    outputSchema: gnqlQuerySchema,
    handler: async ({ query, size, scroll }, { client }) => {
      const params: Record<string, unknown> = { query, size: size ?? 25 };
      if (scroll) params.scroll = scroll;
      const data = await client.get("v3/gnql", gnqlQuerySchema, params);
      return { text: formatGnqlQueryResults(data), structured: data };
    },
  });
}
