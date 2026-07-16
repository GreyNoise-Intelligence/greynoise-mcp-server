import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { ipContextSchema } from "../greynoise/schemas.js";
import { formatIPContext } from "../utils/formatters/ip.js";

export function registerLookupIPContextTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "lookup-ip-context",
    title: "Look Up IP Context",
    description:
      "Get detailed GreyNoise context for a single IP: classification, tags, Internet Scanner Intelligence (scan/HTTP/TLS/SSH/TCP raw data), Business Service Intelligence, geo, and network metadata.",
    inputSchema: { ip: z.union([z.ipv4(), z.ipv6()]).describe("IP address to look up (IPv4 or IPv6)") },
    outputSchema: ipContextSchema,
    handler: async ({ ip }, { client }) => {
      const data = await client.get(`v3/ip/${encodeURIComponent(ip)}`, ipContextSchema);
      return { text: formatIPContext(data), structured: data };
    },
  });
}
