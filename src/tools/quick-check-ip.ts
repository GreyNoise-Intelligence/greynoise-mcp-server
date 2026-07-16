import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { ipQuickCheckSchema } from "../greynoise/schemas.js";
import { formatQuickCheckV3 } from "../utils/formatters/ip.js";

export function registerQuickCheckIPTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "quick-check-ip",
    title: "Quick Check IP",
    description: "Get a fast, lightweight classification and business-service check for a single IP address.",
    inputSchema: { ip: z.union([z.ipv4(), z.ipv6()]).describe("IP address to look up (IPv4 or IPv6)") },
    outputSchema: ipQuickCheckSchema,
    handler: async ({ ip }, { client }) => {
      const data = await client.get(`v3/ip/${encodeURIComponent(ip)}`, ipQuickCheckSchema, { quick: "true" });
      return { text: formatQuickCheckV3(data), structured: data };
    },
  });
}
