import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { multiIpSchema } from "../greynoise/schemas.js";
import { formatMultiIPV3 } from "../utils/formatters/ip.js";

export function registerMultiIPCheckTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "multi-ip-check",
    title: "Multi-IP Check",
    description:
      "Check up to 10,000 IP addresses at once. Returns classification, business-service status, and trust level for each, plus a summary breakdown.",
    inputSchema: {
      ips: z
        .array(z.union([z.ipv4(), z.ipv6()]))
        .min(1)
        .max(10000)
        .describe("List of IP addresses to check (1-10,000, IPv4 or IPv6)"),
    },
    outputSchema: multiIpSchema,
    handler: async ({ ips }, { client }) => {
      const data = await client.post("v3/ip", multiIpSchema, { ips });
      return { text: formatMultiIPV3(data), structured: data };
    },
  });
}
